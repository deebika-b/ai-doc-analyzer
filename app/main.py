import os
import bcrypt
import uvicorn  # Added missing import
from datetime import datetime, timedelta
from typing import List

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pypdf import PdfReader
from jose import JWTError, jwt
from dotenv import load_dotenv
from groq import Groq

# 1. Configuration & Environment
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

client = Groq(api_key=GROQ_API_KEY)

# 2. Database Setup (SQLite) - DEFINED BEFORE MODELS
SQLALCHEMY_DATABASE_URL = "sqlite:////tmp/sql_app.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 3. Database Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    content = Column(Text)
    summary = Column(Text, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"))

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# 4. CORS Setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# 5. Helpers
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password: str):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# 6. Routes
@app.get("/")
def health_check():
    return {"status": "online", "message": "AI SaaS Backend is running"}

@app.post("/register")
def register(email: str, password: str, db: Session = Depends(get_db)):
    user_exists = db.query(User).filter(User.email == email).first()
    if user_exists:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    new_user = User(email=email, hashed_password=get_password_hash(password))
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload")
async def upload_document(
    file: UploadFile = File(...), 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    try:
        reader = PdfReader(file.file)
        text_content = ""
        for page in reader.pages:
            text_content += page.extract_text()
            
        new_doc = Document(
            filename=file.filename,
            content=text_content,
            owner_id=current_user.id
        )
        db.add(new_doc)
        db.commit()
        db.refresh(new_doc)
        return {"id": new_doc.id, "filename": file.filename}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process PDF: {str(e)}")

@app.post("/summarize/{doc_id}")
async def summarize_document(
    doc_id: int, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    doc = db.query(Document).filter(Document.id == doc_id, Document.owner_id == current_user.id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a professional assistant that summarizes documents."},
                {"role": "user", "content": f"Summarize:\n\n{doc.content[:6000]}"}
            ],
            model="llama-3.3-70b-versatile",
        )
        summary = chat_completion.choices[0].message.content
        doc.summary = summary
        db.commit()
        return {"summary": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Summarization failed: {str(e)}")

if __name__ == "__main__":
    # Removed the trailing dot
    uvicorn.run(app, host="0.0.0.0", port=8000)