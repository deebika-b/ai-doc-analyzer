# 📑 AI Document Analyzer

A full-stack AI application that allows users to upload PDF documents and receive intelligent summaries and insights using **Groq (Llama-3)**. Built with a focus on secure authentication and containerized deployment.



## 🚀 Key Features
* **User Authentication:** Secure Sign-up and Login using **OAuth2**, **JWT tokens**, and **Bcrypt** password hashing.
* **PDF Processing:** Extracts text content from uploaded PDFs using `pypdf`.
* **AI Insights:** Generates high-speed summaries via the **Groq Cloud API**.
* **Persistent Storage:** Uses **SQLAlchemy** with SQLite to manage users and document metadata.
* **Containerized:** Fully Dockerized for "one-command" setup.

---

## 🛠️ Tech Stack
* **Frontend:** Streamlit
* **Backend:** FastAPI (Python)
* **Database:** SQLite + SQLAlchemy ORM
* **AI Model:** Llama-3 (via Groq)
* **DevOps:** Docker, Docker Compose

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/deebika-b/ai-doc-analyzer.git](https://github.com/deebika-b/ai-doc-analyzer.git)
cd ai-doc-analyzer

Configure Environment Variables

**2.Create a .env file in the root directory:**

Plaintext
GROQ_API_KEY=your_groq_api_key_here
SECRET_KEY=your_random_secret_key_for_jwt


**3. Run with Docker 🐳**

The easiest way to run the app is using Docker Compose. This starts both the Backend and Frontend automatically.

Bash
docker-compose up --build

**📖 How to Use**
OPEN YOUR BROWSER:
Backend API: http://localhost:8000/docs (Swagger UI)
Frontend UI: http://localhost:8501 (Streamlit).

Register a new account.

Login with your credentials.

Upload any PDF file.

View the AI-generated summary of your document.

**📁 Project Structure**
main.py: FastAPI backend, database models, and AI logic.

app.py: Streamlit frontend and UI components.

requirements.txt: Python dependencies.

docker-compose.yml: Multi-container orchestration.

sql_app.db: (Auto-generated) SQLite database file.

**👨‍💻 Developed By**
Deebika B Full Stack Engineer | AI Enthusiast
