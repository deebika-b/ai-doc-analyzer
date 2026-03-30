# 📄 AI-Powered SaaS Document Analyzer

A full-stack SaaS prototype that allows users to upload PDF documents and receive intelligent summaries using the **Groq Llama 3.3 API**. Built with a focus on modern DevOps practices, including containerization and microservices architecture.

---
_**Schnellstart (Quick Start)
Stellen Sie sicher, dass Docker gestartet ist. Führen Sie dann die folgenden Befehle im Terminal aus: 

Projekt-Ordner öffnen:
cd ai-doc-analyzer

Container bauen und starten:
docker-compose up --build

Anwendung öffnen:
Öffnen Sie Ihren Browser unter: http://localhost:8501/

Hinweis: Das Backend läuft auf Port 8000 und das Frontend auf Port 8501.**

## 🚀 Quick Start (For Recruiters)

To get this project running in less than 2 minutes, follow these steps:

### 1. Prerequisites
* **Docker & Docker Compose** installed.
* A **Groq API Key** (Get one at [console.groq.com](https://console.groq.com/)).

### 2. Environment Setup
Create a `.env` file in the root directory:
```env
GROQ_API_KEY=your_api_key_here
SECRET_KEY=your_random_jwt_secret

3. Launch the App
Run the following command in your terminal:
docker-compose up --build

4. Access the Services
Frontend (Streamlit): http://localhost:8501

Backend API (FastAPI): http://localhost:8000/docs (Interactive Swagger UI)

🛠️ Technical Stack:
Layer	Technology
Frontend	Streamlit (Python-based interactive UI)
Backend	FastAPI (High-performance ASGI framework)
AI Engine	Groq (Llama 3.3-70B Model)
Database	SQLite (SQLAlchemy ORM)
Authentication	JWT (JSON Web Tokens) & Bcrypt password hashing
Deployment	Docker & Docker Compose

Key Features:
Secure Authentication: User registration and login system with encrypted password storage.

PDF Extraction: Automated text extraction from uploaded PDF files using pypdf.

AI Summarization: Real-time processing via Groq's high-speed inference engine.

Microservices Architecture: Fully decoupled frontend and backend services communicating via a internal Docker network.

Persistent Storage: Document metadata and AI summaries stored via SQLAlchemy.

📁 Project Structure
├── app/
│   ├── main.py          # FastAPI Backend (Routes, AI Logic, DB Models)
│   └── __init__.py
├── streamlit_app.py     # Streamlit Frontend (UI & API Integration)
├── Dockerfile           # Multi-service build instructions
├── docker-compose.yml   # Container orchestration
├── requirements.txt     # Python dependencies
└── .env                 # Environment variables (Excluded from Git)

# 📄 AI-Powered SaaS Document Analyzer

(dashboard.png)-------CHECK MY SCREENSHOT HOW IT WORKS!...

## 🚀 Quick Start (For Recruiters)
...

👨‍💻 Author
Deebika Bagavathiraj
