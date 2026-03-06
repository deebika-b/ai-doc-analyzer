# AI-SaaS Document Analyser 🤖📄

A modern, containerized Backend application designed for automated document analysis using Large Language Models (LLMs).

## 🚀 Overview
This project provides a scalable API to upload, process, and analyze documents using Generative AI. It leverages **Llama 3** to extract insights and **FastAPI** for high-performance data handling.

## 🛠️ Tech Stack
* **Language:** Python 3.10+
* **Framework:** FastAPI (Asynchronous)
* **AI Models:** Llama 3 via Groq API / LangChain
* **Database:** PostgreSQL (SQLAlchemy ORM)
* **Containerization:** Docker & Docker-Compose
* **Authentication:** JWT (JSON Web Tokens) with bcrypt

## ✨ Key Features
* **AI Extraction:** Automatically extracts key metadata and summaries from uploaded text.
* **Secure Auth:** Full User Sign-up/Login flow with encrypted passwords.
* **Scalable Architecture:** Built with a clean separation of concerns (Models, Schemas, Routes).
* **Dockerized:** Ready for deployment with a single command.

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/deebika-b/ai-doc-analyzer.git](https://github.com/deebika-b/ai-doc-analyzer.git)
   cd ai-doc-analyzer

 2. Run with Docker:
  docker-compose up --build
  The API will be available at http://localhost:8000
 3. Interactive Documentation:
   Visit http://localhost:8000/docs to see the Swagger UI.

Author: Deebika Bagavathiraj
Focus: Backend Engineering | Generative AI | Cloud-Native Apps
