A professional, containerized backend service designed to automate document intelligence. This project allows users to securely upload PDF documents and receive intelligent, AI-generated summaries using Llama 3.
Key Features:
User Authentication: Secure registration and login using JWT (JSON Web Tokens) and bcrypt password hashing.
Automated PDF Processing: Seamless text extraction from uploaded PDF files.
AI Summarization: Integration with Groq (Llama 3.3-70b) to generate concise, 3-bullet point summaries.
Containerized Architecture: Fully Dockerized setup for consistent "run anywhere" performance.
Relational Database: Persistent storage for users and document metadata using SQLAlchemy and SQLite.
Tech Stack:
Language: Python 3.11+
Framework: FastAPI
AI Engine: Groq Cloud API (Llama 3)
Database: SQLAlchemy ORM
DevOps: Docker & Docker Compose
Getting Started:
1. Prerequisites
Docker and Docker Desktop installed.
A Groq API Key.
2. Environment Setup
Create a .env file in the root directory and add your credentials:
Plaintext
GROQ_API_KEY=########
3. Installation
Run the following command to build and start the entire stack:
Bash
docker-compose up --build
4. API Usage
Once the container is running, access the interactive API documentation at:

