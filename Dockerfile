FROM python:3.11-slim

WORKDIR /app

# Install libraries
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy everything into the /app folder
COPY . .

# Ensure uploads exists
RUN mkdir -p /app/uploads

# Points to 'main.py' inside your local 'app' folder
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]