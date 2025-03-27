# app/Dockerfile
FROM python:3.11.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8001

# Combine commands into a single CMD
CMD ["python3.11", "-m", "flask", "run", "--host=0.0.0.0", "--port=8001"]