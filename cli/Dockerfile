FROM python:3.11-slim
RUN apt-get update && apt-get install -y git gcc python3-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN touch ai/__init__.py scanner/__init__.py remediation/__init__.py
EXPOSE 5001
CMD ["python", "service.py"]
