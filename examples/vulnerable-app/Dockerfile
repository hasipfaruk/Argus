# Intentionally insecure Dockerfile for the IaC scanner demo.
FROM python:latest

WORKDIR /app
COPY . /app

RUN pip install -r requirements.txt

# No USER directive: container runs as root (iac scanner: CWE-250).
EXPOSE 5000
CMD ["python", "app.py"]
