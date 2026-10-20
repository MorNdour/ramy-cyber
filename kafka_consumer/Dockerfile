FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY consumer.py .

# Configuration fournie au lancement via le fichier .env (non copie dans l'image) :
#   docker run --env-file kafka_consumer/.env ...

CMD ["python", "consumer.py"]
