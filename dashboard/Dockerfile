FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY .streamlit/ .streamlit/
COPY app.py ramy-icon.png ./

# URL de l'API LogAnalyzer. "ramy-api" est le nom du conteneur de l'API, resolu par
# le DNS du reseau docker partage (surcharger avec -e API_URL=... si besoin).
ENV API_URL="http://ramy-api:8000"

EXPOSE 8501

HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
