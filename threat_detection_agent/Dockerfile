FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY llm_client.py system_prompt.py log_analysis.py api.py ./

ENV ANTHROPIC_API_KEY=""

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# API HTTP par defaut (docker run <image>). Pour lancer le mode CLI (batch)
# a la place, remplacer entierement la commande :
#   docker run -e ANTHROPIC_API_KEY=... <image> \
#     python log_analysis.py --source file --path /app/logs.txt
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
