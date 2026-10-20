# Ramy Cyberdefense — Dashboard

Dashboard Streamlit de monitoring des analyses de l'API LogAnalyzer (`../threat_detection_agent`).

Les deux services tournent dans des conteneurs séparés, reliés par un réseau docker
partagé : le dashboard joint l'API par le nom de son conteneur (`http://ramy-api:8000`).

## Démarrage

```bash
cd /Users/user/Documents/Ramy-cyber

# 1. Réseau partagé (une seule fois)
docker network create ramy-net

# 2. API LogAnalyzer
docker build -t ramy-api threat_detection_agent
docker run -d --name ramy-api --network ramy-net \
  --env-file threat_detection_agent/.env \
  -p 8000:8000 \
  ramy-api

# 3. Dashboard
docker build -t ramy-dashboard dashboard
docker run -d --name ramy-dashboard --network ramy-net \
  -p 8501:8501 \
  ramy-dashboard
```

- Dashboard : http://localhost:8501
- API : http://localhost:8000/docs (le `-p 8000:8000` est optionnel, le dashboard n'en a pas besoin)

Le nom `--name ramy-api` doit correspondre à `API_URL` (défaut `http://ramy-api:8000`).
Pour un autre nom : `docker run ... -e API_URL=http://<nom>:8000 ramy-dashboard`.

Pour analyser un répertoire local via « Répertoire serveur », monter les logs dans le
conteneur de l'API (`-v /chemin/vers/logs:/data/logs:ro`) et saisir `/data/logs` dans le dashboard.

## Arrêt

```bash
docker rm -f ramy-dashboard ramy-api
docker network rm ramy-net   # optionnel
```

## Variables d'environnement du dashboard

| Variable      | Défaut                  | Rôle                                         |
|---------------|-------------------------|----------------------------------------------|
| `API_URL`     | `http://ramy-api:8000`  | URL de l'API LogAnalyzer                     |
| `API_TIMEOUT` | `900`                   | Timeout (s) d'une requête d'analyse          |
