# Ramy Cyberdefense — Kafka Consumer

Service qui consomme un topic Kafka de logs et les fait analyser par l'API LogAnalyzer
(`../threat_detection_agent`, `POST /analyze/logs`). Il tourne dans son propre conteneur,
sur le réseau docker partagé `ramy-net` (comme `ramy-api` et `ramy-dashboard`).

```
Kafka (topic logs) ──► ramy-kafka-consumer ──POST /analyze/logs──► ramy-api ──► Claude
                               │
                               └──► alertes : logs du conteneur + topic ALERTS_TOPIC (optionnel)
```

## Fonctionnement

- **Lots** : les messages sont regroupés **par topic** jusqu'à `BATCH_MAX_LINES` lignes ou
  `BATCH_MAX_WAIT_S` secondes, puis envoyés en un seul appel à l'API. Le LLM ne corrèle
  que les lignes d'un même appel : garder `BATCH_MAX_LINES` aligné sur `LOG_BATCH_SIZE` de l'API.
- **Fiabilité (au moins une fois)** : les offsets ne sont commités qu'après une analyse
  réussie (et la publication des alertes). Si l'API échoue, les partitions concernées sont
  mises en pause et le lot est réessayé (5 s, 10 s, 20 s… jusqu'à 5 min) ; rien n'est perdu.
- **Arrêt propre** : sur `docker stop`, le lot en cours est analysé avant l'arrêt.

### Formats de messages acceptés

| Message Kafka                                        | Lignes envoyées à l'API                        |
|------------------------------------------------------|------------------------------------------------|
| Texte brut (une ou plusieurs lignes)                 | chaque ligne non vide                          |
| Objet JSON `{"timestamp", "host", "source", "message"}` | `"<timestamp> <host> <source>: <message>"`  |
| Tableau JSON d'entrées                               | une ligne par entrée                           |
| Enveloppe `{"hostname": ..., "logs": [entrées]}`     | une ligne par entrée (host de l'enveloppe)     |

Variantes de champs reconnues : `timestamp/@timestamp/time/ts`, `message/msg/log/line`,
`source/service/container/program`, `hostname/host`. Un objet sans champ message est
envoyé tel quel en JSON. L'horodatage est placé en tête de ligne : le LLM s'en sert pour
remplir le champ `timestamp` des menaces.

### Alertes publiées (`ALERTS_TOPIC`)

Un message par lot contenant au moins une alerte, clé = topic source :
```json
{"source_topic": "logs", "timestamp": "...", "total_analyzed": 100, "total_alerts": 2, "alerts": [...]}
```

## Démarrage

Prérequis : le réseau `ramy-net`, l'API `ramy-api` et Kafka joignables sur ce réseau.

Toute la configuration est dans `kafka_consumer/.env` (non copié dans l'image, ignoré par git) :
l'adapter (au minimum `KAFKA_BOOTSTRAP_SERVERS` et `KAFKA_TOPIC`), puis :

```bash
cd /Users/user/Documents/Ramy-cyber
docker build -t ramy-kafka-consumer kafka_consumer
docker run -d --name ramy-kafka-consumer --network ramy-net \
  --env-file kafka_consumer/.env \
  ramy-kafka-consumer

docker logs -f ramy-kafka-consumer   # suivre les analyses et alertes
```

## Variables du fichier `.env`

Format `docker --env-file` : une variable `CLE=valeur` par ligne, sans guillemets ni
commentaire en fin de ligne. En local (`python consumer.py`), le `.env` est chargé par
`python-dotenv`. Les défauts ci-dessous s'appliquent si une variable est absente.

| Variable                  | Défaut                  | Rôle                                                            |
|---------------------------|-------------------------|-----------------------------------------------------------------|
| `KAFKA_BOOTSTRAP_SERVERS` | — (obligatoire)         | Brokers Kafka, ex. `kafka-1:9092,kafka-2:9092`                  |
| `KAFKA_TOPIC`             | `logs`                  | Topic(s) à consommer, séparés par des virgules ; `^…` = regex   |
| `KAFKA_GROUP_ID`          | `ramy-threat-analysis`  | Groupe de consommateurs (plusieurs conteneurs = charge répartie) |
| `KAFKA_AUTO_OFFSET_RESET` | `latest`                | Premier démarrage du groupe : `latest` ignore l'historique, `earliest` analyse tout (coût LLM !) |
| `API_URL`                 | `http://ramy-api:8000`  | URL de l'API LogAnalyzer                                        |
| `API_TIMEOUT`             | `900`                   | Timeout (s) d'un appel d'analyse                                |
| `THRESHOLD`               | `HAUTE`                 | Seuil d'alerte : `NORMALE`, `FAIBLE`, `MOYENNE`, `HAUTE`, `CRITIQUE` |
| `BATCH_MAX_LINES`         | `100`                   | Lignes max par appel à l'API                                    |
| `BATCH_MAX_WAIT_S`        | `30`                    | Attente max (s) avant d'envoyer un lot incomplet                |
| `ALERTS_TOPIC`            | vide (désactivé)        | Topic où publier les alertes                                    |

## Arrêt

```bash
docker stop ramy-kafka-consumer && docker rm ramy-kafka-consumer
```
