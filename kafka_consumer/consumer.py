"""Service consumer Kafka : consomme un topic de logs et les fait analyser par l'API LogAnalyzer.

Les messages sont regroupes par topic en lots de lignes (BATCH_MAX_LINES lignes ou
BATCH_MAX_WAIT_S secondes), envoyes a POST /analyze/logs, puis les alertes retournees
sont journalisees et, si ALERTS_TOPIC est defini, publiees sur Kafka. Les offsets ne
sont commites qu'apres une analyse reussie (livraison au moins une fois).

Configuration : fichier .env (charge par python-dotenv en local, passe via
docker run --env-file en conteneur), voir Config.from_env() et README.md.
"""

import json
import logging
import os
import signal
import time
from dataclasses import dataclass, field

import requests
from confluent_kafka import Consumer, KafkaError, Message, Producer, TopicPartition
from dotenv import load_dotenv

logger = logging.getLogger("kafka_consumer")

_TIMESTAMP_KEYS = ("timestamp", "@timestamp", "time", "ts")
_MESSAGE_KEYS = ("message", "msg", "log", "line")
_SOURCE_KEYS = ("source", "service", "container", "program")
_HOST_KEYS = ("hostname", "host")

_MAX_RETRY_DELAY_S = 300.0


@dataclass
class Config:
    """Parametres du consumer, lus depuis l'environnement."""

    bootstrap_servers: str
    topics: list[str]
    group_id: str
    auto_offset_reset: str
    api_url: str
    api_timeout: int
    threshold: str
    batch_max_lines: int
    batch_max_wait_s: float
    alerts_topic: str | None

    @classmethod
    def from_env(cls) -> "Config":
        """Construit la configuration depuis les variables d'environnement.

        Raises:
            RuntimeError: Si KAFKA_BOOTSTRAP_SERVERS n'est pas definie.
        """
        bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")
        if not bootstrap:
            raise RuntimeError("La variable d'environnement KAFKA_BOOTSTRAP_SERVERS n'est pas definie.")
        return cls(
            bootstrap_servers=bootstrap,
            # Plusieurs topics separes par des virgules ; un nom commencant par ^ est une regex.
            topics=[t.strip() for t in os.environ.get("KAFKA_TOPIC", "logs").split(",") if t.strip()],
            group_id=os.environ.get("KAFKA_GROUP_ID", "ramy-threat-analysis"),
            auto_offset_reset=os.environ.get("KAFKA_AUTO_OFFSET_RESET", "latest"),
            api_url=os.environ.get("API_URL", "http://ramy-api:8000").rstrip("/"),
            api_timeout=int(os.environ.get("API_TIMEOUT", "900")),
            threshold=os.environ.get("THRESHOLD", "HAUTE"),
            batch_max_lines=int(os.environ.get("BATCH_MAX_LINES", "100")),
            batch_max_wait_s=float(os.environ.get("BATCH_MAX_WAIT_S", "30")),
            alerts_topic=os.environ.get("ALERTS_TOPIC") or None,
        )


# ── Conversion des messages en lignes de logs ─────────────────────────────────

def _first(entry: dict, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = entry.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _entry_to_line(entry, default_host: str | None = None) -> str | None:
    """Convertit une entree de log (texte ou objet JSON) en une ligne lisible par le LLM.

    L'horodatage est place en tete de ligne : le LLM s'en sert pour le champ timestamp.
    """
    if isinstance(entry, str):
        return entry.strip() or None
    if not isinstance(entry, dict):
        return json.dumps(entry, ensure_ascii=False)
    message = _first(entry, _MESSAGE_KEYS)
    if message is None:
        return json.dumps(entry, ensure_ascii=False)
    source = _first(entry, _SOURCE_KEYS)
    parts = [
        _first(entry, _TIMESTAMP_KEYS),
        _first(entry, _HOST_KEYS) or default_host,
        f"{source}:" if source else None,
        message.strip(),
    ]
    return " ".join(p for p in parts if p)


def message_to_lines(value: bytes | None) -> list[str]:
    """Extrait les lignes de logs d'un message Kafka.

    Formats acceptes :
        - texte brut (une ou plusieurs lignes) ;
        - objet JSON representant une entree de log ;
        - tableau JSON d'entrees ;
        - enveloppe JSON {"hostname": ..., "logs": [entrees]}.
    Une entree est une chaine ou un objet dont les champs usuels (timestamp, host,
    source, message et leurs variantes) sont reconnus.
    """
    if not value:
        return []
    text = value.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except ValueError:
        return [line.strip() for line in text.splitlines() if line.strip()]

    if isinstance(data, dict) and isinstance(data.get("logs"), list):
        host, entries = _first(data, _HOST_KEYS), data["logs"]
    elif isinstance(data, list):
        host, entries = None, data
    else:
        host, entries = None, [data]
    lines = (_entry_to_line(entry, host) for entry in entries)
    return [line for line in lines if line]


# ── Lots en attente d'analyse ─────────────────────────────────────────────────

@dataclass
class PendingBatch:
    """Lignes d'un topic en attente d'analyse, avec les offsets a commiter ensuite."""

    started_at: float = field(default_factory=time.monotonic)
    lines: list[tuple[int, str]] = field(default_factory=list)  # (partition, ligne)
    offsets: dict[int, int] = field(default_factory=dict)  # partition -> dernier offset lu
    failures: int = 0
    retry_at: float = 0.0
    paused: bool = False

    def add(self, partition: int, offset: int, lines: list[str]) -> None:
        """Ajoute les lignes d'un message et memorise son offset."""
        self.lines.extend((partition, line) for line in lines)
        self.offsets[partition] = max(offset, self.offsets.get(partition, -1))

    def drop_partition(self, partition: int) -> None:
        """Retire les lignes d'une partition revoquee (elles seront relues par son nouveau proprietaire)."""
        self.lines = [(p, line) for p, line in self.lines if p != partition]
        self.offsets.pop(partition, None)


# ── Consumer ──────────────────────────────────────────────────────────────────

class LogConsumer:
    """Consomme les topics de logs et delegue l'analyse a l'API LogAnalyzer."""

    def __init__(self, config: Config) -> None:
        """Cree le consumer (et le producer d'alertes si ALERTS_TOPIC est defini)."""
        self.config = config
        self.batches: dict[str, PendingBatch] = {}
        self.running = True
        self.consumer = Consumer(
            {
                "bootstrap.servers": config.bootstrap_servers,
                "group.id": config.group_id,
                "auto.offset.reset": config.auto_offset_reset,
                "enable.auto.commit": False,
                # L'appel a l'API est bloquant : laisser le temps a une analyse longue.
                "max.poll.interval.ms": (config.api_timeout + 60) * 1000,
            }
        )
        self.producer = (
            Producer({"bootstrap.servers": config.bootstrap_servers}) if config.alerts_topic else None
        )

    # Callbacks de rebalance -------------------------------------------------

    def _on_revoke(self, consumer: Consumer, partitions: list[TopicPartition]) -> None:
        for tp in partitions:
            batch = self.batches.get(tp.topic)
            if batch:
                batch.drop_partition(tp.partition)
                if not batch.offsets:
                    del self.batches[tp.topic]
        logger.info("Partitions revoquees : %s", [f"{tp.topic}[{tp.partition}]" for tp in partitions])

    def _on_assign(self, consumer: Consumer, partitions: list[TopicPartition]) -> None:
        logger.info("Partitions assignees : %s", [f"{tp.topic}[{tp.partition}]" for tp in partitions])

    # Boucle principale ------------------------------------------------------

    def run(self) -> None:
        """Consomme les messages jusqu'a l'arret (SIGTERM/SIGINT), puis vide les lots en attente."""
        self.consumer.subscribe(self.config.topics, on_assign=self._on_assign, on_revoke=self._on_revoke)
        logger.info(
            "Consumer demarre | topics=%s | groupe=%s | api=%s | seuil=%s",
            self.config.topics, self.config.group_id, self.config.api_url, self.config.threshold,
        )
        try:
            while self.running:
                msg = self.consumer.poll(1.0)
                if msg is not None:
                    self._handle_message(msg)
                self._flush_ready_batches(force=False)
            self._flush_ready_batches(force=True)
        finally:
            self.consumer.close()
            if self.producer:
                self.producer.flush(10)
            logger.info("Consumer arrete.")

    def stop(self, *_args) -> None:
        """Demande l'arret propre de la boucle principale."""
        self.running = False

    def _handle_message(self, msg: Message) -> None:
        if msg.error():
            if msg.error().code() != KafkaError._PARTITION_EOF:
                logger.warning("Erreur Kafka : %s", msg.error())
            return
        batch = self.batches.setdefault(msg.topic(), PendingBatch())
        batch.add(msg.partition(), msg.offset(), message_to_lines(msg.value()))

    def _flush_ready_batches(self, force: bool) -> None:
        now = time.monotonic()
        for topic, batch in list(self.batches.items()):
            full = len(batch.lines) >= self.config.batch_max_lines
            expired = now - batch.started_at >= self.config.batch_max_wait_s
            if (force or full or expired) and now >= batch.retry_at:
                self._flush(topic, batch)

    def _flush(self, topic: str, batch: PendingBatch) -> None:
        """Analyse un lot, publie les alertes puis commite ses offsets ; en cas d'echec, reessaie plus tard."""
        lines = [line for _, line in batch.lines]
        try:
            if lines:
                self._report(topic, self._analyze(lines))
        except RuntimeError as exc:
            batch.failures += 1
            delay = min(_MAX_RETRY_DELAY_S, 5.0 * 2 ** (batch.failures - 1))
            batch.retry_at = time.monotonic() + delay
            if not batch.paused:
                # Plus de lecture sur ces partitions tant que le lot n'est pas analyse.
                self.consumer.pause(self._partitions(topic, batch))
                batch.paused = True
            logger.error("[%s] Analyse echouee (%d lignes), nouvel essai dans %.0fs : %s",
                         topic, len(lines), delay, exc)
            return

        self.consumer.commit(
            offsets=[TopicPartition(topic, p, off + 1) for p, off in batch.offsets.items()],
            asynchronous=False,
        )
        if batch.paused:
            self.consumer.resume(self._partitions(topic, batch))
        del self.batches[topic]

    @staticmethod
    def _partitions(topic: str, batch: PendingBatch) -> list[TopicPartition]:
        return [TopicPartition(topic, p) for p in batch.offsets]

    def _analyze(self, lines: list[str]) -> dict:
        """Appelle POST /analyze/logs ; leve RuntimeError en cas d'echec."""
        try:
            resp = requests.post(
                f"{self.config.api_url}/analyze/logs",
                json={"logs": lines, "threshold": self.config.threshold},
                timeout=self.config.api_timeout,
            )
        except requests.RequestException as exc:
            raise RuntimeError(f"API injoignable ({self.config.api_url}) : {exc}") from exc
        if not resp.ok:
            raise RuntimeError(f"Erreur API {resp.status_code} : {resp.text[:500]}")
        return resp.json()

    def _report(self, topic: str, result: dict) -> None:
        """Journalise le resultat et publie les alertes sur ALERTS_TOPIC si configure."""
        alerts = result.get("alerts", [])
        logger.info("[%s] %d lignes analysees, %d alerte(s)", topic, result.get("total_analyzed", 0), len(alerts))
        for alert in alerts:
            logger.warning("[%s] ALERTE %s | %s | %s", topic, alert.get("severity"),
                           alert.get("threat_type"), alert.get("timestamp"))
        if self.producer and alerts:
            payload = {"source_topic": topic, **result}
            self.producer.produce(
                self.config.alerts_topic,
                key=topic.encode(),
                value=json.dumps(payload, ensure_ascii=False).encode(),
            )
            # Les alertes doivent etre ecrites avant le commit des offsets du lot.
            remaining = self.producer.flush(30)
            if remaining:
                raise RuntimeError(f"{remaining} message(s) d'alerte non publie(s) sur {self.config.alerts_topic}")


def main() -> None:
    """Point d'entree : lit la configuration et lance la boucle de consommation."""
    load_dotenv()  # sans effet si les variables sont deja definies (docker --env-file)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log_consumer = LogConsumer(Config.from_env())
    signal.signal(signal.SIGTERM, log_consumer.stop)
    signal.signal(signal.SIGINT, log_consumer.stop)
    log_consumer.run()


if __name__ == "__main__":
    main()
