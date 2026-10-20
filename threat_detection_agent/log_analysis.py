"""Analyse de logs de cybersecurite via LLM et declenchement d'alertes."""

import argparse
import fnmatch
import json
import logging
import os
import posixpath
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import paramiko

from llm_client import call_llm
from system_prompt import SYSTEM_PROMPT

logger = logging.getLogger(__name__)

# Ordre croissant de severite utilise pour comparer un seuil a une analyse.
SEVERITY_ORDER: dict[str, int] = {
    "NORMALE": 0,
    "FAIBLE": 1,
    "MOYENNE": 2,
    "HAUTE": 3,
    "CRITIQUE": 4,
}

# Nombre de lignes envoyees au LLM par appel. Une menace etalee sur plusieurs lignes
# n'est correlee que si ses lignes tombent dans le meme lot.
DEFAULT_BATCH_SIZE = int(os.environ.get("LOG_BATCH_SIZE", "100"))

# Un lot peut contenir plusieurs menaces : la reponse JSON doit avoir de la marge.
_MAX_RESPONSE_TOKENS = 8192


@dataclass
class RemoteConfig:
    """Parametres de connexion SSH/SFTP pour l'analyse d'un repertoire distant.

    Attributes:
        host: Nom d'hote ou adresse IP du serveur distant.
        username: Nom d'utilisateur pour l'authentification SSH.
        port: Port SSH du serveur distant (defaut : 22).
        password: Mot de passe pour l'authentification (optionnel).
        private_key_path: Chemin vers une cle privee pour l'authentification
            par cle (optionnel).
    """

    host: str
    username: str
    port: int = 22
    password: str | None = None
    private_key_path: str | None = None


@dataclass
class AnalysisReport:
    """Resultat de l'analyse d'un ensemble de logs.

    Attributes:
        lines_analyzed: Nombre de lignes de logs non vides envoyees au LLM.
        threats: Menaces detectees (voir SYSTEM_PROMPT pour le schema), chacune
            pouvant couvrir plusieurs lignes de logs.
    """

    lines_analyzed: int = 0
    threats: list[dict] = field(default_factory=list)

    def merge(self, other: "AnalysisReport") -> None:
        """Ajoute les lignes et menaces d'un autre rapport a celui-ci."""
        self.lines_analyzed += other.lines_analyzed
        self.threats.extend(other.threats)


def _strip_code_fence(text: str) -> str:
    """Retire une eventuelle balise de bloc de code Markdown (```...```)."""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    return stripped


def _connect_sftp(remote: RemoteConfig) -> tuple[paramiko.SSHClient, paramiko.SFTPClient]:
    """Ouvre une connexion SSH/SFTP vers le serveur distant decrit par `remote`."""
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs: dict = {
        "hostname": remote.host,
        "port": remote.port,
        "username": remote.username,
    }
    if remote.private_key_path:
        connect_kwargs["key_filename"] = remote.private_key_path
    if remote.password:
        connect_kwargs["password"] = remote.password
    ssh_client.connect(**connect_kwargs)
    return ssh_client, ssh_client.open_sftp()


def _list_remote_files(sftp: paramiko.SFTPClient, dirpath: str, pattern: str) -> list[str]:
    """Liste recursivement, sur le serveur distant, les fichiers correspondant a `pattern`."""
    matches: list[str] = []
    for entry in sftp.listdir_attr(dirpath):
        remote_path = posixpath.join(dirpath, entry.filename)
        if stat.S_ISDIR(entry.st_mode):
            matches.extend(_list_remote_files(sftp, remote_path, pattern))
        elif fnmatch.fnmatch(entry.filename, pattern):
            matches.append(remote_path)
    return sorted(matches)


class LogAnalyzer:
    """Analyse des logs de securite via un LLM et identifie les alertes.

    Les logs sont envoyes au LLM par lots de lignes consecutives, ce qui lui
    permet de correler plusieurs lignes en une seule menace.

    Attributes:
        severity_threshold: Seuil de severite a partir duquel une analyse est
            consideree comme une alerte (voir SEVERITY_ORDER pour l'ordre).
        batch_size: Nombre maximal de lignes envoyees au LLM par appel.
    """

    def __init__(self, severity_threshold: str = "HAUTE", batch_size: int = DEFAULT_BATCH_SIZE) -> None:
        """Initialise l'analyseur avec un seuil de severite d'alerte.

        Args:
            severity_threshold: Seuil de severite ("NORMALE", "FAIBLE",
                "MOYENNE", "HAUTE" ou "CRITIQUE").
            batch_size: Nombre maximal de lignes par appel au LLM (defaut :
                LOG_BATCH_SIZE ou 100).

        Raises:
            ValueError: Si severity_threshold n'est pas une severite valide ou
                si batch_size n'est pas strictement positif.
        """
        if severity_threshold not in SEVERITY_ORDER:
            raise ValueError(
                f"Seuil de severite invalide : {severity_threshold!r}. "
                f"Valeurs attendues : {list(SEVERITY_ORDER)}."
            )
        if batch_size < 1:
            raise ValueError(f"Taille de lot invalide : {batch_size!r}. Entier >= 1 attendu.")
        self.severity_threshold = severity_threshold
        self.batch_size = batch_size

    def analyze(self, lines: list[str]) -> list[dict]:
        """Analyse un bloc de lignes de logs consecutives en un seul appel au LLM.

        Args:
            lines: Lignes de logs a analyser ensemble.

        Returns:
            La liste des menaces detectees dans le bloc (vide si aucune), chacune
            pouvant couvrir plusieurs lignes (voir SYSTEM_PROMPT pour le schema).

        Raises:
            ValueError: Si la reponse du LLM n'est pas un tableau JSON valide.
        """
        raw_response = call_llm("\n".join(lines), SYSTEM_PROMPT, max_tokens=_MAX_RESPONSE_TOKENS)
        cleaned = _strip_code_fence(raw_response)
        try:
            threats = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Reponse LLM invalide, JSON attendu : {exc}. Reponse brute : {raw_response!r}"
            ) from exc
        if isinstance(threats, dict):  # tolere un objet seul au lieu d'un tableau
            threats = [threats]
        if not isinstance(threats, list) or not all(isinstance(t, dict) for t in threats):
            raise ValueError(f"Reponse LLM invalide, tableau d'objets JSON attendu : {raw_response!r}")
        return threats

    def should_alert(self, analysis: dict) -> bool:
        """Determine si une analyse doit declencher une alerte.

        Args:
            analysis: Dictionnaire d'analyse produit par analyze().

        Returns:
            True si une menace est detectee et que sa severite est superieure
            ou egale au seuil configure, False sinon.
        """
        if not analysis.get("threat_detected"):
            return False
        severity_rank = SEVERITY_ORDER.get(analysis.get("severity", ""), -1)
        return severity_rank >= SEVERITY_ORDER[self.severity_threshold]

    def _analyze_lines(self, lines: Iterable[str]) -> AnalysisReport:
        """Analyse les lignes non vides d'une meme source, par lots de batch_size lignes."""
        kept = [line.strip() for line in lines if line and line.strip()]
        report = AnalysisReport(lines_analyzed=len(kept))
        for start in range(0, len(kept), self.batch_size):
            report.threats.extend(self.analyze(kept[start : start + self.batch_size]))
        return report

    def analyze_from_file(self, filepath: str) -> AnalysisReport:
        """Analyse les lignes non vides d'un fichier texte de logs local.

        Args:
            filepath: Chemin du fichier a analyser (une ligne = un log).

        Returns:
            Le rapport d'analyse du fichier.
        """
        with Path(filepath).open("r", encoding="utf-8") as log_file:
            return self._analyze_lines(log_file)

    def analyze_from_directory(
        self,
        dirpath: str,
        pattern: str = "*.log",
        remote: RemoteConfig | None = None,
    ) -> AnalysisReport:
        """Analyse recursivement tous les fichiers d'un repertoire, local ou distant.

        Chaque fichier est decoupe en lots separement : un lot ne melange jamais
        des lignes de fichiers differents.

        Args:
            dirpath: Chemin du repertoire a parcourir (local ou, si `remote`
                est fourni, chemin sur le serveur distant).
            pattern: Motif glob des fichiers a analyser (defaut : "*.log").
            remote: Parametres de connexion SSH/SFTP. Si fourni, le repertoire
                est parcouru sur le serveur distant via SFTP plutot que sur le
                systeme de fichiers local.

        Returns:
            Le rapport d'analyse, tous fichiers confondus.
        """
        report = AnalysisReport()
        if remote is None:
            for file_path in sorted(Path(dirpath).rglob(pattern)):
                if file_path.is_file():
                    report.merge(self.analyze_from_file(str(file_path)))
            return report

        logger.info(
            "Connexion SFTP a %s@%s:%d pour analyser le repertoire distant %s",
            remote.username,
            remote.host,
            remote.port,
            dirpath,
        )
        ssh_client, sftp_client = _connect_sftp(remote)
        try:
            for remote_file in _list_remote_files(sftp_client, dirpath, pattern):
                with sftp_client.open(remote_file, "r") as handle:
                    content = handle.read().decode("utf-8", errors="replace")
                report.merge(self._analyze_lines(content.splitlines()))
            return report
        finally:
            sftp_client.close()
            ssh_client.close()

    def analyze_from_api(self, logs: list[str]) -> AnalysisReport:
        """Analyse une liste de logs recue depuis une API externe.

        Args:
            logs: Liste de lignes de logs a analyser, dans l'ordre chronologique.

        Returns:
            Le rapport d'analyse de la liste.
        """
        return self._analyze_lines(logs)

    def get_alerts(self, threats: list[dict]) -> list[dict]:
        """Filtre une liste de menaces pour ne garder que les alertes.

        Args:
            threats: Menaces produites par analyze() (ex : AnalysisReport.threats).

        Returns:
            La sous-liste des menaces pour lesquelles should_alert() est True.
        """
        return [threat for threat in threats if self.should_alert(threat)]


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyse des logs de cybersecurite via un LLM et affiche les alertes."
    )
    parser.add_argument(
        "--source",
        required=True,
        choices=["file", "directory", "api"],
        help="Origine des logs a analyser.",
    )
    parser.add_argument(
        "--path",
        help="Chemin vers le fichier ou le repertoire (requis pour --source file/directory).",
    )
    parser.add_argument(
        "--pattern",
        default="*.log",
        help="Motif glob des fichiers a analyser pour --source directory (defaut : *.log).",
    )
    parser.add_argument(
        "--logs",
        help="Tableau JSON de logs, ex: '[\"log1\", \"log2\"]' (requis pour --source api).",
    )
    parser.add_argument(
        "--threshold",
        default="HAUTE",
        choices=list(SEVERITY_ORDER),
        help="Seuil de severite a partir duquel une alerte est declenchee (defaut : HAUTE).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Nombre de lignes envoyees au LLM par appel (defaut : {DEFAULT_BATCH_SIZE}).",
    )
    parser.add_argument(
        "--remote-host",
        help="Hote SSH du repertoire distant (pour --source directory).",
    )
    parser.add_argument(
        "--remote-port",
        type=int,
        default=22,
        help="Port SSH du repertoire distant (defaut : 22).",
    )
    parser.add_argument(
        "--remote-user",
        help="Utilisateur SSH du repertoire distant.",
    )
    parser.add_argument(
        "--remote-password",
        help="Mot de passe SSH du repertoire distant.",
    )
    parser.add_argument(
        "--remote-key",
        help="Chemin vers la cle privee SSH du repertoire distant.",
    )
    return parser


def main() -> None:
    """Point d'entree CLI : analyse les logs et affiche les alertes en JSON."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    parser = _build_arg_parser()
    args = parser.parse_args()

    if args.source in ("file", "directory") and not args.path:
        parser.error(f"--path est requis pour --source {args.source}")
    if args.source == "api" and not args.logs:
        parser.error("--logs est requis pour --source api")
    if args.remote_host and not args.remote_user:
        parser.error("--remote-user est requis lorsque --remote-host est fourni")

    if args.batch_size < 1:
        parser.error("--batch-size doit etre >= 1")

    analyzer = LogAnalyzer(severity_threshold=args.threshold, batch_size=args.batch_size)

    if args.source == "file":
        report = analyzer.analyze_from_file(args.path)
    elif args.source == "directory":
        remote = (
            RemoteConfig(
                host=args.remote_host,
                username=args.remote_user,
                port=args.remote_port,
                password=args.remote_password,
                private_key_path=args.remote_key,
            )
            if args.remote_host
            else None
        )
        report = analyzer.analyze_from_directory(args.path, args.pattern, remote=remote)
    else:
        try:
            logs = json.loads(args.logs)
        except json.JSONDecodeError as exc:
            parser.error(f"--logs doit etre un tableau JSON valide : {exc}")
            return
        report = analyzer.analyze_from_api(logs)

    alerts = analyzer.get_alerts(report.threats)
    print(json.dumps(alerts, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
