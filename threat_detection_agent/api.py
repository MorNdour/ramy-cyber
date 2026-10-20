"""API HTTP (FastAPI) exposant LogAnalyzer pour l'analyse de logs de securite.

Lancement en local :
    uvicorn api:app --host 0.0.0.0 --port 8000

Documentation interactive : http://localhost:8000/docs
"""

import logging
from datetime import datetime, timezone

import anthropic
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from log_analysis import AnalysisReport, LogAnalyzer, RemoteConfig, SEVERITY_ORDER

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = FastAPI(
    title="Ramy CYBER",
    description="AGENT IA de detection de cybermenaces via  l'Analyse de logs.",
    version="1.0.0",
)


class RemoteConfigModel(BaseModel):
    """Parametres de connexion SSH/SFTP pour un repertoire de logs distant."""

    host: str = Field(..., description="Nom d'hote ou adresse IP du serveur distant.")
    username: str = Field(..., description="Nom d'utilisateur pour l'authentification SSH.")
    port: int = Field(22, description="Port SSH du serveur distant.")
    password: str | None = Field(None, description="Mot de passe SSH (optionnel).")
    private_key_path: str | None = Field(
        None, description="Chemin vers une cle privee SSH accessible par le serveur d'API (optionnel)."
    )


class AnalysisResult(BaseModel):
    """Schema d'une menace detectee par le LLM (peut couvrir plusieurs lignes de logs)."""

    threat_detected: bool
    severity: str
    threat_type: str | None
    timestamp: list[str] | None = Field(
        None,
        description="Horodatages [premiere, derniere] des lignes de log impliquees, tels qu'ecrits dans le log.",
    )
    confidence: float
    summary: str
    indicators: list[str]
    recommended_action: str


class AnalyzeResponse(BaseModel):
    """Reponse renvoyee par les endpoints d'analyse."""

    timestamp: datetime = Field(..., description="Date et heure (UTC) de fin de l'analyse.")
    total_analyzed: int = Field(..., description="Nombre total de lignes de logs analysees.")
    total_alerts: int = Field(..., description="Nombre de menaces ayant declenche une alerte.")
    alerts: list[AnalysisResult] = Field(..., description="Menaces ayant declenche une alerte.")


class LogsRequest(BaseModel):
    """Requete pour analyser une liste de logs fournie directement (source api)."""

    logs: list[str] = Field(..., min_length=1, description="Liste de lignes de logs a analyser.")
    threshold: str = Field("HAUTE", description="Seuil de severite declenchant une alerte.")


class DirectoryRequest(BaseModel):
    """Requete pour analyser un repertoire, local au serveur ou distant via SSH."""

    path: str = Field(..., description="Chemin du repertoire (local au serveur, ou sur l'hote distant).")
    pattern: str = Field("*.log", description="Motif glob des fichiers a analyser.")
    threshold: str = Field("HAUTE", description="Seuil de severite declenchant une alerte.")
    remote: RemoteConfigModel | None = Field(
        None, description="Parametres SSH/SFTP a fournir si le repertoire est distant."
    )


def _validate_threshold(threshold: str) -> None:
    if threshold not in SEVERITY_ORDER:
        raise HTTPException(
            status_code=422,
            detail=f"Seuil de severite invalide : {threshold!r}. Valeurs attendues : {list(SEVERITY_ORDER)}.",
        )


def _build_response(analyzer: LogAnalyzer, report: AnalysisReport) -> AnalyzeResponse:
    alerts = analyzer.get_alerts(report.threats)
    return AnalyzeResponse(
        timestamp=datetime.now(timezone.utc),
        total_analyzed=report.lines_analyzed,
        total_alerts=len(alerts),
        alerts=alerts,
    )


@app.get("/health")
def health() -> dict:
    """Verification simple de disponibilite du service."""
    return {"status": "ok"}


@app.post("/analyze/logs", response_model=AnalyzeResponse)
def analyze_logs(request: LogsRequest) -> AnalyzeResponse:
    """Analyse une liste de logs envoyee directement dans le corps de la requete."""
    _validate_threshold(request.threshold)
    analyzer = LogAnalyzer(severity_threshold=request.threshold)
    try:
        report = analyzer.analyze_from_api(request.logs)
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except anthropic.APIError as exc:
        raise HTTPException(status_code=502, detail=f"Erreur de l'API LLM : {exc}") from exc
    return _build_response(analyzer, report)


@app.post("/analyze/file", response_model=AnalyzeResponse)
async def analyze_file(file: UploadFile = File(...), threshold: str = "HAUTE") -> AnalyzeResponse:
    """Analyse un fichier de logs envoye en upload (une ligne = un log)."""
    _validate_threshold(threshold)
    analyzer = LogAnalyzer(severity_threshold=threshold)
    raw_content = await file.read()
    lines = raw_content.decode("utf-8", errors="replace").splitlines()
    try:
        report = analyzer.analyze_from_api(lines)
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except anthropic.APIError as exc:
        raise HTTPException(status_code=502, detail=f"Erreur de l'API LLM : {exc}") from exc
    return _build_response(analyzer, report)


@app.post("/analyze/directory", response_model=AnalyzeResponse)
def analyze_directory(request: DirectoryRequest) -> AnalyzeResponse:
    """Analyse tous les fichiers correspondant au pattern dans un repertoire.

    Le repertoire peut etre local au serveur d'API (`remote` absent) ou
    distant, accede via SSH/SFTP (`remote` fourni).
    """
    _validate_threshold(request.threshold)
    analyzer = LogAnalyzer(severity_threshold=request.threshold)
    remote = RemoteConfig(**request.remote.model_dump()) if request.remote else None
    try:
        report = analyzer.analyze_from_directory(request.path, request.pattern, remote=remote)
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except anthropic.APIError as exc:
        raise HTTPException(status_code=502, detail=f"Erreur de l'API LLM : {exc}") from exc
    except OSError as exc:
        raise HTTPException(status_code=502, detail=f"Erreur d'acces au repertoire : {exc}") from exc
    except Exception as exc:  # erreurs SSH/SFTP (paramiko.SSHException et sous-classes)
        raise HTTPException(status_code=502, detail=f"Erreur de connexion SSH/SFTP : {exc}") from exc
    return _build_response(analyzer, report)
