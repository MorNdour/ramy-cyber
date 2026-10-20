"""Dashboard Streamlit de monitoring des analyses retournees par l'API LogAnalyzer.

Lancement en local :
    API_URL=http://localhost:8000 streamlit run app.py

En conteneur, l'API est jointe via le reseau docker partage (API_URL=http://ramy-api:8000).
"""

import base64
import gzip
import io
import json
import os
import zipfile
from datetime import datetime

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGO_PATH = os.path.join(BASE_DIR, "ramy-icon.png")

API_URL = os.getenv("API_URL", "http://localhost:8000").rstrip("/")
# Un appel LLM par lot de lignes : les analyses de gros fichiers peuvent etre longues.
API_TIMEOUT = int(os.getenv("API_TIMEOUT", "900"))

# Doit rester aligne avec SEVERITY_ORDER dans threat_detection_agent/log_analysis.py.
SEVERITIES = ["NORMALE", "FAIBLE", "MOYENNE", "HAUTE", "CRITIQUE"]
SEVERITY_COLORS = {
    "CRITIQUE": "#dc3545",
    "HAUTE": "#fd7e14",
    "MOYENNE": "#ffc107",
    "FAIBLE": "#20c997",
    "NORMALE": "#6c757d",
}
SEVERITY_EMOJI = {"CRITIQUE": "🔴", "HAUTE": "🟠", "MOYENNE": "🟡", "FAIBLE": "🟢", "NORMALE": "⚪"}
# Libelles affiches ; l'API et le LLM continuent d'utiliser les valeurs francaises.
SEVERITY_LABELS = {"CRITIQUE": "Critical", "HAUTE": "High", "MOYENNE": "Medium", "FAIBLE": "Low", "NORMALE": "Normal"}

SOURCE_FILES = "📁 File(s)"
SOURCE_REMOTE_API = "🌐 Remote API"
SOURCE_DIRECTORY = "📂 Server directory"

st.set_page_config(
    page_title="Ramy Cyberdefense",
    page_icon=LOGO_PATH if os.path.exists(LOGO_PATH) else "🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
    .block-container { padding-top: 3rem; }
    div[data-testid="stMetric"] {
        background: #161b26; border: 1px solid #262c3a; border-radius: 10px; padding: 14px 18px;
    }
    div[data-testid="stMetric"] label { color: #a0a0c0 !important; }
    .info-card {
        background: #14263a; border-radius: 8px; padding: 18px 20px; color: #4da3ff;
        height: 100%; line-height: 1.5;
    }
    .info-card b { color: #5cb0ff; }
    .sev-badge {
        display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem;
        font-weight: 700; color: #0e1117;
    }
    .action-box {
        border-left: 3px solid #E8872A; background: rgba(232,135,42,0.08);
        padding: 8px 12px; border-radius: 4px; margin-top: 6px;
    }
</style>
""",
    unsafe_allow_html=True,
)


# ── Appels API ────────────────────────────────────────────────────────────────

def api_health() -> bool:
    """Indique si l'API LogAnalyzer repond sur /health."""
    try:
        return requests.get(f"{API_URL}/health", timeout=3).ok
    except requests.RequestException:
        return False


def _post(endpoint: str, payload: dict) -> dict:
    """Envoie une requete POST a l'API et renvoie le JSON, ou leve RuntimeError."""
    try:
        resp = requests.post(f"{API_URL}{endpoint}", json=payload, timeout=API_TIMEOUT)
    except requests.RequestException as exc:
        raise RuntimeError(f"API unreachable ({API_URL}): {exc}") from exc
    if not resp.ok:
        try:
            detail = resp.json().get("detail", resp.text)
        except ValueError:
            detail = resp.text
        raise RuntimeError(f"API error {resp.status_code}: {detail}")
    return resp.json()


# Le dashboard demande toujours le seuil minimal a l'API pour recevoir toutes les
# menaces detectees : les statistiques restent completes et le seuil choisi dans la
# sidebar ne filtre que l'affichage.
def analyze_lines(lines: list[str]) -> dict:
    """Analyse une liste de lignes de logs via POST /analyze/logs."""
    lines = [line for line in lines if line.strip()]
    if not lines:
        raise RuntimeError("No non-empty log lines to analyze.")
    return _post("/analyze/logs", {"logs": lines, "threshold": "NORMALE"})


def analyze_directory(path: str, pattern: str, remote: dict | None) -> dict:
    """Analyse un repertoire (local a l'API ou distant via SSH) via POST /analyze/directory."""
    return _post(
        "/analyze/directory",
        {"path": path, "pattern": pattern, "threshold": "NORMALE", "remote": remote},
    )


# ── Extraction des lignes de logs ─────────────────────────────────────────────

def _decode(raw: bytes) -> list[str]:
    return raw.decode("utf-8", errors="replace").splitlines()


def lines_from_upload(name: str, raw: bytes) -> list[str]:
    """Extrait les lignes de logs d'un fichier uploade (.gz et .zip decompresses)."""
    lower = name.lower()
    if lower.endswith(".gz"):
        return _decode(gzip.decompress(raw))
    if lower.endswith(".zip"):
        lines: list[str] = []
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for member in archive.namelist():
                if not member.endswith("/"):
                    lines.extend(_decode(archive.read(member)))
        return lines
    return _decode(raw)


def lines_from_remote_api(url: str) -> list[str]:
    """Recupere des logs depuis une URL REST (texte brut ou liste JSON de lignes)."""
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"Could not fetch logs from {url}: {exc}") from exc
    try:
        data = resp.json()
    except ValueError:
        return resp.text.splitlines()
    if isinstance(data, dict):
        data = data.get("logs", [])
    if not isinstance(data, list):
        raise RuntimeError("Unexpected JSON format: expected a list of lines (or {'logs': [...]}).")
    return [line if isinstance(line, str) else json.dumps(line) for line in data]


# ── En-tete ───────────────────────────────────────────────────────────────────

def render_header() -> None:
    """Affiche le logo et le nom Ramy Cyberdefense."""
    logo_html = ""
    if os.path.exists(LOGO_PATH):
        with open(LOGO_PATH, "rb") as f:
            logo_b64 = base64.b64encode(f.read()).decode()
        logo_html = f"<img src='data:image/png;base64,{logo_b64}' style='height:56px;width:auto;flex-shrink:0'>"
    st.markdown(
        "<div style='display:flex;align-items:center;gap:14px'>"
        f"{logo_html}"
        "<div style='line-height:1.15'>"
        "<div style='font-size:2rem;font-weight:800'>Ram<span style='color:#E8872A'>y</span></div>"
        "<div style='font-size:0.9rem;letter-spacing:0.08em;color:#a0a0c0'>cyberdefense</div>"
        "</div></div>",
        unsafe_allow_html=True,
    )
    st.divider()


def render_welcome() -> None:
    """Affiche les cartes de presentation des sources quand aucune analyse n'existe."""
    cards = [
        f"<b>{SOURCE_FILES}</b> Upload one or more <code>.log</code>, <code>.gz</code>, <code>.zip</code>… files.",
        f"<b>{SOURCE_REMOTE_API}</b> Fetch and analyze logs from a REST URL.",
        f"<b>{SOURCE_DIRECTORY}</b> Analyze an existing directory on the server (local or SSH).",
    ]
    for col, card in zip(st.columns(3), cards):
        col.markdown(f"<div class='info-card'>{card}</div>", unsafe_allow_html=True)


# ── Sidebar ───────────────────────────────────────────────────────────────────

def render_sidebar() -> None:
    """Affiche le choix de la source, lance l'analyse et stocke le resultat en session."""
    with st.sidebar:
        st.markdown("### 🔍 Analysis source")
        source = st.radio(
            "Source", [SOURCE_FILES, SOURCE_REMOTE_API, SOURCE_DIRECTORY], label_visibility="collapsed"
        )
        st.divider()

        remote: dict | None = None
        if source == SOURCE_FILES:
            uploads = st.file_uploader(
                "Drag and drop or browse",
                type=["log", "txt", "csv", "json", "gz", "zip"],
                accept_multiple_files=True,
                help="One line = one log entry. .gz and .zip archives are decompressed.",
            )
            ready = bool(uploads)
        elif source == SOURCE_REMOTE_API:
            url = st.text_input("Logs URL", placeholder="https://siem.local/api/logs")
            ready = bool(url)
        else:
            path = st.text_input("Directory path", placeholder="/data/logs")
            pattern = st.text_input("Pattern", value="*.log")
            if st.toggle("Remote host (SSH)"):
                host = st.text_input("Host")
                user = st.text_input("Username")
                port = st.number_input("Port", value=22, min_value=1, max_value=65535)
                password = st.text_input("Password", type="password")
                key_path = st.text_input("Private key (path on the API host)")
                remote = {
                    "host": host,
                    "username": user,
                    "port": int(port),
                    "password": password or None,
                    "private_key_path": key_path or None,
                }
            ready = bool(path) and (remote is None or bool(remote["host"] and remote["username"]))

        if st.button("🔍 Analyze", width="stretch", disabled=not ready):
            with st.spinner("Analyzing…"):
                try:
                    if source == SOURCE_FILES:
                        lines = [l for up in uploads for l in lines_from_upload(up.name, up.getvalue())]
                        result = analyze_lines(lines)
                    elif source == SOURCE_REMOTE_API:
                        result = analyze_lines(lines_from_remote_api(url))
                    else:
                        result = analyze_directory(path, pattern, remote)
                    st.session_state.result = result
                    st.session_state.error = None
                except (RuntimeError, OSError, zipfile.BadZipFile) as exc:
                    st.session_state.error = str(exc)

        st.divider()
        st.selectbox(
            "Minimum severity shown",
            SEVERITIES[1:],
            index=SEVERITIES[1:].index("MOYENNE"),
            format_func=SEVERITY_LABELS.get,
            key="threshold",
        )
        status = "🟢 API connected" if api_health() else "🔴 API unreachable"
        st.caption(f"{status} · `{API_URL}`")


# ── Statistiques et menaces ───────────────────────────────────────────────────

def _style_fig(fig) -> None:
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=40, b=10),
        height=300,
        showlegend=False,
    )


def format_analysis_time(value: str | None) -> str:
    """Formate l'horodatage ISO 8601 (UTC) renvoye par l'API, ex. Oct 06, 2026 at 14:32:05 UTC."""
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value).strftime("%b %d, %Y at %H:%M:%S UTC")
    except ValueError:
        return value


def format_threat_window(timestamps) -> str | None:
    """Formate la fenetre [premiere, derniere] ligne de log d'une menace."""
    if not isinstance(timestamps, list) or not timestamps:
        return None
    first, last = timestamps[0], timestamps[-1]
    return first if first == last else f"{first} → {last}"


def render_stats(result: dict, threats: pd.DataFrame) -> None:
    """Affiche les indicateurs cles et les repartitions par severite et categorie."""
    total = result["total_analyzed"]
    n_threats = len(threats)
    n_critical = int((threats["severity"] == "CRITIQUE").sum()) if n_threats else 0
    avg_conf = f"{threats['confidence'].mean():.0%}" if n_threats else "—"

    st.caption(f"🕒 Analyzed on {format_analysis_time(result.get('timestamp'))}")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Log lines analyzed", total)
    c2.metric("Threats detected", n_threats)
    c3.metric("Critical", n_critical)
    c4.metric("Average confidence", avg_conf)

    if not n_threats:
        st.success("No threats detected in the analyzed logs.")
        return

    left, right = st.columns(2)
    sev_counts = (
        threats["severity"].value_counts()
        .reindex(SEVERITIES[:0:-1], fill_value=0)
        .rename(index=SEVERITY_LABELS)
        .rename_axis("Severity").reset_index(name="Threats")
    )
    colors = {SEVERITY_LABELS[sev]: color for sev, color in SEVERITY_COLORS.items()}
    fig = px.bar(sev_counts, x="Severity", y="Threats", color="Severity",
                 color_discrete_map=colors, title="Threats by severity")
    _style_fig(fig)
    left.plotly_chart(fig, width="stretch")

    cat_counts = (
        threats["threat_type"].fillna("Unclassified").value_counts()
        .rename_axis("Category").reset_index(name="Threats")
    )
    fig = px.pie(cat_counts, names="Category", values="Threats", hole=0.55, title="Threat categories",
                 color_discrete_sequence=px.colors.sequential.Oranges_r)
    _style_fig(fig)
    fig.update_layout(showlegend=True, legend=dict(orientation="v", x=1, y=0.5))
    fig.update_traces(textinfo="value")
    right.plotly_chart(fig, width="stretch")


def render_threats(threats: pd.DataFrame) -> None:
    """Liste les menaces au-dessus du seuil, detail (cause + action) repliable."""
    threshold = st.session_state.threshold
    min_rank = SEVERITIES.index(threshold)
    shown = threats[threats["severity"].map(lambda s: SEVERITIES.index(s) if s in SEVERITIES else -1) >= min_rank]
    shown = shown.assign(_rank=shown["severity"].map(SEVERITIES.index)).sort_values(
        ["_rank", "confidence"], ascending=False
    )

    st.subheader(f"🚨 Detected threats · {len(shown)}")
    st.caption(f"Severity ≥ {SEVERITY_LABELS[threshold]}")
    if shown.empty:
        st.info("No threats at or above the selected severity.")
        return

    for _, t in shown.iterrows():
        sev = t["severity"]
        category = t["threat_type"] if pd.notna(t["threat_type"]) else "Unclassified"
        title = f"{SEVERITY_EMOJI.get(sev, '')} **{SEVERITY_LABELS.get(sev, sev)}** · {category} · {t['confidence']:.0%}"
        with st.expander(title):
            window = format_threat_window(t["timestamp"])
            if window:
                st.caption(f"🕒 {window}")
            st.markdown(f"**Cause:** {t['summary']}")
            indicators = list(t["indicators"] or [])[:3]
            if indicators:
                st.markdown("\n".join(f"- {i}" for i in indicators))
            st.markdown(
                f"<div class='action-box'><b>Recommended action</b><br>{t['recommended_action']}</div>",
                unsafe_allow_html=True,
            )


# ── Page ──────────────────────────────────────────────────────────────────────

st.session_state.setdefault("result", None)
st.session_state.setdefault("error", None)

render_sidebar()
render_header()

if st.session_state.error:
    st.error(st.session_state.error)

result = st.session_state.result
if result is None:
    render_welcome()
else:
    threats = pd.DataFrame(
        result["alerts"],
        columns=["threat_detected", "severity", "threat_type", "timestamp", "confidence", "summary",
                 "indicators", "recommended_action"],
    )
    render_stats(result, threats)
    st.divider()
    render_threats(threats)
