# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Watchdog LLM: a small Python service that sends security log lines to Claude and gets back a
strict-JSON threat assessment, used to raise SOC alerts. Two ways to drive it: a batch CLI
(`log_analysis.py`) and an HTTP API (`api.py`, FastAPI).

## Setup and commands

```bash
pip install -r requirements.txt
```

API key and model come from `.env` (loaded via `python-dotenv` at import time in `llm_client.py`):
```
ANTHROPIC_API_KEY=...
ANTHROPIC_MODEL=claude-sonnet-4-6   # optional, overrides the default in llm_client.py
ANTHROPIC_WORKSPACE_ID=...          # required only if the API key is not scoped to a workspace
LOG_BATCH_SIZE=100                  # optional, lines sent to the LLM per call
```

Run the CLI:
```bash
python log_analysis.py --source file --path logs.txt [--threshold HAUTE] [--batch-size 100]
python log_analysis.py --source directory --path /var/log/security [--pattern "*.log"]
python log_analysis.py --source directory --path /remote/dir --remote-host HOST --remote-user USER [--remote-password ... | --remote-key ...]
python log_analysis.py --source api --logs '["log line 1", "log line 2"]'
```
Prints only the alerts (JSON array) to stdout, filtered by `--threshold` (default `HAUTE`).

Run the API:
```bash
uvicorn api:app --host 0.0.0.0 --port 8000
```
Docs at `http://localhost:8000/docs`. Endpoints: `POST /analyze/logs`, `POST /analyze/file`
(multipart upload), `POST /analyze/directory` (local or remote via SSH), `GET /health`.

Docker: the API is the default entrypoint; override the command to run the CLI instead
(`docker run ... <image> python log_analysis.py --source file --path /app/logs.txt`).

There is no test suite or linter configured in this repo yet.

## Architecture

- **`system_prompt.py`** — the only place the detection behavior is defined: role, the exact
  output JSON schema, few-shot examples, and severity levels (`NORMALE < FAIBLE < MOYENNE < HAUTE
  < CRITIQUE`). The LLM receives a block of log lines and returns a JSON **array** with one object
  per threat (a threat may span several lines; `timestamp` = [first, last] line), `[]` if none.
  Free-text fields (`threat_type`, `summary`, `indicators`, `recommended_action`) are written in
  English; `severity` values stay French (`CRITIQUE`, `HAUTE`…) since the code compares them. Changing detection behavior means editing this prompt, not the Python logic.
- **`llm_client.py`** — thin wrapper around the `anthropic` SDK. Single public function
  `call_llm(user_message, system_prompt, max_tokens) -> str`. Retries (via `tenacity`) up to 3
  times with exponential backoff (1s, then 2s) on connection/timeout/rate-limit/server errors.
  Logs timestamp + token usage per call.
- **`log_analysis.py`** — business logic, source of truth for severity ordering
  (`SEVERITY_ORDER`), the `RemoteConfig` dataclass for SSH/SFTP access and the `AnalysisReport`
  dataclass (`lines_analyzed`, `threats`) returned by every ingestion method. `LogAnalyzer` is the
  core class:
  - `analyze(lines)` sends one batch of lines in a single LLM call and parses the JSON array of
    threats (strips markdown code fences defensively, raises `ValueError` on invalid JSON).
  - `should_alert(analysis)` compares an analysis's severity against `self.severity_threshold`.
  - Three ingestion methods (`analyze_from_file`, `analyze_from_directory`,
    `analyze_from_api`) all funnel through the private `_analyze_lines()` helper, so
    line-filtering/batching logic lives in exactly one place. Lines are split into batches of
    `batch_size` (default `LOG_BATCH_SIZE`, 100) and each file is batched separately; a threat is
    only correlated across lines that land in the same batch.
  - `analyze_from_directory(dirpath, pattern, remote=None)`: local filesystem walk (`Path.rglob`)
    when `remote` is `None`; otherwise opens an SSH/SFTP session (`paramiko`) and recursively lists
    matching files on the remote host. Host-key checking uses `AutoAddPolicy` — acceptable for a
    controlled internal network, not for untrusted ones.
  - Also runnable standalone as a CLI (`argparse`) — see commands above.
- **`api.py`** — FastAPI layer on top of `LogAnalyzer`. Pydantic models mirror the CLI parameters
  (`LogsRequest`, `DirectoryRequest` with optional `RemoteConfigModel`). Every endpoint returns
  `{timestamp, total_analyzed, total_alerts, alerts}` (`timestamp` = UTC time the analysis
  finished) — alerts only, not the full analysis list, matching the
  CLI's `get_alerts()` filtering behavior.

## Conventions

- Type hints everywhere, French docstrings on every public class/method (matches existing style —
  keep new code consistent with this).
- No third-party dependency beyond what's in `requirements.txt`; add new ones there explicitly.
- Secrets live in `.env` (gitignored), never hardcoded.
