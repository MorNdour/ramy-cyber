"""Client d'appel a l'API Anthropic Claude pour l'analyse de logs de securite."""

import logging
import os
from datetime import datetime, timezone

import anthropic
from dotenv import load_dotenv
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

load_dotenv()

logger = logging.getLogger(__name__)

# Peut etre surchargee via la variable d'environnement ANTHROPIC_MODEL.
DEFAULT_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")

_RETRYABLE_ERRORS = (
    anthropic.APIConnectionError,
    anthropic.APITimeoutError,
    anthropic.RateLimitError,
    anthropic.InternalServerError,
)


def _get_client() -> anthropic.Anthropic:
    """Construit un client Anthropic a partir de la cle API d'environnement.

    Si ANTHROPIC_WORKSPACE_ID est definie, l'en-tete anthropic-workspace-id est
    ajoute a chaque requete (obligatoire pour une cle non rattachee a un workspace).

    Returns:
        Une instance configuree de anthropic.Anthropic.

    Raises:
        RuntimeError: Si la variable d'environnement ANTHROPIC_API_KEY est absente.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "La variable d'environnement ANTHROPIC_API_KEY n'est pas definie."
        )
    workspace_id = os.environ.get("ANTHROPIC_WORKSPACE_ID")
    headers = {"anthropic-workspace-id": workspace_id} if workspace_id else None
    return anthropic.Anthropic(api_key=api_key, default_headers=headers)


@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type(_RETRYABLE_ERRORS),
    before_sleep=before_sleep_log(logger, logging.WARNING),
)
def _create_message(
    client: anthropic.Anthropic,
    user_message: str,
    system_prompt: str,
    max_tokens: int,
) -> anthropic.types.Message:
    """Effectue l'appel brut a l'API Messages, avec retry automatique."""
    return client.messages.create(
        model=DEFAULT_MODEL,
        max_tokens=max_tokens,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
    )


def call_llm(user_message: str, system_prompt: str, max_tokens: int = 1024) -> str:
    """Envoie un message au modele Claude et retourne le texte brut de la reponse.

    Effectue jusqu'a 3 tentatives avec backoff exponentiel (1s puis 2s) en cas
    d'erreur reseau, de timeout, d'erreur serveur ou de limitation de debit (429).

    Args:
        user_message: Contenu envoye en tant que message utilisateur (ex : un log).
        system_prompt: Prompt systeme definissant le comportement du modele.
        max_tokens: Nombre maximum de tokens generes par la reponse.

    Returns:
        Le texte brut de la reponse du modele.

    Raises:
        RuntimeError: Si ANTHROPIC_API_KEY n'est pas definie.
        anthropic.APIError: Si l'appel echoue apres l'ensemble des tentatives.
    """
    client = _get_client()
    started_at = datetime.now(timezone.utc)

    response = _create_message(client, user_message, system_prompt, max_tokens)

    duration = (datetime.now(timezone.utc) - started_at).total_seconds()
    input_tokens = response.usage.input_tokens
    output_tokens = response.usage.output_tokens

    logger.info(
        "Appel LLM termine | timestamp=%s | duree=%.2fs | tokens_entree=%d | "
        "tokens_sortie=%d | tokens_total=%d",
        started_at.isoformat(),
        duration,
        input_tokens,
        output_tokens,
        input_tokens + output_tokens,
    )

    return "".join(block.text for block in response.content if block.type == "text")
