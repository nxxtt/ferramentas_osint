#!/usr/bin/env python3
"""Helpers de rede reutilizáveis e re-exports dos primitivos HTTP.

Modulo de conveniencia que:
  - Re-exporta primitivos HTTP do utils.py (fetch, create_async_client, etc.)
  - Fornece helpers simplificados (fetch_bytes, read_response_text)
  - Classifica respostas por Content-Type
  - Alias: http = httpx, Client = httpx.AsyncClient

Por que existe?
  Evita imports circulares e centraliza dependencias de rede.
  Os modulos importam de 'net' em vez de importar utils e httpx diretamente.
"""
from __future__ import annotations

from collections.abc import Mapping

import httpx

from utils import (
    FetchError,
    RateLimiter,
    __version__,
    add_base_args,
    apply_session_auth,
    create_async_client,
    extract_title,
    fetch,
    header_get,
    normalize_url,
)

__all__ = [
    "http",
    "Client",
    "FetchError",
    "RateLimiter",
    "add_base_args",
    "apply_session_auth",
    "create_async_client",
    "extract_title",
    "fetch",
    "header_get",
    "normalize_url",
    "fetch_bytes",
    "read_response_text",
    "classify_by_content_type",
    "__version__",
]

http = httpx
Client = httpx.AsyncClient


async def fetch_bytes(
    client: httpx.AsyncClient,
    url: str,
    *,
    timeout: float = 5.0,
    max_retries: int = 3,
    rate_limiter: RateLimiter | None = None,
) -> bytes:
    """Busca o conteúdo bruto de uma URL como bytes.

    Wrapper sobre fetch() que retorna apenas o corpo da resposta.
    Levanta FetchError em caso de falha.
    """
    _, _, body, _ = await fetch(
        client, url, timeout=timeout, max_retries=max_retries, rate_limiter=rate_limiter,
    )
    return body


async def read_response_text(
    client: httpx.AsyncClient,
    url: str,
    *,
    timeout: float = 5.0,
    max_retries: int = 3,
    encoding: str = "utf-8",
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Busca uma URL e decodifica o corpo como texto.

    Útil para arquivos de texto (robots.txt, sitemap.xml, HTML).
    Levanta FetchError em caso de falha.
    """
    _, _, body, _ = await fetch(
        client, url, timeout=timeout, max_retries=max_retries, rate_limiter=rate_limiter,
    )
    return body.decode(encoding, errors="replace")


def classify_by_content_type(headers: Mapping[str, str]) -> str:
    """Classifica a resposta como 'html', 'json', 'xml', 'text' ou 'binary'.

    Baseado no header Content-Type.
    """
    content_type = header_get(headers, "content-type").lower()
    if "text/html" in content_type:
        return "html"
    if "application/json" in content_type or "+json" in content_type:
        return "json"
    if "text/xml" in content_type or "application/xml" in content_type:
        return "xml"
    if "text/" in content_type:
        return "text"
    return "binary"
