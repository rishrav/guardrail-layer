"""Extract and normalize security-relevant values from text and tool arguments.

Text and arguments go through the same normalization, so the provenance lookup compares
like with like. Every value becomes a typed key such as ``email:dana@company.com``,
``host:api.company.com``, ``account:ACCNORTHWIND01`` or ``amount:880``.
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from gateway.pipeline.heuristics import normalize

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_URL = re.compile(r"https?://[^\s<>\"'`)\]]+", re.IGNORECASE)
_ACCOUNT = re.compile(
    r"\b(?=[A-Za-z0-9-]*\d)(?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+\b"  # ACC-EVIL-4242
    r"|\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"  # IBAN, optionally grouped
)
_AMOUNT = re.compile(r"(?<![\w.])\$?\s?(\d{1,3}(?:,\d{3})+|\d+)(\.\d+)?(?![\w])")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def canonical_host(host: str) -> str:
    return host.strip().rstrip(".").lower()


def canonical_url(url: str) -> str | None:
    try:
        parts = urlsplit(url.strip().rstrip(".,;"))
    except ValueError:
        return None
    if parts.scheme.lower() not in _DEFAULT_PORTS or not parts.hostname:
        return None
    host = canonical_host(parts.hostname)
    port = parts.port
    netloc = host if port in (None, _DEFAULT_PORTS[parts.scheme.lower()]) else f"{host}:{port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def canonical_account(value: str) -> str:
    return re.sub(r"[\s-]", "", value).upper()


def canonical_amount(value: Any) -> str | None:
    try:
        number = Decimal(str(value).replace(",", "").replace("$", "").strip())
    except (InvalidOperation, ValueError):
        return None
    if not number.is_finite():
        return None
    return format(number.normalize(), "f")


def extract_keys(text: str) -> set[str]:
    """All provenance keys mentioned anywhere in a piece of content."""
    text = normalize(text)
    keys: set[str] = set()
    for email in _EMAIL.findall(text):
        email = email.lower()
        keys.add(f"email:{email}")
        keys.add(f"host:{canonical_host(email.rsplit('@', 1)[1])}")
    for raw_url in _URL.findall(text):
        url = canonical_url(raw_url)
        if url:
            keys.add(f"url:{url}")
            keys.add(f"host:{urlsplit(url).hostname}")
    for match in _ACCOUNT.finditer(text):
        keys.add(f"account:{canonical_account(match.group(0))}")
    for integer, fraction in _AMOUNT.findall(text):
        amount = canonical_amount(integer + (fraction or ""))
        if amount is not None:
            keys.add(f"amount:{amount}")
    return keys


def keys_for_arg(arg_type: str, value: Any) -> list[str]:
    """Keys to look up for one argument value, most specific first."""
    if arg_type == "email" and isinstance(value, str):
        return [f"email:{normalize(value).strip().lower()}"]
    if arg_type == "url" and isinstance(value, str):
        url = canonical_url(normalize(value))
        return [f"url:{url}", f"host:{urlsplit(url).hostname}"] if url else []
    if arg_type == "account" and isinstance(value, str):
        return [f"account:{canonical_account(normalize(value))}"]
    if arg_type in {"number", "integer"}:
        amount = canonical_amount(value)
        return [f"amount:{amount}"] if amount is not None else []
    return []
