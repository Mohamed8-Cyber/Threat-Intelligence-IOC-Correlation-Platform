"""Extract indicators from free-form analyst text such as reports, tickets and emails."""

from __future__ import annotations

import re

from .models import IOCType
from .normalize import parse_ioc, refang

_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>()\[\]{}|\\^`]+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.IGNORECASE)
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_HASH = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.IGNORECASE)
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)

# "invoice.pdf" and "update.exe" look like domains. These extensions are never treated as TLDs.
_FILE_EXTENSIONS = frozenset({
    "exe", "dll", "bat", "ps1", "vbs", "js", "jar", "msi", "lnk", "iso", "zip", "rar", "7z",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "csv", "json", "xml", "log",
    "png", "jpg", "jpeg", "gif", "tmp", "bin", "py", "sh", "php", "html", "htm",
})


def extract_iocs(text: str) -> list[tuple[IOCType, str]]:
    """Return unique, normalized indicators in order of appearance.

    Defanged text is refanged first. Each match is masked before the next pattern runs, so a domain
    inside a URL or an email address is not reported twice.
    """
    working = refang(text)
    positions: list[tuple[int, IOCType | None, str]] = []

    def take(pattern: re.Pattern[str], hint: IOCType | None) -> None:
        nonlocal working

        def mask(match: re.Match[str]) -> str:
            raw = match.group(0)
            if hint is IOCType.URL:
                # A sentence-ending full stop is not part of the URL.
                raw = raw.rstrip(".,;:!?")
            positions.append((match.start(), hint, raw))
            return " " * len(match.group(0))

        working = pattern.sub(mask, working)

    take(_URL, IOCType.URL)
    take(_EMAIL, IOCType.EMAIL)
    take(_IPV4, IOCType.IPV4)
    take(_HASH, None)
    take(_DOMAIN, IOCType.DOMAIN)

    results: list[tuple[IOCType, str]] = []
    seen: set[tuple[IOCType, str]] = set()
    for _, hint, raw in sorted(positions, key=lambda item: item[0]):
        try:
            kind, value = parse_ioc(raw, hint)
        except ValueError:
            continue
        if kind is IOCType.DOMAIN and value.rsplit(".", 1)[-1] in _FILE_EXTENSIONS:
            continue
        if (kind, value) not in seen:
            seen.add((kind, value))
            results.append((kind, value))
    return results
