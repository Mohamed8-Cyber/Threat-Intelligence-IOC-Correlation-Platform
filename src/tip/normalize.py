"""Validation, normalization, defanging and allowlist matching for indicators."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from .models import HASH_TYPES, IOCType

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{1,62}$")
_EMAIL_RE = re.compile(r"^[a-z0-9._%+-]+@((?:[a-z0-9-]+\.)+[a-z][a-z0-9-]{1,62})$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_HASH_LENGTH = {IOCType.MD5: 32, IOCType.SHA1: 40, IOCType.SHA256: 64}
_HASH_BY_LENGTH = {length: kind for kind, length in _HASH_LENGTH.items()}
_URL_SCHEMES = frozenset({"http", "https", "ftp"})


def refang(text: str) -> str:
    """Undo common defanging, so that 'hxxps://evil[.]example' becomes 'https://evil.example'."""
    out = re.sub(r"(?i)\bhxxp(s?)://", lambda m: f"http{m.group(1)}://", text)
    out = out.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    out = re.sub(r"(?i)\[@\]|\[at\]", "@", out)
    return out.strip()


def defang(value: str, ioc_type: IOCType) -> str:
    """Return an analyst-safe form of an indicator that cannot be clicked by accident."""
    out = value
    if ioc_type is IOCType.URL:
        out = re.sub(r"^http", "hxxp", out)
    if ioc_type in {IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.CIDR, IOCType.EMAIL}:
        out = out.replace(".", "[.]")
    if ioc_type is IOCType.EMAIL:
        out = out.replace("@", "[@]")
    return out


def detect_type(value: str) -> IOCType:
    """Guess an indicator's type from its shape. Raises ValueError when nothing fits."""
    v = refang(value)
    if not v:
        raise ValueError("empty indicator")
    if "://" in v:
        return IOCType.URL
    if "@" in v:
        return IOCType.EMAIL
    if "/" in v:
        return IOCType.CIDR
    try:
        return IOCType.IPV4 if ipaddress.ip_address(v).version == 4 else IOCType.IPV6
    except ValueError:
        pass
    lowered = v.lower()
    if _HEX_RE.match(lowered) and len(lowered) in _HASH_BY_LENGTH:
        return _HASH_BY_LENGTH[len(lowered)]
    if _DOMAIN_RE.match(lowered.rstrip(".")):
        return IOCType.DOMAIN
    raise ValueError(f"cannot identify an indicator type for {value!r}")


def parse_ioc(raw: str, ioc_type: IOCType | None = None) -> tuple[IOCType, str]:
    """Validate and normalize one indicator. Returns (type, normalized value)."""
    value = refang(raw)
    if not value:
        raise ValueError("empty indicator")
    kind = ioc_type or detect_type(value)
    return kind, _normalize(kind, value)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _is_host(text: str) -> bool:
    return _is_ip(text) or bool(_DOMAIN_RE.match(text))


def _normalize(kind: IOCType, value: str) -> str:
    if kind in (IOCType.IPV4, IOCType.IPV6):
        addr = ipaddress.ip_address(value)
        expected = 4 if kind is IOCType.IPV4 else 6
        if addr.version != expected:
            raise ValueError(f"{value!r} is not an {kind.value} address")
        return str(addr)
    if kind is IOCType.CIDR:
        return str(ipaddress.ip_network(value, strict=False))
    if kind is IOCType.DOMAIN:
        domain = value.lower().rstrip(".")
        if not _DOMAIN_RE.match(domain):
            raise ValueError(f"invalid domain {value!r}")
        return domain
    if kind is IOCType.URL:
        parts = urlsplit(value)
        host = (parts.hostname or "").lower()
        if parts.scheme.lower() not in _URL_SCHEMES or not _is_host(host):
            raise ValueError(f"invalid URL {value!r}")
        if ":" in host:  # IPv6 literal needs brackets inside a URL
            host = f"[{host}]"
        netloc = host if parts.port is None else f"{host}:{parts.port}"
        return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, ""))
    if kind is IOCType.EMAIL:
        email = value.lower()
        if not _EMAIL_RE.match(email):
            raise ValueError(f"invalid email {value!r}")
        return email
    if kind in HASH_TYPES:
        digest = value.lower()
        if len(digest) != _HASH_LENGTH[kind] or not _HEX_RE.match(digest):
            raise ValueError(f"invalid {kind.value} digest {value!r}")
        return digest
    raise ValueError(f"unsupported indicator type {kind}")


def host_of(kind: IOCType, value: str) -> str | None:
    """The domain or IP an indicator is anchored to, if it has one."""
    if kind is IOCType.URL:
        return urlsplit(value).hostname
    if kind is IOCType.EMAIL:
        return value.rsplit("@", 1)[1]
    if kind is IOCType.DOMAIN:
        return value
    return None


def host_type(host: str) -> IOCType:
    """Whether a host string is an IP address or a domain name."""
    if not _is_ip(host):
        return IOCType.DOMAIN
    return IOCType.IPV4 if ipaddress.ip_address(host).version == 4 else IOCType.IPV6


def parent_domains(domain: str) -> list[str]:
    """Parent domains of a name, excluding the bare TLD: a.b.example gives [b.example]."""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(1, len(labels) - 1)]


def in_allowlist(host: str, allowlist) -> bool:
    """True when the host is an allowlisted domain or one of its subdomains."""
    return any(host == entry or host.endswith("." + entry) for entry in allowlist)
