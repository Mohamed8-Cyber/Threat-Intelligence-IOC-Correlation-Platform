"""Normalization: refanging, type detection, validation and allowlisting."""

from __future__ import annotations

import pytest

from tip.models import IOCType
from tip.normalize import detect_type, host_of, in_allowlist, parent_domains, parse_ioc, refang


def test_refang_restores_defanged_forms():
    assert refang("hxxps://files.evil-site[.]example/gate.php") == \
        "https://files.evil-site.example/gate.php"
    assert refang("198[.]51[.]100[.]23") == "198.51.100.23"


@pytest.mark.parametrize("raw, expected", [
    ("203.0.113.5", IOCType.IPV4),
    ("203.0.113.0/24", IOCType.CIDR),
    ("2001:db8::1", IOCType.IPV6),
    ("evil.example", IOCType.DOMAIN),
    ("http://evil.example/a", IOCType.URL),
    ("billing@evil.example", IOCType.EMAIL),
    ("d" * 32, IOCType.MD5),
    ("a" * 40, IOCType.SHA1),
    ("f" * 64, IOCType.SHA256),
])
def test_detect_type(raw, expected):
    assert detect_type(raw) is expected


def test_parse_ioc_lowercases_a_domain():
    kind, value = parse_ioc("Evil.Example")
    assert kind is IOCType.DOMAIN
    assert value == "evil.example"


def test_parse_ioc_accepts_a_defanged_url():
    kind, value = parse_ioc("hxxp://Files.Evil.example/a")
    assert kind is IOCType.URL
    assert host_of(kind, value) == "files.evil.example"


def test_parse_ioc_rejects_invalid_addresses():
    with pytest.raises(ValueError):
        parse_ioc("999.1.1.1")


def test_host_of_url_and_email():
    assert host_of(IOCType.URL, "https://files.evil.example:8443/x") == "files.evil.example"
    assert host_of(IOCType.EMAIL, "billing@evil.example") == "evil.example"
    assert host_of(IOCType.MD5, "d" * 32) is None


def test_parent_domains_walks_up_the_name():
    parents = parent_domains("a.b.evil.example")
    assert "b.evil.example" in parents
    assert "evil.example" in parents
    assert "a.b.evil.example" not in parents


def test_allowlist_covers_subdomains_but_not_lookalikes():
    allow = ("microsoft.com",)
    assert in_allowlist("login.microsoft.com", allow)
    assert in_allowlist("microsoft.com", allow)
    assert not in_allowlist("notmicrosoft.com", allow)
    assert not in_allowlist("microsoft.com.evil.example", allow)
