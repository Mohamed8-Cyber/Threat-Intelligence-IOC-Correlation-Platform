"""Extraction from analyst prose: masking order, trailing punctuation and file names."""

from __future__ import annotations

from tip.extract import extract_iocs
from tip.models import IOCType


def test_extracts_each_kind_from_prose():
    text = ("Beacon to https://files.evil-site.example/gate.php from 198.51.100.23, "
            "payload sha256 " + "f" * 64 + ", sender billing@evil-site.example.")
    found = set(extract_iocs(text))
    assert (IOCType.URL, "https://files.evil-site.example/gate.php") in found
    assert (IOCType.IPV4, "198.51.100.23") in found
    assert (IOCType.SHA256, "f" * 64) in found
    assert (IOCType.EMAIL, "billing@evil-site.example") in found


def test_sentence_full_stop_is_not_part_of_a_url():
    found = extract_iocs("Fetched http://files.evil-site.example/gate.php.")
    assert (IOCType.URL, "http://files.evil-site.example/gate.php") in found
    assert not any(kind is IOCType.URL and value.endswith(".") for kind, value in found)


def test_file_names_are_not_read_as_domains():
    found = extract_iocs("The lure was invoice-october.pdf and the notes were report.docx")
    assert not any(kind is IOCType.DOMAIN for kind, _ in found)
