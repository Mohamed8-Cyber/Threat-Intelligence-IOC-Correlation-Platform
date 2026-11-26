"""HTTP API: authentication on write endpoints, search, lookup, exports."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tip.api import create_app
from tip.config import Settings
from tip.exporters import stix_pattern
from tip.models import IOCType

SECRET = "test-secret"
KEY = {"X-API-Key": SECRET}


@pytest.fixture
def client(tmp_path, samples):
    settings = Settings(db_path=str(tmp_path / "api.db"),
                        feeds_file=str(samples / "feeds.json"), api_key=SECRET)
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def test_health_reports_that_writes_need_a_key(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["auth_required"] is True


def test_write_endpoints_require_the_api_key(client):
    payload = {"source": "api-test", "format": "text", "text": "198.51.100.23\n"}
    assert client.post("/api/ingest", json=payload).status_code == 401
    assert client.post("/api/ingest", json=payload, headers={"X-API-Key": "wrong"}).status_code == 401
    accepted = client.post("/api/ingest", json=payload, headers=KEY)
    assert accepted.status_code == 200
    assert accepted.json()["accepted"] == 1
    assert client.post("/api/feeds/community-blocklist/run").status_code == 401


def test_read_endpoints_are_open(client):
    assert client.get("/api/iocs").status_code == 200
    assert client.get("/api/feeds").status_code == 200
    assert client.get("/api/clusters").status_code == 200


def test_feed_run_then_search_and_lookup(client):
    assert client.post("/api/feeds/community-blocklist/run", headers=KEY).status_code == 200
    found = client.get("/api/iocs", params={"q": "198.51.100"}).json()
    assert any(item["value"] == "198.51.100.23" for item in found)
    assert client.get("/api/iocs/lookup",
                      params={"type": "ipv4", "value": "198.51.100.23"}).status_code == 200
    miss = client.get("/api/iocs/lookup", params={"type": "domain", "value": "nothing.example"})
    assert miss.status_code == 404


def test_unknown_feed_is_reported_as_not_found(client):
    assert client.post("/api/feeds/nope/run", headers=KEY).status_code == 404


def test_exports_return_each_format(client):
    client.post("/api/feeds/community-blocklist/run", headers=KEY)

    csv_response = client.get("/api/export/csv")
    assert csv_response.headers["content-type"].startswith("text/csv")
    assert csv_response.text.splitlines()[0].startswith("type,value")

    stix = client.get("/api/export/stix").json()
    assert stix["type"] == "bundle"
    assert stix["objects"][0]["spec_version"] == "2.1"

    assert "198.51.100.23" in client.get("/api/export/blocklist").text

    xlsx = client.get("/api/export/xlsx")
    assert xlsx.status_code == 200
    assert xlsx.content[:2] == b"PK"


def test_stix_patterns_use_the_right_object_paths():
    assert stix_pattern(IOCType.IPV4, "198.51.100.23") == "[ipv4-addr:value = '198.51.100.23']"
    assert stix_pattern(IOCType.CIDR, "203.0.113.0/24") == \
        "[ipv4-addr:value ISSUBSET '203.0.113.0/24']"
    assert stix_pattern(IOCType.SHA256, "a" * 64).startswith("[file:hashes.'SHA-256' = ")
