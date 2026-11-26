"""Runtime settings, read from environment variables with safe defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_ALLOWLIST = (
    "microsoft.com",
    "windowsupdate.com",
    "google.com",
    "github.com",
    "cloudflare.com",
    "apple.com",
    "example.com",
)


@dataclass(frozen=True)
class Settings:
    db_path: str = "tip.db"
    feeds_file: str = "data/samples/feeds.json"
    half_life_days: float = 30.0
    allowlist: tuple[str, ...] = DEFAULT_ALLOWLIST
    fetch_timeout: float = 15.0
    # Campaigns larger than this are not expanded into pairwise co-reporting links.
    max_campaign_members: int = 100
    # An indicator linked to more than this many others is treated as shared infrastructure.
    max_fan_in: int = 10
    # A feed link joins a cluster only when this many independent sources assert it.
    min_sources: int = 2
    cluster_min_weight: float = 0.3
    # When set, write endpoints require the X-API-Key header with this value.
    api_key: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        allow = os.getenv("TIP_ALLOWLIST")
        return cls(
            db_path=os.getenv("TIP_DB_PATH", cls.db_path),
            feeds_file=os.getenv("TIP_FEEDS_FILE", cls.feeds_file),
            half_life_days=float(os.getenv("TIP_HALF_LIFE_DAYS", cls.half_life_days)),
            allowlist=(
                tuple(d.strip().lower() for d in allow.split(",") if d.strip())
                if allow is not None
                else DEFAULT_ALLOWLIST
            ),
            fetch_timeout=float(os.getenv("TIP_FETCH_TIMEOUT", cls.fetch_timeout)),
            max_campaign_members=int(os.getenv("TIP_MAX_CAMPAIGN_MEMBERS",
                                               cls.max_campaign_members)),
            max_fan_in=int(os.getenv("TIP_MAX_FAN_IN", cls.max_fan_in)),
            min_sources=int(os.getenv("TIP_MIN_SOURCES", cls.min_sources)),
            cluster_min_weight=float(os.getenv("TIP_CLUSTER_MIN_WEIGHT",
                                               cls.cluster_min_weight)),
            api_key=os.getenv("TIP_API_KEY") or None,
        )
