"""Feed definitions, loaded from a JSON configuration file."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

FORMATS = ("text", "csv", "stix")


@dataclass(frozen=True)
class FeedSpec:
    name: str
    format: str
    reliability: float
    url: str | None = None
    path: str | None = None

    def __post_init__(self) -> None:
        if self.format not in FORMATS:
            raise ValueError(f"feed {self.name!r}: format must be one of {FORMATS}")
        if not 0.0 <= self.reliability <= 1.0:
            raise ValueError(f"feed {self.name!r}: reliability must be between 0 and 1")
        if bool(self.url) == bool(self.path):
            raise ValueError(f"feed {self.name!r}: set exactly one of url or path")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FeedSpec":
        return cls(
            name=str(data["name"]),
            format=str(data.get("format", "text")),
            reliability=float(data.get("reliability", 0.5)),
            url=data.get("url"),
            path=data.get("path"),
        )


def load_feeds(path: str | Path) -> list[FeedSpec]:
    """Read feed definitions. Relative file paths are resolved against the configuration file."""
    config = Path(path)
    data = json.loads(config.read_text(encoding="utf-8"))
    specs: list[FeedSpec] = []
    for entry in data.get("feeds", []):
        spec = FeedSpec.from_dict(entry)
        if spec.path and not Path(spec.path).is_absolute():
            spec = replace(spec, path=str(config.parent / spec.path))
        specs.append(spec)
    return specs
