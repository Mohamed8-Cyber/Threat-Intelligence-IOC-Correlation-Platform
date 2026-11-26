"""HTTP API and dashboard (FastAPI).

Read endpoints are open. Write endpoints (feed runs, ingestion, reports) require the X-API-Key
header when TIP_API_KEY is set. Set it before exposing the service on any network.
"""

from __future__ import annotations

import hmac
import os
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from . import __version__
from .config import Settings
from .models import IOCType
from .service import TIPService

WEB_DIR = Path(__file__).parent / "web"
_MEDIA = {
    "csv": "text/csv",
    "json": "application/json",
    "stix": "application/json",
    "blocklist": "text/plain",
}
_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


class IngestRequest(BaseModel):
    source: str = Field("api", min_length=1, max_length=64)
    format: Literal["text", "csv", "stix"] = "text"
    text: str = Field(..., min_length=1, max_length=10_000_000)
    reliability: float = Field(0.5, ge=0.0, le=1.0)


class ReportRequest(BaseModel):
    source: str = Field("analyst", min_length=1, max_length=64)
    title: str | None = Field(None, max_length=120)
    text: str = Field(..., min_length=1, max_length=5_000_000)
    reliability: float = Field(0.7, ge=0.0, le=1.0)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    service = TIPService(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        service.close()

    def require_key(x_api_key: str | None = Header(default=None)) -> None:
        expected = settings.api_key
        if expected and not hmac.compare_digest(x_api_key or "", expected):
            raise HTTPException(status_code=401, detail="missing or invalid X-API-Key header")

    write_guard = [Depends(require_key)]

    app = FastAPI(title="Threat Intelligence Platform", version=__version__, lifespan=lifespan)
    app.state.service = service
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "auth_required": bool(settings.api_key)}

    @app.get("/api/stats")
    def stats() -> dict:
        return service.stats()

    @app.get("/api/feeds")
    def feeds() -> list[dict]:
        return service.feeds()

    @app.post("/api/feeds/{name}/run", dependencies=write_guard)
    def run_feed(name: str) -> dict:
        try:
            return service.run_feed(name)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown feed {name!r}") from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except Exception as exc:  # network and parse failures are reported, not hidden
            raise HTTPException(status_code=502, detail=f"feed failed: {exc}") from None

    @app.get("/api/iocs")
    def search(
        q: str | None = None,
        ioc_type: IOCType | None = Query(None, alias="type"),
        min_score: float = Query(0.0, ge=0.0, le=1.0),
        limit: int = Query(100, ge=1, le=1000),
    ) -> list[dict]:
        return service.search(text=q, ioc_type=ioc_type.value if ioc_type else None,
                              min_score=min_score, limit=limit)

    @app.get("/api/iocs/lookup")
    def lookup(ioc_type: IOCType = Query(..., alias="type"),
               value: str = Query(..., min_length=1, max_length=2048)) -> dict:
        try:
            found = service.lookup(ioc_type.value, value)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        if found is None:
            raise HTTPException(status_code=404, detail="indicator not found")
        return found

    @app.get("/api/correlate")
    def correlate(ioc_type: IOCType = Query(..., alias="type"),
                  value: str = Query(..., min_length=1, max_length=2048),
                  depth: int = Query(2, ge=1, le=4)) -> dict:
        try:
            result = service.investigate(ioc_type.value, value, depth)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        if result is None:
            raise HTTPException(status_code=404, detail="indicator not found")
        return result

    @app.get("/api/clusters")
    def clusters(min_weight: float | None = Query(None, ge=0.0, le=1.0),
                 limit: int = Query(20, ge=1, le=200)) -> dict:
        return service.clusters(min_weight=min_weight, limit=limit)

    @app.post("/api/ingest", dependencies=write_guard)
    def ingest(body: IngestRequest) -> dict:
        try:
            return service.ingest_payload(text=body.text, source=body.source,
                                          format_name=body.format, reliability=body.reliability)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.post("/api/reports", dependencies=write_guard)
    def ingest_report(body: ReportRequest) -> dict:
        return service.ingest_report(text=body.text, source=body.source, title=body.title,
                                     reliability=body.reliability)

    @app.get("/api/export/{fmt}")
    def export(
        fmt: Literal["csv", "json", "stix", "blocklist", "xlsx"],
        ioc_type: IOCType | None = Query(None, alias="type"),
        min_score: float = Query(0.0, ge=0.0, le=1.0),
    ) -> Response:
        ioc = ioc_type.value if ioc_type else None
        if fmt == "xlsx":
            handle, name = tempfile.mkstemp(suffix=".xlsx")
            os.close(handle)
            service.export("xlsx", ioc_type=ioc, min_score=min_score, path=name)
            return FileResponse(name, media_type=_XLSX, filename="tip-iocs.xlsx",
                                background=BackgroundTask(os.unlink, name))
        body = service.export(fmt, ioc_type=ioc, min_score=min_score)
        extension = "txt" if fmt == "blocklist" else fmt
        return Response(body, media_type=_MEDIA[fmt],
                        headers={"Content-Disposition": f'attachment; filename="tip-iocs.{extension}"'})

    return app
