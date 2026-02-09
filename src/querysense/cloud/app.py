"""
FastAPI application factory for QuerySense Cloud.

Creates the app with:
- Lifespan management (DB init/shutdown)
- API routes (JSON, /api/v1/*)
- Web routes (HTML, /*)
- Static files
- Jinja2 templates
- Exception handlers
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from querysense.cloud.auth import SessionManager
from querysense.cloud.database import create_tables, dispose_engine, init_engine
from querysense.cloud.settings import CloudSettings, get_cloud_settings

logger = logging.getLogger(__name__)

# Module-level singletons (set during app startup)
_session_manager: SessionManager | None = None
_templates: Jinja2Templates | None = None
_settings: CloudSettings | None = None


def get_session_manager() -> SessionManager:
    """Get the session manager (initialized at startup)."""
    if _session_manager is None:
        raise RuntimeError("App not started. SessionManager not initialized.")
    return _session_manager


def get_templates() -> Jinja2Templates:
    """Get the Jinja2 templates (initialized at startup)."""
    if _templates is None:
        raise RuntimeError("App not started. Templates not initialized.")
    return _templates


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan: initialize DB and session manager on startup,
    clean up on shutdown.
    """
    global _session_manager, _templates, _settings

    _settings = get_cloud_settings()

    # Initialize database
    init_engine(_settings.database_url, echo=_settings.database_echo)
    await create_tables()
    logger.info("Database initialized: %s", _settings.database_url.split("?")[0])

    # Initialize session manager
    _session_manager = SessionManager(
        secret_key=_settings.secret_key,
        max_age=_settings.session_max_age,
    )

    # Initialize templates
    _templates = Jinja2Templates(directory=str(_settings.templates_dir))

    logger.info("QuerySense Cloud started on %s:%s", _settings.host, _settings.port)

    yield

    # Shutdown
    await dispose_engine()
    _session_manager = None
    _templates = None
    logger.info("QuerySense Cloud shut down")


def create_app(settings: CloudSettings | None = None) -> FastAPI:
    """
    Create and configure the FastAPI application.

    Args:
        settings: Optional settings override (uses env vars if None).

    Returns:
        Configured FastAPI app.
    """
    global _settings
    if settings is not None:
        _settings = settings

    app = FastAPI(
        title="QuerySense Cloud",
        description="Deterministic PostgreSQL query plan analysis as a service.",
        version="0.5.2",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # ── Mount static files ──────────────────────────────────────────────
    resolved_settings = _settings or get_cloud_settings()
    static_dir = resolved_settings.static_dir
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # ── API routes ──────────────────────────────────────────────────────
    from querysense.cloud.api.router import api_router

    app.include_router(api_router)

    # ── Web routes ──────────────────────────────────────────────────────
    from querysense.cloud.web.routes import web_router

    app.include_router(web_router)

    # ── Exception handlers ──────────────────────────────────────────────

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc: Any) -> HTMLResponse | dict:
        """Custom 404 page for web requests, JSON for API requests."""
        if request.url.path.startswith("/api/"):
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=404, content={"detail": "Not found"}
            )

        templates = get_templates()
        return templates.TemplateResponse(
            "base.html",
            {"request": request, "user": None},
            status_code=404,
        )

    @app.exception_handler(303)
    async def redirect_handler(request: Request, exc: Any) -> RedirectResponse:
        """Handle redirect exceptions (used by _require_auth)."""
        location = getattr(exc, "headers", {}).get("Location", "/login")
        return RedirectResponse(url=location, status_code=303)

    return app
