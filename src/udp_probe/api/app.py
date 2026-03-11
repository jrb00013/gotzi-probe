"""FastAPI application — include Tier 1–3 routers + web UI."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from udp_probe.api.routers import attack_router, rules_router, honeypot_router
from udp_probe.api.routers.security import router as security_router
from udp_probe.api.routes import capture, scan, discovery, digest, config_routes, alerts, dashboard


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create DB tables on startup."""
    try:
        import udp_probe.models  # noqa: F401 - register all models
        from udp_probe.core.database import init_db
        init_db()
    except Exception:
        pass
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Gotzi",
        description="Gotzi — capture, scan, discovery, attack simulation (authorized only), rules, honeypot.",
        lifespan=lifespan,
    )
    app.include_router(attack_router)
    app.include_router(rules_router)
    app.include_router(honeypot_router)
    app.include_router(security_router, prefix="/api")
    app.include_router(capture.router, prefix="/api/capture", tags=["capture"])
    app.include_router(scan.router, prefix="/api/scan", tags=["scan"])
    app.include_router(discovery.router, prefix="/api/discovery", tags=["discovery"])
    app.include_router(digest.router, prefix="/api/digest", tags=["digest"])
    app.include_router(config_routes.router, prefix="/api/config", tags=["config"])
    app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
    app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])

    templates_dir = Path(__file__).resolve().parent / "templates"
    static_dir = Path(__file__).resolve().parent / "static"
    if templates_dir.exists():
        templates = Jinja2Templates(directory=str(templates_dir))
        @app.get("/")
        def index(request: Request):
            return templates.TemplateResponse(request, "index.html", {"request": request})
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    return app
