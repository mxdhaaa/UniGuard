"""
UniGuard Backend Main Application (Milestone 15 Hardened)
FastAPI entry point for the passive network intelligence platform.
Includes production lifespan management, security headers, CORS hardening,
and safe error handling.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import settings
from backend.app.api.system import router as system_router
from backend.app.api.demo import router as demo_router
from backend.app.api.risk import router as risk_router
from backend.app.api.evidence import router as evidence_router
from backend.app.api.websocket import router as websocket_router
from backend.app.api.ingestion import router as ingestion_router
from backend.app.api.pcap import router as pcap_router
from backend.app.api.dashboard import router as dashboard_router
from backend.app.api.investigations import router as investigation_router
from backend.app.api.reports import router as report_router

# Configure centralized structured logging
logging.basicConfig(
    level=getattr(logging, settings.log_level, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("uniguard.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager for startup health verification
    and graceful resource disposal during shutdown.
    """
    logger.info(
        "Starting %s (%s mode) on %s:%d",
        settings.app_name,
        settings.environment,
        settings.api_host,
        settings.api_port,
    )
    
    from backend.app.db.database import check_db_health, engine
    from backend.app.services.ingestion_service import ingestion_service
    from backend.app.services.websocket_manager import websocket_manager

    # 1. Verify database readiness
    if check_db_health():
        logger.info("Database connection established and healthy.")
    else:
        logger.warning("Database unreachable or not configured. Using local/fallback mode.")

    # 2. Ensure PCAP upload isolation directory exists
    try:
        os.makedirs(settings.pcap_upload_dir, exist_ok=True)
        logger.info("PCAP upload directory initialized at %s", settings.pcap_upload_dir)
    except Exception as e:
        logger.error("Failed to initialize PCAP upload directory: %s", e)

    yield

    # 3. Graceful shutdown: stop background threads and release resources
    logger.info("Initiating UniGuard Backend graceful shutdown...")
    try:
        ingestion_service.stop()
        logger.info("Live packet capture stopped cleanly.")
    except Exception as e:
        logger.error("Error stopping live capture: %s", e)

    try:
        await websocket_manager.close_all()
        logger.info("Active WebSocket connections closed cleanly.")
    except Exception as e:
        logger.error("Error closing WebSockets: %s", e)

    try:
        engine.dispose()
        logger.info("Database connection pool disposed cleanly.")
    except Exception as e:
        logger.error("Error disposing database pool: %s", e)

    logger.info("UniGuard Backend shutdown completed.")


# Configure environment-aware OpenAPI documentation
docs_url = "/docs" if settings.enable_docs else None
redoc_url = "/redoc" if settings.enable_docs else None
openapi_url = "/openapi.json" if settings.enable_docs else None

app = FastAPI(
    title=settings.app_name,
    description="AI-Based Detection of Cyber Threats in Unidirectional IP Traffic",
    version=settings.app_version,
    lifespan=lifespan,
    docs_url=docs_url,
    redoc_url=redoc_url,
    openapi_url=openapi_url,
)


# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Inject standard HTTP security headers to protect browser clients."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"
    return response


# Global Unhandled Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Prevents leakage of tracebacks, filesystem paths, and database details in production.
    """
    logger.exception(
        "Unhandled internal exception on %s %s: %s",
        request.method,
        request.url.path,
        exc,
    )
    if settings.is_production:
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error occurred."},
        )
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {str(exc)}"},
    )


# Configure CORS with production protection against unrestricted wildcard '*'
effective_origins = list(settings.cors_origins)
if settings.is_production and "*" in effective_origins:
    logger.warning("Unrestricted wildcard '*' origin stripped in production environment.")
    effective_origins = [o for o in effective_origins if o != "*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=effective_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Mount API endpoints under /api prefix
app.include_router(system_router, prefix="/api")
app.include_router(demo_router, prefix="/api")
app.include_router(risk_router, prefix="/api")
app.include_router(evidence_router, prefix="/api")
app.include_router(websocket_router, prefix="/api")
app.include_router(ingestion_router, prefix="/api")
app.include_router(pcap_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(investigation_router, prefix="/api")
app.include_router(report_router, prefix="/api")
