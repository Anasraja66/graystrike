"""
APT Agents — FastAPI Main Application
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import settings
from app.core.database import engine, Base
from app.api.v1 import auth, organizations, projects, domains, scans, findings, reports, admin, billing, ci, easm
from app.services.scheduler_service import start_scheduler_background_loop
import asyncio


import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    print("[INFO] APT Agents API starting...")
    # Auto-initialize database tables if not existing
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("[INFO] Database tables verified.")

    # Start automated recurring scan scheduler loop
    scheduler_task = asyncio.create_task(start_scheduler_background_loop())
    print("[INFO] Recurring scan scheduler loop initialized.")

    yield

    scheduler_task.cancel()
    print("[INFO] APT Agents API shutting down...")


app = FastAPI(
    title="APT Agents API",
    description="Autonomous AI Web Security Testing Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth.router,          prefix="/api/v1/auth",          tags=["Authentication"])
app.include_router(organizations.router, prefix="/api/v1/organizations",  tags=["Organizations"])
app.include_router(projects.router,      prefix="/api/v1/projects",       tags=["Projects"])
app.include_router(domains.router,       prefix="/api/v1/domains",        tags=["Domains"])
app.include_router(scans.router,         prefix="/api/v1/scans",          tags=["Scans"])
app.include_router(findings.router,      prefix="/api/v1/findings",       tags=["Findings"])
app.include_router(reports.router,       prefix="/api/v1/reports",        tags=["Reports"])
app.include_router(billing.router,       prefix="/api/v1/billing",        tags=["Billing & Subscriptions"])
app.include_router(ci.router,            prefix="/api/v1/ci",             tags=["CI/CD Integration"])
app.include_router(easm.router,          prefix="/api/v1/easm",           tags=["Attack Surface Management"])
app.include_router(admin.router,         prefix="/api/v1/admin",          tags=["Admin"])


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "APT Agents API", "version": "1.0.0"}
