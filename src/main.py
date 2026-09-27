"""
AegisDev: Autonomous Developer Workflow Engine & Code Review Coach
Application entry point — FastAPI app, middleware, and route registration.

Security posture (post-AegisDev audit):
  ✅ TD-08  CORS allow_origins reads from ALLOWED_ORIGINS env var — no wildcard.
  ✅ TD-09  Global exception handler returns sanitised error with UUID correlation
            ID; full detail logged server-side only.
"""

import os
import time
import uuid
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.controllers.auth_controller import router as auth_router
from src.controllers.data_controller import router as data_router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("aegisdev")

# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AegisDev API",
    version="2.0.0",
    description="Autonomous Developer Workflow Engine & Code Review Coach",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# FIX TD-08: CORS — explicit origin allow-list from environment variable.
#   Set ALLOWED_ORIGINS to a comma-separated list of permitted origins, e.g.:
#     ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
#   Defaults to localhost:3000 for local development only.
# ---------------------------------------------------------------------------
_raw_origins: str = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")
_ALLOWED_ORIGINS: list[str] = [
    o.strip() for o in _raw_origins.split(",") if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def request_timing_middleware(request: Request, call_next):
    """Log every request with its duration."""
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    logger.info(
        "%s %s → %s  (%.1f ms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


# ---------------------------------------------------------------------------
# FIX TD-09: Global exception handler — sanitised client response.
#   A UUID error-reference ID is generated per event:
#     • Returned to the client for support correlation.
#     • Logged server-side with the full traceback.
#   No internal error detail is ever forwarded to the caller.
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    error_id = str(uuid.uuid4())
    logger.exception(
        "Unhandled error [%s] on %s %s",
        error_id,
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An unexpected error occurred. Please contact support.",
            "error_id": error_id,
        },
    )


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(data_router, prefix="/api", tags=["Data"])


# ---------------------------------------------------------------------------
# Health / root
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
async def root():
    return {"service": "AegisDev API", "status": "healthy", "version": "2.0.0"}


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "environment": os.getenv("APP_ENV", "development"),
    }
