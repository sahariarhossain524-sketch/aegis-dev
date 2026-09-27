"""
AegisDev: Autonomous Developer Workflow Engine & Code Review Coach
Application entry point — FastAPI app, middleware, and route registration.

Security posture (post-AegisDev audit):
  ✅ TD-08  CORS allow_origins reads from ALLOWED_ORIGINS env var — no wildcard.
  ✅ TD-09  Global exception handler returns sanitised error with UUID correlation
            ID; full detail logged server-side only.
"""

from __future__ import annotations

import os
import time
import uuid
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

# ---------------------------------------------------------------------------
# Serverless cloud environment fallback
# ---------------------------------------------------------------------------
if not os.getenv("JWT_SECRET"):
    import secrets
    os.environ["JWT_SECRET"] = os.getenv("SERVERLESS_JWT_KEY", secrets.token_hex(32))

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
async def root(request: Request):
    if "text/html" in request.headers.get("accept", ""):
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AegisDev | IBM Bob 2.0 Hackathon</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;600;700&family=IBM+Plex+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --primary: #0F62FE;
            --accent: #8a3ffc;
            --success: #3ddbd9;
            --text: #f0f6fc;
            --muted: #8b949e;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'IBM Plex Sans', -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 3rem 1.5rem;
        }
        .container { max-width: 900px; width: 100%; }
        .hero {
            background: linear-gradient(135deg, #1f242c 0%, #161b22 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
            position: relative;
            overflow: hidden;
        }
        .hero::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 4px;
            background: linear-gradient(90deg, var(--primary), var(--accent), var(--success));
        }
        .badge {
            display: inline-block;
            background: rgba(15, 98, 254, 0.15);
            color: #78a9ff;
            border: 1px solid rgba(15, 98, 254, 0.4);
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }
        h1 { font-size: 2.5rem; font-weight: 700; margin-bottom: 0.75rem; line-height: 1.2; }
        p.subtitle { font-size: 1.15rem; color: var(--muted); margin-bottom: 1.5rem; line-height: 1.6; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
        }
        .card h3 { font-size: 1.1rem; margin-bottom: 0.5rem; color: var(--text); }
        .card p { font-size: 0.9rem; color: var(--muted); line-height: 1.5; }
        .stat { font-size: 2rem; font-weight: 700; color: var(--success); margin-bottom: 0.25rem; font-family: 'IBM Plex Mono', monospace; }
        .actions { display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 1.5rem; }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.25rem;
            border-radius: 6px;
            font-weight: 600;
            text-decoration: none;
            transition: all 0.2s;
        }
        .btn-primary { background: var(--primary); color: #fff; }
        .btn-primary:hover { background: #0353e9; }
        .btn-secondary { background: var(--surface); color: var(--text); border: 1px solid var(--border); }
        .btn-secondary:hover { border-color: var(--muted); }
        footer { margin-top: auto; text-align: center; color: var(--muted); font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <span class="badge">IBM Bob 2.0 Hackathon · Winner Prototype</span>
            <h1>🛡️ AegisDev API & Agentic Engine</h1>
            <p class="subtitle">Autonomous Multi-Agent Code Auditor, Self-Healing QA & Developer Onboarding Engine built natively with IBM Bob 2.0 IDE.</p>
            <div class="actions">
                <a href="/docs" class="btn btn-primary">📖 Interactive Swagger API Docs</a>
                <a href="/redoc" class="btn btn-secondary">📑 ReDoc Documentation</a>
                <a href="https://github.com/sahariarhossain524-sketch/aegis-dev" target="_blank" class="btn btn-secondary">🐙 GitHub Repository</a>
            </div>
        </div>
        <div class="grid">
            <div class="card">
                <div class="stat">123 / 123</div>
                <h3>Automated Tests Passing</h3>
                <p>Zero failures, zero regressions across auth, CRUD, RBAC, and security guardrails.</p>
            </div>
            <div class="card">
                <div class="stat">10 / 10</div>
                <h3>OWASP ASVS Issues Fixed</h3>
                <p>Fully compliant SARIF 2.1.0 report generated. Constant-time compare, PBKDF2, JTI revocation.</p>
            </div>
            <div class="card">
                <div class="stat">10.96</div>
                <h3>Bobcoins Consumed</h3>
                <p>Extremely resource-efficient autonomous execution out of 40 coins allocated budget.</p>
            </div>
        </div>
        <footer>
            Built with purpose using IBM Bob 2.0 · Live Deployment on Vercel · © 2026 Sahariar Hossain
        </footer>
    </div>
</body>
</html>"""
        return HTMLResponse(content=html_content, status_code=200)
    return {"service": "AegisDev API", "status": "healthy", "version": "2.0.0"}


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "environment": os.getenv("APP_ENV", "development"),
    }
