from __future__ import annotations

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

os.environ.setdefault("ALLOWED_ORIGINS", "*")
os.environ.setdefault("APP_ENV", "production")

_jwt_sec = os.getenv("JWT_SECRET", "").strip().strip("'\"")
if _jwt_sec:
    os.environ["JWT_SECRET"] = _jwt_sec
elif os.getenv("VERCEL"):
    import secrets
    os.environ["JWT_SECRET"] = secrets.token_hex(32)

try:
    from src.main import app
except Exception as exc:  # pragma: no cover
    import traceback
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    err_trace = traceback.format_exc()
    app = FastAPI(title="AegisDev Vercel Bootstrapper")

    @app.api_route("/{path:path}", methods=["GET", "POST", "PATCH", "DELETE"])
    async def catch_all(path: str):
        return JSONResponse(
            status_code=500,
            content={
                "status": "startup_error",
                "exception": f"{type(exc).__name__}: {exc}",
                "traceback": err_trace,
                "has_jwt_secret": bool(os.getenv("JWT_SECRET")),
                "env_keys": [
                    k for k in os.environ.keys()
                    if not k.startswith("npm_") and not k.startswith("_")
                ],
            },
        )
