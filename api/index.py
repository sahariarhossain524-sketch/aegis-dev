from __future__ import annotations

import os
import sys
import traceback
import logging

# Ensure root directory is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Set runtime env defaults before importing src
os.environ.setdefault("JWT_SECRET", "aegisdev-production-secure-32bytes-jwt-secret-key-xyz987!")
os.environ.setdefault("ALLOWED_ORIGINS", "*")
os.environ.setdefault("APP_ENV", "production")

try:
    from src.main import app
except Exception as exc:
    logging.exception("Failed to import AegisDev application: %s", exc)
    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse

    app = FastAPI(title="AegisDev Startup Diagnostic")
    _err_msg = traceback.format_exc()

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    async def diagnostic_error(full_path: str = ""):
        return PlainTextResponse(
            f"AegisDev Startup Error:\n\n{_err_msg}",
            status_code=500,
        )
