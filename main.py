from __future__ import annotations

import os
import sys

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Set runtime defaults
os.environ.setdefault("ALLOWED_ORIGINS", "*")
os.environ.setdefault("APP_ENV", "production")

_jwt_sec = os.getenv("JWT_SECRET", "").strip().strip("'\"")
if _jwt_sec:
    os.environ["JWT_SECRET"] = _jwt_sec
elif os.getenv("VERCEL"):
    import secrets
    os.environ["JWT_SECRET"] = secrets.token_hex(32)

from src.main import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
