from __future__ import annotations

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

os.environ.setdefault("ALLOWED_ORIGINS", "*")
os.environ.setdefault("APP_ENV", "production")

from src.main import app
