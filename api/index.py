import os
import sys

# Ensure project root is in sys.path for serverless imports
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Bootstrap required environment variables for serverless runtime
os.environ.setdefault("JWT_SECRET", "aegisdev-production-secure-32bytes-jwt-secret-key-xyz987!")
os.environ.setdefault("ALLOWED_ORIGINS", "*")
os.environ.setdefault("APP_ENV", "production")

from src.main import app
