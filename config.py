"""
PyScan Application Configuration

Centralised configuration for the Flask application.
All sensitive settings should be overridden via environment variables.

Author: PyScan Project — BSc Cybersecurity Final Year Project
Institution: Federal University of Technology, Babura (FUTB)
"""

import os
from datetime import timedelta


class Config:
    """Base configuration class for PyScan."""

    # Flask core settings
    SECRET_KEY: str = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
    MAX_CONTENT_LENGTH: int = 1 * 1024 * 1024 * 1024  # 1 GB
    UPLOAD_FOLDER: str = "uploads"

    # Session security
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(hours=2)

    # CSRF protection
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = 3600  # 1 hour

    # Database
    DATABASE_PATH: str = os.environ.get("DATABASE_PATH") or "database/pyscan.db"

    # Model paths
    MODEL_PATH: str = "models/bilstm_attention_model.h5"
    TOKENIZER_PATH: str = "models/tokenizer_config.json"
    LABEL_ENCODER_PATH: str = "models/label_encoder.json"

    # Rate limiting
    RATE_LIMIT_MAX_ATTEMPTS: int = 5
    RATE_LIMIT_WINDOW_SECONDS: int = 900  # 15 minutes
