"""
Application configuration classes.

This module defines configuration classes for different environments
(development, production, testing). Configuration values are loaded
from environment variables using python-dotenv.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """
    Base configuration class with common settings.
    All environment-specific configs inherit from this class.
    """

    # Flask secret key for session management
    # IMPORTANT: Generate a secure key using: python -c "import secrets; print(secrets.token_hex(32))"
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://campersion:campersion_dev@localhost:5432/campersion'
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable Flask-SQLAlchemy event system (saves resources)

    # Session configuration for security
    SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookie (XSS protection)
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)  # Session expires after 7 days

    # OAuth redirect base URL
    OAUTH_REDIRECT_BASE = os.environ.get('OAUTH_REDIRECT_BASE') or 'http://localhost:5000'

    # Google OAuth 2.0 configuration
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

    # Microsoft OAuth 2.0 configuration
    MICROSOFT_CLIENT_ID = os.environ.get('MICROSOFT_CLIENT_ID')
    MICROSOFT_CLIENT_SECRET = os.environ.get('MICROSOFT_CLIENT_SECRET')
    MICROSOFT_AUTHORITY = "https://login.microsoftonline.com/common"
    MICROSOFT_SCOPE = ["openid", "email", "profile"]

    # Flask-WTF CSRF protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # No time limit for CSRF tokens

    # Flask-Mail configuration for email sending
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'localhost')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@campersion.com')

    # Email verification and password reset expiry settings
    EMAIL_VERIFICATION_EXPIRY_HOURS = 24  # 24 hours to verify email
    PASSWORD_RESET_EXPIRY_HOURS = 1  # 1 hour to reset password


class DevelopmentConfig(Config):
    """
    Development environment configuration.
    Enables debug mode and detailed logging.
    """
    DEBUG = True
    TESTING = False

    # Enable SQL query logging for debugging
    SQLALCHEMY_ECHO = True

    # Allow session cookies over HTTP (localhost development)
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    """
    Production environment configuration.
    Enforces security settings and disables debugging.
    """
    DEBUG = False
    TESTING = False

    # Disable SQL query logging in production
    SQLALCHEMY_ECHO = False

    # Require HTTPS for session cookies in production
    SESSION_COOKIE_SECURE = True

    # Override SECRET_KEY requirement - must be set in production
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable must be set in production")


class TestingConfig(Config):
    """
    Testing environment configuration.
    Uses in-memory SQLite database for fast testing.
    """
    TESTING = True
    DEBUG = True

    # Use SQLite in-memory database for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

    # Disable CSRF protection in testing
    WTF_CSRF_ENABLED = False

    # Allow session cookies over HTTP in testing
    SESSION_COOKIE_SECURE = False


# Configuration dictionary for easy access
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
