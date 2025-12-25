"""
Authentication blueprint initialization.

This module creates the authentication blueprint which handles all
OAuth 2.0 authentication routes (login, callback, logout).
"""

from flask import Blueprint

# Create authentication blueprint
# All routes in this blueprint will be prefixed with /auth
auth_bp = Blueprint('auth', __name__)

# Import routes after blueprint creation to avoid circular imports
from app.auth import routes
