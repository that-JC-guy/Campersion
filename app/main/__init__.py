"""
Main blueprint initialization.

This module creates the main application blueprint which handles
the primary application routes (home, dashboard).
"""

from flask import Blueprint

# Create main blueprint
# Routes in this blueprint have no prefix
main_bp = Blueprint('main', __name__)

# Import routes after blueprint creation to avoid circular imports
from app.main import routes
