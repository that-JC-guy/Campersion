"""
Admin blueprint for site administration.

This blueprint provides routes for global administrators to manage
users, roles, and other system-wide settings.
"""

from flask import Blueprint

admin_bp = Blueprint('admin', __name__)

from app.admin import routes
