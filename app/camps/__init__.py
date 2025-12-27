"""
Camps blueprint for camp management.

This blueprint provides routes for creating, viewing, editing, and
managing camps and their associations with events through an approval workflow.
"""

from flask import Blueprint

camps_bp = Blueprint('camps', __name__)

from app.camps import routes
