"""
Events blueprint for event management.

This blueprint provides routes for creating, viewing, editing, and
managing events through an approval workflow. Event managers can create
events which require site admin approval before becoming publicly visible.
"""

from flask import Blueprint

events_bp = Blueprint('events', __name__)

from app.events import routes
