"""
Main application routes.

This module handles the primary application routes including
the home page and user dashboard.
"""

from flask import render_template, redirect, url_for
from flask_login import login_required, current_user
from app.main import main_bp


@main_bp.route('/')
def index():
    """
    Home page route.

    If user is already logged in, redirect to dashboard.
    Otherwise, redirect to login page.

    Returns:
        Redirect to dashboard or login page
    """

    if current_user.is_authenticated:
        # User is logged in, redirect to dashboard
        return redirect(url_for('main.dashboard'))
    else:
        # User is not logged in, redirect to login
        return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """
    User dashboard page.

    Displays the logged-in user's information including:
    - Profile picture (if available)
    - Name
    - Email
    - Linked OAuth providers
    - Account created date
    - Last login timestamp

    This route is protected by @login_required decorator, which means
    unauthenticated users will be redirected to the login page.

    Returns:
        Rendered dashboard template with user information
    """

    # Get all OAuth providers linked to this user
    # This allows users to see which accounts (Google, Microsoft) they've linked
    linked_providers = current_user.oauth_providers.all()

    return render_template(
        'dashboard.html',
        user=current_user,
        linked_providers=linked_providers
    )
