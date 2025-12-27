"""
Application factory module.

This module implements the Flask application factory pattern.
It initializes and configures all Flask extensions (SQLAlchemy, Flask-Login,
Flask-Migrate, Authlib OAuth) and registers application blueprints.
"""

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail
from authlib.integrations.flask_client import OAuth
from config import config

# Initialize Flask extensions
# These are initialized here but configured in create_app()
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
mail = Mail()
oauth = OAuth()


def create_app(config_name='development'):
    """
    Application factory function.

    Creates and configures a Flask application instance based on the
    specified configuration name (development, production, or testing).

    Args:
        config_name (str): Configuration environment name. Defaults to 'development'.

    Returns:
        Flask: Configured Flask application instance.
    """

    # Create Flask application instance
    app = Flask(__name__)

    # Load configuration from config.py based on environment
    app.config.from_object(config[config_name])

    # Initialize Flask extensions with the app
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    oauth.init_app(app)

    # Configure Flask-Login
    login_manager.login_view = 'auth.login'  # Redirect to login page if not authenticated
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    # User loader callback for Flask-Login
    # This tells Flask-Login how to load a user from the session
    @login_manager.user_loader
    def load_user(user_id):
        """
        Load user by ID from database.

        Flask-Login calls this function to reload the user object from
        the user ID stored in the session.

        Args:
            user_id (str): The user ID stored in the session.

        Returns:
            User: User object or None if not found.
        """
        from app.models import User
        return User.query.get(int(user_id))

    # Configure OAuth providers using Authlib
    configure_oauth(app)

    # Register blueprints
    register_blueprints(app)

    # Register error handlers
    register_error_handlers(app)

    return app


def configure_oauth(app):
    """
    Configure OAuth 2.0 providers (Google and Microsoft).

    Registers OAuth clients with Authlib using configuration values
    from the Flask app config.

    Args:
        app (Flask): Flask application instance.
    """

    # Register Google OAuth 2.0 client
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

    # Register Microsoft OAuth 2.0 client
    # Using OpenID Connect discovery URL for automatic configuration
    # Note: Using /common endpoint to support both personal and organizational accounts
    oauth.register(
        name='microsoft',
        client_id=app.config['MICROSOFT_CLIENT_ID'],
        client_secret=app.config['MICROSOFT_CLIENT_SECRET'],
        server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
        client_kwargs={
            # Include User.Read scope for Microsoft Graph API access
            'scope': 'openid email profile User.Read',
            # Skip issuer validation since /common endpoint has variable issuer
            'token_endpoint_auth_method': 'client_secret_post'
        },
        # Disable strict issuer validation for /common endpoint
        authorize_params={
            'response_type': 'code'
        }
    )


def register_error_handlers(app):
    """
    Register error handlers for common HTTP errors.

    Provides custom error pages for 403 Forbidden and 404 Not Found errors.

    Args:
        app (Flask): Flask application instance.
    """

    @app.errorhandler(403)
    def forbidden(e):
        """Handle 403 Forbidden errors."""
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        """Handle 404 Not Found errors."""
        return render_template('errors/404.html'), 404


def register_blueprints(app):
    """
    Register application blueprints.

    Blueprints organize the application into modular components.
    This function imports and registers all application blueprints.

    Args:
        app (Flask): Flask application instance.
    """

    # Import blueprints
    from app.auth import auth_bp
    from app.main import main_bp
    from app.admin import admin_bp
    from app.events import events_bp
    from app.camps import camps_bp

    # Register authentication blueprint
    # All auth routes will be prefixed with /auth
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # Register main blueprint
    # Main routes have no prefix (e.g., /, /dashboard)
    app.register_blueprint(main_bp)

    # Register admin blueprint
    # All admin routes will be prefixed with /admin
    app.register_blueprint(admin_bp, url_prefix='/admin')

    # Register events blueprint
    # All events routes will be prefixed with /events
    app.register_blueprint(events_bp, url_prefix='/events')

    # Register camps blueprint
    # All camps routes will be prefixed with /camps
    app.register_blueprint(camps_bp, url_prefix='/camps')
