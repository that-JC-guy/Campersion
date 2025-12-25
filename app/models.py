"""
Database models for the application.

This module defines SQLAlchemy models for users and OAuth provider
associations. The models support multiple OAuth providers per user
through account linking via email matching.
"""

from datetime import datetime, timedelta
import secrets
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class User(UserMixin, db.Model):
    """
    User model for storing user account information.

    Inherits from UserMixin to provide Flask-Login required properties:
    - is_authenticated
    - is_active
    - is_anonymous
    - get_id()

    Users can link multiple OAuth providers (Google, Microsoft) to the
    same account via email matching.
    """

    __tablename__ = 'users'

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # User profile information
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), nullable=True)
    picture = db.Column(db.String(500), nullable=True)  # Profile picture URL from OAuth provider

    # Account metadata
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Password authentication fields
    # password_hash stores bcrypt-hashed password (nullable for OAuth-only users)
    password_hash = db.Column(db.String(255), nullable=True)

    # Email verification (required for email/password authentication)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    email_verification_token = db.Column(db.String(100), unique=True, nullable=True)
    email_verification_sent_at = db.Column(db.DateTime, nullable=True)

    # Password reset functionality
    password_reset_token = db.Column(db.String(100), unique=True, nullable=True)
    password_reset_sent_at = db.Column(db.DateTime, nullable=True)

    # Relationship to OAuth providers
    # One user can have multiple OAuth provider accounts linked
    oauth_providers = db.relationship('OAuthProvider', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        """String representation of User object."""
        return f'<User {self.email}>'

    def update_last_login(self):
        """Update the last_login timestamp to current time."""
        self.last_login = datetime.utcnow()
        db.session.commit()

    # Password authentication methods
    def set_password(self, password):
        """
        Hash and store a password using bcrypt via Werkzeug.

        Args:
            password (str): Plain text password to hash and store.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """
        Verify a password against the stored hash.

        Args:
            password (str): Plain text password to verify.

        Returns:
            bool: True if password matches, False otherwise.
        """
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    # Email verification methods
    def generate_verification_token(self):
        """
        Generate a cryptographically secure email verification token.

        Returns:
            str: The generated 32-byte hex token.
        """
        self.email_verification_token = secrets.token_hex(32)
        self.email_verification_sent_at = datetime.utcnow()
        return self.email_verification_token

    # Password reset methods
    def generate_reset_token(self):
        """
        Generate a cryptographically secure password reset token.

        Returns:
            str: The generated 32-byte hex token.
        """
        self.password_reset_token = secrets.token_hex(32)
        self.password_reset_sent_at = datetime.utcnow()
        return self.password_reset_token

    def verify_token_expiry(self, sent_at, hours):
        """
        Check if a token is still valid based on expiry time.

        Args:
            sent_at (datetime): When the token was sent.
            hours (int): Number of hours until token expires.

        Returns:
            bool: True if token is still valid, False if expired or missing.
        """
        if not sent_at:
            return False
        expiry_time = sent_at + timedelta(hours=hours)
        return datetime.utcnow() < expiry_time

    # Authentication method properties
    @property
    def has_password_auth(self):
        """
        Check if user has password authentication configured.

        Returns:
            bool: True if password is set, False otherwise.
        """
        return self.password_hash is not None

    @property
    def has_oauth_auth(self):
        """
        Check if user has any OAuth providers linked.

        Returns:
            bool: True if at least one OAuth provider is linked, False otherwise.
        """
        return self.oauth_providers.count() > 0


class OAuthProvider(db.Model):
    """
    OAuth Provider model for linking users to their OAuth accounts.

    This model creates a many-to-one relationship between users and
    OAuth providers. A user can link multiple providers (e.g., both
    Google and Microsoft), but each provider account can only be
    linked to one user.
    """

    __tablename__ = 'oauth_providers'

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # Foreign key to User
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # OAuth provider information
    provider_name = db.Column(db.String(20), nullable=False)  # 'google' or 'microsoft'
    provider_user_id = db.Column(db.String(255), nullable=False)  # Unique user ID from OAuth provider

    # When this OAuth account was linked
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Ensure each OAuth provider account can only be linked once
    # The same provider_user_id from the same provider cannot exist twice
    __table_args__ = (
        db.UniqueConstraint('provider_name', 'provider_user_id', name='uix_provider_oauth_id'),
    )

    def __repr__(self):
        """String representation of OAuthProvider object."""
        return f'<OAuthProvider {self.provider_name}:{self.provider_user_id}>'
