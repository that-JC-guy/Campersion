"""
Database models for the application.

This module defines SQLAlchemy models for users and OAuth provider
associations. The models support multiple OAuth providers per user
through account linking via email matching.
"""

from datetime import datetime, timedelta
import secrets
from enum import Enum
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class UserRole(str, Enum):
    """
    User role enumeration defining access levels.

    Roles are listed in order of decreasing privilege:
    - GLOBAL_ADMIN: Full system access, can manage all users and settings
    - SITE_ADMIN: Can manage site-level content and users
    - EVENT_MANAGER: Can create and manage events
    - CAMP_MANAGER: Can manage specific camps
    - MEMBER: Basic user access
    """
    GLOBAL_ADMIN = 'global admin'
    SITE_ADMIN = 'site admin'
    EVENT_MANAGER = 'event manager'
    CAMP_MANAGER = 'camp manager'
    MEMBER = 'member'

    @classmethod
    def get_role_hierarchy(cls):
        """
        Return roles in order of privilege level (highest to lowest).

        Returns:
            list: List of UserRole enum values in hierarchical order
        """
        return [
            cls.GLOBAL_ADMIN,
            cls.SITE_ADMIN,
            cls.EVENT_MANAGER,
            cls.CAMP_MANAGER,
            cls.MEMBER
        ]


class EventStatus(str, Enum):
    """
    Event status enumeration for approval workflow.

    Events progress through these statuses:
    - PENDING: Event created, awaiting site admin approval
    - APPROVED: Event approved by site admin, publicly visible
    - REJECTED: Event rejected by site admin
    - CANCELLED: Event was cancelled by creator or site admin
    """
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'
    CANCELLED = 'cancelled'


class AssociationStatus(str, Enum):
    """
    Association status enumeration for camp-event approval workflow.

    Camp-event associations progress through these statuses:
    - PENDING: Camp requested to join event, awaiting event creator approval
    - APPROVED: Request approved by event creator, camp is associated with event
    - REJECTED: Request rejected by event creator
    """
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'


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

    # Role-based access control
    # Each user has exactly one role from the UserRole enum
    role = db.Column(db.String(20), nullable=False, default=UserRole.MEMBER.value, server_default=UserRole.MEMBER.value)

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

    # Role-based access control methods
    def has_role(self, role):
        """
        Check if user has the specified role.

        Args:
            role (str or UserRole): Role to check (can be string or UserRole enum)

        Returns:
            bool: True if user has the role, False otherwise
        """
        if isinstance(role, UserRole):
            role = role.value
        return self.role == role

    def has_role_or_higher(self, role):
        """
        Check if user has the specified role or higher privilege level.

        Uses the role hierarchy to determine if user's role has equal or
        greater privileges than the specified role.

        Args:
            role (str or UserRole): Role to check (can be string or UserRole enum)

        Returns:
            bool: True if user has this role or higher, False otherwise
        """
        if isinstance(role, UserRole):
            role = role.value

        hierarchy = UserRole.get_role_hierarchy()
        try:
            user_role_index = hierarchy.index(UserRole(self.role))
            check_role_index = hierarchy.index(UserRole(role))
            return user_role_index <= check_role_index
        except (ValueError, IndexError):
            return False

    @property
    def is_global_admin(self):
        """
        Check if user is a global admin.

        Returns:
            bool: True if user is global admin, False otherwise
        """
        return self.role == UserRole.GLOBAL_ADMIN.value

    @property
    def is_site_admin_or_higher(self):
        """
        Check if user is site admin or higher privilege level.

        Returns:
            bool: True if user is site admin or global admin, False otherwise
        """
        return self.has_role_or_higher(UserRole.SITE_ADMIN)

    @property
    def role_display_name(self):
        """
        Get user-friendly display name for role.

        Returns:
            str: Capitalized role name (e.g., "Global Admin")
        """
        return self.role.title()


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


class Event(db.Model):
    """
    Event model for managing festivals, concerts, and large gatherings.

    Events are created by event managers with 'pending' status and must be
    approved by site administrators before becoming publicly visible.
    """

    __tablename__ = 'events'

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # Basic event information
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(255), nullable=True)

    # Event dates
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)

    # Contact information
    event_manager_email = db.Column(db.String(255), nullable=True)
    event_manager_phone = db.Column(db.String(20), nullable=True)
    safety_manager_email = db.Column(db.String(255), nullable=True)
    safety_manager_phone = db.Column(db.String(20), nullable=True)
    business_manager_email = db.Column(db.String(255), nullable=True)
    business_manager_phone = db.Column(db.String(20), nullable=True)
    board_email = db.Column(db.String(255), nullable=True)

    # Status for approval workflow
    status = db.Column(db.String(20), nullable=False,
                      default=EventStatus.PENDING.value,
                      server_default=EventStatus.PENDING.value)

    # Foreign key to creator (User who created the event)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Relationship to User
    creator = db.relationship('User', backref='created_events', lazy=True)

    # Timestamps
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                          onupdate=datetime.utcnow)

    def __repr__(self):
        """String representation of Event object."""
        return f'<Event {self.title}>'

    @property
    def is_pending(self):
        """Check if event is pending approval."""
        return self.status == EventStatus.PENDING.value

    @property
    def is_approved(self):
        """Check if event is approved."""
        return self.status == EventStatus.APPROVED.value

    @property
    def is_rejected(self):
        """Check if event is rejected."""
        return self.status == EventStatus.REJECTED.value

    @property
    def is_cancelled(self):
        """Check if event is cancelled."""
        return self.status == EventStatus.CANCELLED.value

    @property
    def status_display_name(self):
        """Get user-friendly status name."""
        return self.status.title()


class Camp(db.Model):
    """
    Camp model for managing community camps/villages at events.

    Camps are created by any authenticated member and can request to join events.
    Event creators must approve camp requests before they are associated.
    """

    __tablename__ = 'camps'

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # Basic camp information
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(255), nullable=False)

    # Capacity
    max_sites = db.Column(db.Integer, nullable=False)
    max_people = db.Column(db.Integer, nullable=False)

    # Amenities (boolean fields)
    has_communal_kitchen = db.Column(db.Boolean, default=False, nullable=False, server_default='false')
    has_communal_space = db.Column(db.Boolean, default=False, nullable=False, server_default='false')
    has_art_exhibits = db.Column(db.Boolean, default=False, nullable=False, server_default='false')
    has_member_activities = db.Column(db.Boolean, default=False, nullable=False, server_default='false')
    has_non_member_activities = db.Column(db.Boolean, default=False, nullable=False, server_default='false')

    # Foreign key to creator
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Relationship to User
    creator = db.relationship('User', backref='created_camps', lazy=True)

    # Timestamps
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                          onupdate=datetime.utcnow)

    def __repr__(self):
        """String representation of Camp object."""
        return f'<Camp {self.name}>'

    @property
    def amenities_list(self):
        """Get list of available amenities."""
        amenities = []
        if self.has_communal_kitchen:
            amenities.append('Communal Kitchen')
        if self.has_communal_space:
            amenities.append('Communal Space')
        if self.has_art_exhibits:
            amenities.append('Art Exhibits')
        if self.has_member_activities:
            amenities.append('Member Activities')
        if self.has_non_member_activities:
            amenities.append('Non-Member Activities')
        return amenities


class CampEventAssociation(db.Model):
    """
    Association table linking camps to events with approval workflow.

    When a camp requests to join an event, an association is created with
    'pending' status. The event creator must approve or reject the request.
    """

    __tablename__ = 'camp_event_associations'

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # Foreign keys
    camp_id = db.Column(db.Integer, db.ForeignKey('camps.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)

    # Approval status
    status = db.Column(db.String(20), nullable=False,
                      default=AssociationStatus.PENDING.value,
                      server_default=AssociationStatus.PENDING.value)

    # Timestamps
    requested_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    camp = db.relationship('Camp', backref=db.backref('event_associations', lazy='dynamic',
                                                       cascade='all, delete-orphan'))
    event = db.relationship('Event', backref=db.backref('camp_associations', lazy='dynamic',
                                                         cascade='all, delete-orphan'))

    # Ensure unique camp-event combinations
    __table_args__ = (
        db.UniqueConstraint('camp_id', 'event_id', name='uix_camp_event'),
    )

    def __repr__(self):
        """String representation of CampEventAssociation object."""
        return f'<CampEventAssociation camp_id={self.camp_id} event_id={self.event_id} status={self.status}>'

    @property
    def is_pending(self):
        """Check if association is pending approval."""
        return self.status == AssociationStatus.PENDING.value

    @property
    def is_approved(self):
        """Check if association is approved."""
        return self.status == AssociationStatus.APPROVED.value

    @property
    def is_rejected(self):
        """Check if association is rejected."""
        return self.status == AssociationStatus.REJECTED.value
