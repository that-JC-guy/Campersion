"""
Authentication utility functions.

This module provides helper functions for OAuth authentication,
including account linking logic that allows users to link multiple
OAuth providers to the same account via email matching.
"""

from datetime import datetime
from app import db
from app.models import User, OAuthProvider


def link_or_create_user(email, name, picture, provider, provider_user_id):
    """
    Link OAuth provider to existing user or create new user.

    This function implements the account linking logic:
    1. Check if this OAuth provider account already exists
    2. If yes, return the associated user
    3. If no, check if a user with this email exists
    4. If user exists, link this OAuth provider to existing user
    5. If user doesn't exist, create new user and link OAuth provider

    This allows users to link multiple OAuth providers (Google, Microsoft)
    to the same account by matching email addresses.

    Args:
        email (str): User's email from OAuth provider
        name (str): User's display name from OAuth provider
        picture (str): User's profile picture URL from OAuth provider
        provider (str): OAuth provider name ('google' or 'microsoft')
        provider_user_id (str): Unique user ID from OAuth provider

    Returns:
        User: User object (either existing or newly created)
    """

    # Check if this specific OAuth provider account already exists
    oauth_provider = OAuthProvider.query.filter_by(
        provider_name=provider,
        provider_user_id=provider_user_id
    ).first()

    if oauth_provider:
        # This OAuth account has been used before
        # Return the associated user and update last login
        user = oauth_provider.user
        user.update_last_login()
        return user

    # This is a new OAuth login
    # Check if a user with this email already exists (from different OAuth provider)
    user = User.query.filter_by(email=email).first()

    if not user:
        # Create new user account
        # OAuth users are considered verified since they authenticated with OAuth provider

        # Split OAuth name into first/last if possible
        first_name = None
        last_name = None
        if name:
            name_parts = name.split(' ', 1)
            first_name = name_parts[0]
            last_name = name_parts[1] if len(name_parts) > 1 else None

        user = User(
            email=email,
            name=name,  # Keep for OAuth compatibility
            first_name=first_name,
            last_name=last_name,
            picture=picture,
            email_verified=True
        )
        db.session.add(user)
        # Flush to get user.id without committing
        db.session.flush()
    else:
        # Existing user linking a new OAuth provider
        # Set email_verified=True since they authenticated via OAuth
        user.email_verified = True

    # Link this OAuth provider to the user (new or existing)
    new_oauth_provider = OAuthProvider(
        user_id=user.id,
        provider_name=provider,
        provider_user_id=provider_user_id
    )
    db.session.add(new_oauth_provider)

    # Commit all changes to database
    db.session.commit()

    return user


def parse_google_userinfo(userinfo):
    """
    Parse user information from Google OAuth response.

    Args:
        userinfo (dict): User info dictionary from Google

    Returns:
        dict: Standardized user info with keys: email, name, picture, provider_user_id
    """
    return {
        'email': userinfo.get('email'),
        'name': userinfo.get('name'),
        'picture': userinfo.get('picture'),
        'provider_user_id': userinfo.get('sub')  # Google's unique user ID
    }


def parse_microsoft_userinfo(userinfo):
    """
    Parse user information from Microsoft OAuth response.

    Args:
        userinfo (dict): User info dictionary from Microsoft

    Returns:
        dict: Standardized user info with keys: email, name, picture, provider_user_id
    """
    return {
        'email': userinfo.get('email') or userinfo.get('userPrincipalName'),
        'name': userinfo.get('displayName') or userinfo.get('name'),
        'picture': None,  # Microsoft doesn't provide picture URL in standard response
        'provider_user_id': userinfo.get('id') or userinfo.get('oid')  # Microsoft's unique user ID
    }
