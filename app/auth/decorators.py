"""
Authorization decorators for role-based access control.

This module provides Flask route decorators for enforcing role-based
access control. Decorators check user authentication and role privileges,
returning 403 Forbidden responses for unauthorized access.
"""

from functools import wraps
from flask import flash, redirect, url_for, abort
from flask_login import current_user
from app.models import UserRole


def require_role(*roles):
    """
    Decorator to require specific role(s) for access to a route.

    Args:
        *roles: Variable number of roles (UserRole enum or string values)
                that are allowed to access the route.

    Returns:
        Decorated function that checks user role before allowing access.

    Example:
        @require_role(UserRole.GLOBAL_ADMIN, UserRole.SITE_ADMIN)
        def admin_only_route():
            return "Admin content"
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login'))

            # Convert all roles to string values for comparison
            allowed_roles = [r.value if isinstance(r, UserRole) else r for r in roles]

            if current_user.role not in allowed_roles:
                flash('You do not have permission to access this page.', 'error')
                abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_role_or_higher(role):
    """
    Decorator to require minimum role level for access to a route.

    Checks if the user has the specified role or higher privilege level
    based on the role hierarchy.

    Args:
        role: Minimum role required (UserRole enum or string value).

    Returns:
        Decorated function that checks user role hierarchy before allowing access.

    Example:
        @require_role_or_higher(UserRole.CAMP_MANAGER)
        def manager_route():
            return "Manager content"
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login'))

            required_role = role.value if isinstance(role, UserRole) else role

            if not current_user.has_role_or_higher(required_role):
                flash('You do not have permission to access this page.', 'error')
                abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def global_admin_required(f):
    """
    Decorator to restrict route access to global administrators only.

    This is a convenience decorator equivalent to @require_role(UserRole.GLOBAL_ADMIN).

    Args:
        f: The function to decorate.

    Returns:
        Decorated function that checks for global admin role before allowing access.

    Example:
        @global_admin_required
        def super_admin_route():
            return "Global admin only"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))

        if not current_user.is_global_admin:
            flash('Only global administrators can access this page.', 'error')
            abort(403)

        return f(*args, **kwargs)
    return decorated_function
