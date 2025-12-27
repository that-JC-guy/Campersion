"""
Admin blueprint routes.

This module defines routes for administrative functions including
user management and role assignment.
"""

from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.admin import admin_bp
from app import db
from app.models import User, UserRole
from app.auth.forms import ChangeUserRoleForm
from app.auth.decorators import global_admin_required


@admin_bp.route('/users')
@login_required
@global_admin_required
def list_users():
    """
    Display list of all users with their roles.

    Accessible only to global administrators. Users are sorted by role
    (higher privilege first) and then by creation date.

    Returns:
        Rendered template with user list.
    """
    # Define role order for sorting (lower index = higher privilege)
    role_order = {
        UserRole.GLOBAL_ADMIN.value: 0,
        UserRole.SITE_ADMIN.value: 1,
        UserRole.EVENT_MANAGER.value: 2,
        UserRole.CAMP_MANAGER.value: 3,
        UserRole.MEMBER.value: 4
    }

    users = User.query.all()
    users_sorted = sorted(users,
                         key=lambda u: (role_order.get(u.role, 999), u.created_at))

    return render_template('admin/users.html', users=users_sorted, UserRole=UserRole)


@admin_bp.route('/users/<int:user_id>/change-role', methods=['GET', 'POST'])
@login_required
@global_admin_required
def change_user_role(user_id):
    """
    Change a user's role.

    Allows global administrators to change another user's role.
    Prevents admins from changing their own role for security.

    Args:
        user_id: The ID of the user whose role should be changed.

    Returns:
        On GET: Rendered form template with current role pre-selected.
        On POST: Redirect to user list with success/error message.
    """
    user = User.query.get_or_404(user_id)

    # Prevent admins from changing their own role
    if user.id == current_user.id:
        flash('You cannot change your own role.', 'error')
        return redirect(url_for('admin.list_users'))

    form = ChangeUserRoleForm()

    # Pre-populate form with current role
    if request.method == 'GET':
        form.role.data = user.role

    if form.validate_on_submit():
        old_role = user.role
        new_role = form.role.data

        user.role = new_role
        db.session.commit()

        flash(f"Changed {user.name}'s role from '{old_role.title()}' to '{new_role.title()}'.", 'success')
        return redirect(url_for('admin.list_users'))

    return render_template('admin/change_role.html', user=user, form=form)
