"""
Authentication forms using Flask-WTF.

This module defines WTForms for user authentication including
registration, login, password reset, and email verification.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from app.models import User, UserRole


class RegistrationForm(FlaskForm):
    """
    User registration form.

    Allows users to create a new account with email and password.
    Includes validation to ensure email is not already registered.
    """

    email = StringField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please enter a valid email address'),
            Length(max=255, message='Email must be less than 255 characters')
        ],
        render_kw={'placeholder': 'your.email@example.com'}
    )

    name = StringField(
        'Full Name',
        validators=[
            DataRequired(message='Name is required'),
            Length(max=255, message='Name must be less than 255 characters')
        ],
        render_kw={'placeholder': 'John Doe'}
    )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required'),
            Length(min=8, message='Password must be at least 8 characters long')
        ],
        render_kw={'placeholder': 'Choose a strong password'}
    )

    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message='Please confirm your password'),
            EqualTo('password', message='Passwords must match')
        ],
        render_kw={'placeholder': 'Re-enter your password'}
    )

    submit = SubmitField('Create Account')

    def validate_email(self, field):
        """
        Custom validator to check if email is already registered.

        Args:
            field: The email field to validate

        Raises:
            ValidationError: If email is already in use
        """
        user = User.query.filter_by(email=field.data.lower()).first()
        if user:
            raise ValidationError('This email is already registered. Please log in or use a different email.')


class LoginForm(FlaskForm):
    """
    Email/password login form.

    Allows users to authenticate with their email and password.
    """

    email = StringField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please enter a valid email address')
        ],
        render_kw={'placeholder': 'your.email@example.com'}
    )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required')
        ],
        render_kw={'placeholder': 'Enter your password'}
    )

    remember_me = BooleanField('Keep me logged in')

    submit = SubmitField('Log In')


class ForgotPasswordForm(FlaskForm):
    """
    Password reset request form.

    Allows users to request a password reset link via email.
    """

    email = StringField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please enter a valid email address')
        ],
        render_kw={'placeholder': 'your.email@example.com'}
    )

    submit = SubmitField('Send Reset Link')


class ResetPasswordForm(FlaskForm):
    """
    Password reset form.

    Allows users to set a new password using a valid reset token.
    """

    password = PasswordField(
        'New Password',
        validators=[
            DataRequired(message='Password is required'),
            Length(min=8, message='Password must be at least 8 characters long')
        ],
        render_kw={'placeholder': 'Choose a new password'}
    )

    confirm_password = PasswordField(
        'Confirm New Password',
        validators=[
            DataRequired(message='Please confirm your password'),
            EqualTo('password', message='Passwords must match')
        ],
        render_kw={'placeholder': 'Re-enter your new password'}
    )

    submit = SubmitField('Reset Password')


class ChangeUserRoleForm(FlaskForm):
    """
    Form for global admins to change user roles.

    Provides a dropdown to select from all available roles in the system.
    Only accessible to global administrators.
    """

    role = SelectField(
        'Role',
        choices=[
            (UserRole.GLOBAL_ADMIN.value, 'Global Admin'),
            (UserRole.SITE_ADMIN.value, 'Site Admin'),
            (UserRole.EVENT_MANAGER.value, 'Event Manager'),
            (UserRole.CAMP_MANAGER.value, 'Camp Manager'),
            (UserRole.MEMBER.value, 'Member')
        ],
        validators=[DataRequired(message='Please select a role')]
    )

    submit = SubmitField('Update Role')
