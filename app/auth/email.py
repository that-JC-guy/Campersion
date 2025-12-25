"""
Email utilities for authentication.

This module provides functions for sending authentication-related emails
such as email verification and password reset requests.
"""

from threading import Thread
from flask import current_app, render_template
from flask_mail import Message
from app import mail


def send_async_email(app, msg):
    """
    Send email asynchronously in a separate thread.

    Flask-Mail requires an active application context, so we push
    one in this background thread.

    Args:
        app: Flask application instance
        msg: Flask-Mail Message object to send
    """
    with app.app_context():
        mail.send(msg)


def send_email(subject, recipients, html_body):
    """
    Send an email using Flask-Mail.

    Emails are sent asynchronously in a background thread to avoid
    blocking the request-response cycle.

    Args:
        subject (str): Email subject line
        recipients (list): List of recipient email addresses
        html_body (str): HTML content of the email
    """
    msg = Message(
        subject=subject,
        recipients=recipients,
        html=html_body,
        sender=current_app.config['MAIL_DEFAULT_SENDER']
    )

    # Send email in background thread to avoid blocking
    app = current_app._get_current_object()
    thread = Thread(target=send_async_email, args=(app, msg))
    thread.start()


def send_verification_email(user):
    """
    Send email verification link to user.

    Generates a verification token and sends an email with a link
    that the user must click to verify their email address.

    Args:
        user: User object that needs email verification
    """
    from app import db

    # Generate verification token
    token = user.generate_verification_token()
    db.session.commit()

    # Build verification URL
    verify_url = f"{current_app.config['OAUTH_REDIRECT_BASE']}/auth/verify/{token}"

    # Render email template
    html_body = render_template(
        'emails/verify_email.html',
        user=user,
        verify_url=verify_url,
        expiry_hours=current_app.config['EMAIL_VERIFICATION_EXPIRY_HOURS']
    )

    # Send email
    send_email(
        subject='Verify Your Campersion Account',
        recipients=[user.email],
        html_body=html_body
    )


def send_password_reset_email(user):
    """
    Send password reset link to user.

    Generates a password reset token and sends an email with a link
    that allows the user to reset their password.

    Args:
        user: User object requesting password reset
    """
    from app import db

    # Generate reset token
    token = user.generate_reset_token()
    db.session.commit()

    # Build reset URL
    reset_url = f"{current_app.config['OAUTH_REDIRECT_BASE']}/auth/reset-password/{token}"

    # Render email template
    html_body = render_template(
        'emails/reset_password.html',
        user=user,
        reset_url=reset_url,
        expiry_hours=current_app.config['PASSWORD_RESET_EXPIRY_HOURS']
    )

    # Send email
    send_email(
        subject='Reset Your Campersion Password',
        recipients=[user.email],
        html_body=html_body
    )
