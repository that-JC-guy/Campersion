"""
Authentication routes for OAuth 2.0 and email/password login.

This module handles:
- OAuth 2.0 authorization code flow for Google and Microsoft
- Email/password registration and login
- Email verification
- Password reset functionality
"""

from flask import render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from app.auth import auth_bp
from app import oauth, db
from app.auth.utils import link_or_create_user, parse_google_userinfo, parse_microsoft_userinfo
from app.auth.forms import RegistrationForm, LoginForm, ForgotPasswordForm, ResetPasswordForm
from app.auth.email import send_verification_email, send_password_reset_email
from app.models import User


@auth_bp.route('/login')
def login():
    """
    Display the login page with OAuth provider buttons.

    This is the entry point for unauthenticated users.
    Shows buttons to login with Google or Microsoft.

    Returns:
        Rendered login template
    """
    return render_template('login.html')


@auth_bp.route('/login/<provider>')
def oauth_login(provider):
    """
    Initiate OAuth 2.0 authorization flow for specified provider.

    This route redirects the user to the OAuth provider's authorization
    page where they will authenticate and grant permissions.

    Args:
        provider (str): OAuth provider name ('google' or 'microsoft')

    Returns:
        Redirect to OAuth provider's authorization URL
    """

    # Validate provider
    if provider not in ['google', 'microsoft']:
        flash('Invalid OAuth provider.', 'error')
        return redirect(url_for('auth.login'))

    # Get the OAuth client for this provider
    oauth_client = oauth.create_client(provider)

    # Build the callback URL where OAuth provider will redirect after authentication
    redirect_uri = url_for('auth.oauth_callback', provider=provider, _external=True)

    # Redirect to provider's authorization page
    # Authlib automatically adds state parameter for CSRF protection
    return oauth_client.authorize_redirect(redirect_uri)


@auth_bp.route('/callback/<provider>')
def oauth_callback(provider):
    """
    Handle OAuth 2.0 callback from provider.

    After user authenticates with the OAuth provider, they are redirected
    back to this route with an authorization code. This function:
    1. Exchanges the authorization code for an access token
    2. Fetches user profile information using the access token
    3. Links the OAuth account to existing user or creates new user
    4. Logs the user in using Flask-Login

    Args:
        provider (str): OAuth provider name ('google' or 'microsoft')

    Returns:
        Redirect to dashboard on success, or login page on error
    """

    # Validate provider
    if provider not in ['google', 'microsoft']:
        flash('Invalid OAuth provider.', 'error')
        return redirect(url_for('auth.login'))

    try:
        # Get the OAuth client for this provider
        oauth_client = oauth.create_client(provider)

        # Exchange authorization code for access token
        # Authlib automatically validates the state parameter for CSRF protection
        if provider == 'microsoft':
            # Microsoft /common endpoint requires special handling for issuer validation
            # Skip issuer validation since it varies by tenant
            token = oauth_client.authorize_access_token(
                claims_options={
                    "iss": {"essential": False}
                }
            )
        else:
            token = oauth_client.authorize_access_token()

        # Fetch user profile information using the access token
        if provider == 'google':
            # Google provides userinfo endpoint
            userinfo = oauth_client.userinfo()
            user_data = parse_google_userinfo(userinfo)

        elif provider == 'microsoft':
            # Microsoft requires explicit userinfo request
            userinfo = oauth_client.get('https://graph.microsoft.com/v1.0/me').json()
            # Debug logging to see what Microsoft returns
            current_app.logger.info(f'Microsoft userinfo response: {userinfo}')
            user_data = parse_microsoft_userinfo(userinfo)
            current_app.logger.info(f'Parsed user_data: {user_data}')

        # Validate that we received essential user information
        if not user_data.get('email') or not user_data.get('provider_user_id'):
            current_app.logger.error(f'Missing user data - email: {user_data.get("email")}, provider_user_id: {user_data.get("provider_user_id")}')
            flash('Failed to retrieve user information from OAuth provider.', 'error')
            return redirect(url_for('auth.login'))

        # Link OAuth account to user or create new user
        user = link_or_create_user(
            email=user_data['email'],
            name=user_data.get('name', 'User'),
            picture=user_data.get('picture'),
            provider=provider,
            provider_user_id=user_data['provider_user_id']
        )

        # Log the user in using Flask-Login
        # remember=True keeps the user logged in across browser sessions
        login_user(user, remember=True)

        # Flash success message
        flash(f'Successfully logged in with {provider.capitalize()}!', 'success')

        # Redirect to dashboard
        return redirect(url_for('main.dashboard'))

    except Exception as e:
        # Log the error (in production, use proper logging)
        current_app.logger.error(f'OAuth error for {provider}: {str(e)}')

        # Show user-friendly error message
        flash(f'Authentication failed. Please try again.', 'error')
        return redirect(url_for('auth.login'))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration with email and password.

    GET: Display registration form
    POST: Process registration, send verification email

    Users must verify their email before they can log in.

    Returns:
        Rendered registration form or redirect to login page
    """

    # If user is already logged in, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()

    if form.validate_on_submit():
        # Create new user
        user = User(
            email=form.email.data.lower(),
            name=form.name.data,
            email_verified=False
        )
        user.set_password(form.password.data)

        # Save user to database
        db.session.add(user)
        db.session.commit()

        # Send verification email
        send_verification_email(user)

        flash('Account created! Please check your email to verify your account before logging in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html', form=form)


@auth_bp.route('/login/email', methods=['GET', 'POST'])
def email_login():
    """
    Email/password login.

    GET: Display login form
    POST: Authenticate user with email and password

    Users must have verified their email to log in.

    Returns:
        Rendered login form or redirect to dashboard
    """

    # If user is already logged in, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        # Find user by email
        user = User.query.filter_by(email=form.email.data.lower()).first()

        # Check if user exists and password is correct
        if user and user.check_password(form.password.data):
            # Check if email is verified
            if not user.email_verified:
                flash('Please verify your email address before logging in. Check your inbox for the verification link.', 'warning')
                return render_template('email_login.html', form=form)

            # Log the user in
            login_user(user, remember=form.remember_me.data)
            user.update_last_login()

            flash('Successfully logged in!', 'success')

            # Redirect to next page if specified, otherwise dashboard
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'error')

    return render_template('email_login.html', form=form)


@auth_bp.route('/verify/<token>')
def verify_email(token):
    """
    Email verification handler.

    Validates the verification token and marks the user's email as verified.

    Args:
        token (str): Email verification token from the URL

    Returns:
        Redirect to login page with success or error message
    """

    # Find user by verification token
    user = User.query.filter_by(email_verification_token=token).first()

    if not user:
        flash('Invalid or expired verification link.', 'error')
        return redirect(url_for('auth.login'))

    # Check if token is expired
    if not user.verify_token_expiry(
        user.email_verification_sent_at,
        current_app.config['EMAIL_VERIFICATION_EXPIRY_HOURS']
    ):
        flash('Verification link has expired. Please request a new one.', 'error')
        return redirect(url_for('auth.resend_verification'))

    # Mark email as verified
    user.email_verified = True
    user.email_verification_token = None
    user.email_verification_sent_at = None
    db.session.commit()

    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('auth.login'))


@auth_bp.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    """
    Resend email verification link.

    GET: Display form to enter email
    POST: Send new verification email

    Returns:
        Rendered form or redirect to login page
    """

    if request.method == 'POST':
        email = request.form.get('email', '').lower()
        user = User.query.filter_by(email=email).first()

        # Always show same message to prevent email enumeration
        flash('If that email is registered and not yet verified, we\'ve sent a new verification link.', 'info')

        if user and not user.email_verified:
            send_verification_email(user)

        return redirect(url_for('auth.login'))

    return render_template('resend_verification.html')


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """
    Request password reset link.

    GET: Display form to enter email
    POST: Send password reset email

    Returns:
        Rendered form or redirect to login page
    """

    # If user is already logged in, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = ForgotPasswordForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()

        # Always show same message to prevent email enumeration
        flash('If that email is registered, we\'ve sent password reset instructions.', 'info')

        # Only send email if user exists and has password auth
        if user and user.has_password_auth:
            send_password_reset_email(user)

        return redirect(url_for('auth.login'))

    return render_template('forgot_password.html', form=form)


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """
    Reset password using token from email.

    GET: Display password reset form
    POST: Update password and clear reset token

    Args:
        token (str): Password reset token from the URL

    Returns:
        Rendered reset form or redirect to login page
    """

    # If user is already logged in, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    # Find user by reset token
    user = User.query.filter_by(password_reset_token=token).first()

    if not user:
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('auth.forgot_password'))

    # Check if token is expired
    if not user.verify_token_expiry(
        user.password_reset_sent_at,
        current_app.config['PASSWORD_RESET_EXPIRY_HOURS']
    ):
        flash('Reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('auth.forgot_password'))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        # Set new password
        user.set_password(form.password.data)

        # Clear reset token
        user.password_reset_token = None
        user.password_reset_sent_at = None

        db.session.commit()

        flash('Password reset successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html', form=form, token=token)


@auth_bp.route('/logout')
@login_required
def logout():
    """
    Log out the current user.

    Clears the user's session using Flask-Login and redirects
    to the login page.

    Returns:
        Redirect to login page
    """

    # Clear the user's session
    logout_user()

    # Flash logout message
    flash('You have been logged out successfully.', 'info')

    # Redirect to login page
    return redirect(url_for('auth.login'))
