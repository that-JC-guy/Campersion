# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Starting the Application
```bash
# Activate virtual environment
source venv/bin/activate

# Start PostgreSQL (required)
docker-compose up -d

# Start MailHog for email testing (required for email/password auth)
/tmp/MailHog_linux_amd64 &  # Or install globally and run: mailhog

# Run Flask development server
python run.py
# Application: http://localhost:5000
# MailHog UI: http://localhost:8025
```

### Database Operations
```bash
# Create migration after modifying models
flask db migrate -m "Description of changes"

# Apply migrations
flask db upgrade

# Rollback one migration
flask db downgrade

# View database directly
docker exec -it campersion_postgres psql -U campersion -d campersion
# Useful queries: SELECT * FROM users; SELECT * FROM oauth_providers;
```

### Environment Setup
```bash
# Generate new secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Database connection string format
DATABASE_URL=postgresql://campersion:campersion_dev@localhost:5432/campersion
```

## Architecture Overview

### Application Factory Pattern
The app uses Flask's application factory pattern (`app/__init__.py:create_app()`). Extensions (db, login_manager, migrate, mail, oauth) are initialized globally but configured within the factory. This allows multiple app instances with different configs (development, testing, production).

### Blueprint Structure
- **auth blueprint** (`/auth/*`): Handles all authentication (OAuth and email/password)
- **main blueprint** (`/*`): Handles authenticated user features (dashboard)

### Authentication System: Dual-Method with Account Linking

The app supports two authentication methods that can be linked to the same account:

1. **OAuth 2.0** (Google, Microsoft)
2. **Email/Password** with verification

**Critical Account Linking Logic** (`app/auth/utils.py:link_or_create_user()`):
- Users are matched by email address across authentication methods
- When a user logs in via OAuth, the system checks if a user with that email already exists
- If exists (even with email/password), the OAuth provider is linked to existing user
- OAuth users are automatically marked as `email_verified=True`
- Same logic allows linking multiple OAuth providers (Google + Microsoft) to one account

**Email/Password Flow** (`app/auth/routes.py`):
1. Registration: Creates user with `email_verified=False`, generates token, sends verification email
2. Email verification: Token validates (24hr expiry), sets `email_verified=True`
3. Login: Checks password AND `email_verified` status before allowing access
4. Password reset: Generates token (1hr expiry), sends reset email, updates password

### Database Models

**User model** (`app/models.py:User`):
- Primary authentication entity
- Contains fields for BOTH OAuth (picture) and email/password (password_hash, email_verified, tokens)
- Relationships: One user → many OAuthProviders
- Methods: `set_password()`, `check_password()`, `generate_verification_token()`, `generate_reset_token()`, `verify_token_expiry()`
- Properties: `has_password_auth`, `has_oauth_auth`

**OAuthProvider model**:
- Links OAuth accounts to users
- Unique constraint on (provider_name, provider_user_id) prevents duplicate OAuth links
- Cascade delete: when user deleted, all OAuth links deleted

### Email Infrastructure

**Threading for async sending** (`app/auth/email.py:send_email()`):
- Emails sent in background thread to avoid blocking requests
- Flask application context pushed in thread (required for Flask-Mail)
- Uses MailHog (localhost:1025) in development

**Email types**:
- Verification: 24-hour expiry, required before login
- Password reset: 1-hour expiry

### Form Validation

All forms use Flask-WTF for CSRF protection and WTForms for validation (`app/auth/forms.py`):
- RegistrationForm: Custom validator checks if email already exists
- LoginForm: Simple validation, actual auth happens in route
- Password fields: Minimum 8 characters, EqualTo validator for confirmation

### OAuth Provider Parsing

Google and Microsoft return different userinfo structures. Parser functions (`app/auth/utils.py`) standardize to:
```python
{
    'email': str,
    'name': str,
    'picture': str or None,
    'provider_user_id': str  # 'sub' for Google, 'id' for Microsoft
}
```

**Microsoft-specific quirks**:
- Uses `/common` endpoint to support both personal and organizational accounts
- Requires `User.Read` scope for Microsoft Graph API access
- Must skip issuer validation since `/common` returns variable issuer per tenant
- Uses `userPrincipalName` as fallback for email

### Configuration Environments

Three configs in `config.py`:
- **DevelopmentConfig**: DEBUG=True, SQLALCHEMY_ECHO=True, SESSION_COOKIE_SECURE=False
- **ProductionConfig**: Requires SECRET_KEY env var or raises error, SESSION_COOKIE_SECURE=True
- **TestingConfig**: Uses SQLite in-memory database, WTF_CSRF_ENABLED=False

Selected via: `create_app('development')` or `FLASK_ENV` environment variable.

## Critical Implementation Details

### Password Security
Uses Werkzeug's `generate_password_hash()` which defaults to scrypt with salt. Never store plain passwords.

### Token Generation
Uses `secrets.token_hex(32)` for cryptographically secure tokens (64 hex characters). Tokens stored in database with unique constraint.

### Email Enumeration Prevention
Forgot password and resend verification always show same success message regardless of whether email exists. Only send email if user actually exists server-side.

### Session Security
- HTTPOnly cookies prevent JavaScript access (XSS protection)
- SameSite='Lax' provides CSRF protection
- 7-day expiration with `remember_me` option

## OAuth Setup Requirements

**Redirect URIs must match exactly**:
- Google: `http://localhost:5000/auth/callback/google`
- Microsoft: `http://localhost:5000/auth/callback/microsoft`

**Production**: Update `OAUTH_REDIRECT_BASE` in .env and reconfigure redirect URIs in provider consoles.

## Testing Authentication Flows

1. **Email registration**: Register → Check MailHog → Click verification link → Login
2. **Password reset**: Click forgot password → Check MailHog → Click reset link → Set new password
3. **Account linking**: Register with email → Logout → Login with OAuth using same email → Both methods work
4. **Multiple OAuth**: Login with Google → Logout → Login with Microsoft using same email → Dashboard shows both providers

## Database Migration Strategy

After modifying `app/models.py`:
1. Run `flask db migrate -m "description"`
2. **Review the generated migration file** in `migrations/versions/`
3. Add data migrations if needed (e.g., setting defaults for existing rows)
4. Apply with `flask db upgrade`

Example: The email/password migration includes data migration to set `email_verified=True` for existing OAuth users.
