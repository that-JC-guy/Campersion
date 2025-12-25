# Campersion - OAuth 2.0 Authentication Application

A Flask web application demonstrating OAuth 2.0 authentication with Google and Microsoft. Users can link multiple OAuth providers to a single account via email matching.

## Features

- OAuth 2.0 authentication with Google and Microsoft
- Account linking via email matching
- User can sign in with multiple OAuth providers
- PostgreSQL database running in Docker container
- Responsive UI with Bootstrap 5
- Secure session management with Flask-Login
- Well-commented, maintainable code following Python best practices

## Technology Stack

- **Backend**: Flask 3.0, Python 3.8+
- **Database**: PostgreSQL 14 (Docker)
- **ORM**: Flask-SQLAlchemy
- **Authentication**: Authlib (OAuth 2.0), Flask-Login
- **Frontend**: Jinja2 templates, Bootstrap 5
- **Migrations**: Flask-Migrate

## Prerequisites

Before you begin, ensure you have the following installed:

- Python 3.8 or higher
- Docker and Docker Compose
- pip (Python package manager)
- Git (optional, for version control)

## Project Structure

```
Campersion/
├── app/
│   ├── __init__.py              # Application factory
│   ├── models.py                # Database models
│   ├── auth/                    # Authentication blueprint
│   │   ├── __init__.py
│   │   ├── routes.py            # OAuth routes
│   │   └── utils.py             # OAuth helper functions
│   ├── main/                    # Main application blueprint
│   │   ├── __init__.py
│   │   └── routes.py            # Dashboard routes
│   ├── templates/               # Jinja2 templates
│   │   ├── base.html
│   │   ├── login.html
│   │   └── dashboard.html
│   └── static/                  # Static files (CSS, images)
│       └── css/
│           └── style.css
├── docker-compose.yml           # PostgreSQL container configuration
├── config.py                    # Application configuration
├── requirements.txt             # Python dependencies
├── .env                         # Environment variables (create from .env.example)
├── .env.example                 # Example environment variables
├── .gitignore                   # Git ignore rules
├── run.py                       # Application entry point
└── README.md                    # This file
```

## Setup Instructions

### 1. Clone or Navigate to Project Directory

```bash
cd /mnt/c/Users/joshu/OneDrive/Documents/Development/Campersion
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Start PostgreSQL Database

```bash
# Start PostgreSQL container in background
docker-compose up -d

# Verify PostgreSQL is running
docker-compose ps
```

The PostgreSQL container will be accessible at:
- Host: `localhost`
- Port: `5432`
- Database: `campersion`
- Username: `campersion`
- Password: `campersion_dev`

### 5. Configure Environment Variables

```bash
# Copy the example .env file
cp .env.example .env

# Edit .env file with your configuration
# You'll need to add OAuth credentials (see next section)
```

Generate a secure secret key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Add this to your `.env` file as `SECRET_KEY`.

### 6. Register OAuth Applications

#### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Google+ API**:
   - Navigate to "APIs & Services" > "Library"
   - Search for "Google+ API"
   - Click "Enable"
4. Create OAuth 2.0 credentials:
   - Navigate to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Choose "Web application"
   - Add authorized redirect URI: `http://localhost:5000/auth/callback/google`
   - Click "Create"
5. Copy the **Client ID** and **Client Secret** to your `.env` file:
   ```
   GOOGLE_CLIENT_ID=your-google-client-id-here
   GOOGLE_CLIENT_SECRET=your-google-client-secret-here
   ```

#### Microsoft OAuth Setup

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to "Azure Active Directory"
3. Click "App registrations" > "New registration"
4. Register your application:
   - Name: `Campersion` (or your preferred name)
   - Supported account types: "Accounts in any organizational directory and personal Microsoft accounts"
   - Redirect URI: Select "Web" and enter `http://localhost:5000/auth/callback/microsoft`
   - Click "Register"
5. Copy the **Application (client) ID** from the Overview page
6. Create a client secret:
   - Navigate to "Certificates & secrets"
   - Click "New client secret"
   - Add a description and set expiration
   - Click "Add"
   - **Copy the secret value immediately** (it won't be shown again)
7. Add credentials to your `.env` file:
   ```
   MICROSOFT_CLIENT_ID=your-microsoft-client-id-here
   MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret-here
   ```

### 7. Initialize Database

```bash
# Initialize Flask-Migrate
flask db init

# Create initial migration
flask db migrate -m "Initial migration with User and OAuthProvider models"

# Apply migration to database
flask db upgrade
```

### 8. Run the Application

```bash
# Run Flask development server
python run.py
```

The application will be available at: `http://localhost:5000`

## Using the Application

### First Time Login

1. Navigate to `http://localhost:5000`
2. Click "Continue with Google" or "Continue with Microsoft"
3. Authenticate with your OAuth provider
4. You'll be redirected to the dashboard showing your user information

### Linking Additional OAuth Provider

1. After logging in with one provider (e.g., Google)
2. Log out from the dashboard
3. Click "Continue with Microsoft" (using the **same email address**)
4. The Microsoft account will be linked to your existing user profile
5. Log in again to see both providers listed under "Linked Accounts"

### Dashboard Features

The dashboard displays:
- Profile picture (from OAuth provider)
- Name
- Email address
- Account creation date
- Last login timestamp
- List of linked OAuth providers

## Database Schema

### Users Table

| Column      | Type         | Description                    |
|-------------|--------------|--------------------------------|
| id          | Integer      | Primary key                    |
| email       | String(255)  | User email (unique)            |
| name        | String(255)  | User display name              |
| picture     | String(500)  | Profile picture URL            |
| created_at  | DateTime     | Account creation timestamp     |
| last_login  | DateTime     | Last login timestamp           |

### OAuth Providers Table

| Column           | Type         | Description                          |
|------------------|--------------|--------------------------------------|
| id               | Integer      | Primary key                          |
| user_id          | Integer      | Foreign key to users table           |
| provider_name    | String(20)   | OAuth provider ('google', 'microsoft')|
| provider_user_id | String(255)  | Unique user ID from provider         |
| created_at       | DateTime     | When OAuth account was linked        |

## Account Linking Logic

The application uses email matching to link OAuth providers:

1. **First OAuth Login**: Creates new User + OAuthProvider record
2. **Existing OAuth Login**: Updates last_login timestamp
3. **New Provider, Same Email**: Links new OAuthProvider to existing User

This allows users to seamlessly switch between Google and Microsoft while maintaining a single user profile.

## Security Features

- **OAuth 2.0 Authorization Code Flow**: Most secure OAuth flow for server-side apps
- **State Parameter**: Automatic CSRF protection via Authlib
- **HTTPOnly Cookies**: Session cookies inaccessible to JavaScript (XSS protection)
- **SameSite Cookies**: CSRF protection for session cookies
- **Secure Secret Key**: Strong random key for session encryption
- **SQL Injection Protection**: SQLAlchemy ORM parameterizes all queries
- **No Password Storage**: Credentials managed by OAuth providers

## Development Tips

### Viewing Database Records

```bash
# Access PostgreSQL container
docker exec -it campersion_postgres psql -U campersion -d campersion

# View users
SELECT * FROM users;

# View OAuth providers
SELECT * FROM oauth_providers;

# Exit PostgreSQL
\q
```

### Stopping PostgreSQL Container

```bash
# Stop container
docker-compose down

# Stop and remove volumes (deletes database data)
docker-compose down -v
```

### Database Migrations

After modifying models in `app/models.py`:

```bash
# Create migration
flask db migrate -m "Description of changes"

# Apply migration
flask db upgrade
```

### Running in Production

For production deployment:

1. Update `.env` with production values:
   - Set `FLASK_ENV=production`
   - Use strong `SECRET_KEY`
   - Update `DATABASE_URL` to production database
   - Update `OAUTH_REDIRECT_BASE` to your domain (HTTPS)
2. Update OAuth redirect URIs in Google Cloud Console and Azure Portal
3. Use a production WSGI server:
   ```bash
   gunicorn -w 4 -b 0.0.0.0:8000 run:app
   ```
4. Use a reverse proxy (nginx, Apache) to handle HTTPS

## Troubleshooting

### OAuth Error: Redirect URI Mismatch

- Verify redirect URIs in Google Cloud Console and Azure Portal **exactly match**:
  - Google: `http://localhost:5000/auth/callback/google`
  - Microsoft: `http://localhost:5000/auth/callback/microsoft`
- Include `http://` or `https://` prefix
- Check for trailing slashes

### Database Connection Error

- Verify PostgreSQL container is running: `docker-compose ps`
- Check `DATABASE_URL` in `.env` file matches container configuration
- Restart container: `docker-compose restart`

### Missing OAuth Credentials

- Ensure `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `MICROSOFT_CLIENT_ID`, and `MICROSOFT_CLIENT_SECRET` are set in `.env`
- Verify credentials are correct (no extra spaces)

### ModuleNotFoundError

- Activate virtual environment: `source venv/bin/activate`
- Reinstall dependencies: `pip install -r requirements.txt`

## Next Steps

This OAuth login feature provides a solid foundation for adding more features:

- User profile editing
- Additional OAuth providers (GitHub, Facebook, etc.)
- Email/password authentication option
- Two-factor authentication (2FA)
- User roles and permissions
- API endpoints with token authentication
- Activity logging and audit trails

## Contributing

When adding new features, please:

1. Follow PEP 8 Python style guidelines
2. Add comments explaining code blocks
3. Use the blueprint pattern for new routes
4. Create database migrations for model changes
5. Test thoroughly before committing

## License

This project is for educational and demonstration purposes.

## Support

For issues or questions, please review this README or check:
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Authlib Documentation](https://docs.authlib.org/)
- [Flask-Login Documentation](https://flask-login.readthedocs.io/)
