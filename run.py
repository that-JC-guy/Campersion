"""
Application entry point.

This module creates and runs the Flask application. It imports the
application factory function and creates an app instance using the
configuration specified in the FLASK_ENV environment variable.
"""

import os
from app import create_app

# Get the environment from FLASK_ENV, default to 'development'
config_name = os.environ.get('FLASK_ENV', 'development')

# Create the Flask application using the application factory pattern
app = create_app(config_name)

if __name__ == '__main__':
    """
    Run the development server.

    Note: This is only for development. In production, use a WSGI server
    like gunicorn: gunicorn -w 4 run:app
    """
    app.run(host='0.0.0.0', port=5000, debug=True)
