import os
import secrets
from datetime import timedelta

class Config:
    #DEBUG = True
    # Checking for secret key, if does not exist, make one
    if 'SECRET_KEY' not in os.environ:
        os.environ['SECRET_KEY'] = secrets.token_hex(32)
    
    # Setting secret key
    SECRET_KEY = os.environ.get('SECRET_KEY')
    #print(f"Secret key: {SECRET_KEY}")

    # Where is the db located (automatically creates if missing)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///password_manager.db'

    # No need to track modifications (more performance)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Transmit cookies over HTTPS
    SESSION_COOKIE_SECURE = True #False

    # Session expires after X-minutes
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5) #timedelta(days=31)

    # Cookies not accessible via JavaScript (Againts XSS)
    SESSION_COOKIE_HTTPONLY = True #False

    # 'Strictly' controls cookie cross-site requests
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Cookies path
    #SESSION_COOKIE_PATH = '/'

    ################################
    MAIL_SERVER = 'localhost'  # Use localhost for a debugging SMTP server
    MAIL_PORT = 1025  # Port for the local SMTP server
    MAIL_USE_TLS = False  # TLS not needed for the local server
    MAIL_USE_SSL = False  # SSL not needed for the local server
    MAIL_USERNAME = None  # No username for local debugging
    MAIL_PASSWORD = None  # No password for local debugging
    MAIL_DEFAULT_SENDER = 'noreply@example.com'  # Default sender for emails