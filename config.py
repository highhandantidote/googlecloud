import os

class Config:
    """Base configuration for the application."""
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'dev_key')
    
    # Mail settings
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USERNAME = os.environ.get('SMTP_EMAIL', os.environ.get('MAIL_USERNAME', 'your-email@gmail.com'))
    MAIL_PASSWORD = os.environ.get('SMTP_PASSWORD', os.environ.get('MAIL_PASSWORD', 'your-password'))
    MAIL_DEFAULT_SENDER = os.environ.get('SMTP_EMAIL', os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@antidote.com'))
    
    # File Upload Configuration
    # Set maximum content length to 50MB for face analysis images (50 * 1024 * 1024 bytes)
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024
    
    # SQLAlchemy database configuration - Using Supabase
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Database configuration - MOVED TO database_connection_optimizer.py
    # Centralized database config eliminates SSL errors and optimizes for 1500+ users
    # SQLALCHEMY_ENGINE_OPTIONS = {
    #     'pool_recycle': 600,          # OLD: Now 3600s for better stability  
    #     'pool_pre_ping': True,        # KEPT: Critical for connection health
    #     'pool_timeout': 60,           # OLD: Now 45s for faster response
    #     'pool_size': 10,              # OLD: Now 25 for high traffic
    #     'max_overflow': 15,           # OLD: Now 50 for traffic spikes
    #     'connect_args': {
    #         'sslmode': 'allow',       # OLD: This caused SSL errors! Now 'require'
    #         'sslcert': None,          
    #         'sslkey': None,          
    #         'sslrootcert': None,     
    #         'connect_timeout': 30,    # OLD: Now 20s for faster failure detection
    #         'application_name': 'antidote_flask_app',
    #         'keepalives_idle': 600,   # OLD: Now 300s for better responsiveness
    #         'keepalives_interval': 30,
    #         'keepalives_count': 3
    #     }
    # }
    
    # Debug configuration
    DEBUG = True
