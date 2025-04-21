import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Basic Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a06a9bd260fe721228023cba29bead91eeb69af069dff08bc7443ce83273c899'
    
    # SQLAlchemy configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'instance', 'factory.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'connect_args': {
            'check_same_thread': False  # Allow multiple threads for SQLite
        }
    }
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SESSION_TYPE = 'filesystem'
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Upload configuration
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx'}
    
    # Logging configuration
    LOG_FOLDER = os.path.join(basedir, 'logs')
    LOG_FILENAME = 'app.log'
    LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
    LOG_LEVEL = 'INFO'
    
    # Application configuration
    ITEMS_PER_PAGE = 10
    NOTIFICATION_EXPIRY_DAYS = 30
    MAINTENANCE_REMINDER_DAYS = 7
    PASSWORD_MIN_LENGTH = 8
    
    # Initialize required directories
    @staticmethod
    def init_app(app):
        # Create required directories if they don't exist
        os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(Config.LOG_FOLDER, exist_ok=True)
        
        # Create .gitkeep files to preserve empty directories
        for folder in [Config.UPLOAD_FOLDER, Config.LOG_FOLDER]:
            gitkeep_file = os.path.join(folder, '.gitkeep')
            if not os.path.exists(gitkeep_file):
                with open(gitkeep_file, 'w') as f:
                    pass

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True
    SESSION_COOKIE_SECURE = False
    # Use absolute path for SQLite database in development
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'instance', 'factory.db')

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_ECHO = False
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Production-specific initialization
        import logging
        from logging.handlers import RotatingFileHandler
        
        # Configure logging
        handler = RotatingFileHandler(
            os.path.join(cls.LOG_FOLDER, cls.LOG_FILENAME),
            maxBytes=10000000,  # 10MB
            backupCount=5
        )
        handler.setFormatter(logging.Formatter(cls.LOG_FORMAT))
        handler.setLevel(cls.LOG_LEVEL)
        app.logger.addHandler(handler)

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
} 