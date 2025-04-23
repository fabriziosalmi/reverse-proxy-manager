import os
from datetime import timedelta

class Config:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-should-change-this-in-production'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'another-secret-key-for-jwt'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    PASSWORD_ENCRYPTION_KEY = os.environ.get('PASSWORD_ENCRYPTION_KEY') or 'encryption-key-for-passwords-change-in-production'
    
    # Security headers
    SECURE_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
    }
    
    # Cookie security settings
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Git Repository for Nginx configs
    NGINX_CONFIG_GIT_REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'nginx_configs')
    
    # Nginx Templates Directory
    NGINX_TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'nginx_templates')
    
    # Node Discovery
    AUTO_NODE_DISCOVERY = os.environ.get('AUTO_NODE_DISCOVERY', 'false').lower() == 'true'
    AUTO_ACTIVATE_DISCOVERED_NODES = os.environ.get('AUTO_ACTIVATE_DISCOVERED_NODES', 'true').lower() == 'true'
    NODES_YAML_PATH = os.environ.get('NODES_YAML_PATH')
    
    # Rate limiting
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')
    RATELIMIT_STRATEGY = 'fixed-window'
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    
    # Authentication rate limits
    AUTH_RATE_LIMIT = "10 per minute;100 per day"

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    # In production, make sure to set these environment variables
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}