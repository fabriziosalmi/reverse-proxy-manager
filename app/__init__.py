from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
import os

# Create extensions here but don't initialize them yet
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()

def create_app(config_name="default"):
    app = Flask(__name__)
    
    # Import config here to avoid circular imports
    from config import config
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    
    # Set up login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    
    # Create Nginx config repo directory if it doesn't exist
    nginx_config_repo = app.config.get('NGINX_CONFIG_GIT_REPO')
    if not os.path.exists(nginx_config_repo):
        os.makedirs(nginx_config_repo, exist_ok=True)
    
    # Register blueprints
    from app.controllers.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    
    from app.controllers.admin import admin as admin_blueprint
    app.register_blueprint(admin_blueprint, url_prefix='/admin')
    
    from app.controllers.client import client as client_blueprint
    app.register_blueprint(client_blueprint, url_prefix='/client')
    
    from app.controllers.api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')
    
    # Route for the index page
    @app.route('/')
    def index():
        return app.send_static_file('index.html')
    
    return app