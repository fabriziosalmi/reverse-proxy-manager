from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import os

# Create extensions here but don't initialize them yet
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
# Configure Limiter with proper storage options
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
csrf = CSRFProtect()

def create_app(config_name="default"):
    app = Flask(__name__)
    
    # Import config here to avoid circular imports
    from config import config
    app.config.from_object(config[config_name])
    
    # Set up Flask-Limiter with appropriate storage backend
    app.config['RATELIMIT_STORAGE_URI'] = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
    # Remove the distributed option that's causing the error
    app.config['RATELIMIT_STORAGE_OPTIONS'] = {}
    app.config['RATELIMIT_HEADERS_ENABLED'] = True
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    csrf.init_app(app)
    
    # Set up login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    
    # Apply security headers middleware
    @app.after_request
    def apply_security_headers(response):
        secure_headers = app.config.get('SECURE_HEADERS', {})
        for header, value in secure_headers.items():
            response.headers[header] = value
        return response
    
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
    
    # Register GeoIP blueprint
    from app.services.geoip_service import geoip_bp
    app.register_blueprint(geoip_bp)
    
    # Initialize auto node discovery if enabled
    with app.app_context():
        if app.config.get('AUTO_NODE_DISCOVERY', False):
            from app.services.node_discovery_service import NodeDiscoveryService
            
            # Use specified path or default path
            yaml_path = app.config.get('NODES_YAML_PATH', None)
            if not yaml_path:
                yaml_path = NodeDiscoveryService.get_default_yaml_path()
                
            if yaml_path:
                app.logger.info(f"Auto-discovering nodes from: {yaml_path}")
                added, updated, failed, messages = NodeDiscoveryService.discover_nodes_from_yaml(
                    yaml_path, 
                    auto_activate=app.config.get('AUTO_ACTIVATE_DISCOVERED_NODES', True)
                )
                
                app.logger.info(f"Node discovery results: {added} added, {updated} updated, {failed} failed")
                for msg in messages:
                    app.logger.debug(f"Node discovery: {msg}")
    
    # Initialize configuration service
    from app.services.configuration_service import ConfigurationService
    ConfigurationService.initialize()
    
    # Initialize our scheduled task service for automated GeoIP updates and SSL checks
    from app.services.scheduled_task_service import initialize_scheduled_tasks
    initialize_scheduled_tasks(app)
    
    # Route for the index page - redirect to appropriate dashboard based on user role
    @app.route('/')
    def index():
        from flask_login import current_user
        if current_user.is_authenticated:
            if current_user.is_admin():
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
        return app.send_static_file('index.html')
    
    # Add a route for /dashboard that redirects to the appropriate dashboard
    @app.route('/dashboard')
    def dashboard_redirect():
        from flask_login import current_user
        if current_user.is_authenticated:
            if current_user.is_admin():
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
        return redirect(url_for('auth.login'))
    
    return app