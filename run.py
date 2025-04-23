import os
import threading
import time
import schedule
from app import create_app, db
from app.models.models import User, Node, Site, SiteNode, SSLCertificate, DeploymentLog, SystemLog
from app.services.node_inspection_service import NodeInspectionService
from app.services.ssl_certificate_service import SSLCertificateService
from app.services.logger_service import log_activity
from flask_migrate import Migrate

# Get environment from environment variable or default to development
# FLASK_ENV is deprecated in newer Flask versions
config_name = os.environ.get('FLASK_CONFIG', 'development')
app = create_app(config_name)

# Set debug mode based on environment
app.debug = os.environ.get('FLASK_DEBUG', 'development' in config_name) == '1'

# Set up Flask-Migrate
migrate = Migrate(app, db)

# Create a shell context for Flask CLI
@app.shell_context_processor
def make_shell_context():
    return dict(
        app=app, 
        db=db, 
        User=User, 
        Node=Node, 
        Site=Site, 
        SiteNode=SiteNode, 
        SSLCertificate=SSLCertificate, 
        DeploymentLog=DeploymentLog,
        SystemLog=SystemLog
    )

# Add a command to create an admin user
@app.cli.command("create-admin")
def create_admin():
    """Create an admin user."""
    import getpass
    
    username = input("Admin username: ")
    email = input("Admin email: ")
    password = getpass.getpass("Admin password: ")
    
    if User.query.filter_by(username=username).first():
        print(f"Error: Username '{username}' already exists")
        return
    
    if User.query.filter_by(email=email).first():
        print(f"Error: Email '{email}' already exists")
        return
    
    admin = User(username=username, email=email, password=password, role='admin')
    db.session.add(admin)
    db.session.commit()
    
    print(f"Admin user '{username}' created successfully")

# Scheduler and background task functions
def run_scheduler():
    """Run scheduler in a background thread"""
    while True:
        schedule.run_pending()
        time.sleep(1)

def run_node_health_checks():
    """Run health checks on all active nodes"""
    with app.app_context():
        try:
            log_activity('info', 'Starting scheduled node health checks')
            results = NodeInspectionService.health_check_all_nodes()
            log_activity('info', f'Completed node health checks: {results["healthy_nodes"]} healthy, {results["unhealthy_nodes"]} unhealthy, {results["unreachable_nodes"]} unreachable')
        except Exception as e:
            log_activity('error', f'Error running scheduled node health checks: {str(e)}')

def run_certificate_health_checks():
    """Check SSL certificate status across all nodes"""
    with app.app_context():
        try:
            log_activity('info', 'Starting scheduled SSL certificate health checks')
            results = SSLCertificateService.certificate_health_check()
            log_activity('info', f'Completed SSL certificate checks: {results["healthy_count"]} healthy, {results["expiring_soon_count"]} expiring soon, {results["expired_count"]} expired')
        except Exception as e:
            log_activity('error', f'Error running scheduled SSL certificate checks: {str(e)}')

def run_auto_replace_self_signed_certificates():
    """Automatically replace self-signed certificates with real ones if available"""
    with app.app_context():
        try:
            log_activity('info', 'Starting auto-replacement of self-signed certificates')
            results = SSLCertificateService.auto_replace_self_signed_certificates()
            if results["replaced_count"] > 0:
                log_activity('info', f'Auto-replaced {results["replaced_count"]} self-signed certificates with real ones')
            if results["failed_count"] > 0:
                log_activity('warning', f'Failed to replace {results["failed_count"]} self-signed certificates')
        except Exception as e:
            log_activity('error', f'Error auto-replacing self-signed certificates: {str(e)}')

# Initialize the scheduler
def init_scheduler():
    """Initialize the scheduler with tasks"""
    # Run node health checks every hour
    schedule.every(1).hour.do(run_node_health_checks)
    
    # Run SSL certificate checks daily
    schedule.every(1).day.at("03:00").do(run_certificate_health_checks)
    
    # Try to auto-replace self-signed certificates daily
    schedule.every(1).day.at("04:00").do(run_auto_replace_self_signed_certificates)
    
    # Start the scheduler thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    
    log_activity('info', 'Scheduler initialized with background tasks')
    return scheduler_thread

# Add a CLI command to run health checks
@app.cli.command("health-check")
def health_check_command():
    """Run health checks on all nodes."""
    results = NodeInspectionService.health_check_all_nodes()
    print(f"Health check completed: {results['healthy_nodes']} healthy, {results['unhealthy_nodes']} unhealthy, {results['unreachable_nodes']} unreachable")
    return results

# Add a CLI command to check SSL certificates
@app.cli.command("check-certificates")
def check_certificates_command():
    """Check SSL certificates on all nodes."""
    results = SSLCertificateService.certificate_health_check()
    print(f"Certificate check completed: {results['healthy_count']} healthy, {results['expiring_soon_count']} expiring soon, {results['expired_count']} expired")
    return results

if __name__ == '__main__':
    # Initialize the scheduler when running the app directly
    scheduler_thread = init_scheduler()
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000)