import os
from app import create_app, db
from app.models.models import User, Node, Site, SiteNode, SSLCertificate, DeploymentLog
from flask_migrate import Migrate

# Get environment from environment variable or default to development
env = os.environ.get('FLASK_ENV', 'development')
app = create_app(env)

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
        DeploymentLog=DeploymentLog
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)