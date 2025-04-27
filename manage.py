#!/usr/bin/env python3
import os
import sys
import click
import getpass
import json
from datetime import datetime
from flask.cli import FlaskGroup
from app import create_app, db
from app.models.models import User, Node, Site, SiteNode, SSLCertificate

app = create_app(os.getenv('FLASK_ENV', 'development'))
cli = FlaskGroup(create_app=lambda: app)

@cli.command('init-db')
def init_db():
    """Initialize the database."""
    click.echo('Creating database tables...')
    db.create_all()
    click.echo('Database tables created.')

@cli.command('create-admin')
@click.option('--username', prompt=True, help='Admin username')
@click.option('--email', prompt=True, help='Admin email')
@click.option('--password', prompt=False, hide_input=True, confirmation_prompt=True, help='Admin password')
def create_admin(username, email, password):
    """Create an admin user."""
    if password is None:
        password = getpass.getpass('Admin password: ')
    
    if User.query.filter_by(username=username).first():
        click.echo(f"Error: Username '{username}' already exists")
        return
    
    if User.query.filter_by(email=email).first():
        click.echo(f"Error: Email '{email}' already exists")
        return
    
    admin = User(username=username, email=email, password=password, role='admin')
    db.session.add(admin)
    db.session.commit()
    
    click.echo(f"Admin user '{username}' created successfully")

@cli.command('list-users')
@click.option('--role', help='Filter users by role (admin, client)')
@click.option('--active-only', is_flag=True, help='Show only active users')
def list_users(role, active_only):
    """List all users with optional filtering."""
    query = User.query
    
    if role:
        if role not in ['admin', 'client']:
            click.echo("Error: Role must be 'admin' or 'client'")
            return
        query = query.filter(User.role == role)
    
    if active_only:
        query = query.filter(User.is_active == True)
    
    users = query.all()
    if not users:
        click.echo("No users found.")
        return
    
    click.echo("\nUsers:")
    click.echo("=" * 80)
    click.echo(f"{'ID':<5} {'Username':<20} {'Email':<30} {'Role':<10} {'Active':<6}")
    click.echo("-" * 80)
    
    for user in users:
        click.echo(f"{user.id:<5} {user.username:<20} {user.email:<30} {user.role:<10} {'Yes' if user.is_active else 'No':<6}")
    
    click.echo(f"\nTotal: {len(users)} users")

@cli.command('list-nodes')
@click.option('--active-only', is_flag=True, help='Show only active nodes')
@click.option('--proxy-type', help='Filter by proxy type (nginx, caddy, traefik)')
def list_nodes(active_only, proxy_type):
    """List all nodes with optional filtering."""
    query = Node.query
    
    if active_only:
        query = query.filter(Node.is_active == True)
    
    if proxy_type:
        valid_types = ['nginx', 'caddy', 'traefik']
        if proxy_type not in valid_types:
            click.echo(f"Error: Proxy type must be one of: {', '.join(valid_types)}")
            return
        query = query.filter(Node.proxy_type == proxy_type)
    
    nodes = query.all()
    if not nodes:
        click.echo("No nodes found.")
        return
    
    click.echo("\nNodes:")
    click.echo("=" * 100)
    click.echo(f"{'ID':<5} {'Name':<20} {'IP Address':<15} {'Proxy Type':<12} {'SSH User':<15} {'Active':<6} {'Discovered':<10}")
    click.echo("-" * 100)
    
    for node in nodes:
        click.echo(f"{node.id:<5} {node.name:<20} {node.ip_address:<15} {node.proxy_type:<12} {node.ssh_user:<15} "
                  f"{'Yes' if node.is_active else 'No':<6} {'Yes' if node.is_discovered else 'No':<10}")
    
    click.echo(f"\nTotal: {len(nodes)} nodes")

@cli.command('list-sites')
@click.option('--active-only', is_flag=True, help='Show only active sites')
@click.option('--owner', help='Filter sites by owner username')
@click.option('--proxy-type', help='Filter sites by proxy type (nginx, caddy, traefik)')
def list_sites(active_only, owner, proxy_type):
    """List all sites with optional filtering."""
    query = Site.query
    
    if active_only:
        query = query.filter(Site.is_active == True)
    
    if owner:
        user = User.query.filter_by(username=owner).first()
        if not user:
            click.echo(f"Error: User '{owner}' not found")
            return
        query = query.filter(Site.user_id == user.id)
    
    sites = query.all()
    if not sites:
        click.echo("No sites found.")
        return
    
    # Filter by proxy type if needed (requires additional processing)
    if proxy_type:
        valid_types = ['nginx', 'caddy', 'traefik']
        if proxy_type not in valid_types:
            click.echo(f"Error: Proxy type must be one of: {', '.join(valid_types)}")
            return
        
        # This is more complex and requires joining with nodes
        filtered_sites = []
        for site in sites:
            site_nodes = SiteNode.query.filter_by(site_id=site.id).all()
            for site_node in site_nodes:
                node = Node.query.get(site_node.node_id)
                if node and node.proxy_type == proxy_type:
                    filtered_sites.append(site)
                    break
        sites = filtered_sites
        
        if not sites:
            click.echo(f"No sites found with proxy type '{proxy_type}'.")
            return
    
    click.echo("\nSites:")
    click.echo("=" * 100)
    click.echo(f"{'ID':<5} {'Name':<20} {'Domain':<30} {'Origin':<25} {'Owner':<10} {'Active':<6}")
    click.echo("-" * 100)
    
    for site in sites:
        owner = User.query.get(site.user_id).username
        origin = f"{site.protocol}://{site.origin_address}:{site.origin_port}"
        click.echo(f"{site.id:<5} {site.name:<20} {site.domain:<30} {origin:<25} {owner:<10} {'Yes' if site.is_active else 'No':<6}")
    
    click.echo(f"\nTotal: {len(sites)} sites")

@cli.command('backup-db')
@click.option('--output', '-o', default=None, help='Output file name')
def backup_db(output):
    """Backup the database to a SQL file."""
    if not os.path.exists('backups'):
        os.makedirs('backups')
    
    # Generate a default filename if none provided
    if not output:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output = f'backup_{timestamp}.sql'
    
    backup_path = os.path.join('backups', output)
    
    # Get database path from config
    db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    
    if not os.path.exists(db_path):
        click.echo(f"Error: Database file '{db_path}' not found")
        return
    
    try:
        # Export database to SQL using sqlite3 command
        result = os.system(f"sqlite3 {db_path} .dump > {backup_path}")
        if result != 0:
            click.echo(f"Error: Failed to create backup (exit code {result})")
            return
        
        # Check if the file was created and has content
        if os.path.exists(backup_path) and os.path.getsize(backup_path) > 0:
            click.echo(f"Database backup created at {backup_path}")
        else:
            click.echo("Error: Backup file was created but appears to be empty")
    except Exception as e:
        click.echo(f"Error during backup: {str(e)}")

@cli.command('restore-db')
@click.option('--input', '-i', required=True, help='Input SQL file')
@click.confirmation_option(prompt='This will overwrite the current database. Continue?')
def restore_db(input):
    """Restore the database from a SQL file."""
    backup_path = os.path.join('backups', input) if not os.path.exists(input) else input
    
    if not os.path.exists(backup_path):
        click.echo(f"Error: Backup file '{backup_path}' not found")
        return
    
    # Get database path from config
    db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    
    # Create a backup before restoration
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f'pre_restore_backup_{timestamp}.sql'
    backup_path_before = os.path.join('backups', backup_filename)
    
    try:
        # Create backup of current database
        os.system(f"sqlite3 {db_path} .dump > {backup_path_before}")
        click.echo(f"Created backup of current database at {backup_path_before}")
        
        # Restore database from SQL file
        result = os.system(f"sqlite3 {db_path} < {backup_path}")
        if result != 0:
            click.echo(f"Error: Failed to restore database (exit code {result})")
            click.echo(f"Your original database is backed up at {backup_path_before}")
            return
        
        click.echo(f"Database restored from {backup_path}")
    except Exception as e:
        click.echo(f"Error during restoration: {str(e)}")
        click.echo(f"Your original database might be backed up at {backup_path_before}")

@cli.command('discover-nodes')
@click.option('--yaml-path', '-y', help='Path to the YAML file containing node information')
@click.option('--activate/--no-activate', default=True, help='Whether to automatically activate discovered nodes')
def discover_nodes(yaml_path=None, activate=True):
    """Discover nodes from a YAML configuration file and add them to the database."""
    from app.services.node_discovery_service import NodeDiscoveryService
    
    if not yaml_path:
        yaml_path = NodeDiscoveryService.get_default_yaml_path()
        if not yaml_path:
            click.echo("No nodes.yaml file found. Please specify the path with --yaml-path.")
            return
    
    click.echo(f"Discovering nodes from: {yaml_path}")
    added, updated, failed, messages = NodeDiscoveryService.discover_nodes_from_yaml(yaml_path, activate)
    
    click.echo("\nDiscovery Results:")
    click.echo(f"✅ Added: {added} nodes")
    click.echo(f"🔄 Updated: {updated} nodes")
    click.echo(f"❌ Failed: {failed} nodes\n")
    
    if messages:
        click.echo("Details:")
        for msg in messages:
            click.echo(f"  - {msg}")

@cli.command('create-migration-is-discovered')
def create_migration_is_discovered():
    """Create a migration for adding the is_discovered field to the Node model."""
    with app.app_context():
        migration_message = "Add is_discovered to Node model"
        upgrade_operations = """
        op.add_column('nodes', sa.Column('is_discovered', sa.Boolean(), nullable=True))
        op.execute('UPDATE nodes SET is_discovered = false')
        op.alter_column('nodes', 'is_discovered', nullable=False, server_default=sa.text('false'))
        """
        
        downgrade_operations = """
        op.drop_column('nodes', 'is_discovered')
        """
        
        # Define the migrations directory
        migrations_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'migrations')
        version_path = os.path.join(migrations_dir, 'versions')
        os.makedirs(version_path, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        revision = timestamp + '_' + migration_message.lower().replace(' ', '_')
        filename = revision + '.py'
        filepath = os.path.join(version_path, filename)
        
        with open(filepath, 'w') as f:
            f.write(f'''"""
{migration_message}

Revision ID: {timestamp}
Revises: 
Create Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
from alembic import op
import sqlalchemy as sa


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
{upgrade_operations}
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
{downgrade_operations}
    # ### end Alembic commands ###
'''
            )
        
        click.echo(f"Created migration: {filepath}")
        click.echo("Run 'flask db upgrade' to apply this migration")

@cli.command('reset-db')
@click.confirmation_option(prompt='This will erase ALL data in the database. Are you sure?')
def reset_db():
    """Reset the database by dropping all tables and recreating them."""
    click.echo('Dropping all tables...')
    db.drop_all()
    click.echo('Creating database tables...')
    db.create_all()
    click.echo('Database has been reset successfully.')

@cli.command('verify-node-connectivity')
@click.argument('node_id', type=int, required=False)
def verify_node_connectivity(node_id):
    """Test SSH connectivity to nodes and report status."""
    from app.services.proxy_service_base import ProxyServiceBase
    
    if node_id:
        # Check a specific node
        node = Node.query.get(node_id)
        if not node:
            click.echo(f"Error: Node with ID {node_id} not found")
            return
        
        nodes = [node]
    else:
        # Check all active nodes
        nodes = Node.query.filter_by(is_active=True).all()
        if not nodes:
            click.echo("No active nodes found to verify")
            return
    
    click.echo(f"Verifying connectivity to {len(nodes)} node(s)...")
    click.echo("=" * 80)
    
    success_count = 0
    for node in nodes:
        click.echo(f"Testing {node.name} ({node.ip_address})... ", nl=False)
        
        try:
            service = ProxyServiceBase(node)
            connected = service.test_connection()
            
            if connected:
                click.echo(click.style("✓ Success", fg="green"))
                success_count += 1
            else:
                click.echo(click.style("✗ Failed", fg="red"))
        except Exception as e:
            click.echo(click.style(f"✗ Error: {str(e)}", fg="red"))
    
    click.echo("=" * 80)
    click.echo(f"Successfully connected to {success_count} out of {len(nodes)} nodes")

@cli.command('list-certificates')
@click.option('--expired', is_flag=True, help='Show only expired certificates')
@click.option('--expiring', is_flag=True, help='Show certificates expiring within 30 days')
@click.option('--domain', help='Filter by domain name')
def list_certificates(expired, expiring, domain):
    """List SSL certificates with filtering options."""
    from datetime import datetime, timedelta
    
    query = SSLCertificate.query
    
    if domain:
        query = query.filter(SSLCertificate.domain.like(f"%{domain}%"))
    
    certificates = query.all()
    if not certificates:
        click.echo("No certificates found.")
        return
    
    now = datetime.now()
    expiry_threshold = now + timedelta(days=30)
    
    # Apply expiry filters
    if expired:
        certificates = [cert for cert in certificates if cert.expires_at and cert.expires_at < now]
    elif expiring:
        certificates = [cert for cert in certificates if cert.expires_at and now < cert.expires_at < expiry_threshold]
    
    if not certificates:
        click.echo("No certificates found matching the criteria.")
        return
    
    click.echo("\nSSL Certificates:")
    click.echo("=" * 100)
    click.echo(f"{'ID':<5} {'Domain':<30} {'Status':<10} {'Expires':<20} {'Issuer':<15} {'Type':<15}")
    click.echo("-" * 100)
    
    for cert in certificates:
        # Calculate status
        if not cert.expires_at:
            status = "Unknown"
        elif cert.expires_at < now:
            status = click.style("Expired", fg="red")
        elif cert.expires_at < expiry_threshold:
            status = click.style("Expiring", fg="yellow")
        else:
            status = click.style("Valid", fg="green")
        
        # Format expiry date
        expires = cert.expires_at.strftime("%Y-%m-%d %H:%M") if cert.expires_at else "Unknown"
        
        click.echo(f"{cert.id:<5} {cert.domain:<30} {status:<20} {expires:<20} {cert.issuer:<15} {cert.cert_type:<15}")
    
    click.echo(f"\nTotal: {len(certificates)} certificates")

@cli.command('check-proxy-configs')
@click.option('--node-id', type=int, help='Check configurations on a specific node')
def check_proxy_configs(node_id):
    """Validate proxy configurations on nodes."""
    from app.services.proxy_service_factory import ProxyServiceFactory
    
    if node_id:
        nodes = [Node.query.get(node_id)]
        if not nodes[0]:
            click.echo(f"Error: Node with ID {node_id} not found")
            return
    else:
        nodes = Node.query.filter_by(is_active=True).all()
    
    if not nodes:
        click.echo("No active nodes found")
        return
    
    click.echo(f"Checking proxy configurations on {len(nodes)} node(s)...")
    click.echo("=" * 80)
    
    for node in nodes:
        click.echo(f"Node: {node.name} ({node.ip_address}) - Type: {node.proxy_type}")
        
        try:
            service = ProxyServiceFactory.create(node)
            is_valid, messages = service.validate_configs()
            
            if is_valid:
                click.echo(click.style("  ✓ Configuration is valid", fg="green"))
            else:
                click.echo(click.style("  ✗ Configuration has errors:", fg="red"))
                for msg in messages:
                    click.echo(f"    - {msg}")
        except Exception as e:
            click.echo(click.style(f"  ✗ Error checking configuration: {str(e)}", fg="red"))
        
        click.echo("-" * 80)

@cli.command('export-data')
@click.option('--output', '-o', default=None, help='Output JSON file name')
@click.option('--users/--no-users', default=True, help='Include users data')
@click.option('--nodes/--no-nodes', default=True, help='Include nodes data')
@click.option('--sites/--no-sites', default=True, help='Include sites data')
@click.option('--certs/--no-certs', default=True, help='Include SSL certificates data')
def export_data(output, users, nodes, sites, certs):
    """Export system data to a JSON file."""
    if not os.path.exists('exports'):
        os.makedirs('exports')
    
    # Generate a default filename if none provided
    if not output:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output = f'system_export_{timestamp}.json'
    
    export_path = os.path.join('exports', output)
    export_data = {'meta': {'exported_at': datetime.now().isoformat(), 'version': app.config.get('VERSION', '1.0.0')}}
    
    try:
        # Export users if requested
        if users:
            user_data = []
            for user in User.query.all():
                user_dict = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'is_active': user.is_active,
                    # Don't export password hash for security
                }
                user_data.append(user_dict)
            export_data['users'] = user_data
        
        # Export nodes if requested
        if nodes:
            node_data = []
            for node in Node.query.all():
                node_dict = {
                    'id': node.id,
                    'name': node.name,
                    'ip_address': node.ip_address,
                    'proxy_type': node.proxy_type,
                    'ssh_user': node.ssh_user,
                    'ssh_port': node.ssh_port,
                    'is_active': node.is_active,
                    'is_discovered': node.is_discovered,
                    # Don't export SSH credentials for security
                }
                node_data.append(node_dict)
            export_data['nodes'] = node_data
        
        # Export sites if requested
        if sites:
            site_data = []
            for site in Site.query.all():
                # Get nodes this site is deployed to
                site_nodes = SiteNode.query.filter_by(site_id=site.id).all()
                deployed_node_ids = [sn.node_id for sn in site_nodes]
                
                site_dict = {
                    'id': site.id,
                    'name': site.name,
                    'domain': site.domain,
                    'protocol': site.protocol,
                    'origin_address': site.origin_address,
                    'origin_port': site.origin_port,
                    'user_id': site.user_id,
                    'is_active': site.is_active,
                    'deployed_to_nodes': deployed_node_ids,
                }
                site_data.append(site_dict)
            export_data['sites'] = site_data
        
        # Export SSL certificates if requested
        if certs:
            cert_data = []
            for cert in SSLCertificate.query.all():
                cert_dict = {
                    'id': cert.id,
                    'domain': cert.domain,
                    'issuer': cert.issuer,
                    'cert_type': cert.cert_type,
                    'expires_at': cert.expires_at.isoformat() if cert.expires_at else None,
                }
                cert_data.append(cert_dict)
            export_data['certificates'] = cert_data
        
        # Write data to file
        with open(export_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        click.echo(f"Data exported to {export_path}")
        
        # Summary of what was exported
        sections = []
        if users: sections.append(f"{len(export_data.get('users', []))} users")
        if nodes: sections.append(f"{len(export_data.get('nodes', []))} nodes")
        if sites: sections.append(f"{len(export_data.get('sites', []))} sites")
        if certs: sections.append(f"{len(export_data.get('certificates', []))} certificates")
        
        click.echo(f"Exported {', '.join(sections)}")
        
    except Exception as e:
        click.echo(f"Error during export: {str(e)}")

@cli.command('system-check')
def system_check():
    """Run a comprehensive system health check."""
    click.echo("Running system health check...")
    click.echo("=" * 80)
    
    # Check database
    click.echo("Database:")
    try:
        # Test connection by executing a simple query
        db.session.execute("SELECT 1")
        click.echo(click.style("  ✓ Database connection successful", fg="green"))
        
        # Check if important tables exist
        tables = ['users', 'nodes', 'sites', 'site_nodes', 'ssl_certificates']
        missing_tables = []
        
        for table in tables:
            try:
                db.session.execute(f"SELECT 1 FROM {table} LIMIT 1")
            except Exception:
                missing_tables.append(table)
        
        if missing_tables:
            click.echo(click.style(f"  ✗ Missing tables: {', '.join(missing_tables)}", fg="red"))
        else:
            click.echo(click.style("  ✓ All required tables exist", fg="green"))
    except Exception as e:
        click.echo(click.style(f"  ✗ Database error: {str(e)}", fg="red"))
    
    # Check required directories
    click.echo("\nDirectories:")
    required_dirs = [
        ('backups', 'Database backups directory'),
        ('exports', 'Data export directory'),
        ('nginx_configs', 'Nginx configurations directory'),
        ('nginx_templates', 'Nginx templates directory')
    ]
    
    for dir_name, desc in required_dirs:
        if os.path.isdir(dir_name):
            click.echo(click.style(f"  ✓ {desc} exists", fg="green"))
        else:
            click.echo(click.style(f"  ✗ {desc} missing ({dir_name}/)", fg="red"))
    
    # Enhanced check for nginx_templates directory
    templates_dir = app.config.get('NGINX_TEMPLATES_DIR', 'nginx_templates')
    if os.path.isdir(templates_dir):
        click.echo("\nNginx Templates:")
        
        # Check for crucial template files
        essential_templates = ['http.conf', 'https.conf']
        missing_templates = []
        
        for template in essential_templates:
            template_path = os.path.join(templates_dir, template)
            if not os.path.isfile(template_path):
                missing_templates.append(template)
                continue
            
            # Check file permissions
            try:
                mode = os.stat(template_path).st_mode
                is_readable = bool(mode & 0o400)  # Check if file is readable
                
                if not is_readable:
                    click.echo(click.style(f"  ⚠ Template {template} has insufficient permissions", fg="yellow"))
                    continue
                
                # Basic template validation
                try:
                    with open(template_path, 'r') as f:
                        content = f.read()
                        
                    # Check for basic required directives in templates
                    required_directives = ['server_name', 'listen']
                    missing_directives = [d for d in required_directives if d not in content]
                    
                    # Check for unmatched brackets
                    open_braces = content.count('{')
                    close_braces = content.count('}')
                    
                    if missing_directives:
                        click.echo(click.style(f"  ⚠ Template {template} is missing essential directives: {', '.join(missing_directives)}", fg="yellow"))
                    elif open_braces != close_braces:
                        click.echo(click.style(f"  ⚠ Template {template} has unmatched braces ({open_braces} opening vs {close_braces} closing)", fg="yellow"))
                    else:
                        click.echo(click.style(f"  ✓ Template {template} is valid", fg="green"))
                        
                except Exception as e:
                    click.echo(click.style(f"  ⚠ Error validating template {template}: {str(e)}", fg="yellow"))
            except Exception as e:
                click.echo(click.style(f"  ⚠ Error checking template {template} permissions: {str(e)}", fg="yellow"))
        
        if missing_templates:
            click.echo(click.style(f"  ✗ Missing essential templates: {', '.join(missing_templates)}", fg="red"))
        
        # Check total number of templates
        template_files = [f for f in os.listdir(templates_dir) if f.endswith('.conf')]
        click.echo(f"  • Total templates: {len(template_files)}")
    
    # Check users
    click.echo("\nUsers:")
    admin_count = User.query.filter_by(role='admin').count()
    if admin_count > 0:
        click.echo(click.style(f"  ✓ {admin_count} admin users exist", fg="green"))
    else:
        click.echo(click.style("  ✗ No admin users found", fg="red"))
    
    # Check nodes
    click.echo("\nNodes:")
    active_nodes = Node.query.filter_by(is_active=True).count()
    if active_nodes > 0:
        click.echo(click.style(f"  ✓ {active_nodes} active nodes exist", fg="green"))
    else:
        click.echo(click.style("  ✗ No active nodes found", fg="yellow"))
    
    # Proxy type distribution
    node_types = {}
    for node in Node.query.all():
        proxy_type = node.proxy_type or 'unknown'
        node_types[proxy_type] = node_types.get(proxy_type, 0) + 1
    
    for proxy_type, count in node_types.items():
        click.echo(f"  • {proxy_type}: {count} nodes")
    
    # Check configuration
    click.echo("\nConfiguration:")
    try:
        # Check version
        version = app.config.get('VERSION', 'unknown')
        click.echo(f"  • Application version: {version}")
        
        # Check environment
        env = app.config.get('ENV', 'production')
        if env == 'development':
            click.echo(click.style("  ⚠ Running in development mode", fg="yellow"))
        else:
            click.echo(click.style("  ✓ Running in production mode", fg="green"))
        
        # Check debug mode
        debug = app.config.get('DEBUG', False)
        if debug:
            click.echo(click.style("  ⚠ Debug mode is enabled", fg="yellow"))
        else:
            click.echo(click.style("  ✓ Debug mode is disabled", fg="green"))
    
    except Exception as e:
        click.echo(click.style(f"  ✗ Error checking configuration: {str(e)}", fg="red"))
    
    click.echo("=" * 80)
    click.echo("System health check complete")

if __name__ == '__main__':
    cli()