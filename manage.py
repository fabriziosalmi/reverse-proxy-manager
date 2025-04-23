#!/usr/bin/env python3
import os
import sys
import click
import getpass
from datetime import datetime
from flask.cli import FlaskGroup
from app import create_app, db
from app.models.models import User, Node, Site

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
def list_users():
    """List all users."""
    users = User.query.all()
    if not users:
        click.echo("No users found.")
        return
    
    click.echo("\nUsers:")
    click.echo("=" * 80)
    click.echo(f"{'ID':<5} {'Username':<20} {'Email':<30} {'Role':<10} {'Active':<6}")
    click.echo("-" * 80)
    
    for user in users:
        click.echo(f"{user.id:<5} {user.username:<20} {user.email:<30} {user.role:<10} {'Yes' if user.is_active else 'No':<6}")

@cli.command('list-nodes')
def list_nodes():
    """List all nodes."""
    nodes = Node.query.all()
    if not nodes:
        click.echo("No nodes found.")
        return
    
    click.echo("\nNodes:")
    click.echo("=" * 80)
    click.echo(f"{'ID':<5} {'Name':<20} {'IP Address':<15} {'SSH User':<15} {'Active':<6}")
    click.echo("-" * 80)
    
    for node in nodes:
        click.echo(f"{node.id:<5} {node.name:<20} {node.ip_address:<15} {node.ssh_user:<15} {'Yes' if node.is_active else 'No':<6}")

@cli.command('list-sites')
def list_sites():
    """List all sites."""
    sites = Site.query.all()
    if not sites:
        click.echo("No sites found.")
        return
    
    click.echo("\nSites:")
    click.echo("=" * 100)
    click.echo(f"{'ID':<5} {'Name':<20} {'Domain':<30} {'Origin':<25} {'Owner':<10} {'Active':<6}")
    click.echo("-" * 100)
    
    for site in sites:
        owner = User.query.get(site.user_id).username
        origin = f"{site.protocol}://{site.origin_address}:{site.origin_port}"
        click.echo(f"{site.id:<5} {site.name:<20} {site.domain:<30} {origin:<25} {owner:<10} {'Yes' if site.is_active else 'No':<6}")

@cli.command('backup-db')
@click.option('--output', '-o', default='backup.sql', help='Output file name')
def backup_db(output):
    """Backup the database to a SQL file."""
    if not os.path.exists('backups'):
        os.makedirs('backups')
    
    backup_path = os.path.join('backups', output)
    
    # Get database path from config
    db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    
    if not os.path.exists(db_path):
        click.echo(f"Error: Database file '{db_path}' not found")
        return
    
    # Export database to SQL using sqlite3 command
    os.system(f"sqlite3 {db_path} .dump > {backup_path}")
    click.echo(f"Database backup created at {backup_path}")

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
    timestamp = os.path.splitext(os.path.basename(db_path))[0] + '_before_restore.sql'
    os.system(f"sqlite3 {db_path} .dump > backups/{timestamp}")
    click.echo(f"Created backup of current database at backups/{timestamp}")
    
    # Restore database from SQL file
    os.system(f"sqlite3 {db_path} < {backup_path}")
    click.echo(f"Database restored from {backup_path}")

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

if __name__ == '__main__':
    cli()