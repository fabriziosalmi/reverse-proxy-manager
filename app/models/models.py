from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from app import db

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    email = db.Column(db.String(120), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='client')  # 'admin' or 'client'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationship with sites (only for clients)
    sites = db.relationship('Site', backref='owner', lazy='dynamic')
    
    def __init__(self, username, email, password, role='client'):
        self.username = username
        self.email = email
        self.set_password(password)
        self.role = role
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_client(self):
        return self.role == 'client'
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class Node(db.Model):
    __tablename__ = 'nodes'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv4 or IPv6
    ssh_port = db.Column(db.Integer, default=22)
    ssh_user = db.Column(db.String(64), nullable=False)
    ssh_key_path = db.Column(db.String(256), nullable=True)  # Path to SSH key file
    ssh_password = db.Column(db.String(256), nullable=True)  # Encrypted password (if using password auth)
    is_active = db.Column(db.Boolean, default=True)
    is_discovered = db.Column(db.Boolean, default=False)  # Whether this node was discovered from YAML
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    nginx_config_path = db.Column(db.String(256), default='/etc/nginx/conf.d')
    nginx_reload_command = db.Column(db.String(256), default='sudo systemctl reload nginx')
    
    # Relationships
    site_nodes = db.relationship('SiteNode', backref='node', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'ip_address': self.ip_address,
            'ssh_port': self.ssh_port,
            'ssh_user': self.ssh_user,
            'is_active': self.is_active,
            'is_discovered': self.is_discovered,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'nginx_config_path': self.nginx_config_path
        }


class Site(db.Model):
    __tablename__ = 'sites'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    protocol = db.Column(db.String(10), nullable=False, default='https')  # http or https
    origin_protocol = db.Column(db.String(10), nullable=False, default='http')  # http or https for origin
    origin_address = db.Column(db.String(255), nullable=False)  # Backend server address
    origin_port = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Allow null for discovered sites
    is_active = db.Column(db.Boolean, default=True)
    is_blocked = db.Column(db.Boolean, default=False) 
    is_discovered = db.Column(db.Boolean, default=False)  # Whether this site was discovered from node
    use_waf = db.Column(db.Boolean, default=False)
    force_https = db.Column(db.Boolean, default=True)  # New column to force HTTP to HTTPS redirect
    # Cache configuration
    enable_cache = db.Column(db.Boolean, default=True)
    cache_time = db.Column(db.Integer, default=3600)  # Cache time in seconds, default 1 hour
    cache_static_time = db.Column(db.Integer, default=86400)  # Cache time for static assets in seconds, default 1 day
    custom_cache_rules = db.Column(db.Text, nullable=True)  # Custom cache rules in Nginx format
    cache_browser_time = db.Column(db.Integer, default=3600)  # Browser cache time in seconds, default 1 hour
    # End of cache configuration
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    custom_config = db.Column(db.Text, nullable=True)  # Additional Nginx configuration
    
    # Relationships
    site_nodes = db.relationship('SiteNode', backref='site', lazy='dynamic')
    ssl_certificates = db.relationship('SSLCertificate', backref='site', lazy='dynamic')
    config_versions = db.relationship('ConfigVersion', backref='site', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'domain': self.domain,
            'protocol': self.protocol,
            'origin_protocol': self.origin_protocol,
            'origin_address': self.origin_address,
            'origin_port': self.origin_port,
            'user_id': self.user_id,
            'is_active': self.is_active,
            'is_blocked': self.is_blocked, 
            'is_discovered': self.is_discovered,
            'use_waf': self.use_waf,
            'force_https': self.force_https,  # New column to force HTTP to HTTPS redirect
            'enable_cache': self.enable_cache,
            'cache_time': self.cache_time,
            'cache_static_time': self.cache_static_time,
            'custom_cache_rules': self.custom_cache_rules,
            'cache_browser_time': self.cache_browser_time,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'nodes': [site_node.node_id for site_node in self.site_nodes]
        }


class SiteNode(db.Model):
    __tablename__ = 'site_nodes'
    
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.id'), nullable=False)
    node_id = db.Column(db.Integer, db.ForeignKey('nodes.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, deployed, error, discovered
    config_path = db.Column(db.String(256), nullable=True)  # Path to the config file on the node
    error_message = db.Column(db.Text, nullable=True)
    deployed_at = db.Column(db.DateTime, nullable=True)
    discovered_at = db.Column(db.DateTime, nullable=True)  # When was this config discovered
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Composite unique constraint
    __table_args__ = (db.UniqueConstraint('site_id', 'node_id', name='_site_node_uc'),)
    
    def to_dict(self):
        return {
            'id': self.id,
            'site_id': self.site_id,
            'node_id': self.node_id,
            'status': self.status,
            'config_path': self.config_path,
            'error_message': self.error_message,
            'deployed_at': self.deployed_at.isoformat() if self.deployed_at else None,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class SSLCertificate(db.Model):
    __tablename__ = 'ssl_certificates'
    
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    certificate_path = db.Column(db.String(256), nullable=True)
    private_key_path = db.Column(db.String(256), nullable=True)
    fullchain_path = db.Column(db.String(256), nullable=True)
    issuer = db.Column(db.String(64), default='letsencrypt')
    status = db.Column(db.String(20), default='pending')  # pending, active, expired, error
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'site_id': self.site_id,
            'domain': self.domain,
            'issuer': self.issuer,
            'status': self.status,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }


class DeploymentLog(db.Model):
    __tablename__ = 'deployment_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.id'), nullable=False)
    node_id = db.Column(db.Integer, db.ForeignKey('nodes.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Who performed the action
    action = db.Column(db.String(64), nullable=False)  # deploy, update, remove, ssl_renew, discovery, rollback
    status = db.Column(db.String(20), nullable=False)  # success, error
    message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    site = db.relationship('Site', backref=db.backref('deployment_logs', lazy='dynamic'))
    node = db.relationship('Node', backref=db.backref('deployment_logs', lazy='dynamic'))
    user = db.relationship('User', backref=db.backref('deployment_logs', lazy='dynamic'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'site_id': self.site_id,
            'node_id': self.node_id,
            'user_id': self.user_id,
            'user': self.user.username if self.user else None,
            'action': self.action,
            'status': self.status,
            'message': self.message,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class SystemLog(db.Model):
    """System-wide log model for tracking all activities beyond deployments"""
    __tablename__ = 'system_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Null for system events
    category = db.Column(db.String(32), nullable=False)  # auth, admin, system, security, etc.
    action = db.Column(db.String(64), nullable=False)    # login, logout, create, delete, etc.
    resource_type = db.Column(db.String(32), nullable=True)  # user, node, site, etc.
    resource_id = db.Column(db.Integer, nullable=True)       # ID of the affected resource
    details = db.Column(db.Text, nullable=True)              # Additional details
    ip_address = db.Column(db.String(45), nullable=True)     # IP address of user/system
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('system_logs', lazy='dynamic'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'user': self.user.username if self.user else None,
            'category': self.category,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ConfigVersion(db.Model):
    """Model for tracking configuration versions for sites"""
    __tablename__ = 'config_versions'
    
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.id'), nullable=False)
    commit_hash = db.Column(db.String(64), nullable=False)  # Git commit hash
    message = db.Column(db.Text, nullable=True)             # Commit message
    author = db.Column(db.String(64), nullable=False)       # Who made the change
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'site_id': self.site_id,
            'commit_hash': self.commit_hash,
            'short_hash': self.commit_hash[:8] if self.commit_hash else None,
            'message': self.message,
            'author': self.author,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }