from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from app import db

class User(db.Model, UserMixin):
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
        """Set the password hash with a stronger hashing algorithm"""
        # Enforce password complexity
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
            
        # Check for complexity requirements (at least one uppercase, lowercase, and digit)
        if not any(char.isupper() for char in password) or not any(char.islower() for char in password) or not any(char.isdigit() for char in password):
            raise ValueError("Password must contain at least one uppercase letter, one lowercase letter, and one digit")
            
        # Use a stronger hashing method 
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256:260000')
    
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
    _ssh_password = db.Column('ssh_password', db.String(256), nullable=True)  # Encrypted password (if using password auth)
    is_active = db.Column(db.Boolean, default=True)
    is_discovered = db.Column(db.Boolean, default=False)  # Whether this node was discovered from YAML
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    nginx_config_path = db.Column(db.String(256), default='/etc/nginx/conf.d')
    nginx_reload_command = db.Column(db.String(256), default='sudo systemctl reload nginx')
    detected_nginx_path = db.Column(db.String(256), nullable=True)  # Store detected nginx path
    
    # Relationships
    site_nodes = db.relationship('SiteNode', backref='node', lazy='dynamic')
    
    @property
    def ssh_password(self):
        """Decrypt password when accessed"""
        from cryptography.fernet import Fernet
        from flask import current_app
        import base64
        
        if not self._ssh_password:
            return None
            
        try:
            # Get encryption key from config or generate a secure key if needed
            key = current_app.config.get('PASSWORD_ENCRYPTION_KEY')
            if not key:
                import logging
                logging.warning("PASSWORD_ENCRYPTION_KEY not configured in application settings")
                # Fall back to a development key only if not in production
                if current_app.config.get('ENV') == 'production':
                    raise ValueError("Missing PASSWORD_ENCRYPTION_KEY in production environment")
                key = 'fallback_key_for_development_only'
                
            key = key.encode()
            # Create a proper Fernet key using SHA256 to ensure correct length
            import hashlib
            key_hash = hashlib.sha256(key).digest()
            fernet_key = base64.urlsafe_b64encode(key_hash)
            
            cipher = Fernet(fernet_key)
            decrypted = cipher.decrypt(self._ssh_password.encode())
            return decrypted.decode()
        except Exception as e:
            # Log the error but don't expose details
            import logging
            logging.error(f"Error decrypting SSH password: {str(e)}")
            return None
    
    @ssh_password.setter
    def ssh_password(self, password):
        """Encrypt password when set"""
        if not password:
            self._ssh_password = None
            return
            
        from cryptography.fernet import Fernet
        from flask import current_app
        import base64
        
        try:
            # Get encryption key from config or generate a secure key if needed
            key = current_app.config.get('PASSWORD_ENCRYPTION_KEY')
            if not key:
                import logging
                logging.warning("PASSWORD_ENCRYPTION_KEY not configured in application settings")
                # Fall back to a development key only if not in production
                if current_app.config.get('ENV') == 'production':
                    raise ValueError("Missing PASSWORD_ENCRYPTION_KEY in production environment")
                key = 'fallback_key_for_development_only'
            
            key = key.encode()
            # Create a proper Fernet key using SHA256 to ensure correct length
            import hashlib
            key_hash = hashlib.sha256(key).digest()
            fernet_key = base64.urlsafe_b64encode(key_hash)
            
            cipher = Fernet(fernet_key)
            encrypted = cipher.encrypt(password.encode())
            self._ssh_password = encrypted.decode()
        except Exception as e:
            # Log the error but don't expose details
            import logging
            logging.error(f"Error encrypting SSH password: {str(e)}")
            self._ssh_password = None
    
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
        
    def install_nginx(self, user_id=None):
        """
        Install Nginx on the remote node
        
        Args:
            user_id: Optional ID of the user performing the installation
            
        Returns:
            tuple: (success, message)
        """
        import paramiko
        from app.services.logger_service import log_activity
        
        try:
            # Connect to the node via SSH
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect using key or password
            if self.ssh_key_path:
                ssh_client.connect(
                    hostname=self.ip_address,
                    port=self.ssh_port,
                    username=self.ssh_user,
                    key_filename=self.ssh_key_path,
                    timeout=20  # Longer timeout for installation
                )
            else:
                ssh_client.connect(
                    hostname=self.ip_address,
                    port=self.ssh_port,
                    username=self.ssh_user,
                    password=self.ssh_password,
                    timeout=20  # Longer timeout for installation
                )
            
            # Detect OS
            stdin, stdout, stderr = ssh_client.exec_command(
                "lsb_release -ds 2>/dev/null || "
                "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d '\"' -f 2 || "
                "echo 'Unknown'"
            )
            os_info = stdout.read().decode('utf-8').strip()
            
            # Set up installation commands based on OS
            install_commands = []
            
            if "Ubuntu" in os_info or "Debian" in os_info:
                # Ubuntu/Debian installation
                install_commands = [
                    "sudo apt update -y",
                    "sudo apt install -y nginx",
                    # Install GeoIP modules and databases
                    "sudo apt install -y nginx-module-geoip geoip-database libgeoip-dev",
                    # Download and prepare latest GeoIP databases
                    "sudo mkdir -p /usr/share/GeoIP",
                    "cd /tmp && sudo wget -q https://dl.miyuru.lk/geoip/maxmind/country/maxmind4.dat.gz && sudo gunzip -f maxmind4.dat.gz && sudo mv maxmind4.dat /usr/share/GeoIP/GeoIP.dat",
                    "cd /tmp && sudo wget -q https://dl.miyuru.lk/geoip/maxmind/country/maxmind6.dat.gz && sudo gunzip -f maxmind6.dat.gz && sudo mv maxmind6.dat /usr/share/GeoIP/GeoIPv6.dat",
                    "sudo systemctl enable nginx",
                    "sudo systemctl start nginx",
                    "sudo mkdir -p /var/www/letsencrypt",  # Create directory for ACME challenges
                    "sudo mkdir -p /var/cache/nginx"  # Create cache directory
                ]
            elif "CentOS" in os_info or "Red Hat" in os_info or "Fedora" in os_info:
                # CentOS/RHEL/Fedora installation
                install_commands = [
                    "sudo yum -y update",
                    "sudo yum -y install epel-release",
                    "sudo yum -y install nginx",
                    # Install GeoIP modules and databases
                    "sudo yum -y install nginx-module-geoip GeoIP GeoIP-devel",
                    # Download and prepare latest GeoIP databases
                    "sudo mkdir -p /usr/share/GeoIP",
                    "cd /tmp && sudo wget -q https://dl.miyuru.lk/geoip/maxmind/country/maxmind4.dat.gz && sudo gunzip -f maxmind4.dat.gz && sudo mv maxmind4.dat /usr/share/GeoIP/GeoIP.dat",
                    "cd /tmp && sudo wget -q https://dl.miyuru.lk/geoip/maxmind/country/maxmind6.dat.gz && sudo gunzip -f maxmind6.dat.gz && sudo mv maxmind6.dat /usr/share/GeoIP/GeoIPv6.dat",
                    "sudo systemctl enable nginx",
                    "sudo systemctl start nginx",
                    "sudo mkdir -p /var/www/letsencrypt",
                    "sudo mkdir -p /var/cache/nginx",
                    "sudo setsebool -P httpd_can_network_connect 1"  # Allow proxy connections
                ]
            elif "Alpine" in os_info:
                # Alpine Linux installation
                install_commands = [
                    "sudo apk update",
                    "sudo apk add nginx",
                    # Install GeoIP modules and databases
                    "sudo apk add nginx-mod-http-geoip geoip",
                    # Download and prepare latest GeoIP databases
                    "sudo mkdir -p /usr/share/GeoIP",
                    "cd /tmp && sudo wget -q https://dl.miyuru.lk/geoip/maxmind/country/maxmind4.dat.gz && sudo gunzip -f maxmind4.dat.gz && sudo mv maxmind4.dat /usr/share/GeoIP/GeoIP.dat",
                    "cd /tmp && sudo wget -q https://dl.miyuru.lk/geoip/maxmind/country/maxmind6.dat.gz && sudo gunzip -f maxmind6.dat.gz && sudo mv maxmind6.dat /usr/share/GeoIP/GeoIPv6.dat",
                    "sudo rc-update add nginx default",
                    "sudo service nginx start",
                    "sudo mkdir -p /var/www/letsencrypt",
                    "sudo mkdir -p /var/cache/nginx"
                ]
            else:
                ssh_client.close()
                return False, f"Unsupported OS detected: {os_info}. Please install Nginx manually."
            
            # Execute installation commands
            all_output = []
            for cmd in install_commands:
                stdin, stdout, stderr = ssh_client.exec_command(cmd, get_pty=True)
                stdout_output = stdout.read().decode('utf-8').strip()
                stderr_output = stderr.read().decode('utf-8').strip()
                all_output.append(f"Command: {cmd}")
                if stdout_output:
                    all_output.append(f"Output: {stdout_output}")
                if stderr_output:
                    all_output.append(f"Error: {stderr_output}")
                all_output.append("---")
            
            # Verify installation
            stdin, stdout, stderr = ssh_client.exec_command("nginx -v 2>&1")
            version_output = stdout.read().decode('utf-8').strip() + stderr.read().decode('utf-8').strip()
            
            # Create Nginx config directory if it doesn't exist
            stdin, stdout, stderr = ssh_client.exec_command(f"sudo mkdir -p {self.nginx_config_path}")
            
            # Configure GeoIP module in nginx.conf if not already configured
            stdin, stdout, stderr = ssh_client.exec_command("grep -q 'load_module.*ngx_http_geoip_module.so' /etc/nginx/nginx.conf || echo 'not_found'")
            if stdout.read().decode('utf-8').strip() == 'not_found':
                # Find the path to the GeoIP module on different systems
                stdin, stdout, stderr = ssh_client.exec_command("find /usr/lib -name '*ngx_http_geoip_module.so' | head -1")
                module_path = stdout.read().decode('utf-8').strip()
                
                if not module_path:
                    stdin, stdout, stderr = ssh_client.exec_command("find /usr/share -name '*ngx_http_geoip_module.so' | head -1")
                    module_path = stdout.read().decode('utf-8').strip()
                
                if module_path:
                    # Add the load_module directive to nginx.conf
                    stdin, stdout, stderr = ssh_client.exec_command(f"sudo sed -i '1i load_module {module_path};' /etc/nginx/nginx.conf")
                    
                    # Verify if the module was added correctly
                    stdin, stdout, stderr = ssh_client.exec_command("grep -q 'load_module.*ngx_http_geoip_module.so' /etc/nginx/nginx.conf && echo 'added' || echo 'failed'")
                    if stdout.read().decode('utf-8').strip() != 'added':
                        all_output.append("Warning: Could not add GeoIP module automatically to nginx.conf")
                else:
                    all_output.append("Warning: Could not find GeoIP module path")
            
            # Add GeoIP configuration to http section if not already present
            geoip_config = r"""
    # GeoIP configuration
    geoip_country /usr/share/GeoIP/GeoIP.dat;
    geoip_city /usr/share/GeoIP/GeoIPCity.dat;
"""
            stdin, stdout, stderr = ssh_client.exec_command("grep -q 'geoip_country' /etc/nginx/nginx.conf || echo 'not_found'")
            if stdout.read().decode('utf-8').strip() == 'not_found':
                # Add GeoIP config to the http section
                stdin, stdout, stderr = ssh_client.exec_command(f"sudo sed -i '/http {{/a{geoip_config}' /etc/nginx/nginx.conf")
                all_output.append("Added GeoIP configuration to nginx.conf")
            
            # Create a test GeoIP config to verify it works
            test_geoip_config = """
server {
    listen 80;
    server_name geoip-test.local;
    
    location /geoip-test {
        default_type text/plain;
        return 200 "Country: $geoip_country_code / $geoip_country_name\\nIP: $remote_addr";
    }
}
"""
            stdin, stdout, stderr = ssh_client.exec_command(f"echo '{test_geoip_config}' | sudo tee {self.nginx_config_path}/geoip-test.conf > /dev/null")
            
            # Test if Nginx config is valid with GeoIP
            stdin, stdout, stderr = ssh_client.exec_command("sudo nginx -t")
            test_output = stdout.read().decode('utf-8').strip() + stderr.read().decode('utf-8').strip()
            
            # If Nginx test failed, remove the test file to prevent issues
            if "failed" in test_output or "error" in test_output.lower():
                ssh_client.exec_command(f"sudo rm -f {self.nginx_config_path}/geoip-test.conf")
                all_output.append(f"Warning: GeoIP test config failed: {test_output}")
            else:
                all_output.append("GeoIP configuration test successful")
                # Reload Nginx to apply changes
                ssh_client.exec_command("sudo systemctl reload nginx || sudo service nginx reload")
            
            # Close the SSH connection
            ssh_client.close()
            
            if "nginx version" in version_output.lower():
                # Installation was successful
                installation_output = "\n".join(all_output)
                success_message = f"Nginx installed successfully on {self.name} ({self.ip_address}) with GeoIP support"
                
                # Log the successful installation
                log_details = {
                    'node_id': self.id,
                    'user_id': user_id,
                    'output': installation_output,
                    'nginx_version': version_output
                }
                # Convert log_details to a string to store in the database
                details_str = f"Nginx installed successfully. Version: {version_output}. Command output stored in system logs."
                log_activity('info', f"Nginx installed on node {self.name}", 'node', self.id, details_str, user_id)
                
                # Create a system log entry
                system_log = SystemLog(
                    user_id=user_id,
                    category='admin',
                    action='install_nginx',
                    resource_type='node',
                    resource_id=self.id,
                    details=f"Nginx installed successfully: {version_output}"
                )
                db.session.add(system_log)
                db.session.commit()
                
                return True, success_message
            else:
                # Installation failed
                error_msg = f"Nginx installation failed on {self.name}. Commands executed but Nginx not found."
                
                # Log the failure
                log_details = {
                    'node_id': self.id,
                    'user_id': user_id,
                    'output': "\n".join(all_output)
                }
                # Convert log_details to a string for the database
                error_details = f"Commands executed, but Nginx not found. Installation failed on {self.name}."
                log_activity('error', f"Failed to install Nginx on node {self.name}", 'node', self.id, error_details, user_id)
                
                # Create a system log entry for the failure
                system_log = SystemLog(
                    user_id=user_id,
                    category='admin',
                    action='install_nginx',
                    resource_type='node',
                    resource_id=self.id,
                    details=f"Nginx installation failed: {error_msg}"
                )
                db.session.add(system_log)
                db.session.commit()
                
                return False, error_msg
                
        except Exception as e:
            error_msg = f"Failed to install Nginx: {str(e)}"
            
            # Log the exception
            log_activity('error', f"Exception during Nginx installation on node {self.name}", 'node', self.id, f"Error: {str(e)}", user_id)
            
            # Create a system log entry for the error
            system_log = SystemLog(
                user_id=user_id,
                category='admin',
                action='install_nginx',
                resource_type='node',
                resource_id=self.id,
                details=error_msg
            )
            db.session.add(system_log)
            db.session.commit()
            
            return False, error_msg


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
    # Advanced WAF settings
    waf_rule_level = db.Column(db.String(10), default='basic')  # basic, medium, strict
    waf_custom_rules = db.Column(db.Text, nullable=True)  # Custom WAF rules
    waf_max_request_size = db.Column(db.Integer, default=1)  # Max request size in MB
    waf_request_timeout = db.Column(db.Integer, default=60)  # Request timeout in seconds
    waf_block_tor_exit_nodes = db.Column(db.Boolean, default=False)  # Block Tor exit nodes
    waf_rate_limiting_enabled = db.Column(db.Boolean, default=False)  # Enable rate limiting
    waf_rate_limiting_requests = db.Column(db.Integer, default=100)  # Requests per minute
    waf_rate_limiting_burst = db.Column(db.Integer, default=200)  # Burst requests
    # OWASP ModSecurity CRS settings
    waf_use_owasp_crs = db.Column(db.Boolean, default=False)  # Use OWASP Core Rule Set
    waf_owasp_crs_paranoia = db.Column(db.Integer, default=1)  # Paranoia level (1-4)
    waf_enabled_crs_rules = db.Column(db.Text, nullable=True)  # Enabled CRS rule IDs (comma-separated)
    waf_disabled_crs_rules = db.Column(db.Text, nullable=True)  # Disabled CRS rule IDs (comma-separated)
    # End of advanced WAF settings
    force_https = db.Column(db.Boolean, default=True)  # New column to force HTTP to HTTPS redirect
    # Cache configuration
    enable_cache = db.Column(db.Boolean, default=True)
    cache_time = db.Column(db.Integer, default=3600)  # Cache time in seconds, default 1 hour
    cache_static_time = db.Column(db.Integer, default=86400)  # Cache time for static assets in seconds, default 1 day
    custom_cache_rules = db.Column(db.Text, nullable=True)  # Custom cache rules in Nginx format
    cache_browser_time = db.Column(db.Integer, default=3600)  # Browser cache time in seconds, default 1 hour
    # End of cache configuration
    # GeoIP configuration
    use_geoip = db.Column(db.Boolean, default=False)  # Whether to use GeoIP filtering
    geoip_mode = db.Column(db.String(10), default='blacklist')  # 'blacklist' or 'whitelist'
    geoip_countries = db.Column(db.Text, nullable=True)  # Comma-separated list of country codes
    geoip_level = db.Column(db.String(10), default='nginx')  # 'nginx' or 'iptables'
    # End of GeoIP configuration
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
            'waf_rule_level': self.waf_rule_level,
            'waf_custom_rules': self.waf_custom_rules,
            'waf_max_request_size': self.waf_max_request_size,
            'waf_request_timeout': self.waf_request_timeout,
            'waf_block_tor_exit_nodes': self.waf_block_tor_exit_nodes,
            'waf_rate_limiting_enabled': self.waf_rate_limiting_enabled,
            'waf_rate_limiting_requests': self.waf_rate_limiting_requests,
            'waf_rate_limiting_burst': self.waf_rate_limiting_burst,
            'waf_use_owasp_crs': self.waf_use_owasp_crs,
            'waf_owasp_crs_paranoia': self.waf_owasp_crs_paranoia,
            'waf_enabled_crs_rules': self.waf_enabled_crs_rules,
            'waf_disabled_crs_rules': self.waf_disabled_crs_rules,
            'force_https': self.force_https,
            'enable_cache': self.enable_cache,
            'cache_time': self.cache_time,
            'cache_static_time': self.cache_static_time,
            'custom_cache_rules': self.custom_cache_rules,
            'cache_browser_time': self.cache_browser_time,
            'use_geoip': self.use_geoip,
            'geoip_mode': self.geoip_mode,
            'geoip_countries': self.geoip_countries,
            'geoip_level': self.geoip_level,
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
    node_id = db.Column(db.Integer, db.ForeignKey('nodes.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    certificate_path = db.Column(db.String(256), nullable=True)
    private_key_path = db.Column(db.String(256), nullable=True)
    fullchain_path = db.Column(db.String(256), nullable=True)
    issuer = db.Column(db.String(64), default='letsencrypt')
    subject = db.Column(db.String(255), nullable=True)
    fingerprint = db.Column(db.String(255), nullable=True)
    valid_from = db.Column(db.DateTime, nullable=True)
    valid_until = db.Column(db.DateTime, nullable=True)
    days_remaining = db.Column(db.Integer, nullable=True)
    is_wildcard = db.Column(db.Boolean, default=False)
    is_self_signed = db.Column(db.Boolean, default=False)
    # Status can be: 'valid', 'expired', 'expiring_soon', 'not_yet_valid'
    status = db.Column(db.String(20), default='pending')
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Use foreign_keys to explicitly indicate which columns to join on
    node = db.relationship('Node', foreign_keys=[node_id])
    
    def to_dict(self):
        return {
            'id': self.id,
            'site_id': self.site_id,
            'node_id': self.node_id,
            'domain': self.domain,
            'issuer': self.issuer,
            'subject': self.subject,
            'valid_from': self.valid_from.isoformat() if self.valid_from else None,
            'valid_until': self.valid_until.isoformat() if self.valid_until else None,
            'days_remaining': self.days_remaining,
            'status': self.status,
            'is_wildcard': self.is_wildcard,
            'is_self_signed': self.is_self_signed,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
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