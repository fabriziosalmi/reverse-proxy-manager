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

# Add the ActivityLog model
class ActivityLog(db.Model):
    """Model to track user activity for security and audit purposes"""
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(64), nullable=False)  # login, logout, profile_update, etc.
    ip_address = db.Column(db.String(45), nullable=True)  # Store IP address for security monitoring
    details = db.Column(db.Text, nullable=True)  # Additional details about the activity
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to the User model
    user = db.relationship('User', backref=db.backref('activity_logs', lazy='dynamic'))
    
    def __repr__(self):
        return f'<ActivityLog id={self.id} user_id={self.user_id} action={self.action}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'user': self.user.username if self.user else None,
            'action': self.action,
            'ip_address': self.ip_address,
            'details': self.details,
            'created_at': self.created_at.isoformat() if self.created_at else None
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
    
    # Proxy type and configuration
    proxy_type = db.Column(db.String(20), default='nginx')  # 'nginx', 'caddy', 'traefik'
    proxy_config_path = db.Column(db.String(256), default='/etc/nginx/conf.d')  # Path to proxy config directory
    proxy_reload_command = db.Column(db.String(256), default='sudo systemctl reload nginx')  # Command to reload proxy
    proxy_binary_path = db.Column(db.String(256), nullable=True)  # Path to proxy binary
    detected_binary_path = db.Column(db.String(256), nullable=True)  # Store detected proxy binary path
    
    # Container-related fields
    is_container_node = db.Column(db.Boolean, default=False)  # Whether this node is a container
    container_connection_type = db.Column(db.String(10), default='socket')  # socket, tcp, ssh
    container_port = db.Column(db.Integer, default=2375)  # Docker daemon port
    container_name = db.Column(db.String(64), nullable=True)  # Name of the container
    container_image = db.Column(db.String(256), default='nginx:latest')  # Docker image
    container_id = db.Column(db.String(64), nullable=True)  # Docker container ID
    container_http_port = db.Column(db.Integer, default=80)  # HTTP port mapping
    container_https_port = db.Column(db.Integer, default=443)  # HTTPS port mapping
    container_config_path = db.Column(db.String(256), default='/var/nginx/conf.d')  # Local path to config
    container_certs_path = db.Column(db.String(256), default='/var/nginx/certs')  # Local path to certs
    container_webroot_path = db.Column(db.String(256), default='/var/nginx/webroot')  # Local path to webroot
    container_cache_path = db.Column(db.String(256), default='/var/nginx/cache')  # Local path to cache
    container_timezone = db.Column(db.String(64), default='UTC')  # Container timezone
    
    # Relationships
    site_nodes = db.relationship('SiteNode', backref='node', lazy='dynamic')
    
    # For backward compatibility
    @property
    def nginx_config_path(self):
        return self.proxy_config_path
        
    @nginx_config_path.setter
    def nginx_config_path(self, value):
        self.proxy_config_path = value
        
    @property
    def nginx_reload_command(self):
        return self.proxy_reload_command
        
    @nginx_reload_command.setter
    def nginx_reload_command(self, value):
        self.proxy_reload_command = value
        
    @property
    def detected_nginx_path(self):
        return self.detected_binary_path
        
    @detected_nginx_path.setter
    def detected_nginx_path(self, value):
        self.detected_binary_path = value
    
    @property
    def ssh_password(self):
        """Decrypt password when accessed"""
        from cryptography.fernet import Fernet
        from flask import current_app
        import base64
        
        if not self._ssh_password:
            return None
            
        try:
            # Get encryption key from config
            key = current_app.config.get('PASSWORD_ENCRYPTION_KEY')
            if not key:
                import logging
                logging.error("PASSWORD_ENCRYPTION_KEY not configured in application settings")
                # No fallback key in any environment for security reasons
                raise ValueError("Missing PASSWORD_ENCRYPTION_KEY in configuration")
                
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
            # Get encryption key from config
            key = current_app.config.get('PASSWORD_ENCRYPTION_KEY')
            if not key:
                import logging
                logging.error("PASSWORD_ENCRYPTION_KEY not configured in application settings")
                # No fallback key in any environment for security reasons
                raise ValueError("Missing PASSWORD_ENCRYPTION_KEY in configuration")
            
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
        
    def install_proxy(self, user_id=None):
        """
        Install the appropriate proxy server on the remote node
        
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
            
            # Set up installation commands based on OS and proxy type
            install_commands = []
            
            if self.proxy_type == 'nginx':
                if "Ubuntu" in os_info or "Debian" in os_info:
                    # Ubuntu/Debian installation for Nginx
                    install_commands = [
                        "sudo apt update -y",
                        "sudo apt install -y nginx",
                        # Install GeoIP modules and databases
                        "sudo apt install -y nginx-module-geoip geoip-database libgeoip-dev",
                        # Install ModSecurity and OWASP CRS
                        "sudo apt install -y libmodsecurity3 libapache2-mod-security2 modsecurity-crs",
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
                    # CentOS/RHEL/Fedora installation for Nginx
                    install_commands = [
                        "sudo yum -y update",
                        "sudo yum -y install epel-release",
                        "sudo yum -y install nginx",
                        # Install GeoIP modules and databases
                        "sudo yum -y install nginx-module-geoip GeoIP GeoIP-devel",
                        # Install ModSecurity and OWASP CRS
                        "sudo yum -y install mod_security mod_security_crs",
                        # Download and prepare latest GeoIP databases
                        "sudo mkdir -p /usr/share/GeoIP",
                        "cd /tmp && sudo wget -q https://dl.miyuru.lk/geoip/maxmind/country/maxmind4.dat.gz && sudo gunzip -f maxmind4.dat.gz && sudo mv maxmind4.dat /usr/share/GeoIP/GeoIP.dat",
                        "cd /tmp && sudo wget -q https://dl.miyuru.lk/geoip/maxmind/country/maxmind6.dat.gz && sudo gunzip -f maxmind6.dat.gz && sudo mv maxmind6.dat /usr/share/GeoIP/GeoIPv6.dat",
                        "sudo systemctl enable nginx",
                        "sudo systemctl start nginx",
                        "sudo mkdir -p /var/www/letsencrypt",  # Create directory for ACME challenges
                        "sudo mkdir -p /var/cache/nginx",  # Create cache directory
                        "sudo setsebool -P httpd_can_network_connect 1"  # Allow proxy connections
                    ]
                elif "Alpine" in os_info:
                    # Alpine Linux installation for Nginx
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
            elif self.proxy_type == 'caddy':
                if "Ubuntu" in os_info or "Debian" in os_info:
                    # Ubuntu/Debian installation for Caddy
                    install_commands = [
                        "sudo apt update -y",
                        # Install dependencies
                        "sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl",
                        # Add Caddy official repository
                        "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg",
                        "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list",
                        "sudo apt update -y",
                        "sudo apt install -y caddy",
                        # Create directories
                        "sudo mkdir -p /etc/caddy/sites",
                        "sudo mkdir -p /var/www/letsencrypt",
                        # Set permissions
                        "sudo chown -R caddy:caddy /etc/caddy",
                        # Start and enable service
                        "sudo systemctl enable caddy",
                        "sudo systemctl start caddy"
                    ]
                elif "CentOS" in os_info or "Red Hat" in os_info or "Fedora" in os_info:
                    # CentOS/RHEL/Fedora installation for Caddy
                    install_commands = [
                        "sudo yum -y update",
                        # Install EPEL repository
                        "sudo yum -y install epel-release",
                        # Install dependencies
                        "sudo yum -y install yum-utils",
                        # Add Caddy repo
                        "sudo dnf copr enable @caddy/caddy -y",
                        "sudo yum -y install caddy",
                        # Create directories
                        "sudo mkdir -p /etc/caddy/sites",
                        "sudo mkdir -p /var/www/letsencrypt",
                        # Set permissions
                        "sudo chown -R caddy:caddy /etc/caddy",
                        # Start and enable service
                        "sudo systemctl enable caddy",
                        "sudo systemctl start caddy"
                    ]
                elif "Alpine" in os_info:
                    # Alpine Linux installation for Caddy
                    install_commands = [
                        "sudo apk update",
                        "sudo apk add caddy",
                        # Create directories
                        "sudo mkdir -p /etc/caddy/sites",
                        "sudo mkdir -p /var/www/letsencrypt",
                        # Set permissions
                        "sudo chown -R caddy:caddy /etc/caddy",
                        # Start and enable service
                        "sudo rc-update add caddy default",
                        "sudo service caddy start"
                    ]
            elif self.proxy_type == 'traefik':
                if "Ubuntu" in os_info or "Debian" in os_info:
                    # Ubuntu/Debian installation for Traefik
                    install_commands = [
                        "sudo apt update -y",
                        # Install dependencies
                        "sudo apt install -y curl",
                        # Download Traefik binary
                        "sudo curl -L https://github.com/traefik/traefik/releases/download/v2.10.1/traefik_v2.10.1_linux_amd64.tar.gz -o /tmp/traefik.tar.gz",
                        "sudo tar -zxvf /tmp/traefik.tar.gz -C /tmp",
                        "sudo mv /tmp/traefik /usr/local/bin/",
                        "sudo chmod +x /usr/local/bin/traefik",
                        # Create directories
                        "sudo mkdir -p /etc/traefik/providers",
                        "sudo mkdir -p /var/www/letsencrypt",
                        # Create minimal configuration file
                        "echo 'providers:\n  file:\n    directory: /etc/traefik/providers\n    watch: true\napi:\n  dashboard: true\n  insecure: true\nentryPoints:\n  web:\n    address: :80\n  websecure:\n    address: :443\ncertificatesResolvers:\n  letsencrypt:\n    acme:\n      email: admin@example.com\n      storage: /etc/traefik/acme.json\n      httpChallenge:\n        entryPoint: web' | sudo tee /etc/traefik/traefik.yml",
                        # Create systemd service
                        "echo '[Unit]\nDescription=Traefik\nDocumentation=https://docs.traefik.io\nAfter=network-online.target\n[Service]\nUser=root\nGroup=root\nExecStart=/usr/local/bin/traefik --configfile=/etc/traefik/traefik.yml\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target' | sudo tee /etc/systemd/system/traefik.service",
                        "sudo systemctl daemon-reload",
                        "sudo systemctl enable traefik",
                        "sudo systemctl start traefik"
                    ]
                elif "CentOS" in os_info or "Red Hat" in os_info or "Fedora" in os_info:
                    # CentOS/RHEL/Fedora installation for Traefik
                    install_commands = [
                        "sudo yum -y update",
                        # Install dependencies
                        "sudo yum -y install curl",
                        # Download Traefik binary
                        "sudo curl -L https://github.com/traefik/traefik/releases/download/v2.10.1/traefik_v2.10.1_linux_amd64.tar.gz -o /tmp/traefik.tar.gz",
                        "sudo tar -zxvf /tmp/traefik.tar.gz -C /tmp",
                        "sudo mv /tmp/traefik /usr/local/bin/",
                        "sudo chmod +x /usr/local/bin/traefik",
                        # Create directories
                        "sudo mkdir -p /etc/traefik/providers",
                        "sudo mkdir -p /var/www/letsencrypt",
                        # Create minimal configuration file
                        "echo 'providers:\n  file:\n    directory: /etc/traefik/providers\n    watch: true\napi:\n  dashboard: true\n  insecure: true\nentryPoints:\n  web:\n    address: :80\n  websecure:\n    address: :443\ncertificatesResolvers:\n  letsencrypt:\n    acme:\n      email: admin@example.com\n      storage: /etc/traefik/acme.json\n      httpChallenge:\n        entryPoint: web' | sudo tee /etc/traefik/traefik.yml",
                        # Create systemd service
                        "echo '[Unit]\nDescription=Traefik\nDocumentation=https://docs.traefik.io\nAfter=network-online.target\n[Service]\nUser=root\nGroup=root\nExecStart=/usr/local/bin/traefik --configfile=/etc/traefik/traefik.yml\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target' | sudo tee /etc/systemd/system/traefik.service",
                        "sudo systemctl daemon-reload",
                        "sudo systemctl enable traefik",
                        "sudo systemctl start traefik"
                    ]
                elif "Alpine" in os_info:
                    # Alpine Linux installation for Traefik
                    install_commands = [
                        "sudo apk update",
                        # Install dependencies
                        "sudo apk add curl",
                        # Download Traefik binary
                        "sudo curl -L https://github.com/traefik/traefik/releases/download/v2.10.1/traefik_v2.10.1_linux_amd64.tar.gz -o /tmp/traefik.tar.gz",
                        "sudo tar -zxvf /tmp/traefik.tar.gz -C /tmp",
                        "sudo mv /tmp/traefik /usr/local/bin/",
                        "sudo chmod +x /usr/local/bin/traefik",
                        # Create directories
                        "sudo mkdir -p /etc/traefik/providers",
                        "sudo mkdir -p /var/www/letsencrypt",
                        # Create minimal configuration file
                        "echo 'providers:\n  file:\n    directory: /etc/traefik/providers\n    watch: true\napi:\n  dashboard: true\n  insecure: true\nentryPoints:\n  web:\n    address: :80\n  websecure:\n    address: :443\ncertificatesResolvers:\n  letsencrypt:\n    acme:\n      email: admin@example.com\n      storage: /etc/traefik/acme.json\n      httpChallenge:\n        entryPoint: web' | sudo tee /etc/traefik/traefik.yml",
                        # Create init.d script
                        "echo '#!/sbin/openrc-run\ndescription=\"Traefik reverse proxy\"\ncommand=\"/usr/local/bin/traefik\"\ncommand_args=\"--configfile=/etc/traefik/traefik.yml\"\ndepend() {\n    need net\n}\n' | sudo tee /etc/init.d/traefik",
                        "sudo chmod +x /etc/init.d/traefik",
                        "sudo rc-update add traefik default",
                        "sudo service traefik start"
                    ]
            else:
                ssh_client.close()
                return False, f"Unsupported proxy type: {self.proxy_type}. Supported types are: nginx, caddy, traefik"
                
            if not install_commands:
                ssh_client.close()
                return False, f"Unsupported OS detected: {os_info}. Please install {self.proxy_type} manually."
            
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
            
            # Verify installation based on proxy type
            version_command = ""
            if self.proxy_type == 'nginx':
                version_command = "nginx -v 2>&1"
            elif self.proxy_type == 'caddy':
                version_command = "caddy version"
            elif self.proxy_type == 'traefik':
                version_command = "traefik version"
                
            stdin, stdout, stderr = ssh_client.exec_command(version_command)
            version_output = stdout.read().decode('utf-8').strip() + stderr.read().decode('utf-8').strip()
            
            # Create proxy config directory if it doesn't exist
            stdin, stdout, stderr = ssh_client.exec_command(f"sudo mkdir -p {self.proxy_config_path}")
            
            # Additional proxy-specific configuration
            if self.proxy_type == 'nginx':
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
                stdin, stdout, stderr = ssh_client.exec_command(f"echo '{test_geoip_config}' | sudo tee {self.proxy_config_path}/geoip-test.conf > /dev/null")
                
                # Test if Nginx config is valid with GeoIP
                stdin, stdout, stderr = ssh_client.exec_command("sudo nginx -t")
                test_output = stdout.read().decode('utf-8').strip() + stderr.read().decode('utf-8').strip()
                
                # If Nginx test failed, remove the test file to prevent issues
                if "failed" in test_output or "error" in test_output.lower():
                    ssh_client.exec_command(f"sudo rm -f {self.proxy_config_path}/geoip-test.conf")
                    all_output.append(f"Warning: GeoIP test config failed: {test_output}")
                else:
                    all_output.append("GeoIP configuration test successful")
                    # Reload Nginx to apply changes
                    ssh_client.exec_command("sudo systemctl reload nginx || sudo service nginx reload")
                
                # Set up ModSecurity if it was installed
                if "Ubuntu" in os_info or "Debian" in os_info:
                    modsec_commands = [
                        "sudo mkdir -p /etc/nginx/modsec",
                        # Copy and configure main ModSecurity config file
                        "sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/nginx/modsec/main.conf",
                        # Enable ModSecurity in detection mode (less disruptive initially)
                        "sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/main.conf",
                        # Set up OWASP CRS
                        "sudo mkdir -p /etc/nginx/modsec/owasp-crs",
                        "cd /etc/nginx/modsec && sudo cp -R /usr/share/modsecurity-crs/* owasp-crs/ 2>/dev/null || echo 'CRS not found in default location'",
                        # Create ModSecurity nginx config inclusion
                        "echo 'modsecurity on; modsecurity_rules_file /etc/nginx/modsec/main.conf;' | sudo tee /etc/nginx/conf.d/modsecurity.conf"
                    ]
                elif "CentOS" in os_info or "Red Hat" in os_info or "Fedora" in os_info:
                    modsec_commands = [
                        "sudo mkdir -p /etc/nginx/modsec",
                        # Copy and configure main ModSecurity config file (different paths for RHEL-based systems)
                        "sudo cp /etc/nginx/modsecurity/modsecurity.conf-recommended /etc/nginx/modsec/main.conf 2>/dev/null || sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/nginx/modsec/main.conf 2>/dev/null || echo 'Could not find modsecurity.conf-recommended'",
                        # Enable ModSecurity in detection mode (less disruptive initially)
                        "sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/main.conf",
                        # Set up OWASP CRS
                        "sudo mkdir -p /etc/nginx/modsec/owasp-crs",
                        "cd /etc/nginx/modsec && sudo cp -R /usr/share/modsecurity-crs/* owasp-crs/ 2>/dev/null || echo 'CRS not found in default location'",
                        # Create ModSecurity nginx config inclusion
                        "echo 'modsecurity on; modsecurity_rules_file /etc/nginx/modsec/main.conf;' | sudo tee /etc/nginx/conf.d/modsecurity.conf"
                    ]
                elif "Alpine" in os_info:
                    modsec_commands = [
                        "sudo apk add nginx-mod-http-modsecurity",
                        "sudo mkdir -p /etc/nginx/modsec",
                        # Copy and configure main ModSecurity config file
                        "sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/nginx/modsec/main.conf 2>/dev/null || echo 'Could not find modsecurity.conf-recommended'",
                        # Create main.conf if it wasn't found
                        "test -f /etc/nginx/modsec/main.conf || echo 'SecRuleEngine On\nSecRequestBodyAccess On\nSecAuditEngine RelevantOnly\nSecAuditLogParts ABIJDEFHZ\nSecAuditLogType Serial\nSecAuditLog /var/log/nginx/modsec_audit.log' | sudo tee /etc/nginx/modsec/main.conf",
                        # Set up OWASP CRS
                        "sudo mkdir -p /etc/nginx/modsec/owasp-crs",
                        # Create ModSecurity nginx config inclusion
                        "echo 'modsecurity on; modsecurity_rules_file /etc/nginx/modsec/main.conf;' | sudo tee /etc/nginx/conf.d/modsecurity.conf"
                    ]
                else:
                    # For unsupported OS, just create basic directories
                    modsec_commands = [
                        "sudo mkdir -p /etc/nginx/modsec",
                        "echo 'SecRuleEngine On\nSecRequestBodyAccess On\nSecAuditEngine RelevantOnly\nSecAuditLogParts ABIJDEFHZ\nSecAuditLogType Serial\nSecAuditLog /var/log/nginx/modsec_audit.log' | sudo tee /etc/nginx/modsec/main.conf",
                        "echo 'modsecurity on; modsecurity_rules_file /etc/nginx/modsec/main.conf;' | sudo tee /etc/nginx/conf.d/modsecurity.conf"
                    ]
                
                # Run ModSecurity setup commands
                for cmd in modsec_commands:
                    stdin, stdout, stderr = ssh_client.exec_command(cmd)
                    stdout_output = stdout.read().decode('utf-8').strip()
                    stderr_output = stderr.read().decode('utf-8').strip()
                    all_output.append(f"ModSec command: {cmd}")
                    if stdout_output:
                        all_output.append(f"Output: {stdout_output}")
                    if stderr_output:
                        all_output.append(f"Error: {stderr_output}")
                    all_output.append("---")
                
                # Create a test for ModSecurity
                modsec_test_config = """
# ModSecurity test configuration
modsecurity on;
modsecurity_rules '
    SecRuleEngine On
    SecRule ARGS:testparam "@contains test" "id:1234,phase:1,deny,status:403,msg:\'ModSecurity test rule triggered\'"
';
"""
                stdin, stdout, stderr = ssh_client.exec_command(f"echo '{modsec_test_config}' | sudo tee {self.proxy_config_path}/modsec-test.conf > /dev/null")
                all_output.append("Created ModSecurity test configuration")
            
            # Close the SSH connection
            ssh_client.close()
            
            # Check if installation was successful based on version output
            success = False
            success_message = ""
            
            if self.proxy_type == 'nginx' and "nginx version" in version_output.lower():
                success = True
                success_message = f"Nginx installed successfully on {self.name} ({self.ip_address}) with GeoIP support"
            elif self.proxy_type == 'caddy' and "v2." in version_output.lower():
                success = True
                success_message = f"Caddy installed successfully on {self.name} ({self.ip_address})"
            elif self.proxy_type == 'traefik' and "version" in version_output.lower():
                success = True
                success_message = f"Traefik installed successfully on {self.name} ({self.ip_address})"
            
            if success:
                # Installation was successful
                installation_output = "\n".join(all_output)
                
                # Log the successful installation
                log_details = {
                    'node_id': self.id,
                    'user_id': user_id,
                    'output': installation_output,
                    'proxy_version': version_output
                }
                # Convert log_details to a string to store in the database
                details_str = f"{self.proxy_type.capitalize()} installed successfully. Version: {version_output}. Command output stored in system logs."
                log_activity('info', f"{self.proxy_type.capitalize()} installed on node {self.name}", 'node', self.id, details_str, user_id)
                
                # Create a system log entry
                system_log = SystemLog(
                    user_id=user_id,
                    category='admin',
                    action=f'install_{self.proxy_type}',
                    resource_type='node',
                    resource_id=self.id,
                    details=f"{self.proxy_type.capitalize()} installed successfully: {version_output}"
                )
                db.session.add(system_log)
                db.session.commit()
                
                return True, success_message
            else:
                # Installation failed
                error_msg = f"{self.proxy_type.capitalize()} installation failed on {self.name}. Commands executed but {self.proxy_type} not found."
                
                # Log the failure
                log_details = {
                    'node_id': self.id,
                    'user_id': user_id,
                    'output': "\n".join(all_output)
                }
                # Convert log_details to a string for the database
                error_details = f"Commands executed, but {self.proxy_type} not found. Installation failed on {self.name}."
                log_activity('error', f"Failed to install {self.proxy_type} on node {self.name}", 'node', self.id, error_details, user_id)
                
                # Create a system log entry for the failure
                system_log = SystemLog(
                    user_id=user_id,
                    category='admin',
                    action=f'install_{self.proxy_type}',
                    resource_type='node',
                    resource_id=self.id,
                    details=f"{self.proxy_type.capitalize()} installation failed: {error_msg}"
                )
                db.session.add(system_log)
                db.session.commit()
                
                return False, error_msg
                
        except Exception as e:
            error_msg = f"Failed to install {self.proxy_type}: {str(e)}"
            
            # Log the exception
            log_activity('error', f"Exception during {self.proxy_type} installation on node {self.name}", 'node', self.id, f"Error: {str(e)}", user_id)
            
            # Create a system log entry for the error
            system_log = SystemLog(
                user_id=user_id,
                category='admin',
                action=f'install_{self.proxy_type}',
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


class SystemSetting(db.Model):
    """Model to store system-wide settings"""
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @classmethod
    def get(cls, key, default=None):
        """Get a setting value by key with optional default"""
        setting = cls.query.filter_by(key=key).first()
        if setting:
            return setting.value
        return default
    
    @classmethod
    def set(cls, key, value):
        """Set or update a setting value"""
        setting = cls.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            setting = cls(key=key, value=value)
            db.session.add(setting)
        db.session.commit()
        return setting
    
    @classmethod
    def get_all_by_prefix(cls, prefix):
        """Get all settings with a specific prefix"""
        settings = cls.query.filter(cls.key.startswith(prefix)).all()
        return {s.key.replace(prefix, ''): s.value for s in settings}
    
    def to_dict(self):
        return {
            'id': self.id,
            'key': self.key,
            'value': self.value,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }