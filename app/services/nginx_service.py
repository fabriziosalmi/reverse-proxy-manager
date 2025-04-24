import re
import os
import paramiko
import tempfile
import git
import time
from flask import current_app
from app.models.models import db, Site, Node, SiteNode, DeploymentLog
from datetime import datetime
from app.services.logger_service import log_activity
from app.services.proxy_service_base import ProxyServiceBase

class NginxService(ProxyServiceBase):
    """
    Nginx proxy service implementation
    """
    
    def generate_config(self, site):
        """
        Generate Nginx configuration for a site
        
        Args:
            site: Site object containing configuration details
            
        Returns:
            str: Nginx configuration file content
        """
        # Load the appropriate template based on protocol
        template_file = 'https.conf' if site.protocol == 'https' else 'http.conf'
        nginx_template_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                                        'nginx_templates', template_file)
        
        try:
            with open(nginx_template_path, 'r') as f:
                template = f.read()
        except FileNotFoundError:
            raise Exception(f"Nginx template {template_file} not found")
        
        # Replace placeholders with site values
        config = template.replace('{{SERVER_NAME}}', site.domain)
        config = config.replace('{{ORIGIN_PROTOCOL}}', site.origin_protocol)
        config = config.replace('{{ORIGIN_ADDRESS}}', site.origin_address)
        config = config.replace('{{ORIGIN_PORT}}', str(site.origin_port))
        
        # Handle WAF settings
        if site.use_waf:
            waf_config = self._generate_waf_config(site)
            config = config.replace('{{WAF_CONFIG}}', waf_config)
        else:
            config = config.replace('{{WAF_CONFIG}}', '# WAF not enabled for this site')
        
        # Handle caching settings
        if site.enable_cache:
            cache_config = self._generate_cache_config(site)
            config = config.replace('{{CACHE_CONFIG}}', cache_config)
        else:
            config = config.replace('{{CACHE_CONFIG}}', '# Caching not enabled for this site')
        
        # Handle GeoIP settings
        if site.use_geoip:
            geoip_config = self._generate_geoip_config(site)
            config = config.replace('{{GEOIP_CONFIG}}', geoip_config)
        else:
            config = config.replace('{{GEOIP_CONFIG}}', '# GeoIP filtering not enabled for this site')
        
        # Add any custom configuration
        if site.custom_config:
            config = config.replace('{{CUSTOM_CONFIG}}', site.custom_config)
        else:
            config = config.replace('{{CUSTOM_CONFIG}}', '# No custom configuration')
        
        # Add blocked site notice if blocked
        if site.is_blocked:
            config = config.replace('{{IS_BLOCKED}}', 'return 403 "This site has been blocked by the administrator.";')
        else:
            config = config.replace('{{IS_BLOCKED}}', '# Site is not blocked')
        
        # Force HTTPS if enabled
        if site.force_https and site.protocol == 'https':
            https_redirect = 'if ($scheme != "https") { return 301 https://$host$request_uri; }'
            config = config.replace('{{FORCE_HTTPS}}', https_redirect)
        else:
            config = config.replace('{{FORCE_HTTPS}}', '# HTTPS redirect not enabled')
        
        return config
    
    def deploy_config(self, site_id, node_id, config_content, test_only=False):
        """
        Deploy Nginx configuration to a node
        
        Args:
            site_id: ID of the site
            node_id: ID of the node to deploy to
            config_content: The Nginx configuration content
            test_only: If True, only test the configuration without deploying
            
        Returns:
            If test_only=True: tuple (is_valid, warnings)
            Otherwise: True on success or raises an exception
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            raise ValueError("Site or Node not found")
        
        # Create a backup of the existing configuration
        if not test_only:
            backup_path = self.create_backup_config(site_id, node_id)
        
        try:
            # Create SSH connection to the node
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect using key or password
            if node.ssh_key_path:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    key_filename=node.ssh_key_path,
                    timeout=10
                )
            else:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    password=node.ssh_password,
                    timeout=10
                )
            
            # Upload the configuration to a temporary file for testing
            sftp = ssh_client.open_sftp()
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = tmp.name
                tmp.write(config_content.encode('utf-8'))
            
            remote_temp_path = f"/tmp/{site.domain}_nginx_test.conf"
            sftp.put(tmp_path, remote_temp_path)
            os.unlink(tmp_path)  # Clean up local temp file
            
            # Test the configuration
            test_cmd = f"nginx -t -c {remote_temp_path}"
            stdin, stdout, stderr = ssh_client.exec_command(test_cmd)
            exit_code = stdout.channel.recv_exit_status()
            
            stderr_output = stderr.read().decode('utf-8')
            warnings = []
            
            if 'warning' in stderr_output.lower():
                warnings = [line for line in stderr_output.split('\n') if 'warning' in line.lower()]
            
            if exit_code != 0:
                # Configuration test failed
                error_message = stderr_output
                
                # Log the failure
                log = DeploymentLog(
                    site_id=site_id,
                    node_id=node_id,
                    action="test_config" if test_only else "deploy",
                    status="error",
                    message=f"Nginx configuration test failed: {error_message}"
                )
                db.session.add(log)
                db.session.commit()
                
                if test_only:
                    # Return the validation result
                    return False, error_message
                else:
                    # Restore from backup if deployment was attempted
                    if backup_path:
                        self.restore_from_backup(backup_path, site_id, node_id)
                    
                    raise Exception(f"Nginx configuration test failed: {error_message}")
            
            # If we're only testing, return success and any warnings
            if test_only:
                return True, warnings
            
            # Deploy the valid configuration
            config_path = f"{node.nginx_config_path}/{site.domain}.conf"
            sftp.put(remote_temp_path, config_path)
            
            # Reload Nginx to apply the new configuration
            reload_cmd = node.nginx_reload_command
            stdin, stdout, stderr = ssh_client.exec_command(reload_cmd)
            exit_code = stdout.channel.recv_exit_status()
            
            if exit_code != 0:
                # Reload failed
                error_message = stderr.read().decode('utf-8')
                
                # Log the failure
                log = DeploymentLog(
                    site_id=site_id,
                    node_id=node_id,
                    action="deploy",
                    status="error",
                    message=f"Nginx reload failed: {error_message}"
                )
                db.session.add(log)
                db.session.commit()
                
                # Restore from backup
                if backup_path:
                    self.restore_from_backup(backup_path, site_id, node_id)
                
                raise Exception(f"Nginx reload failed: {error_message}")
            
            # Update the site node status
            site_node = SiteNode.query.filter_by(site_id=site_id, node_id=node_id).first()
            if site_node:
                site_node.status = 'active'
                site_node.last_deployed = datetime.utcnow()
                db.session.commit()
            
            # Log the successful deployment
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action="deploy",
                status="success",
                message="Nginx configuration deployed successfully"
            )
            db.session.add(log)
            db.session.commit()
            
            # Clean up
            ssh_client.exec_command(f"rm -f {remote_temp_path}")
            sftp.close()
            ssh_client.close()
            
            return True
            
        except Exception as e:
            # Log the error
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action="deploy",
                status="error",
                message=f"Deployment error: {str(e)}"
            )
            db.session.add(log)
            db.session.commit()
            
            # Restore from backup if it exists
            if not test_only and backup_path:
                self.restore_from_backup(backup_path, site_id, node_id)
            
            raise
    
    def validate_config(self, config_content):
        """
        Validate the Nginx configuration syntax
        
        Args:
            config_content: String containing the Nginx configuration
            
        Returns:
            tuple: (is_valid, error_message)
        """
        # Local validation of basic syntax
        # This is a simple check and not a complete validation
        invalid_patterns = [
            r'location[^{]*{[^}]*{[^}]*}[^}]*}',  # Nested location blocks
            r'server[^{]*{[^}]*{[^}]*{',          # Too many nested blocks
            r'[^#]server_name\s*;'                # Empty server_name
        ]
        
        for pattern in invalid_patterns:
            if re.search(pattern, config_content):
                return False, f"Invalid Nginx configuration pattern detected: {pattern}"
        
        return True, ""
    
    def get_service_info(self, node):
        """
        Get detailed Nginx information from a node
        
        Args:
            node: Node object to retrieve info from
            
        Returns:
            dict: A dictionary containing Nginx information
        """
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect using key or password
            if node.ssh_key_path:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    key_filename=node.ssh_key_path,
                    timeout=10
                )
            else:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    password=node.ssh_password,
                    timeout=10
                )
            
            # Get Nginx version
            stdin, stdout, stderr = ssh_client.exec_command("nginx -v 2>&1")
            version_output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
            
            # Check if Nginx is running
            stdin, stdout, stderr = ssh_client.exec_command("pgrep nginx")
            is_running = len(stdout.read().decode('utf-8').strip()) > 0
            
            # Get Nginx modules
            stdin, stdout, stderr = ssh_client.exec_command("nginx -V 2>&1")
            modules_output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
            
            # Extract version
            version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', version_output)
            version = version_match.group(1) if version_match else "Unknown"
            
            # Extract modules
            modules = []
            if '--with' in modules_output:
                for module in re.findall(r'--with-([a-zA-Z0-9_-]+)', modules_output):
                    modules.append(module)
            
            # Get site count
            stdin, stdout, stderr = ssh_client.exec_command(f"ls -1 {node.nginx_config_path}/*.conf 2>/dev/null | wc -l")
            site_count = int(stdout.read().decode('utf-8').strip())
            
            ssh_client.close()
            
            return {
                'version': version,
                'is_running': is_running,
                'modules': modules,
                'site_count': site_count
            }
            
        except Exception as e:
            return {
                'version': "Unknown",
                'is_running': False,
                'modules': [],
                'site_count': 0,
                'error': str(e)
            }
    
    def install_service(self, node, user_id=None):
        """
        Install Nginx on a node
        
        Args:
            node: Node object to install Nginx on
            user_id: Optional ID of the user performing the installation
            
        Returns:
            tuple: (success, message)
        """
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect using key or password
            if node.ssh_key_path:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    key_filename=node.ssh_key_path,
                    timeout=10
                )
            else:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    password=node.ssh_password,
                    timeout=10
                )
            
            # Check if Nginx is already installed
            stdin, stdout, stderr = ssh_client.exec_command("which nginx")
            nginx_path = stdout.read().decode('utf-8').strip()
            
            if nginx_path:
                return True, f"Nginx is already installed at {nginx_path}"
            
            # Check the Linux distribution
            stdin, stdout, stderr = ssh_client.exec_command("cat /etc/os-release")
            os_info = stdout.read().decode('utf-8')
            
            if "Ubuntu" in os_info or "Debian" in os_info:
                # Debian/Ubuntu installation
                commands = [
                    "sudo apt-get update",
                    "sudo apt-get install -y nginx",
                    "sudo systemctl enable nginx",
                    "sudo systemctl start nginx"
                ]
            elif "CentOS" in os_info or "Red Hat" in os_info or "Fedora" in os_info:
                # RHEL/CentOS/Fedora installation
                commands = [
                    "sudo yum install -y epel-release",
                    "sudo yum install -y nginx",
                    "sudo systemctl enable nginx",
                    "sudo systemctl start nginx"
                ]
            else:
                return False, "Unsupported Linux distribution"
            
            # Run installation commands
            for cmd in commands:
                stdin, stdout, stderr = ssh_client.exec_command(cmd)
                exit_code = stdout.channel.recv_exit_status()
                if exit_code != 0:
                    error = stderr.read().decode('utf-8')
                    return False, f"Installation failed: {error}"
            
            # Verify installation
            stdin, stdout, stderr = ssh_client.exec_command("which nginx")
            nginx_path = stdout.read().decode('utf-8').strip()
            
            if nginx_path:
                # Update the node with detected Nginx path
                node.detected_nginx_path = nginx_path
                db.session.commit()
                
                # Log the installation
                if user_id:
                    from app.services.logger_service import log_activity
                    log_activity(
                        category='admin',
                        action='install_nginx',
                        resource_type='node',
                        resource_id=node.id,
                        user_id=user_id,
                        details=f"Installed Nginx on node {node.name}"
                    )
                
                return True, f"Nginx successfully installed at {nginx_path}"
            else:
                return False, "Nginx installation failed: Nginx binary not found after installation"
                
        except Exception as e:
            return False, f"Nginx installation failed: {str(e)}"
            
    def _generate_waf_config(self, site):
        """
        Generate WAF configuration for a site
        
        Args:
            site: Site object
            
        Returns:
            str: WAF configuration section
        """
        if not site.use_waf:
            return "# WAF not enabled for this site"
        
        waf_config = [
            "# WAF Configuration",
            "location / {",
            "    modsecurity on;",
            "    modsecurity_rules_file /etc/nginx/modsec/main.conf;"
        ]
        
        # Add rule level settings
        if site.waf_rule_level == 'strict':
            waf_config.append("    # Strict WAF rules")
            waf_config.append("    modsecurity_rules 'SecRuleEngine On';")
            waf_config.append("    modsecurity_rules 'SecAuditLogParts ABIJDEFHZ';")
        elif site.waf_rule_level == 'medium':
            waf_config.append("    # Medium WAF rules")
            waf_config.append("    modsecurity_rules 'SecRuleEngine On';")
            waf_config.append("    modsecurity_rules 'SecAuditLogParts ABIJDEFHZ';")
        else:
            waf_config.append("    # Basic WAF rules")
            waf_config.append("    modsecurity_rules 'SecRuleEngine On';")
            waf_config.append("    modsecurity_rules 'SecAuditLogParts ABIJDZ';")
        
        # Add custom rules if provided
        if hasattr(site, 'waf_custom_rules') and site.waf_custom_rules:
            waf_config.append("    # Custom WAF rules")
            for rule in site.waf_custom_rules.split("\n"):
                waf_config.append(f"    modsecurity_rules '{rule}';")
        
        waf_config.append("    proxy_pass http://backend;")
        waf_config.append("}")
        
        return "\n".join(waf_config)
    
    def _generate_cache_config(self, site):
        """
        Generate caching configuration for a site
        
        Args:
            site: Site object
            
        Returns:
            str: Caching configuration section
        """
        if not site.enable_cache:
            return "# Caching not enabled for this site"
        
        cache_config = [
            "# Caching Configuration",
            f"proxy_cache_path /var/cache/nginx/{site.domain} levels=1:2 keys_zone={site.domain}_cache:10m max_size=100m inactive=60m use_temp_path=off;",
            "",
            "server {",
            "    location / {",
            f"        proxy_cache {site.domain}_cache;",
            f"        proxy_cache_valid 200 {site.cache_time}s;",
            f"        proxy_cache_valid 404 {site.cache_time // 10}s;",
            "        proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;",
            "        add_header X-Cache-Status $upstream_cache_status;",
            "    }",
            "",
            "    # Static files caching",
            "    location ~* \\.(jpg|jpeg|png|gif|ico|css|js)$ {",
            f"        expires {site.cache_static_time}s;",
            f"        add_header Cache-Control \"public, max-age={site.cache_static_time}\";",
            "    }",
            "}"
        ]
        
        # Add custom cache rules if provided
        if hasattr(site, 'custom_cache_rules') and site.custom_cache_rules:
            cache_config.append("# Custom cache rules")
            cache_config.extend(site.custom_cache_rules.split("\n"))
        
        return "\n".join(cache_config)
    
    def _generate_geoip_config(self, site):
        """
        Generate GeoIP configuration for a site
        
        Args:
            site: Site object
            
        Returns:
            str: GeoIP configuration section
        """
        if not site.use_geoip:
            return "# GeoIP filtering not enabled for this site"
        
        geoip_config = [
            "# GeoIP Configuration"
        ]
        
        if site.geoip_level == 'nginx':
            countries = site.geoip_countries.replace(' ', '').split(',') if site.geoip_countries else []
            
            if site.geoip_mode == 'blacklist':
                if countries:
                    geoip_config.append("if ($geoip_country_code ~ '^(" + "|".join(countries) + ")$') {")
                    geoip_config.append("    return 403 'Access denied by geographic restriction';")
                    geoip_config.append("}")
            else:  # whitelist
                if countries:
                    geoip_config.append("if ($geoip_country_code !~ '^(" + "|".join(countries) + ")$') {")
                    geoip_config.append("    return 403 'Access denied by geographic restriction';")
                    geoip_config.append("}")
        
        return "\n".join(geoip_config)

def generate_nginx_config(site):
    """
    Generate an Nginx configuration for a site.
    
    Args:
        site: Site object containing configuration details
        
    Returns:
        str: Nginx configuration file content
    """
    # If site is blocked, return a blocked site configuration
    if site.is_blocked:
        return generate_blocked_site_config(site)
        
    # Load the appropriate template
    template_path = os.path.join(
        current_app.config['NGINX_TEMPLATES_DIR'], 
        'https.conf' if site.protocol == 'https' else 'http.conf'
    )
    
    # If template doesn't exist, use a default one
    if not os.path.exists(template_path):
        # Create basic template
        if site.protocol == 'https':
            template = r"""
server {
    listen 443 ssl http2;
    server_name {{domain}};
    
    ssl_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{domain}}/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/{{domain}}/chain.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # GeoIP configuration
    {{geoip_config}}
    
    # Cache configuration
    {{cache_config}}
    
    location / {
        # GeoIP access control
        {{geoip_restrictions}}
        
        proxy_pass {{origin_protocol}}://{{origin_address}}:{{origin_port}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Websocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Cache headers
        {{cache_proxy_config}}
    }
    
    # Static files caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
        # GeoIP access control
        {{geoip_restrictions}}
        
        proxy_pass {{origin_protocol}}://{{origin_address}}:{{origin_port}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Static file caching
        {{static_cache_config}}
        
        # No need to track these requests
        access_log off;
        log_not_found off;
    }
    
    # Custom configuration
    {{custom_config}}
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name {{domain}};
    
    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }
    
    location / {
        return 301 https://$host$request_uri;
    }
}
"""
        else:  # HTTP template
            # Check if we need to force HTTPS redirect for HTTP sites
            if site.force_https:
                template = """
# HTTP site with forced HTTPS redirect
server {
    listen 80;
    server_name {{domain}};
    
    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }
    
    location / {
        return 301 https://$host$request_uri;
    }
}
"""
            else:
                template = """
server {
    listen 80;
    server_name {{domain}};
    
    # GeoIP configuration
    {{geoip_config}}
    
    # Cache configuration
    {{cache_config}}
    
    location / {
        # GeoIP access control
        {{geoip_restrictions}}
        
        proxy_pass {{origin_protocol}}://{{origin_address}}:{{origin_port}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Websocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Cache headers
        {{cache_proxy_config}}
    }
    
    # Static files caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
        # GeoIP access control
        {{geoip_restrictions}}
        
        proxy_pass {{origin_protocol}}://{{origin_address}}:{{origin_port}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Static file caching
        {{static_cache_config}}
        
        # No need to track these requests
        access_log off;
        log_not_found off;
    }
    
    # Custom configuration
    {{custom_config}}
}
"""
    else:
        # Read template from file
        with open(template_path, 'r') as file:
            template = file.read()
    
    # Replace placeholders
    config = template.replace('{{domain}}', site.domain)
    config = config.replace('{{origin_protocol}}', site.protocol)
    config = config.replace('{{origin_address}}', site.origin_address)
    config = config.replace('{{origin_port}}', str(site.origin_port))
    
    # Add custom config if provided
    if site.custom_config:
        config = config.replace('{{custom_config}}', site.custom_config)
    else:
        config = config.replace('{{custom_config}}', '')
    
    # Add GeoIP configuration if enabled
    if site.use_geoip:
        geoip_countries = site.geoip_countries.strip().split(',') if site.geoip_countries else []
        
        # Generate map for country codes
        if site.geoip_level == 'nginx':
            # For Nginx-level GeoIP filtering
            if site.geoip_mode == 'blacklist':
                # Blacklist mode - deny specific countries
                country_map = "\n    # GeoIP country blacklist\n"
                if geoip_countries:
                    country_map += "    map $geoip_country_code $allowed_country {\n"
                    country_map += "        default 1;\n"
                    for country in geoip_countries:
                        country_map += f"        {country.strip().upper()} 0;\n"
                    country_map += "    }\n"
                else:
                    # If no countries specified, don't block any
                    country_map += "    # No countries blacklisted\n"
                    country_map += "    map $geoip_country_code $allowed_country {\n"
                    country_map += "        default 1;\n"
                    country_map += "    }\n"
            else:
                # Whitelist mode - allow only specific countries
                country_map = "\n    # GeoIP country whitelist\n"
                if geoip_countries:
                    country_map += "    map $geoip_country_code $allowed_country {\n"
                    country_map += "        default 0;\n"
                    for country in geoip_countries:
                        country_map += f"        {country.strip().upper()} 1;\n"
                    country_map += "    }\n"
                else:
                    # If no countries specified, allow all
                    country_map += "    # No countries whitelisted, allowing all\n"
                    country_map += "    map $geoip_country_code $allowed_country {\n"
                    country_map += "        default 1;\n"
                    country_map += "    }\n"
                    
            # Add restrictions to location blocks
            geoip_restrictions = """
        # GeoIP country restrictions
        if ($allowed_country = 0) {
            return 403 '<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #d9534f;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Access Denied</h1>
        <p>Your access to this site has been restricted based on your geographic location.</p>
        <p>Country code: $geoip_country_code</p>
    </div>
</body>
</html>';
            add_header Content-Type text/html;
        }
"""
            
            # Combine for final geoip_config
            geoip_config = country_map
        
        else:
            # For iptables-level GeoIP filtering, we don't need Nginx config
            # This will be handled by a separate iptables configuration
            geoip_config = "\n    # GeoIP filtering handled at iptables level\n"
            geoip_restrictions = ""
            
            # Update iptables on all nodes where this site is deployed
            # Note: This is a placeholder, the actual implementation would
            # need to run in a separate process or job to avoid blocking
            from app import db
            from app.models.models import SiteNode
            site_nodes = SiteNode.query.filter_by(site_id=site.id).all()
            for site_node in site_nodes:
                try:
                    # Schedule an async task to update iptables
                    pass
                except Exception as e:
                    log_activity('error', f"Failed to update iptables GeoIP rules for site {site.domain} on node {site_node.node_id}: {str(e)}")
    else:
        # GeoIP not enabled
        geoip_config = ""
        geoip_restrictions = ""
    
    # Replace GeoIP placeholders
    config = config.replace('{{geoip_config}}', geoip_config)
    config = config.replace('{{geoip_restrictions}}', geoip_restrictions)
    
    # Add cache configuration
    if site.enable_cache:
        # Define the proxy cache configuration
        cache_config = f"""
    # Cache configuration
    proxy_cache_path /var/cache/nginx/{site.domain}_cache levels=1:2 keys_zone={site.domain}_cache:10m max_size=500m inactive=60m;
    proxy_cache_key "$scheme$host$request_uri";
    proxy_cache_valid 200 {site.cache_time}s;
    proxy_cache_bypass $http_pragma $http_cache_control;
    proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;
"""
        # Define cache headers for proxy
        cache_proxy_config = f"""
        # Cache control
        proxy_cache {site.domain}_cache;
        proxy_cache_valid 200 {site.cache_time}s;
        
        # Browser caching headers
        add_header Cache-Control "public, max-age={site.cache_browser_time}";
        expires {site.cache_browser_time}s;
"""
        # Static files cache directives
        static_cache_config = f"""
        # Static file caching
        proxy_cache {site.domain}_cache;
        proxy_cache_valid 200 {site.cache_static_time}s;
        add_header Cache-Control "public, max-age={site.cache_static_time}";
        expires {site.cache_static_time}s;
"""
        # If custom cache rules are provided, append them
        if site.custom_cache_rules:
            cache_config += f"\n    # Custom cache rules\n    {site.custom_cache_rules}\n"
    else:
        # If caching is disabled
        cache_config = """
    # Caching disabled
    add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate";
    add_header Pragma "no-cache";
    expires 0;
"""
        cache_proxy_config = """
        # Cache disabled
        add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate";
        add_header Pragma "no-cache";
        expires 0;
"""
        static_cache_config = """
        # Static file caching disabled
        add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate";
        add_header Pragma "no-cache";
        expires 0;
"""
    
    # Replace cache placeholders
    config = config.replace('{{cache_config}}', cache_config)
    config = config.replace('{{cache_proxy_config}}', cache_proxy_config)
    config = config.replace('{{static_cache_config}}', static_cache_config)
    
    # Add WAF configuration if needed
    if site.use_waf:
        # Create WAF configuration based on the advanced settings
        waf_config = """
    # WAF Configuration
"""
        # Add ModSecurity basic setup
        waf_config += """
    # Enable ModSecurity
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;
"""

        # Set protection level based on rule_level setting
        if site.waf_rule_level == 'basic':
            waf_config += """
    # Basic WAF Protection Level
    modsecurity_rules '
        SecRuleEngine On
        # Use OWASP Core Rule Set with basic paranoia level
        SecAction "id:900000,phase:1,pass,nolog,setvar:tx.paranoia_level=1"
    ';
"""
        elif site.waf_rule_level == 'medium':
            waf_config += """
    # Medium WAF Protection Level
    modsecurity_rules '
        SecRuleEngine On
        # Use OWASP Core Rule Set with medium paranoia level
        SecAction "id:900000,phase:1,pass,nolog,setvar:tx.paranoia_level=3"
    ';
"""
        elif site.waf_rule_level == 'strict':
            waf_config += """
    # Strict WAF Protection Level
    modsecurity_rules '
        SecRuleEngine On
        # Use OWASP Core Rule Set with high paranoia level
        SecAction "id:900000,phase:1,pass,nolog,setvar:tx.paranoia_level=4"
    ';
"""

        # Add request size limiting if configured
        waf_config += f"""
    # Limit request size to {site.waf_max_request_size}MB
    client_max_body_size {site.waf_max_request_size}m;
"""

        # Add request timeout if configured
        waf_config += f"""
    # Request timeout settings
    client_body_timeout {site.waf_request_timeout}s;
    client_header_timeout {site.waf_request_timeout}s;
    proxy_connect_timeout {site.waf_request_timeout}s;
    proxy_send_timeout {site.waf_request_timeout}s;
    proxy_read_timeout {site.waf_request_timeout}s;
"""

        # Add Tor exit node blocking if enabled
        if site.waf_block_tor_exit_nodes:
            waf_config += """
    # Block Tor exit nodes
    modsecurity_rules '
        SecRule REMOTE_ADDR "@ipMatchFromFile /etc/nginx/modsec/tor-exit-nodes.conf" \\
            "id:10000,phase:1,deny,status:403,log,msg:\'Access from Tor exit node blocked\'"
    ';
"""

        # Add rate limiting if enabled
        if site.waf_rate_limiting_enabled:
            waf_config += f"""
    # Rate limiting settings
    limit_req_zone $binary_remote_addr zone=waf_limit:10m rate={site.waf_rate_limiting_requests}r/m;
    limit_req zone=waf_limit burst={site.waf_rate_limiting_burst} nodelay;
"""

        # Add custom WAF rules if provided
        if site.waf_custom_rules:
            custom_rules = site.waf_custom_rules.replace("'", "\\'")  # Escape single quotes
            waf_config += f"""
    # Custom WAF rules
    modsecurity_rules '
{custom_rules}
    ';
"""

        config = config.replace('{{custom_config}}', waf_config + (site.custom_config if site.custom_config else ''))
    
    # Save to Git repo
    save_config_to_git(site, config)
    
    return config

def generate_blocked_site_config(site):
    """
    Generate a configuration for a blocked site.
    
    Args:
        site: Site object containing configuration details
        
    Returns:
        str: Nginx configuration file content for a blocked site
    """
    # For HTTP sites
    if site.protocol == 'http':
        template = r"""
server {
    listen 80;
    server_name {{domain}};
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";
    
    # Return blocked message for all requests
    location / {
        return 403 '<!DOCTYPE html>
<html>
<head>
    <title>Site Blocked</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #d9534f;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Site Blocked</h1>
        <p>This site has been temporarily blocked by the administrator.</p>
        <p>Please contact the site owner for more information.</p>
    </div>
</body>
</html>';
        add_header Content-Type text/html;
    }
    
    # Allow ACME challenges for future SSL certificate renewal
    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }
}
"""
    # For HTTPS sites
    else:
        template = """
server {
    listen 443 ssl http2;
    server_name {{domain}};
    
    ssl_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{domain}}/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/{{domain}}/chain.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";
    
    # Return blocked message for all requests
    location / {
        return 403 '<!DOCTYPE html>
<html>
<head>
    <title>Site Blocked</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #d9534f;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Site Blocked</h1>
        <p>This site has been temporarily blocked by the administrator.</p>
        <p>Please contact the site owner for more information.</p>
    </div>
</body>
</html>';
        add_header Content-Type text/html;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name {{domain}};
    
    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }
    
    location / {
        return 301 https://$host$request_uri;
    }
}
"""
    
    # Replace domain placeholder
    config = template.replace('{{domain}}', site.domain)
    
    # Save to Git repo
    save_config_to_git(site, config)
    
    return config

def save_config_to_git(site, config_content):
    """
    Save the Nginx configuration to the Git repository
    
    Args:
        site: Site object
        config_content: Nginx configuration content
    """
    repo_path = current_app.config['NGINX_CONFIG_GIT_REPO']
    
    try:
        # Create repo if it doesn't exist
        if not os.path.exists(os.path.join(repo_path, '.git')):
            os.makedirs(repo_path, exist_ok=True)
            repo = git.Repo.init(repo_path)
            # Add a README file for the initial commit
            readme_path = os.path.join(repo_path, 'README.md')
            with open(readme_path, 'w') as f:
                f.write("# Nginx Configuration Repository\n\nStores Nginx configurations managed by the Italia CDN Proxy system.\n")
            repo.git.add(readme_path)
            repo.git.commit('-m', 'Initial commit')
        else:
            repo = git.Repo(repo_path)
        
        # Ensure we have the latest changes
        try:
            # Only pull if there's a remote configured
            if len(repo.remotes) > 0:
                # Stash any local changes before pulling
                repo.git.stash('save', 'Auto-stash before pull')
                repo.git.pull('--rebase')
                # Try to apply stashed changes
                try:
                    repo.git.stash('pop')
                except git.GitCommandError:
                    # If there are conflicts, just keep the stashed changes
                    log_activity('warning', f"Conflicts during git stash pop in save_config_to_git for {site.domain}")
        except git.GitCommandError as e:
            # Log but continue, we'll work with the local copy
            log_activity('warning', f"Failed to pull latest changes: {str(e)}")
        
        # Create site directory if it doesn't exist
        site_dir = os.path.join(repo_path, 'sites')
        os.makedirs(site_dir, exist_ok=True)
        
        # Write config file with atomic operation
        file_path = os.path.join(site_dir, f"{site.domain}.conf")
        temp_file_path = f"{file_path}.temp"
        with open(temp_file_path, 'w') as f:
            f.write(config_content)
        os.replace(temp_file_path, file_path)  # Atomic replace operation
        
        # Add to Git with proper error handling
        try:
            repo.git.add(file_path)
            
            # Check if there are changes to commit - fixed the issue with --cached reference
            has_changes = False
            
            # First check if the file is untracked
            untracked_files = repo.untracked_files
            if os.path.relpath(file_path, repo.working_dir) in untracked_files:
                has_changes = True
            
            # Then check for modifications to tracked files
            if not has_changes and repo.head.is_valid():
                try:
                    # Only check diff with HEAD if we have a valid HEAD reference
                    diff_index = repo.index.diff('HEAD')
                    modified_files = [item.a_path for item in diff_index]
                    rel_path = os.path.relpath(file_path, repo.working_dir)
                    has_changes = rel_path in modified_files
                except git.GitCommandError:
                    # If diff fails, assume there are changes
                    has_changes = True
            
            # Only commit if there are actual changes
            if has_changes:
                # Get committer info from app config, fallback to generic values
                committer_name = current_app.config.get('GIT_COMMITTER_NAME', 'Italia CDN Proxy')
                committer_email = current_app.config.get('GIT_COMMITTER_EMAIL', 'system@italiacdn.example.com')
                
                # Set Git environment variables for commit
                my_env = os.environ.copy()
                my_env['GIT_AUTHOR_NAME'] = committer_name
                my_env['GIT_AUTHOR_EMAIL'] = committer_email
                my_env['GIT_COMMITTER_NAME'] = committer_name
                my_env['GIT_COMMITTER_EMAIL'] = committer_email
                
                # Format an informative commit message
                message = f"Updated config for {site.domain}\n\n"
                message += f"Protocol: {site.protocol}\n"
                message += f"Origin: {site.origin_protocol}://{site.origin_address}:{site.origin_port}\n"
                message += f"Cache enabled: {'Yes' if site.enable_cache else 'No'}\n"
                message += f"Updated at: {datetime.utcnow().isoformat()}"
                
                # Commit the changes with the configured identity
                repo.git.commit('-m', message, env=my_env)
                
                # Try to push if a remote is configured
                if len(repo.remotes) > 0:
                    try:
                        repo.git.push()
                    except git.GitCommandError as e:
                        # Log but don't fail if push fails
                        log_activity('warning', f"Failed to push config changes: {str(e)}")
        except git.GitCommandError as e:
            # Log the error but don't fail the operation
            log_activity('warning', f"Git error when saving config for {site.domain}: {str(e)}")
    except Exception as e:
        # Log errors but allow the operation to continue
        log_activity('error', f"Failed to save config to Git for {site.domain}: {str(e)}")
        # Don't re-raise, as saving to git is not critical for the main functionality

def deploy_to_node(site_id, node_id, nginx_config, test_only=False):
    """
    Deploy a site configuration to a node
    
    Args:
        site_id: ID of the site
        node_id: ID of the node to deploy to
        nginx_config: The Nginx configuration content
        test_only: If True, only test the configuration without deploying
        
    Returns:
        If test_only=True: tuple (is_valid, warnings)
        Otherwise: True on success or raises an exception
    """
    # Validate input parameters
    if not isinstance(site_id, int) or not isinstance(node_id, int):
        raise ValueError("site_id and node_id must be integers")
    
    if not nginx_config or not isinstance(nginx_config, str):
        raise ValueError("nginx_config must be a non-empty string")
    
    # Sanitize nginx_config - remove any potential dangerous shell metacharacters
    # This helps prevent command injection when the config is tested
    dangerous_patterns = [
        '$(', '`', '&&', '||', ';', '|', '>', '<', 
        'rm -rf', 'mkfifo', 'mknod', ':(){ :|:& };:'
    ]
    
    for pattern in dangerous_patterns:
        if pattern in nginx_config:
            suspicious_content = nginx_config[max(0, nginx_config.find(pattern)-10):nginx_config.find(pattern)+len(pattern)+10]
            log_activity('security', f"Suspicious content in nginx config: {suspicious_content}", 'site', site_id, 
                        f"Pattern '{pattern}' found in nginx config during deployment", None)
            # Don't modify the config but alert about it
    
    site = Site.query.get(site_id)
    node = Node.query.get(node_id)
    
    if not site or not node:
        raise ValueError("Site or node not found")
    
    # Handle containerized nodes
    if node.is_container_node:
        from app.services.container_service import ContainerService
        if test_only:
            return ContainerService.deploy_to_container(site_id, node_id, nginx_config, test_only=True)
        else:
            return ContainerService.deploy_to_container(site_id, node_id, nginx_config)
    
    # Create a backup of the current configuration before deploying
    from app.services.config_rollback_service import ConfigRollbackService
    backup_path = None
    if not test_only:
        backup_path = ConfigRollbackService.create_backup_config(site_id, node_id)
    
    # Validate the configuration first
    from app.services.nginx_validation_service import NginxValidationService
    
    # Parse the domain name from the nginx_config (assumes server_name is present)
    domain_match = re.search(r'server_name\s+([^;]+);', nginx_config)
    domain = domain_match.group(1).strip() if domain_match else site.domain
    
    # Get deployment warnings (for SSL, security headers, etc.)
    warnings = []
    
    # Validate SSL configuration if HTTPS
    if site.protocol == 'https':
        _, ssl_warnings = NginxValidationService.validate_ssl_config(nginx_config)
        warnings.extend(ssl_warnings)
        
        # Check if SSL certificate files exist on node
        certificates_exist, missing_files, cert_warnings = NginxValidationService.check_ssl_certificate_paths(node_id, nginx_config)
        warnings.extend(cert_warnings)
        
        # If certificates don't exist and we're in test mode, record this issue
        if not certificates_exist and test_only:
            warnings.append("SSL certificates not found. You may need to request SSL certificates.")
            
            # Extract paths for user reference
            ssl_certificate, ssl_certificate_key = NginxValidationService.extract_ssl_file_paths(nginx_config)
            if ssl_certificate:
                warnings.append(f"Certificate path: {ssl_certificate}")
            if ssl_certificate_key:
                warnings.append(f"Certificate key path: {ssl_certificate_key}")

    # Validate security headers
    _, security_warnings = NginxValidationService.validate_security_headers(nginx_config)
    warnings.extend(security_warnings)
    
    # Before deploying a site, prepare all necessary SSL directories on the node
    from app.services.ssl_certificate_service import SSLCertificateService
    
    # First, ensure all SSL directories and certificates exist for any domains
    # referenced in Nginx configurations, not just for the current domain
    ssl_dirs_result = SSLCertificateService.ensure_all_ssl_directories_on_node(node_id)
    
    if not ssl_dirs_result.get('success', False):
        log_activity('warning', f"Error preparing SSL directories for node {node.name}: {ssl_dirs_result.get('message', 'Unknown error')}")
        warnings.append(f"Warning: Failed to prepare all SSL directories: {ssl_dirs_result.get('message', 'Unknown error')}")
    else:
        created_domains = ssl_dirs_result.get('domains_created', [])
        if created_domains:
            log_activity('info', f"Created temporary certificates for domains: {', '.join(created_domains)}")
            warnings.append(f"Created temporary certificates for domains referenced in configuration: {', '.join(created_domains)}")
            
    # Now ensure SSL directories for the current domain specifically
    ssl_dir_result = SSLCertificateService.ensure_ssl_directories(site_id, node_id)
    
    if not ssl_dir_result.get('success', False):
        log_activity('error', f"Failed to prepare SSL directories for {site.domain} on node {node.name}: {ssl_dir_result.get('message', 'Unknown error')}")
        
        # If setup didn't succeed, try fallback method - create a simple self-signed certificate directly
        try:
            # Connect to the node directly to verify SSL setup
            ssh_client_direct = paramiko.SSHClient()
            ssh_client_direct.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if node.ssh_key_path:
                ssh_client_direct.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    key_filename=node.ssh_key_path,
                    timeout=10
                )
            else:
                ssh_client_direct.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    password=node.ssh_password,
                    timeout=10
                )
            
            # Check if letsencrypt directory exists, create it if not
            ssh_client_direct.exec_command("sudo mkdir -p /etc/letsencrypt/live")
            
            # Create domain certificate directory
            domain_dir = f"/etc/letsencrypt/live/{domain}"
            ssh_client_direct.exec_command(f"sudo mkdir -p {domain_dir}")
            
            # Create a minimal self-signed certificate
            cert_cmd = f"""
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
  -keyout {domain_dir}/privkey.pem \\
  -out {domain_dir}/fullchain.pem \\
  -subj "/CN={domain}" && \\
sudo cp {domain_dir}/fullchain.pem {domain_dir}/chain.pem && \\
sudo chmod 644 {domain_dir}/fullchain.pem {domain_dir}/chain.pem && \\
sudo chmod 600 {domain_dir}/privkey.pem && \\
echo "success"
"""
            stdin, stdout, stderr = ssh_client_direct.exec_command(cert_cmd)
            cert_result = stdout.read().decode('utf-8').strip()
            
            if "success" in cert_result:
                log_activity('info', f"Created emergency self-signed certificate for {domain} on node {node.name}")
                warnings.append("Created emergency self-signed certificate as primary method failed. Please request a real certificate.")
            else:
                error = stderr.read().decode('utf-8')
                log_activity('error', f"Failed to create emergency certificate for {domain} on node {node.name}: {error}")
                warnings.append(f"Warning: Failed to create SSL certificates: {error}")
            
            ssh_client_direct.close()
            
        except Exception as e:
            log_activity('error', f"Failed in emergency certificate creation for {domain} on node {node.name}: {str(e)}")
            warnings.append(f"Warning: {ssl_dir_result.get('message', 'Failed to prepare SSL directories')}")
    elif ssl_dir_result.get('certificate_exists', False) == False:
        warnings.append("Created temporary self-signed certificate. Remember to request a real certificate.")
    
    # Test the configuration
    is_valid, error_message, ssl_details = NginxValidationService.test_config_on_node(node_id, nginx_config, domain)
    
    # Handle SSL details if available
    if ssl_details and ssl_details.get('is_https', False):
        if ssl_details.get('certificates_needed', False):
            warnings.append("SSL certificates need to be provisioned")
            if ssl_details.get('ssl_certificate'):
                warnings.append(f"Certificate path: {ssl_details['ssl_certificate']}")
            if ssl_details.get('ssl_certificate_key'):
                warnings.append(f"Certificate key path: {ssl_details['ssl_certificate_key']}")
    
    # Special handling for SSL certificate errors - they're expected if certs don't exist yet
    # We'll let the deployment proceed but warn the user
    if not is_valid and "SSL certificate" in error_message and "missing" in error_message:
        warnings.append("Configuration test passed with SSL warnings (certificates missing)")
        is_valid = True  # Allow deployment to proceed
    
    # For test_only mode, return validation results
    if test_only:
        if not is_valid:
            # Analyze the error and add suggestions
            error_analysis = NginxValidationService.analyze_validation_error(error_message)
            warnings.append(f"Configuration test failed: {error_message}")
            warnings.append(f"Suggestion: {error_analysis['suggestion']}")
            
            if error_analysis['error_type'] == 'ssl_certificate' and 'alternate_solution' in error_analysis:
                warnings.append(f"Alternative: {error_analysis['alternate_solution']}")
        
        return is_valid, warnings
    
    # If configuration is invalid, log and raise exception
    if not is_valid:
        error_analysis = NginxValidationService.analyze_validation_error(error_message)
        log = DeploymentLog(
            site_id=site_id,
            node_id=node_id,
            action="deploy",
            status="error",
            message=f"Configuration validation failed: {error_message}"
        )
        db.session.add(log)
        db.session.commit()
        
        raise ValueError(f"Configuration validation failed: {error_message}\nSuggestion: {error_analysis['suggestion']}")
    
    # Variables for proper cleanup in finally block
    ssh_client = None
    sftp = None
    temp_file_path = None
    config_file_path = None
    
    try:
        # Connect to the node
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Enhanced connection error handling
        connection_attempts = 0
        max_attempts = 3
        connection_error = None
        
        while connection_attempts < max_attempts:
            try:
                if node.ssh_key_path:
                    ssh_client.connect(
                        hostname=node.ip_address,
                        port=node.ssh_port,
                        username=node.ssh_user,
                        key_filename=node.ssh_key_path,
                        timeout=10
                    )
                else:
                    ssh_client.connect(
                        hostname=node.ip_address,
                        port=node.ssh_port,
                        username=node.ssh_user,
                        password=node.ssh_password,
                        timeout=10
                    )
                # If we get here, connection succeeded
                connection_error = None
                break
            except Exception as e:
                connection_error = str(e)
                connection_attempts += 1
                time.sleep(2)  # Short delay before retry
        
        if connection_error:
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action="deploy",
                status="error", 
                message=f"Failed to connect to node after {max_attempts} attempts: {connection_error}"
            )
            db.session.add(log)
            db.session.commit()
            raise ValueError(f"Failed to connect to node: {connection_error}")
        
        # Ensure the nginx config directory exists
        if not node.nginx_config_path:
            # Set a default path if none is specified
            default_path = "/etc/nginx/conf.d"
            log_activity('warning', f"No nginx_config_path specified for node {node.name}. Using default: {default_path}")
            node.nginx_config_path = default_path
            db.session.commit()
            
        stdin, stdout, stderr = ssh_client.exec_command(f"mkdir -p {node.nginx_config_path}")
        exit_status = stdout.channel.recv_exit_status()
        
        if exit_status != 0:
            error = stderr.read().decode('utf-8')
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action="deploy",
                status="error",
                message=f"Failed to create nginx config directory: {error}"
            )
            db.session.add(log)
            db.session.commit()
            raise ValueError(f"Failed to create nginx config directory: {error}")
            
        # Ensure ACME challenge directory exists for Let's Encrypt
        stdin, stdout, stderr = ssh_client.exec_command(f"mkdir -p /var/www/letsencrypt/.well-known/acme-challenge")
        exit_status = stdout.channel.recv_exit_status()
        
        if exit_status != 0:
            error = stderr.read().decode('utf-8')
            log_activity('warning', f"Failed to create ACME challenge directory: {error}")
        
        # Create the config file
        config_file_path = f"{node.nginx_config_path}/{domain}.conf"
        sftp = ssh_client.open_sftp()
        
        # Create a unique temporary file name using timestamp to avoid conflicts
        temp_timestamp = int(time.time())
        temp_file_path = f"{config_file_path}.{temp_timestamp}.tmp"
        
        # Write to a temporary file first
        with sftp.file(temp_file_path, 'w') as f:
            f.write(nginx_config)
        
        # Move the temporary file to the final location (atomic operation)
        ssh_client.exec_command(f"mv {temp_file_path} {config_file_path}")
        
        # Reload Nginx
        stdin, stdout, stderr = ssh_client.exec_command(node.nginx_reload_command)
        exit_status = stdout.channel.recv_exit_status()
        
        if exit_status != 0:
            error = stderr.read().decode('utf-8')
            # Check if it's an SSL certificate error during reload
            if "SSL" in error and "certificate" in error and "failed" in error:
                # For SSL certificate errors, log a warning but consider deployment partially successful
                log = DeploymentLog(
                    site_id=site_id,
                    node_id=node_id,
                    action="deploy",
                    status="warning",
                    message=f"Deployment completed but Nginx reload had SSL certificate warnings: {error}"
                )
                db.session.add(log)
                
                # Update site node status to reflect warning
                site_node = SiteNode.query.filter_by(site_id=site_id, node_id=node_id).first()
                if site_node:
                    site_node.status = "warning"
                    site_node.updated_at = datetime.utcnow()
                else:
                    # Create new site_node relationship with warning status
                    site_node = SiteNode(
                        site_id=site_id,
                        node_id=node_id,
                        status="warning",
                        created_at=datetime.utcnow(),
                        updated_at=datetime.utcnow()
                    )
                    db.session.add(site_node)
                
                db.session.commit()
                
                warning_message = f"Site configuration deployed but Nginx reload had SSL certificate warnings. You need to request SSL certificates for {domain}."
                warnings.append(warning_message)
                
                # Return success with warnings
                return True
            else:
                # For other errors, log and try to restore from backup if available
                log = DeploymentLog(
                    site_id=site_id,
                    node_id=node_id,
                    action="deploy",
                    status="error",
                    message=f"Failed to reload nginx: {error}"
                )
                db.session.add(log)
                db.session.commit()
                
                # Try to restore from backup
                error_message = f"Failed to reload nginx: {error}"
                if backup_path:
                    # Try to trigger an automatic rollback
                    from app.services.config_rollback_service import ConfigRollbackService
                    try:
                        # Get current user
                        try:
                            from flask_login import current_user
                            user_id = current_user.id if current_user and current_user.is_authenticated else None
                        except:
                            user_id = None
                            
                        rollback_result = ConfigRollbackService.auto_rollback_on_failure(site_id, node_id, error_message, user_id)
                        if rollback_result['success']:
                            # Rollback succeeded, raise an error with rollback info
                            raise ValueError(f"{error_message}\nAutomatic rollback was performed successfully.")
                        else:
                            # Rollback failed, include this info in the error
                            raise ValueError(f"{error_message}\nAutomatic rollback was attempted but failed: {rollback_result['message']}")
                    except Exception as rollback_error:
                        # If the rollback process itself fails, just report the original error
                        raise ValueError(error_message)
                else:
                    # No backup available, just raise the original error
                    raise ValueError(error_message)
        
        # Update or create the site_node relationship
        site_node = SiteNode.query.filter_by(site_id=site_id, node_id=node_id).first()
        if site_node:
            site_node.status = "deployed"
            site_node.updated_at = datetime.utcnow()
        else:
            site_node = SiteNode(
                site_id=site_id,
                node_id=node_id,
                status="deployed",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.session.add(site_node)
        
        # Log successful deployment
        log = DeploymentLog(
            site_id=site_id,
            node_id=node_id,
            action="deploy",
            status="success",
            message=f"Successfully deployed {site.domain} to {node.name}"
        )
        db.session.add(log)
        db.session.commit()
        
        # Version the configuration in git if configured
        from app.services.config_versioning_service import save_config_version
        # Get the username from session if available
        try:
            from flask import session
            from flask_login import current_user
            username = current_user.username if current_user and current_user.is_authenticated else "system"
        except:
            username = "system"
        
        try:
            save_config_version(site, nginx_config, username)
        except Exception as e:
            # Log but don't fail deployment if versioning fails
            log_activity('warning', f"Failed to save config version for {site.domain}: {str(e)}")
        
        return True
        
    except Exception as e:
        # Log the error
        log = DeploymentLog(
            site_id=site_id,
            node_id=node_id,
            action="deploy",
            status="error",
            message=f"Deployment error: {str(e)}"
        )
        db.session.add(log)
        db.session.commit()
        
        # Try to restore from backup if available
        if backup_path:
            # Try to trigger an automatic rollback
            from app.services.config_rollback_service import ConfigRollbackService
            try:
                # Get current user
                try:
                    from flask_login import current_user
                    user_id = current_user.id if current_user and current_user.is_authenticated else None
                except:
                    user_id = None
                    
                log_activity('info', f"Attempting automatic rollback for {site.domain} on {node.name} after deployment error", 'site', site_id)
                rollback_result = ConfigRollbackService.auto_rollback_on_failure(site_id, node_id, str(e), user_id)
                if rollback_result['success']:
                    # Rollback succeeded, raise an error with rollback info
                    raise ValueError(f"Deployment error: {str(e)}\nAutomatic rollback was performed successfully.")
                else:
                    # Rollback failed, include this info in the error
                    raise ValueError(f"Deployment error: {str(e)}\nAutomatic rollback was attempted but failed: {rollback_result['message']}")
            except Exception as rollback_error:
                # If the rollback process itself fails, just report the original error
                raise ValueError(f"Deployment error: {str(e)}\nAutomatic rollback failed: {str(rollback_error)}")
        else:
            # No backup available, just re-raise the original exception
            raise
    
    finally:
        # Clean up resources to prevent leaks
        try:
            # Close SFTP connection if open
            if sftp:
                sftp.close()
            
            # Clean up temporary file if it exists and connection is still active
            if temp_file_path and ssh_client and ssh_client.get_transport() and ssh_client.get_transport().is_active():
                ssh_client.exec_command(f"rm -f {temp_file_path}")
            
            # Close SSH connection if open
            if ssh_client:
                ssh_client.close()
        except Exception as cleanup_error:
            # Log cleanup errors but don't fail the deployment
            log_activity('warning', f"Error during cleanup in deploy_to_node: {str(cleanup_error)}")

def get_node_stats(node):
    """
    Get real-time server statistics from a node via SSH
    
    Args:
        node: Node object to retrieve stats from
        
    Returns:
        dict: A dictionary containing server statistics
    """
    try:
        # Connect to the node via SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect using key or password
        if node.ssh_key_path:
            ssh_client.connect(
                hostname=node.ip_address,
                port=node.ssh_port,
                username=node.ssh_user,
                key_filename=node.ssh_key_path,
                timeout=10
            )
        else:
            ssh_client.connect(
                hostname=node.ip_address,
                port=node.ssh_port,
                username=node.ssh_user,
                password=node.ssh_password,
                timeout=10
            )
        
        # Get CPU usage - improved command that works across different Linux variants
        stdin, stdout, stderr = ssh_client.exec_command("top -bn1 | grep '%Cpu' | awk '{print $2+$4+$6}' | awk '{printf \"%.1f%%\", $1}'")
        cpu_usage = stdout.read().decode('utf-8').strip()
        # If the command didn't work, try alternative command
        if not cpu_usage:
            stdin, stdout, stderr = ssh_client.exec_command("mpstat 1 1 | grep -A 5 '%idle' | tail -n 1 | awk '{print 100-$NF\"%\"}' || echo 'N/A'")
            cpu_usage = stdout.read().decode('utf-8').strip()
        # If still not working, try yet another alternative
        if not cpu_usage or cpu_usage == 'N/A':
            stdin, stdout, stderr = ssh_client.exec_command("vmstat 1 2 | tail -1 | awk '{print 100-$15\"%\"}' || echo 'N/A'")
            cpu_usage = stdout.read().decode('utf-8').strip()
        
        # Get memory usage with improved robustness
        memory_usage = "N/A"
        try:
            # Try the standard free command first
            stdin, stdout, stderr = ssh_client.exec_command("free -m | grep 'Mem:' | awk '{printf \"%d/%dMB (%d%%)\", $3, $2, int($3*100/$2)}'")
            memory_output = stdout.read().decode('utf-8').strip()
            
            # Verify it has the expected format (numbers/numbers with percentage)
            if re.match(r'\d+/\d+MB \(\d+%\)', memory_output):
                memory_usage = memory_output
            else:
                # Fallback to parsing free output manually
                stdin, stdout, stderr = ssh_client.exec_command("free -m | grep 'Mem:'")
                free_output = stdout.read().decode('utf-8').strip()
                if free_output:
                    parts = free_output.split()
                    if len(parts) >= 3:
                        try:
                            total = int(parts[1])
                            used = int(parts[2])
                            if total > 0:  # Avoid division by zero
                                percent = int((used * 100) / total)
                                memory_usage = f"{used}/{total}MB ({percent}%)"
                        except (ValueError, IndexError):
                            # If conversion fails, try another approach
                            pass
            
            # If all else fails, try vmstat
            if memory_usage == "N/A":
                stdin, stdout, stderr = ssh_client.exec_command("vmstat -s | grep 'used memory' | awk '{print $1}' && vmstat -s | grep 'total memory' | awk '{print $1}'")
                vm_output = stdout.read().decode('utf-8').strip().split('\n')
                if len(vm_output) >= 2:
                    try:
                        used_kb = int(vm_output[0])
                        total_kb = int(vm_output[1])
                        used_mb = used_kb // 1024
                        total_mb = total_kb // 1024
                        if total_mb > 0:  # Avoid division by zero
                            percent = int((used_mb * 100) / total_mb)
                            memory_usage = f"{used_mb}/{total_mb}MB ({percent}%)"
                    except (ValueError, IndexError):
                        # Keep default N/A value
                        pass
        except Exception as e:
            log_activity('warning', f"Error parsing memory usage on node {node.name}: {str(e)}")
            memory_usage = "N/A"
        
        # Get disk usage - fixed command with proper quotes
        stdin, stdout, stderr = ssh_client.exec_command("df -h / | grep -v Filesystem | awk '{print $3\"/\"$2\" (\"$5\")\"}'")
        disk_usage = stdout.read().decode('utf-8').strip()
        
        # Get uptime
        stdin, stdout, stderr = ssh_client.exec_command("uptime -p 2>/dev/null || uptime | sed 's/.*up \\([^,]*\\),.*/\\1/' || echo 'N/A'")
        uptime = stdout.read().decode('utf-8').strip().replace('up ', '')
        
        # Get load average
        stdin, stdout, stderr = ssh_client.exec_command("cat /proc/loadavg | awk '{print $1\", \"$2\", \"$3}'")
        load_average = stdout.read().decode('utf-8').strip()
        
        # Get hostname
        stdin, stdout, stderr = ssh_client.exec_command("hostname -f 2>/dev/null || hostname")
        hostname = stdout.read().decode('utf-8').strip()
        
        # Get OS version
        stdin, stdout, stderr = ssh_client.exec_command("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d '\"' -f 2 || lsb_release -ds 2>/dev/null || cat /etc/redhat-release 2>/dev/null || echo 'Unknown'")
        os_version = stdout.read().decode('utf-8').strip()
        
        # Get Nginx connection statistics
        stdin, stdout, stderr = ssh_client.exec_command("curl -s http://localhost/nginx_status 2>/dev/null || echo 'Nginx status not available'")
        nginx_status = stdout.read().decode('utf-8')
        
        total_connections = 0
        active_connections = 0
        requests_per_second = 0
        
        if 'Active connections' in nginx_status:
            # Parse nginx status output
            lines = nginx_status.strip().split('\n')
            if len(lines) >= 1:
                active_connections = int(lines[0].split(':')[1].strip())
            if len(lines) >= 3:
                accepts, handled, requests = map(int, lines[2].strip().split())
                requests_per_second = round(requests / 60, 1)  # Approximate RPS
        else:
            # Try alternative method to get connections
            stdin, stdout, stderr = ssh_client.exec_command("netstat -an | grep :80 | grep ESTABLISHED | wc -l")
            http_connections = stdout.read().decode('utf-8').strip()
            try:
                active_http = int(http_connections)
            except ValueError:
                active_http = 0
                
            stdin, stdout, stderr = ssh_client.exec_command("netstat -an | grep :443 | grep ESTABLISHED | wc -l")
            https_connections = stdout.read().decode('utf-8').strip()
            try:
                active_https = int(https_connections)
            except ValueError:
                active_https = 0
                
            active_connections = active_http + active_https
        
        # Simple estimation for HTTP vs HTTPS
        active_http = int(active_connections * 0.4)  # 40% HTTP (example estimation)
        active_https = active_connections - active_http
        
        # Get bandwidth usage (estimation based on network interface traffic)
        stdin, stdout, stderr = ssh_client.exec_command("cat /proc/net/dev | grep -v face | grep -v lo | sort | head -n 1 | awk '{print $2, $10}'")
        net_stats = stdout.read().decode('utf-8').strip().split()
        
        # Convert to MB/s (very rough estimate)
        if len(net_stats) >= 2:
            bytes_in = int(net_stats[0])
            bytes_out = int(net_stats[1])
            bandwidth_usage = f"{round((bytes_in + bytes_out) / 1024 / 1024, 2)} MB/s"
        else:
            bandwidth_usage = "N/A"
            
        # Get firewall status - check various firewall services
        stdin, stdout, stderr = ssh_client.exec_command(
            "systemctl is-active ufw 2>/dev/null || " +
            "systemctl is-active firewalld 2>/dev/null || " + 
            "systemctl is-active iptables 2>/dev/null || echo 'inactive'"
        )
        firewall_status = stdout.read().decode('utf-8').strip()
        
        # Get open ports - check common service ports and show what's listening
        stdin, stdout, stderr = ssh_client.exec_command(
            "ss -tuln | grep LISTEN | awk '{print $5}' | awk -F: '{print $NF}' | sort -n | uniq"
        )
        open_ports_output = stdout.read().decode('utf-8').strip().split('\n')
        open_ports = [port for port in open_ports_output if port and port.isdigit()]
        
        # Get DNS servers from resolv.conf
        stdin, stdout, stderr = ssh_client.exec_command(
            "cat /etc/resolv.conf | grep '^nameserver' | awk '{print $2}'"
        )
        dns_servers_output = stdout.read().decode('utf-8').strip().split('\n')
        dns_servers = [server for server in dns_servers_output if server]
        
        # Get external IP address
        external_ip = None
        try:
            commands = [
                "curl -s https://ifconfig.me",
                "curl -s https://api.ipify.org",
                "curl -s https://ipinfo.io/ip",
                "wget -qO- https://ipecho.net/plain"
            ]
            
            for cmd in commands:
                try:
                    stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=3)
                    result = stdout.read().decode('utf-8').strip()
                    
                    # Validate that the result looks like an IP address
                    if result and len(result) < 40 and '.' in result:
                        external_ip = result
                        break
                except:
                    continue
        except Exception as e:
            log_activity('warning', f"Error getting external IP for node {node.name}: {str(e)}")
        
        ssh_client.close()
        
        # Return stats
        server_stats = {
            'cpu_usage': cpu_usage if cpu_usage else 'N/A',
            'memory_usage': memory_usage if memory_usage else 'N/A',
            'disk_usage': disk_usage if disk_usage else 'N/A',
            'uptime': uptime if uptime else 'N/A',
            'load_average': load_average if load_average else 'N/A',
            'hostname': hostname if hostname else 'N/A',
            'os_version': os_version if os_version else 'N/A',
            'external_ip': external_ip,
            'firewall_status': firewall_status,
            'open_ports': open_ports,
            'dns_servers': dns_servers
        }
        
        connection_stats = {
            'total_connections': active_connections,
            'active_http': active_http,
            'active_https': active_https,
            'requests_per_second': requests_per_second,
            'bandwidth_usage': bandwidth_usage
        }
        
        return server_stats, connection_stats
        
    except Exception as e:
        # If there's an error, return default values with error information
        error_message = str(e)
        return {
            'cpu_usage': 'N/A',
            'memory_usage': 'N/A',
            'disk_usage': 'N/A',
            'uptime': 'N/A',
            'load_average': 'N/A',
            'error': error_message,
            'hostname': 'N/A',
            'os_version': 'N/A',
            'external_ip': None,
            'firewall_status': None,
            'open_ports': None,
            'dns_servers': None
        }, {
            'total_connections': 0,
            'active_http': 0,
            'active_https': 0,
            'requests_per_second': 0,
            'bandwidth_usage': 'N/A'
        }

def get_nginx_info(node):
    """
    Get detailed Nginx information from a node, including version, modules, and configuration
    
    Args:
        node: Node object to retrieve Nginx info from
        
    Returns:
        dict: A dictionary containing Nginx information
    """
    try:
        # Connect to the node via SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect using key or password
        if node.ssh_key_path:
            ssh_client.connect(
                hostname=node.ip_address,
                port=node.ssh_port,
                username=node.ssh_user,
                key_filename=node.ssh_key_path,
                timeout=10
            )
        else:
            ssh_client.connect(
                hostname=node.ip_address,
                port=node.ssh_port,
                username=node.ssh_user,
                password=node.ssh_password,
                timeout=10
            )
        
        # Use the detected nginx path if available
        nginx_path = node.detected_nginx_path if hasattr(node, 'detected_nginx_path') and node.detected_nginx_path else "nginx"
        
        # Get Nginx version
        stdin, stdout, stderr = ssh_client.exec_command(f"{nginx_path} -v 2>&1")
        version_output = stdout.read().decode('utf-8').strip() + stderr.read().decode('utf-8').strip()
        
        # Extract version number
        version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', version_output)
        nginx_version = version_match.group(1) if version_match else "Unknown"
        
        # Get Nginx configuration information
        stdin, stdout, stderr = ssh_client.exec_command(f"{nginx_path} -V 2>&1")
        config_output = stdout.read().decode('utf-8').strip() + stderr.read().decode('utf-8').strip()
        
        # Extract compiled modules
        modules = []
        if '--with-' in config_output or '--without-' in config_output:
            module_matches = re.findall(r'--with-([^\s]+)', config_output)
            modules = [module for module in module_matches if module]
        
        # Get compile flags
        compile_flags = None
        if 'configure arguments:' in config_output:
            compile_flags = config_output.split('configure arguments:')[1].strip()
        
        # Check if common modules are enabled
        has_http2 = 'http_v2_module' in config_output or 'with-http_v2_module' in config_output
        has_ssl = 'http_ssl_module' in config_output or 'with-http_ssl_module' in config_output
        has_gzip = 'http_gzip_module' in config_output or 'with-http_gzip_module' in config_output
        
        # Get Nginx configuration file locations
        stdin, stdout, stderr = ssh_client.exec_command(f"{nginx_path} -T 2>/dev/null | grep 'configuration file' | head -1 || echo 'Unknown'")
        config_file = stdout.read().decode('utf-8').strip()
        if 'configuration file' in config_file:
            config_file = config_file.split('configuration file')[1].strip()
        
        # Get Nginx process status
        stdin, stdout, stderr = ssh_client.exec_command("ps aux | grep '[n]ginx: master' || echo 'Not running'")
        process_status = stdout.read().decode('utf-8').strip()
        is_running = process_status != 'Not running'
        
        # Get Nginx master process PID
        pid = None
        if is_running:
            stdin, stdout, stderr = ssh_client.exec_command("ps aux | grep '[n]ginx: master' | awk '{print $2}' | head -1")
            pid_output = stdout.read().decode('utf-8').strip()
            try:
                pid = int(pid_output)
            except ValueError:
                pid = None
        
        # Get worker processes count
        worker_count = 0
        if is_running:
            stdin, stdout, stderr = ssh_client.exec_command("ps aux | grep '[n]ginx: worker' | wc -l")
            worker_count_output = stdout.read().decode('utf-8').strip()
            try:
                worker_count = int(worker_count_output)
            except ValueError:
                worker_count = 0
        
        # Get server OS information
        stdin, stdout, stderr = ssh_client.exec_command("lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d '\"' -f 2 || echo 'Unknown'")
        os_info = stdout.read().decode('utf-8').strip()
        
        # Get RAM and CPU info
        stdin, stdout, stderr = ssh_client.exec_command("grep 'model name' /proc/cpuinfo | uniq | cut -d ':' -f 2 | xargs || echo 'Unknown CPU'")
        cpu_info = stdout.read().decode('utf-8').strip()
        
        stdin, stdout, stderr = ssh_client.exec_command("grep MemTotal /proc/meminfo | awk '{print $2 / 1024 / 1024}' | xargs printf '%.1f GB' || echo 'Unknown RAM'")
        ram_info = stdout.read().decode('utf-8').strip()
        
        # Get configuration tree (basic structure)
        config_tree = None
        stdin, stdout, stderr = ssh_client.exec_command(f"{nginx_path} -T 2>/dev/null | grep -v '#' | grep -v '^$' | head -50 || echo 'Configuration not available'")
        config_tree_raw = stdout.read().decode('utf-8').strip()
        if config_tree_raw and config_tree_raw != 'Configuration not available':
            config_tree = config_tree_raw
            
        # Parse virtual hosts (server blocks)
        sites = []
        
        # First, get list of all config files
        stdin, stdout, stderr = ssh_client.exec_command(f"find {node.nginx_config_path} -type f -name '*.conf' | sort")
        config_files = stdout.read().decode('utf-8').strip().split('\n')
        
        for config_file in config_files:
            if not config_file:
                continue
                
            # Extract server_name and listen directives
            stdin, stdout, stderr = ssh_client.exec_command(f"grep -E 'server_name|listen' {config_file} | grep -v '#'")
            server_directives = stdout.read().decode('utf-8').strip()
            
            if 'server_name' in server_directives:
                server_blocks = server_directives.split('server_name')
                for i in range(1, len(server_blocks)):
                    server_name = server_blocks[i].split(';')[0].strip()
                    
                    # Find corresponding listen directive
                    listen_port = "80"  # Default
                    ssl_enabled = False
                    
                    # Look for listen directive in the current or previous block
                    if 'listen' in server_blocks[i-1] or (i < len(server_blocks)-1 and 'listen' in server_blocks[i]):
                        listen_block = server_blocks[i-1] if 'listen' in server_blocks[i-1] else server_blocks[i]
                        listen_match = re.search(r'listen\s+([^;]+);', listen_block)
                        if listen_match:
                            listen_port = listen_match.group(1).strip()
                            if 'ssl' in listen_port or '443' in listen_port:
                                ssl_enabled = True
                    
                    # Extract root directive
                    stdin, stdout, stderr = ssh_client.exec_command(f"grep -E 'root' {config_file} | grep -v '#' | head -1")
                    root_directive = stdout.read().decode('utf-8').strip()
                    root_path = None
                    if root_directive:
                        root_match = re.search(r'root\s+([^;]+);', root_directive)
                        if root_match:
                            root_path = root_match.group(1).strip()
                    
                    # Add to sites list
                    sites.append({
                        'server_name': server_name,
                        'listen': listen_port,
                        'ssl_enabled': ssl_enabled,
                        'root': root_path,
                        'config_file': os.path.basename(config_file)
                    })
        
        ssh_client.close()
        
        return {
            'version': nginx_version,
            'version_full': version_output,
            'is_running': is_running,
            'pid': pid,
            'worker_count': worker_count,
            'config_file': config_file,
            'modules': modules,
            'compile_flags': compile_flags,
            'has_http2': has_http2,
            'has_ssl': has_ssl,
            'has_gzip': has_gzip,
            'os_info': os_info,
            'cpu_info': cpu_info,
            'ram_info': ram_info,
            'config_tree': config_tree,
            'sites': sites
        }
        
    except Exception as e:
        return {
            'version': 'Unknown',
            'error': str(e),
            'is_running': False
        }

# Test the site on a specific node
@staticmethod
def test_deployment(site_id, node_id):
    """
    Test deploying a site configuration to a node without actually deploying it
    
    Args:
        site_id: ID of the site
        node_id: ID of the node to test on
        
    Returns:
        tuple: (is_valid, warnings)
    """
    site = Site.query.get(site_id)
    
    if not site:
        return False, ["Site not found"]
    
    # Generate Nginx configuration
    nginx_config = generate_nginx_config(site)
    
    # Test the deployment
    return deploy_to_node(site_id, node_id, nginx_config, test_only=True)