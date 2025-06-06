import os
import re
import tempfile
from datetime import datetime

from app.services.proxy_service_base import ProxyServiceBase
from app.models.models import db, Node, Site, SiteNode, DeploymentLog, SystemLog
from app.services.ssh_connection_service import SSHConnectionService
from app.services.logger_service import log_activity

class CaddyService(ProxyServiceBase):
    """Concrete implementation of ProxyServiceBase for Caddy"""
    
    def generate_config(self, site):
        """
        Generate Caddy configuration for a site
        
        Args:
            site: Site object containing configuration details
            
        Returns:
            str: Caddy configuration file content
        """
        # Define Caddy configuration
        config = []
        
        # Add basic site configuration
        config.append(f"{site.domain} {{")
        
        # Add TLS configuration if HTTPS
        if site.protocol == 'https':
            config.append("    tls {")
            config.append("        protocols tls1.2 tls1.3")
            config.append("    }")
        
        # Add reverse proxy configuration
        config.append(f"    reverse_proxy {site.origin_protocol}://{site.origin_address}:{site.origin_port} {{")
        
        # Add headers
        config.append("        header_up Host {host}")
        config.append("        header_up X-Real-IP {remote}")
        config.append("        header_up X-Forwarded-For {remote}")
        config.append("        header_up X-Forwarded-Proto {scheme}")
        
        # Handle Health Checks
        config.append("        health_timeout 5s")
        
        # Close reverse_proxy block
        config.append("    }")
        
        # Handle caching if enabled
        if site.enable_cache:
            config.append(f"    cache {{")
            config.append(f"        ttl {site.cache_time}s")
            
            # Add static file extensions
            config.append("        match_path *.css *.js *.jpg *.jpeg *.png *.gif *.ico *.svg *.woff *.woff2")
            
            # Close cache block
            config.append("    }")
        
        # Handle GeoIP filtering if enabled
        if site.use_geoip and site.geoip_countries:
            countries = site.geoip_countries.replace(' ', '').split(',')
            
            if site.geoip_mode == 'blacklist':
                # Blacklist specific countries
                country_list = ', '.join([f'"{c.strip().upper()}"' for c in countries])
                config.append(f"    @blocked_countries {{")
                config.append(f"        client_ip_country {country_list}")
                config.append(f"    }}")
                config.append(f"    respond @blocked_countries 403 {{")
                config.append(f"        body \"Access denied by geographic restriction.\"")
                config.append(f"    }}")
            else:
                # Whitelist specific countries (only allow these countries)
                country_list = ', '.join([f'"{c.strip().upper()}"' for c in countries])
                config.append(f"    @allowed_countries {{")
                config.append(f"        client_ip_country {country_list}")
                config.append(f"    }}")
                config.append(f"    @non_allowed_countries {{")
                config.append(f"        not client_ip_country {country_list}")
                config.append(f"    }}")
                config.append(f"    respond @non_allowed_countries 403 {{")
                config.append(f"        body \"Access denied by geographic restriction.\"")
                config.append(f"    }}")
        
        # Add custom configuration if provided
        if site.custom_config:
            config.append("    # Custom configuration")
            config.append(site.custom_config)
        
        # Add blocked site configuration if site is blocked
        if site.is_blocked:
            config.append("    respond 403 {")
            config.append("        body \"This site has been blocked by the administrator.\"")
            config.append("    }")
        
        # Close site block
        config.append("}")
        
        return "\n".join(config)
    
    def deploy_config(self, site_id, node_id, config_content, test_only=False):
        """
        Deploy Caddy configuration to a node
        
        Args:
            site_id: ID of the site
            node_id: ID of the node to deploy to
            config_content: The Caddy configuration content
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
        backup_path = None
        if not test_only:
            backup_path = self.create_backup_config(site_id, node_id)
        
        try:
            # Create a temporary file with the configuration content
            temp_file_path = SSHConnectionService.create_temp_file_with_content(config_content)
            remote_temp_path = f"/tmp/{site.domain}_caddy_test"
            
            with SSHConnectionService.get_sftp_connection(node) as (ssh_client, sftp):
                # Upload the configuration to a temporary file for testing
                sftp.put(temp_file_path, remote_temp_path)
                os.unlink(temp_file_path)  # Clean up local temp file
                
                # Test the configuration
                test_cmd = f"caddy validate --config {remote_temp_path}"
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, test_cmd)
                
                warnings = []
                
                if exit_code != 0:
                    # Configuration test failed
                    error_message = stderr
                    
                    # Use common error handling for test failures
                    if test_only:
                        return False, error_message
                    else:
                        # Use the common error handler
                        return self.handle_deployment_error(
                            site_id, 
                            node_id, 
                            "deploy", 
                            Exception(f"Caddy configuration test failed: {error_message}"),
                            backup_path
                        )
                
                # If we're only testing, return success and any warnings
                if test_only:
                    return True, warnings
                
                # Get the Caddy config directory from the node
                caddy_sites_dir = node.proxy_config_path
                if not caddy_sites_dir:
                    caddy_sites_dir = "/etc/caddy/sites"  # Default path
                    
                # Ensure the sites directory exists
                mkdir_cmd = f"mkdir -p {caddy_sites_dir}"
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, mkdir_cmd)
                
                if exit_code != 0:
                    error_message = stderr
                    return self.handle_deployment_error(
                        site_id, 
                        node_id, 
                        "deploy", 
                        Exception(f"Failed to create Caddy sites directory: {error_message}"),
                        backup_path
                    )
                
                # Deploy the valid configuration
                config_path = f"{caddy_sites_dir}/{site.domain}.caddy"
                sftp.put(remote_temp_path, config_path)
                
                # Reload Caddy to apply the new configuration
                reload_cmd = "systemctl reload caddy"
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, reload_cmd)
                
                if exit_code != 0:
                    # Reload failed
                    error_message = stderr
                    return self.handle_deployment_error(
                        site_id, 
                        node_id, 
                        "deploy", 
                        Exception(f"Caddy reload failed: {error_message}"),
                        backup_path
                    )
                
                # Update the site node status
                site_node = SiteNode.query.filter_by(site_id=site_id, node_id=node_id).first()
                if site_node:
                    site_node.status = 'active'
                    site_node.last_deployed = datetime.utcnow()
                    db.session.commit()
                
                # Log the successful deployment
                self.log_deployment(
                    site_id=site_id,
                    node_id=node_id,
                    action="deploy",
                    status="success",
                    message="Caddy configuration deployed successfully"
                )
                
                # Clean up
                ssh_client.exec_command(f"rm -f {remote_temp_path}")
                
                return True
            
        except Exception as e:
            # Use the common error handler for all other exceptions
            return self.handle_deployment_error(site_id, node_id, "deploy", e, backup_path, test_only)
    
    def validate_config(self, config_content):
        """
        Validate the Caddy configuration syntax
        
        Args:
            config_content: String containing the Caddy configuration
            
        Returns:
            tuple: (is_valid, error_message)
        """
        # Simple validation of Caddy configuration
        # Check for matching braces
        open_braces = config_content.count('{')
        close_braces = config_content.count('}')
        
        if open_braces != close_braces:
            return False, f"Mismatched braces in Caddy configuration: {open_braces} opening vs {close_braces} closing"
        
        # Check for site definition
        if not re.search(r'^\s*[a-zA-Z0-9.-]+\s*{', config_content, re.MULTILINE):
            return False, "Missing site definition in Caddy configuration"
        
        return True, ""
    
    def get_service_info(self, node):
        """
        Get detailed Caddy information from a node
        
        Args:
            node: Node object to retrieve info from
            
        Returns:
            dict: A dictionary containing Caddy information
        """
        try:
            with SSHConnectionService.get_connection(node) as ssh_client:
                # Get Caddy version
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, "caddy version")
                version_output = stdout.strip()
                
                # Check if Caddy is running
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, "systemctl is-active caddy")
                is_running = stdout.strip() == 'active'
                
                # Get site count
                caddy_sites_dir = node.proxy_config_path if node.proxy_config_path else "/etc/caddy/sites"
                exit_code, stdout, stderr = SSHConnectionService.execute_command(
                    ssh_client, f"find {caddy_sites_dir} -type f -name '*.caddy' | wc -l"
                )
                site_count = int(stdout.strip())
                
                return {
                    'version': version_output,
                    'is_running': is_running,
                    'site_count': site_count
                }
            
        except Exception as e:
            return {
                'version': "Unknown",
                'is_running': False,
                'site_count': 0,
                'error': str(e)
            }
    
    def install_service(self, node, user_id=None):
        """
        Install Caddy on a node
        
        Args:
            node: Node object to install Caddy on
            user_id: Optional ID of the user performing the installation
            
        Returns:
            tuple: (success, message)
        """
        try:
            with SSHConnectionService.get_connection(node) as ssh_client:
                # Check if Caddy is already installed
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, "which caddy")
                caddy_path = stdout.strip()
                
                if caddy_path:
                    return True, f"Caddy is already installed at {caddy_path}"
                
                # Check the Linux distribution
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, "cat /etc/os-release")
                os_info = stdout
                
                if "Ubuntu" in os_info or "Debian" in os_info:
                    # Debian/Ubuntu installation
                    commands = [
                        "sudo apt-get update",
                        "sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl",
                        "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg",
                        "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list",
                        "sudo apt-get update",
                        "sudo apt-get install -y caddy",
                        "sudo systemctl enable caddy",
                        "sudo systemctl start caddy"
                    ]
                elif "CentOS" in os_info or "Red Hat" in os_info or "Fedora" in os_info:
                    # RHEL/CentOS/Fedora installation
                    commands = [
                        "sudo yum install -y yum-utils",
                        "sudo yum-config-manager --add-repo https://copr.fedorainfracloud.org/coprs/g/caddy/caddy/repo/epel-7/group_caddy-caddy-epel-7.repo",
                        "sudo yum install -y caddy",
                        "sudo systemctl enable caddy",
                        "sudo systemctl start caddy"
                    ]
                else:
                    # Generic installation using the official script
                    commands = [
                        "curl -1sLf 'https://caddyserver.com/api/download?os=linux&arch=amd64' -o /tmp/caddy",
                        "sudo mv /tmp/caddy /usr/bin/caddy",
                        "sudo chmod +x /usr/bin/caddy",
                        "sudo setcap cap_net_bind_service=+ep /usr/bin/caddy",
                        # Create a service file
                        """echo '[Unit]
Description=Caddy web server
Documentation=https://caddyserver.com/docs/
After=network.target

[Service]
User=www-data
Group=www-data
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=512
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target' | sudo tee /etc/systemd/system/caddy.service""",
                        "sudo mkdir -p /etc/caddy",
                        "sudo touch /etc/caddy/Caddyfile",
                        "sudo mkdir -p /etc/caddy/sites",
                        "sudo systemctl daemon-reload",
                        "sudo systemctl enable caddy",
                        "sudo systemctl start caddy"
                    ]
                
                # Run installation commands
                success, results = SSHConnectionService.execute_commands(ssh_client, commands)
                
                if not success:
                    # Find the command that failed
                    for cmd, exit_code, stdout, stderr in results:
                        if exit_code != 0:
                            return False, f"Installation failed: {stderr}"
                
                # Create necessary directories for Caddy
                exit_code, stdout, stderr = SSHConnectionService.execute_command(
                    ssh_client, "sudo mkdir -p /etc/caddy/sites"
                )
                
                # Set default Caddyfile to import site configurations
                caddyfile_content = """
# Global Caddy settings
{
    admin off  # Disable the admin API for security
    email admin@example.com  # Default email for ACME
    http_port 80
    https_port 443
}

# Import all site configurations
import /etc/caddy/sites/*.caddy
"""
                temp_file_path = SSHConnectionService.create_temp_file_with_content(caddyfile_content)
                
                with SSHConnectionService.get_sftp_connection(node) as (ssh_client, sftp):
                    sftp.put(temp_file_path, "/tmp/Caddyfile")
                    os.unlink(temp_file_path)
                
                # Move the Caddyfile and set permissions
                commands = [
                    "sudo mv /tmp/Caddyfile /etc/caddy/Caddyfile",
                    "sudo chown root:root /etc/caddy/Caddyfile",
                    "sudo chmod 644 /etc/caddy/Caddyfile"
                ]
                
                SSHConnectionService.execute_commands(ssh_client, commands)
                
                # Verify installation
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, "which caddy")
                caddy_path = stdout.strip()
                
                if caddy_path:
                    # Update the node with Caddy config path
                    node.proxy_config_path = "/etc/caddy/sites"
                    node.proxy_type = "caddy"
                    db.session.commit()
                    
                    # Log the installation
                    if user_id:
                        self.log_system_action(
                            category='admin',
                            action='install_caddy',
                            resource_type='node',
                            resource_id=node.id,
                            details=f"Installed Caddy on node {node.name}",
                            user_id=user_id
                        )
                    
                    return True, f"Caddy successfully installed at {caddy_path}"
                else:
                    return False, "Caddy installation failed: Caddy binary not found after installation"
                
        except Exception as e:
            return False, f"Caddy installation failed: {str(e)}"