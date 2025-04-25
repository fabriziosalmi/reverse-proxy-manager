import os
import tempfile
import re
from datetime import datetime

from app.services.proxy_service_base import ProxyServiceBase
from app.models.models import db, Site, Node, SiteNode, DeploymentLog
from app.services.ssh_connection_service import SSHConnectionService
from app.services.logger_service import log_activity

class TraefikService(ProxyServiceBase):
    """Concrete implementation of ProxyServiceBase for Traefik"""
    
    def generate_config(self, site):
        """
        Generate Traefik configuration for a site
        
        Args:
            site: Site object containing configuration details
            
        Returns:
            str: Traefik configuration file content
        """
        # Define the configuration in YAML format for Traefik
        config = []
        
        # Add header
        config.append(f"# Traefik configuration for {site.domain}")
        config.append("http:")
        config.append("  routers:")
        
        # Add the router configuration
        config.append(f"    {site.domain.replace('.', '-')}:")
        config.append(f"      rule: \"Host(`{site.domain}`)\"")
        
        # Handle TLS for HTTPS
        if site.protocol == 'https':
            config.append("      tls: true")
            config.append("      tls.certresolver: letsencrypt")
            config.append("      entryPoints: websecure")
        else:
            config.append("      entryPoints: web")
        
        config.append(f"      service: {site.domain.replace('.', '-')}")
        
        # Add the service configuration
        config.append("  services:")
        config.append(f"    {site.domain.replace('.', '-')}:")
        config.append("      loadBalancer:")
        config.append("        servers:")
        config.append(f"          - url: \"{site.origin_protocol}://{site.origin_address}:{site.origin_port}\"")
        
        # Add middlewares section
        middlewares = []
        
        # Add caching middleware if enabled
        if site.enable_cache:
            cache_middleware_name = f"{site.domain.replace('.', '-')}-cache"
            middlewares.append(cache_middleware_name)
            
            # Define cache configuration
            config.append("  middlewares:")
            config.append(f"    {cache_middleware_name}:")
            config.append("      plugin:")
            config.append("        httpCache:")
            config.append(f"          maxTtl: \"{site.cache_time}s\"")
            
            # Add custom cache paths
            config.append("          paths:")
            config.append("            - path: \"/\"")
            config.append(f"              ttl: \"{site.cache_time}s\"")
            config.append("            - path: \"/*.css\"")
            config.append(f"              ttl: \"{site.cache_static_time}s\"")
            config.append("            - path: \"/*.js\"")
            config.append(f"              ttl: \"{site.cache_static_time}s\"")
            config.append("            - path: \"/*.jpg\"")
            config.append(f"              ttl: \"{site.cache_static_time}s\"")
            config.append("            - path: \"/*.jpeg\"")
            config.append(f"              ttl: \"{site.cache_static_time}s\"")
            config.append("            - path: \"/*.png\"")
            config.append(f"              ttl: \"{site.cache_static_time}s\"")
            config.append("            - path: \"/*.gif\"")
            config.append(f"              ttl: \"{site.cache_static_time}s\"")
            config.append("            - path: \"/*.svg\"")
            config.append(f"              ttl: \"{site.cache_static_time}s\"")
            
        # Add GeoIP middleware if enabled
        if site.use_geoip and site.geoip_countries:
            geoip_middleware_name = f"{site.domain.replace('.', '-')}-geoip"
            middlewares.append(geoip_middleware_name)
            
            # Ensure middlewares section exists
            if not site.enable_cache:
                config.append("  middlewares:")
                
            # Define GeoIP configuration
            config.append(f"    {geoip_middleware_name}:")
            config.append("      ipAllowList:")
            
            # Add country codes based on mode
            countries = site.geoip_countries.replace(' ', '').split(',')
            
            if site.geoip_mode == 'whitelist':
                config.append("        sourceRange:")
                for country in countries:
                    config.append(f"          - \"countrycode:{country.strip().upper()}\"")
            else:  # blacklist
                config.append("        ipStrategy:")
                config.append("          depth: 1")
                config.append("        excludedIPs:")
                for country in countries:
                    config.append(f"          - \"countrycode:{country.strip().upper()}\"")
        
        # Add HTTPS redirect middleware if needed
        if site.force_https and site.protocol == 'https':
            https_middleware_name = f"{site.domain.replace('.', '-')}-https"
            middlewares.append(https_middleware_name)
            
            # Ensure middlewares section exists
            if not site.enable_cache and not site.use_geoip:
                config.append("  middlewares:")
                
            # Define HTTPS redirect configuration
            config.append(f"    {https_middleware_name}:")
            config.append("      redirectScheme:")
            config.append("        scheme: https")
            config.append("        permanent: true")
            
        # Add blocked site middleware if site is blocked
        if site.is_blocked:
            blocked_middleware_name = f"{site.domain.replace('.', '-')}-blocked"
            middlewares.append(blocked_middleware_name)
            
            # Ensure middlewares section exists
            if not middlewares:
                config.append("  middlewares:")
                
            # Define blocked site configuration
            config.append(f"    {blocked_middleware_name}:")
            config.append("      errors:")
            config.append("        status: [\"403\"]")
            config.append("        service: error")
            config.append("        query: \"/{status}.html\"")
        
        # Apply middlewares to the router if any are defined
        if middlewares:
            middleware_list = " , ".join(middlewares)
            # Find the router section to add the middleware
            for i, line in enumerate(config):
                if line.strip().startswith(f"{site.domain.replace('.', '-')}:"):
                    # Add middleware to this router
                    config.insert(i + 5, f"      middlewares: {middleware_list}")
                    break
        
        # Add custom configuration if provided
        if site.custom_config:
            config.append("# Custom configuration")
            for line in site.custom_config.split('\n'):
                config.append(line)
        
        return "\n".join(config)
    
    def deploy_config(self, site_id, node_id, config_content, test_only=False):
        """
        Deploy Traefik configuration to a node
        
        Args:
            site_id: ID of the site
            node_id: ID of the node to deploy to
            config_content: The Traefik configuration content
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
            remote_temp_path = f"/tmp/{site.domain}_traefik_test.yml"
            
            with SSHConnectionService.get_sftp_connection(node) as (ssh_client, sftp):
                # Upload the configuration to a temporary file for testing
                sftp.put(temp_file_path, remote_temp_path)
                os.unlink(temp_file_path)  # Clean up local temp file
                
                # Test the configuration
                test_cmd = f"traefik configtest --config.file={remote_temp_path}"
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, test_cmd)
                
                warnings = []
                
                if exit_code != 0:
                    # Configuration test failed
                    error_message = stderr
                    
                    # Use common error handler for test failures
                    if test_only:
                        return False, error_message
                    else:
                        return self.handle_deployment_error(
                            site_id, 
                            node_id, 
                            "deploy", 
                            Exception(f"Traefik configuration test failed: {error_message}"),
                            backup_path
                        )
                
                # If we're only testing, return success and any warnings
                if test_only:
                    return True, warnings
                
                # Get the Traefik config directory from the node
                traefik_sites_dir = node.proxy_config_path
                if not traefik_sites_dir:
                    traefik_sites_dir = "/etc/traefik/conf.d"  # Default path
                    
                # Ensure the sites directory exists
                mkdir_cmd = f"mkdir -p {traefik_sites_dir}"
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, mkdir_cmd)
                
                if exit_code != 0:
                    error_message = stderr
                    return self.handle_deployment_error(
                        site_id,
                        node_id,
                        "deploy",
                        Exception(f"Failed to create Traefik configuration directory: {error_message}"),
                        backup_path
                    )
                
                # Deploy the valid configuration
                config_path = f"{traefik_sites_dir}/{site.domain}.yml"
                sftp.put(remote_temp_path, config_path)
                
                # Reload Traefik to apply the new configuration
                reload_cmd = node.proxy_reload_command or "systemctl reload traefik"
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, reload_cmd)
                
                if exit_code != 0:
                    # Reload failed
                    error_message = stderr
                    return self.handle_deployment_error(
                        site_id,
                        node_id,
                        "deploy",
                        Exception(f"Traefik reload failed: {error_message}"),
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
                    message="Traefik configuration deployed successfully"
                )
                
                # Clean up
                ssh_client.exec_command(f"rm -f {remote_temp_path}")
                
                return True
            
        except Exception as e:
            # Use the common error handler for all exceptions
            return self.handle_deployment_error(site_id, node_id, "deploy", e, backup_path, test_only)
    
    def validate_config(self, config_content):
        """
        Validate the Traefik configuration syntax
        
        Args:
            config_content: String containing the Traefik configuration
            
        Returns:
            tuple: (is_valid, error_message)
        """
        # Simple validation of Traefik YAML configuration
        # Check for basic YAML structure
        if not config_content.strip():
            return False, "Empty configuration"
        
        if "http:" not in config_content:
            return False, "Missing 'http:' section in Traefik configuration"
        
        if "routers:" not in config_content:
            return False, "Missing 'routers:' section in Traefik configuration"
        
        if "services:" not in config_content:
            return False, "Missing 'services:' section in Traefik configuration"
        
        # Check for indentation issues (very basic)
        lines = config_content.split('\n')
        for i, line in enumerate(lines):
            if line.strip() and not line.startswith('#'):
                # Check if indentation is a multiple of 2 spaces
                indent = len(line) - len(line.lstrip())
                if indent % 2 != 0:
                    return False, f"Indentation error on line {i + 1}: '{line}'"
        
        return True, ""
    
    def get_service_info(self, node):
        """
        Get detailed Traefik information from a node
        
        Args:
            node: Node object to retrieve info from
            
        Returns:
            dict: A dictionary containing Traefik information
        """
        try:
            with SSHConnectionService.get_connection(node) as ssh_client:
                # Get Traefik version
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, "traefik version")
                version_output = stdout.strip()
                
                # Extract version number from the output
                version_match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
                version = version_match.group(1) if version_match else "Unknown"
                
                # Check if Traefik is running
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, "systemctl is-active traefik")
                is_running = stdout.strip() == 'active'
                
                # Get site count
                traefik_sites_dir = node.proxy_config_path if node.proxy_config_path else "/etc/traefik/conf.d"
                exit_code, stdout, stderr = SSHConnectionService.execute_command(
                    ssh_client, f"find {traefik_sites_dir} -type f -name '*.yml' | wc -l"
                )
                site_count = int(stdout.strip())
                
                # Get provider information
                providers = []
                exit_code, stdout, stderr = SSHConnectionService.execute_command(
                    ssh_client, "grep -r 'providers' /etc/traefik/traefik.yml 2>/dev/null || echo ''"
                )
                
                if stdout.strip():
                    # Extract providers from the configuration
                    if "file" in stdout:
                        providers.append("file")
                    if "docker" in stdout:
                        providers.append("docker")
                    if "consul" in stdout:
                        providers.append("consul")
                    if "etcd" in stdout:
                        providers.append("etcd")
                
                return {
                    'version': version,
                    'is_running': is_running,
                    'site_count': site_count,
                    'providers': providers
                }
            
        except Exception as e:
            return {
                'version': "Unknown",
                'is_running': False,
                'site_count': 0,
                'providers': [],
                'error': str(e)
            }
    
    def install_service(self, node, user_id=None):
        """
        Install Traefik on a node
        
        Args:
            node: Node object to install Traefik on
            user_id: Optional ID of the user performing the installation
            
        Returns:
            tuple: (success, message)
        """
        try:
            with SSHConnectionService.get_connection(node) as ssh_client:
                # Check if Traefik is already installed
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, "which traefik")
                traefik_path = stdout.strip()
                
                if traefik_path:
                    return True, f"Traefik is already installed at {traefik_path}"
                
                # Check the Linux distribution
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, "cat /etc/os-release")
                os_info = stdout
                
                if "Ubuntu" in os_info or "Debian" in os_info:
                    # Debian/Ubuntu installation
                    commands = [
                        "sudo apt-get update",
                        "sudo apt-get install -y wget",
                        "wget -q https://github.com/traefik/traefik/releases/latest/download/traefik_linux_amd64.tar.gz -O /tmp/traefik.tar.gz",
                        "sudo tar -xzf /tmp/traefik.tar.gz -C /tmp",
                        "sudo mv /tmp/traefik /usr/bin/",
                        "sudo chmod +x /usr/bin/traefik",
                        "sudo groupadd -f traefik",
                        "sudo useradd -g traefik -s /bin/false -M traefik || true",
                        "sudo mkdir -p /etc/traefik/conf.d",
                        "sudo mkdir -p /etc/traefik/acme",
                        "sudo chown -R traefik:traefik /etc/traefik"
                    ]
                elif "CentOS" in os_info or "Red Hat" in os_info or "Fedora" in os_info:
                    # RHEL/CentOS/Fedora installation
                    commands = [
                        "sudo yum install -y wget",
                        "wget -q https://github.com/traefik/traefik/releases/latest/download/traefik_linux_amd64.tar.gz -O /tmp/traefik.tar.gz",
                        "sudo tar -xzf /tmp/traefik.tar.gz -C /tmp",
                        "sudo mv /tmp/traefik /usr/bin/",
                        "sudo chmod +x /usr/bin/traefik",
                        "sudo groupadd -f traefik",
                        "sudo useradd -g traefik -s /bin/false -M traefik || true",
                        "sudo mkdir -p /etc/traefik/conf.d",
                        "sudo mkdir -p /etc/traefik/acme",
                        "sudo chown -R traefik:traefik /etc/traefik"
                    ]
                else:
                    # Generic installation
                    commands = [
                        "wget -q https://github.com/traefik/traefik/releases/latest/download/traefik_linux_amd64.tar.gz -O /tmp/traefik.tar.gz",
                        "sudo tar -xzf /tmp/traefik.tar.gz -C /tmp",
                        "sudo mv /tmp/traefik /usr/bin/",
                        "sudo chmod +x /usr/bin/traefik",
                        "sudo mkdir -p /etc/traefik/conf.d",
                        "sudo mkdir -p /etc/traefik/acme"
                    ]
                
                # Run installation commands
                success, results = SSHConnectionService.execute_commands(ssh_client, commands)
                
                if not success:
                    # Find the command that failed
                    for cmd, exit_code, stdout, stderr in results:
                        if exit_code != 0:
                            return False, f"Installation failed: {stderr}"
                
                # Create Traefik configuration file
                traefik_config = """
# Traefik static configuration
global:
  checkNewVersion: true
  sendAnonymousUsage: false

log:
  level: INFO

api:
  dashboard: true
  insecure: false

entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

providers:
  file:
    directory: "/etc/traefik/conf.d"
    watch: true

certificatesResolvers:
  letsencrypt:
    acme:
      email: "admin@example.com"
      storage: "/etc/traefik/acme/acme.json"
      caServer: "https://acme-v02.api.letsencrypt.org/directory"
      tlsChallenge: true
"""
                
                # Write Traefik configuration to a temporary file
                temp_file_path = SSHConnectionService.create_temp_file_with_content(traefik_config)
                
                with SSHConnectionService.get_sftp_connection(node) as (ssh_client, sftp):
                    sftp.put(temp_file_path, "/tmp/traefik.yml")
                    os.unlink(temp_file_path)
                
                # Move the configuration file to the right location and set up systemd service
                commands = [
                    "sudo mv /tmp/traefik.yml /etc/traefik/traefik.yml",
                    "sudo touch /etc/traefik/acme/acme.json",
                    "sudo chmod 600 /etc/traefik/acme/acme.json"
                ]
                
                # Set up systemd service
                systemd_service = """
[Unit]
Description=Traefik
Documentation=https://docs.traefik.io
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=traefik
Group=traefik
ExecStart=/usr/bin/traefik --configfile=/etc/traefik/traefik.yml
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""
                
                # Write systemd service file to a temporary file
                temp_file_path = SSHConnectionService.create_temp_file_with_content(systemd_service)
                
                with SSHConnectionService.get_sftp_connection(node) as (ssh_client, sftp):
                    sftp.put(temp_file_path, "/tmp/traefik.service")
                    os.unlink(temp_file_path)
                
                # Move the service file and enable the service
                commands.extend([
                    "sudo mv /tmp/traefik.service /etc/systemd/system/traefik.service",
                    "sudo systemctl daemon-reload",
                    "sudo systemctl enable traefik",
                    "sudo systemctl start traefik"
                ])
                
                # Run final setup commands
                success, results = SSHConnectionService.execute_commands(ssh_client, commands)
                
                if not success:
                    # Find the command that failed
                    for cmd, exit_code, stdout, stderr in results:
                        if exit_code != 0:
                            return False, f"Service setup failed: {stderr}"
                
                # Verify installation
                exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, "which traefik")
                traefik_path = stdout.strip()
                
                if traefik_path:
                    # Update the node with Traefik config path
                    node.proxy_config_path = "/etc/traefik/conf.d"
                    node.proxy_type = "traefik"
                    db.session.commit()
                    
                    # Log the installation
                    if user_id:
                        self.log_system_action(
                            category='admin',
                            action='install_traefik',
                            resource_type='node',
                            resource_id=node.id,
                            details=f"Installed Traefik on node {node.name}",
                            user_id=user_id
                        )
                    
                    return True, f"Traefik successfully installed at {traefik_path}"
                else:
                    return False, "Traefik installation failed: Traefik binary not found after installation"
                
        except Exception as e:
            return False, f"Traefik installation failed: {str(e)}"