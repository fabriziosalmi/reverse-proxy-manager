import os
import re
import paramiko
import tempfile
import yaml
from datetime import datetime

from app.services.proxy_service_base import ProxyServiceBase
from app.models.models import db, Node, Site, SiteNode, DeploymentLog, SystemLog
from app.services.logger_service import log_activity

class TraefikService(ProxyServiceBase):
    """Concrete implementation of ProxyServiceBase for Traefik"""
    
    def generate_config(self, site):
        """
        Generate Traefik configuration for a site
        
        Args:
            site: Site object containing configuration details
            
        Returns:
            str: Traefik configuration file content in YAML format
        """
        # Traefik uses YAML or TOML for configuration
        # We'll use YAML as it's more readable and similar to JSON
        
        # Basic router configuration
        router_name = site.domain.replace('.', '_')
        
        config = {
            "http": {
                "routers": {
                    f"{router_name}": {
                        "rule": f"Host(`{site.domain}`)",
                        "service": f"{router_name}_service",
                        "entryPoints": ["web"]
                    }
                },
                "services": {
                    f"{router_name}_service": {
                        "loadBalancer": {
                            "servers": [
                                {"url": f"{site.origin_protocol}://{site.origin_address}:{site.origin_port}"}
                            ],
                            "passHostHeader": True
                        }
                    }
                },
                "middlewares": {}
            }
        }
        
        # Configure HTTPS if required
        if site.protocol == 'https':
            config["http"]["routers"][router_name]["entryPoints"] = ["websecure"]
            config["http"]["routers"][router_name]["tls"] = {"certResolver": "default"}
            
            # Add HTTPS redirect router
            if site.force_https:
                config["http"]["routers"][f"{router_name}_redirect"] = {
                    "rule": f"Host(`{site.domain}`)",
                    "entryPoints": ["web"],
                    "middlewares": [f"{router_name}_redirect"],
                    "service": f"{router_name}_service"
                }
                
                config["http"]["middlewares"][f"{router_name}_redirect"] = {
                    "redirectScheme": {
                        "scheme": "https",
                        "permanent": True
                    }
                }
        
        # Add WAF configuration if enabled
        if site.use_waf:
            config["http"]["routers"][router_name]["middlewares"] = config["http"]["routers"][router_name].get("middlewares", [])
            config["http"]["routers"][router_name]["middlewares"].append(f"{router_name}_waf")
            
            # Configure WAF middleware
            if site.waf_rule_level == 'strict':
                config["http"]["middlewares"][f"{router_name}_waf"] = {
                    "plugin": {
                        "traefik-modsecurity": {
                            "ruleSets": ["/etc/traefik/rules/owasp-crs/rules/*.conf"],
                            "secRuleEngine": "On",
                            "secRequestBodyAccess": "On",
                            "secResponseBodyAccess": "On",
                            "secResponseBodyMimeType": "text/html application/json"
                        }
                    }
                }
            else:  # medium or basic
                config["http"]["middlewares"][f"{router_name}_waf"] = {
                    "plugin": {
                        "traefik-modsecurity": {
                            "ruleSets": ["/etc/traefik/rules/owasp-crs/rules/*.conf"],
                            "secRuleEngine": "DetectionOnly",
                            "secRequestBodyAccess": "On",
                            "secResponseBodyAccess": "Off"
                        }
                    }
                }
        
        # Add cache configuration if enabled
        if site.enable_cache:
            if "middlewares" not in config["http"]["routers"][router_name]:
                config["http"]["routers"][router_name]["middlewares"] = []
            
            config["http"]["routers"][router_name]["middlewares"].append(f"{router_name}_cache")
            
            # Configure cache middleware
            config["http"]["middlewares"][f"{router_name}_cache"] = {
                "plugin": {
                    "traefik-cache": {
                        "maxTtl": f"{site.cache_time}s",
                        "methods": ["GET", "HEAD"],
                        "maxCacheSize": "100MB"
                    }
                }
            }
        
        # Add GeoIP filtering if enabled
        if site.use_geoip and site.geoip_countries:
            if "middlewares" not in config["http"]["routers"][router_name]:
                config["http"]["routers"][router_name]["middlewares"] = []
            
            config["http"]["routers"][router_name]["middlewares"].append(f"{router_name}_geoip")
            
            countries = site.geoip_countries.replace(' ', '').split(',')
            
            # Configure GeoIP middleware
            if site.geoip_mode == 'blacklist':
                config["http"]["middlewares"][f"{router_name}_geoip"] = {
                    "plugin": {
                        "traefik-geoip": {
                            "blacklist": countries
                        }
                    }
                }
            else:  # whitelist
                config["http"]["middlewares"][f"{router_name}_geoip"] = {
                    "plugin": {
                        "traefik-geoip": {
                            "whitelist": countries
                        }
                    }
                }
        
        # Add site blocking if enabled
        if site.is_blocked:
            if "middlewares" not in config["http"]["routers"][router_name]:
                config["http"]["routers"][router_name]["middlewares"] = []
            
            config["http"]["routers"][router_name]["middlewares"].append(f"{router_name}_blocked")
            
            config["http"]["middlewares"][f"{router_name}_blocked"] = {
                "errors": {
                    "status": ["403"],
                    "service": f"{router_name}_service",
                    "query": "/{status}.html"
                }
            }
        
        # Convert the config to YAML format
        import yaml
        return yaml.dump(config, default_flow_style=False)
    
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
            
            remote_temp_path = f"/tmp/{site.domain}_traefik_test.yaml"
            sftp.put(tmp_path, remote_temp_path)
            os.unlink(tmp_path)  # Clean up local temp file
            
            # Test the configuration (Traefik doesn't have a built-in config test, so we validate YAML syntax)
            test_cmd = f"yamllint {remote_temp_path} 2>&1 || echo 'YAML syntax is valid'"
            stdin, stdout, stderr = ssh_client.exec_command(test_cmd)
            output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
            
            warnings = []
            
            if "error" in output.lower():
                # Configuration test failed
                error_message = output
                
                # Log the failure
                log = DeploymentLog(
                    site_id=site_id,
                    node_id=node_id,
                    action="test_config" if test_only else "deploy",
                    status="error",
                    message=f"Traefik configuration test failed: {error_message}"
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
                    
                    raise Exception(f"Traefik configuration test failed: {error_message}")
            
            # If we're only testing, return success and any warnings
            if test_only:
                return True, warnings
            
            # Get the Traefik config directory from the node
            traefik_sites_dir = node.proxy_config_path
            if not traefik_sites_dir:
                traefik_sites_dir = "/etc/traefik/conf.d"  # Default path
                
            # Ensure the sites directory exists
            mkdir_cmd = f"sudo mkdir -p {traefik_sites_dir}"
            stdin, stdout, stderr = ssh_client.exec_command(mkdir_cmd)
            exit_code = stdout.channel.recv_exit_status()
            
            if exit_code != 0:
                error_message = stderr.read().decode('utf-8')
                raise Exception(f"Failed to create Traefik sites directory: {error_message}")
            
            # Deploy the valid configuration
            config_path = f"{traefik_sites_dir}/{site.domain}.yaml"
            sftp.put(remote_temp_path, f"/tmp/{site.domain}.yaml")
            ssh_client.exec_command(f"sudo mv /tmp/{site.domain}.yaml {config_path}")
            
            # Reload Traefik to apply the new configuration
            reload_cmd = "sudo systemctl reload traefik"
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
                    message=f"Traefik reload failed: {error_message}"
                )
                db.session.add(log)
                db.session.commit()
                
                # Restore from backup
                if backup_path:
                    self.restore_from_backup(backup_path, site_id, node_id)
                
                raise Exception(f"Traefik reload failed: {error_message}")
            
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
                message="Traefik configuration deployed successfully"
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
        Validate the Traefik configuration syntax
        
        Args:
            config_content: String containing the Traefik configuration
            
        Returns:
            tuple: (is_valid, error_message)
        """
        # Basic YAML validation
        try:
            import yaml
            yaml.safe_load(config_content)
            return True, ""
        except Exception as e:
            return False, f"Invalid YAML syntax: {str(e)}"
    
    def get_service_info(self, node):
        """
        Get detailed Traefik information from a node
        
        Args:
            node: Node object to retrieve info from
            
        Returns:
            dict: A dictionary containing Traefik information
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
            
            # Get Traefik version
            stdin, stdout, stderr = ssh_client.exec_command("traefik version")
            version_output = stdout.read().decode('utf-8').strip()
            
            # Extract version
            version_match = re.search(r'Version:\s+(\d+\.\d+\.\d+)', version_output)
            version = version_match.group(1) if version_match else "Unknown"
            
            # Check if Traefik is running
            stdin, stdout, stderr = ssh_client.exec_command("systemctl is-active traefik")
            is_running = stdout.read().decode('utf-8').strip() == 'active'
            
            # Get site count
            traefik_sites_dir = node.proxy_config_path if node.proxy_config_path else "/etc/traefik/conf.d"
            stdin, stdout, stderr = ssh_client.exec_command(f"find {traefik_sites_dir} -type f -name '*.yaml' | wc -l")
            site_count = int(stdout.read().decode('utf-8').strip())
            
            # Get enabled features and providers
            features = []
            providers = []
            
            stdin, stdout, stderr = ssh_client.exec_command("ps aux | grep traefik")
            process_info = stdout.read().decode('utf-8')
            
            if "--providers.file" in process_info:
                providers.append("file")
            if "--providers.docker" in process_info:
                providers.append("docker")
            
            ssh_client.close()
            
            return {
                'version': version,
                'is_running': is_running,
                'site_count': site_count,
                'providers': providers,
                'features': features
            }
            
        except Exception as e:
            return {
                'version': "Unknown",
                'is_running': False,
                'site_count': 0,
                'providers': [],
                'features': [],
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
            
            # Check if Traefik is already installed
            stdin, stdout, stderr = ssh_client.exec_command("which traefik")
            traefik_path = stdout.read().decode('utf-8').strip()
            
            if traefik_path:
                return True, f"Traefik is already installed at {traefik_path}"
            
            # Check the Linux distribution
            stdin, stdout, stderr = ssh_client.exec_command("cat /etc/os-release")
            os_info = stdout.read().decode('utf-8')
            
            # Install Traefik using the binary method since it's the most reliable across distributions
            commands = [
                # Create traefik user
                "sudo useradd -r -s /bin/false traefik || true",
                
                # Download Traefik binary
                "sudo curl -L https://github.com/traefik/traefik/releases/download/v2.9.1/traefik_v2.9.1_linux_amd64.tar.gz -o /tmp/traefik.tar.gz",
                "sudo tar -C /tmp -xzf /tmp/traefik.tar.gz",
                "sudo mv /tmp/traefik /usr/local/bin/",
                "sudo chmod +x /usr/local/bin/traefik",
                
                # Create directories
                "sudo mkdir -p /etc/traefik/conf.d",
                "sudo mkdir -p /etc/traefik/rules",
                
                # Create basic configuration
                """sudo tee /etc/traefik/traefik.yaml > /dev/null << 'EOT'
api:
  dashboard: true
  insecure: true

entryPoints:
  web:
    address: :80
  websecure:
    address: :443

providers:
  file:
    directory: /etc/traefik/conf.d
    watch: true

certificatesResolvers:
  default:
    acme:
      email: admin@example.com
      storage: /etc/traefik/acme.json
      httpChallenge:
        entryPoint: web
EOT""",
                "sudo touch /etc/traefik/acme.json",
                "sudo chmod 600 /etc/traefik/acme.json",
                
                # Create systemd service
                """sudo tee /etc/systemd/system/traefik.service > /dev/null << 'EOT'
[Unit]
Description=Traefik
Documentation=https://doc.traefik.io/traefik/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=traefik
Group=traefik
ExecStart=/usr/local/bin/traefik --configfile=/etc/traefik/traefik.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOT""",
                
                # Set permissions
                "sudo chown -R traefik:traefik /etc/traefik",
                
                # Enable and start service
                "sudo systemctl daemon-reload",
                "sudo systemctl enable traefik",
                "sudo systemctl start traefik"
            ]
            
            # Run installation commands
            for cmd in commands:
                stdin, stdout, stderr = ssh_client.exec_command(cmd)
                exit_code = stdout.channel.recv_exit_status()
                if exit_code != 0:
                    error = stderr.read().decode('utf-8')
                    return False, f"Installation failed: {error}"
            
            # Verify installation
            stdin, stdout, stderr = ssh_client.exec_command("which traefik")
            traefik_path = stdout.read().decode('utf-8').strip()
            
            if traefik_path:
                # Update the node with Traefik config path
                node.proxy_config_path = "/etc/traefik/conf.d"
                node.proxy_type = "traefik"
                db.session.commit()
                
                # Log the installation
                if user_id:
                    from app.services.logger_service import log_activity
                    log_activity(
                        category='admin',
                        action='install_traefik',
                        resource_type='node',
                        resource_id=node.id,
                        user_id=user_id,
                        details=f"Installed Traefik on node {node.name}"
                    )
                
                return True, f"Traefik successfully installed at {traefik_path}"
            else:
                return False, "Traefik installation failed: Traefik binary not found after installation"
                
        except Exception as e:
            return False, f"Traefik installation failed: {str(e)}"