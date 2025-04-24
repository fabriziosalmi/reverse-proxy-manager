from abc import ABC, abstractmethod
import os
import paramiko
import tempfile
from datetime import datetime
from app.models.models import db, Node, Site, SiteNode, DeploymentLog

class ProxyServiceBase(ABC):
    """Base abstract class for proxy services (Nginx, Caddy, Traefik)"""
    
    @abstractmethod
    def generate_config(self, site):
        """
        Generate configuration for a site
        
        Args:
            site: Site object containing configuration details
            
        Returns:
            str: Configuration file content
        """
        pass
    
    @abstractmethod
    def deploy_config(self, site_id, node_id, config_content, test_only=False):
        """
        Deploy a site configuration to a node
        
        Args:
            site_id: ID of the site
            node_id: ID of the node to deploy to
            config_content: The configuration content
            test_only: If True, only test the configuration without deploying
            
        Returns:
            If test_only=True: tuple (is_valid, warnings)
            Otherwise: True on success or raises an exception
        """
        pass
    
    @abstractmethod
    def validate_config(self, config_content):
        """
        Validate the configuration syntax
        
        Args:
            config_content: String containing the configuration
            
        Returns:
            tuple: (is_valid, error_message)
        """
        pass
    
    @abstractmethod
    def get_service_info(self, node):
        """
        Get detailed service information from a node
        
        Args:
            node: Node object to retrieve info from
            
        Returns:
            dict: A dictionary containing service information
        """
        pass
    
    @abstractmethod
    def install_service(self, node, user_id=None):
        """
        Install the proxy service on a node
        
        Args:
            node: Node object to install the service on
            user_id: Optional ID of the user performing the installation
            
        Returns:
            tuple: (success, message)
        """
        pass
    
    def check_ssl_certificate_paths(self, node_id, config_content):
        """
        Check if SSL certificate files exist on the node
        
        Args:
            node_id: ID of the node
            config_content: Configuration content
            
        Returns:
            tuple: (all_exist, missing_files, warnings)
        """
        pass
    
    def create_backup_config(self, site_id, node_id):
        """
        Create a backup of the current configuration before deployment
        
        Args:
            site_id: ID of the site
            node_id: ID of the node
            
        Returns:
            str: Path to the backup file, or None if backup failed
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return None
        
        try:
            # Determine backup location
            backup_dir = os.path.join('/tmp/proxy_backups', str(site_id), str(node_id))
            os.makedirs(backup_dir, exist_ok=True)
            
            # Generate a backup filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = os.path.join(backup_dir, f"{site.domain}_{timestamp}.conf")
            
            if node.is_container_node:
                # For container nodes, read from local volume
                config_path = os.path.join(node.container_config_path, f"{site.domain}.conf")
                if os.path.exists(config_path):
                    import shutil
                    shutil.copy2(config_path, backup_path)
                    return backup_path
            else:
                # For traditional nodes, use SSH to get the config
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
                
                # Open SFTP connection
                sftp = ssh_client.open_sftp()
                
                # Get the config file path based on proxy type
                if node.proxy_type == 'nginx':
                    config_path = f"{node.proxy_config_path}/{site.domain}.conf"
                elif node.proxy_type == 'caddy':
                    config_path = f"{node.proxy_config_path}/sites/{site.domain}.caddy"
                elif node.proxy_type == 'traefik':
                    config_path = f"{node.proxy_config_path}/{site.domain}.yml"
                else:
                    config_path = f"{node.proxy_config_path}/{site.domain}.conf"
                
                try:
                    # Try to retrieve the config file
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        tmp_path = tmp.name
                        try:
                            sftp.get(config_path, tmp_path)
                            # Copy to backup location
                            import shutil
                            shutil.copy2(tmp_path, backup_path)
                        finally:
                            # Clean up temp file
                            if os.path.exists(tmp_path):
                                os.unlink(tmp_path)
                    
                    return backup_path
                except FileNotFoundError:
                    # Config doesn't exist yet, nothing to backup
                    return None
                finally:
                    sftp.close()
                    ssh_client.close()
            
            return None
        except Exception as e:
            from app.services.logger_service import log_activity
            log_activity('error', f"Failed to create backup for {site.domain} on {node.name}: {str(e)}", 'site', site_id)
            return None
    
    def restore_from_backup(self, backup_path, site_id, node_id, user_id=None):
        """
        Restore configuration from a backup file
        
        Args:
            backup_path: Path to the backup file
            site_id: ID of the site
            node_id: ID of the node
            user_id: Optional ID of the user performing the restore
            
        Returns:
            bool: True if restore was successful, False otherwise
        """
        if not backup_path or not os.path.exists(backup_path):
            return False
        
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return False
        
        try:
            # Read the backup file
            with open(backup_path, 'r') as f:
                config_content = f.read()
            
            # Deploy the backup content
            return self.deploy_config(site_id, node_id, config_content)
            
        except Exception as e:
            from app.services.logger_service import log_activity
            log_activity('error', f"Failed to restore from backup for {site.domain} on {node.name}: {str(e)}", 'site', site_id, None, user_id)
            return False