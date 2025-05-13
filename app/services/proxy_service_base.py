from abc import ABC, abstractmethod
import os
import tempfile
from datetime import datetime
from app.models.models import db, Node, Site, SiteNode, DeploymentLog, SystemLog
from app.services.ssh_connection_service import SSHConnectionService
from app.services.logger_service import log_activity

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
        # Default implementation that can be overridden by subclasses
        return (True, [], [])
    
    def validate_configs(self, node_id=None):
        """
        Validate all configurations for a node or for all nodes of this proxy type
        
        Args:
            node_id: Optional ID of the node to validate. If None, validates all nodes.
            
        Returns:
            tuple: (is_valid, messages)
        """
        is_valid = True
        messages = []
        
        try:
            # Get nodes to validate
            if node_id:
                nodes = [Node.query.get(node_id)]
                if not nodes[0]:
                    return (False, [f"Node with ID {node_id} not found"])
            else:
                # Get all active nodes of this proxy type
                from app.services.proxy_service_factory import ProxyServiceFactory
                proxy_type = None
                
                # Determine proxy type based on class
                if self.__class__.__name__ == 'NginxService':
                    proxy_type = 'nginx'
                elif self.__class__.__name__ == 'CaddyService':
                    proxy_type = 'caddy'
                elif self.__class__.__name__ == 'TraefikService':
                    proxy_type = 'traefik'
                
                if not proxy_type:
                    return (False, ["Could not determine proxy type"])
                
                nodes = Node.query.filter_by(is_active=True, proxy_type=proxy_type).all()
            
            if not nodes:
                return (True, ["No nodes to validate"])
            
            # Validate each node
            for node in nodes:
                with SSHConnectionService.get_connection(node) as ssh_client:
                    node_name = f"{node.name} ({node.ip_address})"
                    
                    # Test connectivity
                    exit_code, stdout, stderr = SSHConnectionService.execute_command(
                        ssh_client, "echo 'Connection test'"
                    )
                    
                    if exit_code != 0:
                        is_valid = False
                        messages.append(f"Cannot connect to {node_name}: {stderr}")
                        continue
                    
                    # Test proxy service based on proxy type
                    if node.proxy_type == 'nginx':
                        cmd = "nginx -t 2>&1"
                    elif node.proxy_type == 'caddy':
                        cmd = "caddy validate --config /etc/caddy/Caddyfile 2>&1"
                    elif node.proxy_type == 'traefik':
                        cmd = "traefik healthcheck --ping 2>&1"
                    else:
                        messages.append(f"Unknown proxy type for {node_name}: {node.proxy_type}")
                        continue
                    
                    exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, cmd)
                    output = stdout + stderr
                    
                    if exit_code != 0:
                        is_valid = False
                        messages.append(f"Configuration invalid on {node_name}: {output}")
                    else:
                        messages.append(f"Configuration valid on {node_name}")
                        
                        # Check for warnings in the output
                        if 'warning' in output.lower():
                            warnings = [line for line in output.split('\n') if 'warning' in line.lower()]
                            for warning in warnings:
                                messages.append(f"Warning on {node_name}: {warning}")
            
            return (is_valid, messages)
            
        except Exception as e:
            return (False, [f"Error validating configurations: {str(e)}"])
    
    def test_connection(self, node_id=None, node=None):
        """
        Test SSH connection to a node
        
        Args:
            node_id: Optional ID of the node to test
            node: Optional Node object to test
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        if not node and not node_id:
            return False
        
        if not node:
            node = Node.query.get(node_id)
            if not node:
                return False
        
        try:
            with SSHConnectionService.get_connection(node) as ssh_client:
                exit_code, stdout, stderr = SSHConnectionService.execute_command(
                    ssh_client, "echo 'Connection test'"
                )
                return exit_code == 0
        except Exception:
            return False
    
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
                # Get the config file path based on proxy type
                if node.proxy_type == 'nginx':
                    config_path = f"{node.proxy_config_path}/{site.domain}.conf"
                elif node.proxy_type == 'caddy':
                    config_path = f"{node.proxy_config_path}/sites/{site.domain}.caddy"
                elif node.proxy_type == 'traefik':
                    config_path = f"{node.proxy_config_path}/{site.domain}.yaml"
                else:
                    config_path = f"{node.proxy_config_path}/{site.domain}.conf"
                
                try:
                    # Create a temp file to store the downloaded config
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        tmp_path = tmp.name
                    
                    # Download the config file
                    if SSHConnectionService.download_file(node, config_path, tmp_path):
                        # Copy to backup location
                        import shutil
                        shutil.copy2(tmp_path, backup_path)
                        
                        # Clean up temp file
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                        
                        return backup_path
                except FileNotFoundError:
                    # Config doesn't exist yet, nothing to backup
                    return None
            
            return None
        except Exception as e:
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
            result = self.deploy_config(site_id, node_id, config_content)
            
            # Log the restore activity
            log_activity(
                'admin', 
                f"Restored configuration from backup for {site.domain} on {node.name}", 
                'site', 
                site_id, 
                None, 
                user_id
            )
            
            return result
            
        except Exception as e:
            log_activity('error', f"Failed to restore from backup for {site.domain} on {node.name}: {str(e)}", 'site', site_id, None, user_id)
            return False
    
    def log_deployment(self, site_id, node_id, action, status, message):
        """
        Log a deployment action in the database
        
        Args:
            site_id: ID of the site
            node_id: ID of the node
            action: Action performed (e.g., 'deploy', 'test_config')
            status: Status of the action (e.g., 'success', 'error')
            message: Description of the result
            
        Returns:
            DeploymentLog: The created log entry
        """
        log = DeploymentLog(
            site_id=site_id,
            node_id=node_id,
            action=action,
            status=status,
            message=message
        )
        db.session.add(log)
        db.session.commit()
        return log
    
    def log_system_action(self, category, action, resource_type, resource_id, details, user_id=None):
        """
        Log a system action in the database
        
        Args:
            category: Category of the action (e.g., 'admin', 'system')
            action: Action performed (e.g., 'install_nginx')
            resource_type: Type of resource affected (e.g., 'node', 'site')
            resource_id: ID of the affected resource
            details: Description of the action
            user_id: Optional ID of the user performing the action
            
        Returns:
            SystemLog: The created log entry
        """
        system_log = SystemLog(
            category=category,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            user_id=user_id
        )
        db.session.add(system_log)
        db.session.commit()
        return system_log
    
    def handle_deployment_error(self, site_id, node_id, action, e, backup_path=None, test_only=False):
        """
        Common error handling for deployment operations
        
        Args:
            site_id: ID of the site
            node_id: ID of the node
            action: Action being performed (e.g., 'deploy', 'test_config')
            e: The exception that occurred
            backup_path: Optional path to a backup file for restoration
            test_only: Whether this was just a test operation
            
        Returns:
            For test_only=True: tuple (False, error_message)
            Otherwise: Raises the exception after logging
        """
        # Extract error message
        error_message = str(e)
        
        # Log the error to the deployment logs
        deployment_log = self.log_deployment(
            site_id=site_id,
            node_id=node_id,
            action=action,
            status="error",
            message=f"Error during {action}: {error_message}"
        )
        
        # Send email notification if it's a deployment failure (not just a test)
        if not test_only:
            try:
                from app.services.deployment_notification_service import notify_on_failed_deployment
                notify_on_failed_deployment(deployment_log)
            except Exception as notify_error:
                import logging
                logging.getLogger(__name__).error(f"Failed to send deployment notification: {str(notify_error)}")
        
        # For test operations, return the result
        if test_only:
            return False, error_message
            
        # Try to restore from backup if it exists
        if backup_path:
            try:
                self.restore_from_backup(backup_path, site_id, node_id)
                # Add restoration info to the error message
                error_message += " (Previous configuration restored)"
            except Exception as restore_error:
                # Log the restoration failure
                self.log_deployment(
                    site_id=site_id,
                    node_id=node_id,
                    action="restore_backup",
                    status="error",
                    message=f"Failed to restore backup: {str(restore_error)}"
                )
                error_message += f" (Failed to restore previous configuration: {str(restore_error)})"
        
        # Re-raise the exception with the complete error information
        raise Exception(error_message) from e