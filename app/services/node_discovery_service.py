import yaml
import os
import logging
from datetime import datetime
from app.models.models import Node
from app import db
import paramiko

logger = logging.getLogger(__name__)

class NodeDiscoveryService:
    """Service for discovering and importing nodes from YAML configuration files"""
    
    @staticmethod
    def discover_nodes_from_yaml(yaml_path, auto_activate=True):
        """
        Discovers nodes from a YAML file and adds them to the database if they don't exist
        
        Args:
            yaml_path (str): Path to the YAML file containing node information
            auto_activate (bool): Whether to automatically set discovered nodes as active
            
        Returns:
            tuple: (num_added, num_updated, num_failed, messages)
                - num_added: Number of new nodes added
                - num_updated: Number of existing nodes updated
                - num_failed: Number of nodes that failed to add/update
                - messages: List of result messages for reporting
        """
        if not os.path.exists(yaml_path):
            return 0, 0, 1, [f"YAML file not found: {yaml_path}"]
        
        try:
            with open(yaml_path, 'r') as file:
                nodes_data = yaml.safe_load(file)
                
            if not nodes_data or not isinstance(nodes_data, list):
                return 0, 0, 1, ["Invalid YAML format. Expected a list of nodes."]
            
            num_added = 0
            num_updated = 0
            num_failed = 0
            messages = []
            
            for node_data in nodes_data:
                try:
                    # Basic validation
                    required_fields = ['name', 'ip_address', 'ssh_user']
                    missing_fields = [field for field in required_fields if field not in node_data]
                    
                    if missing_fields:
                        num_failed += 1
                        messages.append(f"Node missing required fields: {', '.join(missing_fields)}. Skipping.")
                        continue
                    
                    # Check if node already exists
                    existing_node = Node.query.filter_by(name=node_data['name']).first()
                    
                    if existing_node:
                        if existing_node.is_discovered:
                            # Update existing node
                            existing_node.ip_address = node_data['ip_address']
                            existing_node.ssh_port = node_data.get('ssh_port', 22)
                            existing_node.ssh_user = node_data['ssh_user']
                            
                            if 'ssh_key_path' in node_data:
                                existing_node.ssh_key_path = node_data['ssh_key_path']
                            
                            if 'ssh_password' in node_data:
                                existing_node.ssh_password = node_data['ssh_password']
                                
                            if 'nginx_config_path' in node_data:
                                existing_node.nginx_config_path = node_data.get('nginx_config_path', '/etc/nginx/conf.d')
                                
                            if 'nginx_reload_command' in node_data:
                                existing_node.nginx_reload_command = node_data.get('nginx_reload_command', 'sudo systemctl reload nginx')
                            
                            existing_node.updated_at = datetime.utcnow()
                            num_updated += 1
                            messages.append(f"Updated existing node: {node_data['name']}")
                        else:
                            # Skip non-discovered nodes to prevent overwriting manual changes
                            messages.append(f"Node {node_data['name']} exists but was not originally discovered. Skipping update.")
                            continue
                    else:
                        # Create new node
                        new_node = Node(
                            name=node_data['name'],
                            ip_address=node_data['ip_address'],
                            ssh_port=node_data.get('ssh_port', 22),
                            ssh_user=node_data['ssh_user'],
                            ssh_key_path=node_data.get('ssh_key_path'),
                            ssh_password=node_data.get('ssh_password'),
                            nginx_config_path=node_data.get('nginx_config_path', '/etc/nginx/conf.d'),
                            nginx_reload_command=node_data.get('nginx_reload_command', 'sudo systemctl reload nginx'),
                            is_active=auto_activate,
                            is_discovered=True
                        )
                        
                        db.session.add(new_node)
                        num_added += 1
                        messages.append(f"Added new node: {node_data['name']}")
                        
                except Exception as e:
                    num_failed += 1
                    messages.append(f"Error processing node {node_data.get('name', 'unknown')}: {str(e)}")
            
            # Commit all changes
            db.session.commit()
            return num_added, num_updated, num_failed, messages
            
        except Exception as e:
            logger.error(f"Error reading YAML file: {str(e)}")
            return 0, 0, 1, [f"Error reading YAML file: {str(e)}"]
    
    @staticmethod
    def get_default_yaml_path():
        """Get the default path for nodes.yaml file"""
        # First check environment variable
        yaml_path = os.environ.get('NODES_YAML_PATH')
        if yaml_path and os.path.exists(yaml_path):
            return yaml_path
            
        # Then check common locations
        possible_paths = [
            '/etc/italiacdn/nodes.yaml',
            '/etc/italiacdn/nodes.yml',
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../config/nodes.yaml'),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../nodes.yaml'),
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
                
        return None
    
    @staticmethod
    def verify_node_connectivity(node_id=None):
        """
        Verify connectivity to one or all nodes and update their status
        
        Args:
            node_id (int, optional): Specific node ID to check, or None to check all active nodes
            
        Returns:
            dict: Results of the connectivity check with node statuses
        """
        import socket
        import paramiko
        import time
        
        # Initialize results
        results = {
            'checked': 0,
            'reachable': 0,
            'unreachable': 0,
            'node_results': []
        }
        
        # Get nodes to check
        if node_id:
            nodes = [Node.query.get(node_id)]
            if not nodes[0]:
                return {'error': f'Node ID {node_id} not found'}
        else:
            nodes = Node.query.filter_by(is_active=True).all()
            
        for node in nodes:
            node_result = {
                'node_id': node.id,
                'name': node.name,
                'ip_address': node.ip_address,
                'previous_status': node.last_status
            }
            
            # First do a quick check with socket
            is_reachable = False
            ssh_connection_successful = False
            connection_error = None
            start_time = time.time()
            
            try:
                # Port connectivity check with timeout
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)  # 3 second timeout for initial check
                result = sock.connect_ex((node.ip_address, node.ssh_port))
                sock.close()
                
                if result == 0:
                    is_reachable = True
                    
                    # Now try SSH connection with retry logic
                    max_retries = 2
                    retry_delay = 1  # seconds
                    
                    for attempt in range(max_retries):
                        try:
                            ssh_client = paramiko.SSHClient()
                            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            
                            # Set a reasonable timeout for SSH connection
                            if node.ssh_key_path:
                                ssh_client.connect(
                                    hostname=node.ip_address,
                                    port=node.ssh_port,
                                    username=node.ssh_user,
                                    key_filename=node.ssh_key_path,
                                    timeout=5
                                )
                            else:
                                ssh_client.connect(
                                    hostname=node.ip_address,
                                    port=node.ssh_port,
                                    username=node.ssh_user,
                                    password=node.ssh_password,
                                    timeout=5
                                )
                                
                            # If we get here, connection successful
                            ssh_connection_successful = True
                            
                            # Get basic system info for validation
                            stdin, stdout, stderr = ssh_client.exec_command(
                                "hostname && uptime && uname -a"
                            )
                            
                            # Wait for command to complete (with timeout)
                            if stdout.channel.recv_exit_status() == 0:
                                system_info = stdout.read().decode('utf-8').strip()
                                node_result['system_info'] = system_info
                                
                                # Check for Nginx
                                stdin, stdout, stderr = ssh_client.exec_command(
                                    "which nginx 2>/dev/null || echo 'not installed'"
                                )
                                nginx_status = stdout.read().decode('utf-8').strip()
                                node_result['has_nginx'] = nginx_status != 'not installed'
                                
                                # Check Nginx configuration directory
                                if node.nginx_config_path:
                                    stdin, stdout, stderr = ssh_client.exec_command(
                                        f"test -d {node.nginx_config_path} && echo 'exists' || echo 'not found'"
                                    )
                                    config_dir_status = stdout.read().decode('utf-8').strip()
                                    node_result['nginx_config_path_exists'] = config_dir_status == 'exists'
                                
                                # Check disk space
                                stdin, stdout, stderr = ssh_client.exec_command(
                                    "df -h / | tail -1 | awk '{print $5}'"
                                )
                                disk_usage = stdout.read().decode('utf-8').strip()
                                if disk_usage.endswith('%'):
                                    disk_usage_pct = int(disk_usage.rstrip('%'))
                                    node_result['disk_usage'] = disk_usage
                                    if disk_usage_pct > 90:
                                        node_result['disk_warning'] = True
                            
                            ssh_client.close()
                            break
                            
                        except Exception as ssh_error:
                            connection_error = str(ssh_error)
                            if attempt < max_retries - 1:
                                time.sleep(retry_delay)
                                
            except Exception as e:
                connection_error = str(e)
                
            # Calculate response time
            response_time = time.time() - start_time
            node_result['response_time'] = round(response_time * 1000)  # in milliseconds
            
            # Update status based on test results
            if ssh_connection_successful:
                node_status = 'connected'
                node_result['status'] = 'reachable'
                results['reachable'] += 1
            elif is_reachable:
                node_status = 'unreachable-ssh'
                node_result['status'] = 'partially-reachable'
                node_result['error'] = f"SSH connection failed: {connection_error}"
                results['unreachable'] += 1
            else:
                node_status = 'unreachable'
                node_result['status'] = 'unreachable'
                node_result['error'] = "Connection failed" if not connection_error else f"Connection failed: {connection_error}"
                results['unreachable'] += 1
                
            # Update node record in database
            node.last_checked = datetime.utcnow()
            node.last_status = node_status
            node.response_time = node_result['response_time']
            
            if node.status_changed_at is None or node.last_status != node_result['previous_status']:
                node.status_changed_at = datetime.utcnow()
                
            results['node_results'].append(node_result)
            results['checked'] += 1
            
        # Commit all changes
        db.session.commit()
        
        return results
    
    @staticmethod
    def run_heartbeat_check():
        """
        Run a heartbeat check on all active nodes and update their status
        This method is meant to be called by a scheduled job
        
        Returns:
            dict: Summary of heartbeat check results
        """
        import json
        import logging
        
        logger = logging.getLogger('heartbeat')
        
        try:
            # Run connection check on all active nodes
            results = NodeDiscoveryService.verify_node_connectivity()
            
            # Log the summary
            logger.info(f"Heartbeat check: {results['reachable']} reachable, {results['unreachable']} unreachable out of {results['checked']} nodes")
            
            # Check for status changes for notifications
            status_changes = []
            for node_result in results.get('node_results', []):
                if node_result.get('previous_status') != node_result.get('status'):
                    status_changes.append({
                        'node_id': node_result.get('node_id'),
                        'name': node_result.get('name'),
                        'from_status': node_result.get('previous_status'),
                        'to_status': node_result.get('status')
                    })
            
            # If there are status changes, we might want to trigger notifications
            if status_changes:
                logger.warning(f"Node status changes detected: {json.dumps(status_changes)}")
                # TODO: Implement notification system
                
            return {
                'success': True,
                'checked': results['checked'],
                'reachable': results['reachable'],
                'unreachable': results['unreachable'],
                'status_changes': status_changes
            }
            
        except Exception as e:
            logger.error(f"Error in heartbeat check: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @staticmethod
    def export_nodes_to_yaml(output_path, include_inactive=False):
        """
        Export nodes from the database to a YAML file
        
        Args:
            output_path (str): Path where the YAML file should be saved
            include_inactive (bool): Whether to include inactive nodes
            
        Returns:
            tuple: (success, message)
        """
        try:
            # Get nodes from database
            query = Node.query
            if not include_inactive:
                query = query.filter_by(is_active=True)
                
            nodes = query.all()
            
            # Convert to YAML-friendly format
            nodes_data = []
            for node in nodes:
                node_data = {
                    'name': node.name,
                    'ip_address': node.ip_address,
                    'ssh_port': node.ssh_port,
                    'ssh_user': node.ssh_user
                }
                
                # Only include non-empty attributes
                if node.ssh_key_path:
                    node_data['ssh_key_path'] = node.ssh_key_path
                
                if node.ssh_password:
                    # Option to mask passwords for security
                    node_data['ssh_password'] = '********'  # Masked for security
                
                if node.nginx_config_path:
                    node_data['nginx_config_path'] = node.nginx_config_path
                
                if node.nginx_reload_command:
                    node_data['nginx_reload_command'] = node.nginx_reload_command
                
                # Include metadata
                node_data['is_active'] = node.is_active
                node_data['is_discovered'] = node.is_discovered
                
                # Add to list
                nodes_data.append(node_data)
            
            # Write to YAML file
            with open(output_path, 'w') as file:
                yaml.dump(nodes_data, file, default_flow_style=False)
                
            return True, f"Successfully exported {len(nodes_data)} nodes to {output_path}"
            
        except Exception as e:
            logger.error(f"Error exporting nodes to YAML: {str(e)}")
            return False, f"Error exporting nodes: {str(e)}"