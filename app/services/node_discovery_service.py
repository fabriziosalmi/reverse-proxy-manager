import yaml
import os
import logging
from datetime import datetime
from app.models.models import Node
from app import db

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