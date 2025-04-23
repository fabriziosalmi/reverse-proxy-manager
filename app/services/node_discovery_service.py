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
    
    @staticmethod
    def scan_network_for_nodes(network_range, ssh_user, ssh_key_path=None, ssh_password=None, 
                              ports=[22], timeout=2, max_threads=10):
        """
        Scan a network range for potential proxy nodes by looking for systems with SSH access
        
        Args:
            network_range (str): CIDR notation for the network range to scan (e.g., '192.168.1.0/24')
            ssh_user (str): SSH username to try when connecting
            ssh_key_path (str, optional): Path to SSH private key file
            ssh_password (str, optional): Password for SSH authentication (if not using key)
            ports (list, optional): List of ports to scan. Defaults to [22]
            timeout (int, optional): Connection timeout in seconds. Defaults to 2
            max_threads (int, optional): Maximum number of concurrent threads. Defaults to 10
            
        Returns:
            dict: Results of the scan including discovered hosts
        """
        try:
            import ipaddress
            import socket
            import threading
            import paramiko
            from concurrent.futures import ThreadPoolExecutor
            
            # Parse the network range
            try:
                network = ipaddress.ip_network(network_range)
            except ValueError as e:
                return {"success": False, "message": f"Invalid network range: {str(e)}"}
            
            # Prepare results
            results = {
                "hosts_scanned": 0,
                "hosts_found": 0,
                "ssh_accessible": 0,
                "discovered_nodes": [],
                "errors": []
            }
            
            # Function to check a single host
            def check_host(ip, port):
                host_result = {"ip": str(ip), "port": port, "status": "unknown"}
                
                # Check if port is open
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                try:
                    sock.connect((str(ip), port))
                    host_result["status"] = "open"
                    
                    # If the port is open, check if it's SSH
                    if port == 22:  # Only check SSH on port 22
                        try:
                            # Try to connect via SSH
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            
                            if ssh_key_path:
                                ssh.connect(
                                    hostname=str(ip),
                                    port=port,
                                    username=ssh_user,
                                    key_filename=ssh_key_path,
                                    timeout=timeout
                                )
                            elif ssh_password:
                                ssh.connect(
                                    hostname=str(ip),
                                    port=port,
                                    username=ssh_user,
                                    password=ssh_password,
                                    timeout=timeout
                                )
                            else:
                                # Try key-based auth with default keys
                                ssh.connect(
                                    hostname=str(ip),
                                    port=port,
                                    username=ssh_user,
                                    timeout=timeout
                                )
                            
                            # If we get here, the SSH connection was successful
                            host_result["ssh_accessible"] = True
                            
                            # Try to detect if this is a potential proxy node by checking for nginx
                            stdin, stdout, stderr = ssh.exec_command("which nginx || which openresty")
                            nginx_path = stdout.read().decode('utf-8').strip()
                            
                            if nginx_path:
                                # Check Nginx version
                                stdin, stdout, stderr = ssh.exec_command(f"{nginx_path} -v 2>&1")
                                nginx_version = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                                
                                # Get hostname
                                stdin, stdout, stderr = ssh.exec_command("hostname -f 2>/dev/null || hostname")
                                hostname = stdout.read().decode('utf-8').strip()
                                
                                # Check for existing config path
                                stdin, stdout, stderr = ssh.exec_command("[ -d /etc/nginx/conf.d ] && echo '/etc/nginx/conf.d' || echo 'not found'")
                                nginx_config_path = stdout.read().decode('utf-8').strip()
                                if nginx_config_path == 'not found':
                                    # Try alternative paths
                                    stdin, stdout, stderr = ssh.exec_command("[ -d /usr/local/nginx/conf ] && echo '/usr/local/nginx/conf' || echo 'not found'")
                                    nginx_config_path = stdout.read().decode('utf-8').strip()
                                    
                                # Get OS information
                                stdin, stdout, stderr = ssh.exec_command(
                                    "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d '\"' -f 2 || "
                                    "lsb_release -ds 2>/dev/null || "
                                    "cat /etc/redhat-release 2>/dev/null || echo 'Unknown'"
                                )
                                os_info = stdout.read().decode('utf-8').strip()
                                
                                # This is likely a proxy node
                                host_result["is_proxy_candidate"] = True
                                host_result["nginx_version"] = nginx_version
                                host_result["hostname"] = hostname
                                host_result["os_info"] = os_info
                                host_result["nginx_config_path"] = nginx_config_path if nginx_config_path != 'not found' else None
                                
                                # Add to discovered nodes
                                results["discovered_nodes"].append({
                                    "name": hostname or str(ip),
                                    "ip_address": str(ip),
                                    "ssh_port": port,
                                    "ssh_user": ssh_user,
                                    "ssh_key_path": ssh_key_path,
                                    "ssh_password": "****" if ssh_password else None,  # Don't store actual password in results
                                    "nginx_config_path": nginx_config_path if nginx_config_path != 'not found' else '/etc/nginx/conf.d',
                                    "nginx_reload_command": "sudo systemctl reload nginx",
                                    "nginx_version": nginx_version,
                                    "os_info": os_info
                                })
                                results["ssh_accessible"] += 1
                            
                            ssh.close()
                        except paramiko.AuthenticationException:
                            host_result["ssh_accessible"] = False
                            host_result["error"] = "SSH authentication failed"
                        except Exception as e:
                            host_result["ssh_accessible"] = False
                            host_result["error"] = str(e)
                except socket.timeout:
                    host_result["status"] = "timeout"
                except ConnectionRefusedError:
                    host_result["status"] = "closed"
                except Exception as e:
                    host_result["status"] = "error"
                    host_result["error"] = str(e)
                finally:
                    sock.close()
                
                return host_result
            
            # Use ThreadPoolExecutor to scan hosts in parallel
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                
                # Submit scan tasks
                for ip in network.hosts():
                    for port in ports:
                        futures.append(executor.submit(check_host, ip, port))
                
                # Process results as they complete
                for future in futures:
                    try:
                        host_result = future.result()
                        results["hosts_scanned"] += 1
                        
                        if host_result["status"] == "open":
                            results["hosts_found"] += 1
                            
                        if "error" in host_result:
                            results["errors"].append(f"Error scanning {host_result['ip']}: {host_result['error']}")
                    except Exception as e:
                        results["errors"].append(f"Thread error: {str(e)}")
            
            # Return scan results
            return {
                "success": True,
                "hosts_scanned": results["hosts_scanned"],
                "hosts_found": results["hosts_found"],
                "ssh_accessible": results["ssh_accessible"],
                "discovered_nodes": results["discovered_nodes"],
                "errors": results["errors"]
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Network scan failed: {str(e)}"
            }
            
    @staticmethod
    def import_discovered_nodes(discovered_nodes, auto_activate=True):
        """
        Import discovered nodes into the database
        
        Args:
            discovered_nodes (list): List of node dictionaries from scan_network_for_nodes
            auto_activate (bool): Whether to automatically set discovered nodes as active
            
        Returns:
            tuple: (num_added, num_updated, num_skipped, messages)
        """
        num_added = 0
        num_updated = 0
        num_skipped = 0
        messages = []
        
        for node_data in discovered_nodes:
            try:
                # Check if node already exists (by IP or hostname)
                existing_node = Node.query.filter(
                    (Node.name == node_data['name']) | 
                    (Node.ip_address == node_data['ip_address'])
                ).first()
                
                if existing_node:
                    # Skip if the node wasn't originally discovered
                    if not existing_node.is_discovered:
                        num_skipped += 1
                        messages.append(f"Node {node_data['name']} ({node_data['ip_address']}) exists but was not originally discovered. Skipping update.")
                        continue
                    
                    # Update existing node
                    existing_node.ip_address = node_data['ip_address']
                    existing_node.ssh_port = node_data['ssh_port']
                    existing_node.ssh_user = node_data['ssh_user']
                    
                    if node_data.get('ssh_key_path'):
                        existing_node.ssh_key_path = node_data['ssh_key_path']
                    
                    if node_data.get('nginx_config_path'):
                        existing_node.nginx_config_path = node_data['nginx_config_path']
                    
                    existing_node.updated_at = datetime.utcnow()
                    num_updated += 1
                    messages.append(f"Updated existing node: {node_data['name']} ({node_data['ip_address']})")
                else:
                    # Create new node
                    new_node = Node(
                        name=node_data['name'],
                        ip_address=node_data['ip_address'],
                        ssh_port=node_data['ssh_port'],
                        ssh_user=node_data['ssh_user'],
                        ssh_key_path=node_data.get('ssh_key_path'),
                        nginx_config_path=node_data.get('nginx_config_path', '/etc/nginx/conf.d'),
                        nginx_reload_command='sudo systemctl reload nginx',
                        is_active=auto_activate,
                        is_discovered=True,
                        created_at=datetime.utcnow(),
                        updated_at=datetime.utcnow()
                    )
                    
                    db.session.add(new_node)
                    num_added += 1
                    messages.append(f"Added new node: {node_data['name']} ({node_data['ip_address']})")
            except Exception as e:
                num_skipped += 1
                messages.append(f"Error processing node {node_data.get('name', 'unknown')}: {str(e)}")
        
        # Commit all changes
        db.session.commit()
        return num_added, num_updated, num_skipped, messages