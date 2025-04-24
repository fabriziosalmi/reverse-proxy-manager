import yaml
import os
import logging
from datetime import datetime
from app.models.models import Node
from app import db
import paramiko

logger = logging.getLogger(__name__)

class NodeDiscoveryService:
    """Service for discovering nodes in the network"""
    
    @staticmethod
    def discover_nodes(network_range, port=22, timeout=2, max_threads=10):
        """
        Discover SSH-enabled nodes in a network range
        
        Args:
            network_range: Network range in CIDR notation (e.g., 192.168.1.0/24)
            port: Port to scan (default 22 for SSH)
            timeout: Connection timeout in seconds
            max_threads: Maximum number of concurrent threads
            
        Returns:
            list: Discovered nodes with their IP addresses
        """
        import ipaddress
        import socket
        import concurrent.futures
        
        # Parse network range
        try:
            network = ipaddress.ip_network(network_range)
        except ValueError as e:
            log_activity('error', f"Invalid network range format: {str(e)}")
            return {
                "success": False,
                "message": f"Invalid network range format: {str(e)}"
            }
        
        # Check if network is too large
        network_size = network.num_addresses
        if network_size > 1024:  # Arbitrary limit to prevent massive scans
            return {
                "success": False,
                "message": f"Network range too large ({network_size} addresses). Maximum allowed is 1024."
            }
        
        nodes = []
        active_ips = []
        
        # Function to check a single IP
        def check_ip(ip):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((str(ip), port))
                sock.close()
                
                if result == 0:
                    return str(ip)
                return None
            except Exception as e:
                log_activity('warning', f"Error checking {ip}: {str(e)}")
                return None
        
        # Use ThreadPoolExecutor for concurrent scanning with controlled resources
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all IP addresses for checking
            future_to_ip = {executor.submit(check_ip, ip): ip for ip in network.hosts()}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future.result()
                if ip:
                    active_ips.append(ip)
        
        # For each active IP, gather basic information
        for ip in active_ips:
            try:
                hostname = socket.getfqdn(ip)
                nodes.append({
                    "ip_address": ip,
                    "hostname": hostname if hostname != ip else "Unknown",
                    "ssh_port": port,
                    "status": "discovered"
                })
            except Exception as e:
                log_activity('warning', f"Error resolving hostname for {ip}: {str(e)}")
                nodes.append({
                    "ip_address": ip,
                    "hostname": "Unknown",
                    "ssh_port": port,
                    "status": "discovered"
                })
        
        return {
            "success": True,
            "message": f"Discovered {len(nodes)} nodes in network {network_range}",
            "nodes": nodes
        }
    
    @staticmethod
    def verify_ssh_access(ip_address, port=22, username=None, password=None, key_path=None, timeout=5):
        """
        Verify SSH access to a node
        
        Args:
            ip_address: IP address of the node
            port: SSH port
            username: SSH username
            password: SSH password (optional)
            key_path: Path to SSH private key (optional)
            timeout: Connection timeout in seconds
            
        Returns:
            dict: Verification result with node details
        """
        import paramiko
        import socket
        import time
        
        # Validate required parameters
        if not username:
            return {
                "success": False,
                "message": "SSH username is required"
            }
        
        if not password and not key_path:
            return {
                "success": False,
                "message": "Either SSH password or key path is required"
            }
        
        # Try to connect via SSH with retry logic
        max_attempts = 2
        connection_delay = 1  # seconds
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        for attempt in range(max_attempts):
            try:
                # Try to connect with password or key
                if key_path:
                    ssh.connect(
                        hostname=ip_address,
                        port=port,
                        username=username,
                        key_filename=key_path,
                        timeout=timeout
                    )
                else:
                    ssh.connect(
                        hostname=ip_address,
                        port=port,
                        username=username,
                        password=password,
                        timeout=timeout
                    )
                
                # If connection succeeded, get system information
                result = {
                    "success": True,
                    "ip_address": ip_address,
                    "ssh_port": port,
                    "ssh_user": username,
                    "ssh_key_path": key_path,
                    "system_info": {}
                }
                
                # Get system information
                try:
                    # Get OS information
                    stdin, stdout, stderr = ssh.exec_command(
                        "lsb_release -ds 2>/dev/null || "
                        "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d '\"' -f 2 || "
                        "cat /etc/redhat-release 2>/dev/null || "
                        "cat /etc/issue 2>/dev/null | head -1 || "
                        "echo 'Unknown OS'"
                    )
                    os_info = stdout.read().decode('utf-8').strip()
                    result["system_info"]["os"] = os_info
                    
                    # Get hostname
                    stdin, stdout, stderr = ssh.exec_command("hostname")
                    hostname = stdout.read().decode('utf-8').strip()
                    result["hostname"] = hostname
                    
                    # Check if Nginx is installed and get its version
                    stdin, stdout, stderr = ssh.exec_command("nginx -v 2>&1 || echo 'Not installed'")
                    nginx_version = stdout.read().decode('utf-8').strip()
                    result["system_info"]["nginx_installed"] = "Not installed" not in nginx_version
                    result["system_info"]["nginx_version"] = nginx_version if "Not installed" not in nginx_version else None
                    
                    # Get Nginx configuration path
                    stdin, stdout, stderr = ssh.exec_command("find /etc -type d -name 'nginx' 2>/dev/null | grep -v modules")
                    nginx_paths = stdout.read().decode('utf-8').strip().split('\n')
                    
                    for path in nginx_paths:
                        if path and os.path.exists(path):
                            # Check if this contains configuration files
                            stdin, stdout, stderr = ssh.exec_command(f"find {path} -name '*.conf' | wc -l")
                            conf_count = int(stdout.read().decode('utf-8').strip() or 0)
                            
                            if conf_count > 0:
                                result["nginx_conf_path"] = path
                                break
                    
                    # Get available disk space
                    stdin, stdout, stderr = ssh.exec_command("df -h / | tail -1 | awk '{print $4}'")
                    disk_space = stdout.read().decode('utf-8').strip()
                    result["system_info"]["available_disk"] = disk_space
                    
                    # Get total memory
                    stdin, stdout, stderr = ssh.exec_command("free -h | grep Mem | awk '{print $2}'")
                    total_memory = stdout.read().decode('utf-8').strip()
                    result["system_info"]["total_memory"] = total_memory
                    
                    # Get CPU info
                    stdin, stdout, stderr = ssh.exec_command("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2")
                    cpu_model = stdout.read().decode('utf-8').strip()
                    result["system_info"]["cpu_model"] = cpu_model
                    
                    stdin, stdout, stderr = ssh.exec_command("grep -c processor /proc/cpuinfo")
                    cpu_cores = stdout.read().decode('utf-8').strip()
                    result["system_info"]["cpu_cores"] = cpu_cores
                    
                except Exception as info_error:
                    log_activity('warning', f"Error getting system information for {ip_address}: {str(info_error)}")
                    result["system_info"]["error"] = str(info_error)
                
                ssh.close()
                return result
                
            except (paramiko.AuthenticationException, paramiko.SSHException) as auth_error:
                error_message = f"Authentication failed for {username}@{ip_address}: {str(auth_error)}"
                log_activity('warning', error_message)
                
                if attempt < max_attempts - 1:
                    time.sleep(connection_delay)
                    continue
                    
                ssh.close()
                return {
                    "success": False,
                    "message": error_message
                }
                
            except (socket.timeout, socket.error, ConnectionError) as conn_error:
                error_message = f"Connection error to {ip_address}:{port}: {str(conn_error)}"
                log_activity('warning', error_message)
                
                if attempt < max_attempts - 1:
                    time.sleep(connection_delay)
                    continue
                    
                ssh.close()
                return {
                    "success": False,
                    "message": error_message
                }
                
            except Exception as e:
                error_message = f"Error verifying SSH access to {ip_address}: {str(e)}"
                log_activity('warning', error_message)
                
                ssh.close()
                return {
                    "success": False,
                    "message": error_message
                }
        
        # If we get here, all attempts failed with different errors
        return {
            "success": False,
            "message": f"Failed to connect to {ip_address} after {max_attempts} attempts"
        }
    
    @staticmethod
    def add_discovered_nodes(nodes, auto_verify=False, username=None, password=None, key_path=None):
        """
        Add discovered nodes to the database
        
        Args:
            nodes: List of node dictionaries with IP addresses
            auto_verify: Whether to automatically verify SSH access
            username: SSH username for verification
            password: SSH password for verification
            key_path: Path to SSH private key for verification
            
        Returns:
            dict: Result of adding nodes
        """
        from app.models.models import Node, db
        
        added_count = 0
        updated_count = 0
        verified_count = 0
        failed_count = 0
        failures = []
        
        for node_info in nodes:
            ip_address = node_info.get("ip_address")
            if not ip_address:
                failed_count += 1
                failures.append({
                    "node": node_info,
                    "reason": "Missing IP address"
                })
                continue
            
            # Check if node already exists
            existing_node = Node.query.filter_by(ip_address=ip_address).first()
            
            if existing_node:
                # Update existing node with discovered information
                existing_node.hostname = node_info.get("hostname") or existing_node.hostname
                existing_node.ssh_port = node_info.get("ssh_port") or existing_node.ssh_port
                existing_node.updated_at = datetime.utcnow()
                existing_node.is_discovered = True
                
                # Add/update other fields from node_info if present
                for field in ["nginx_conf_path", "nginx_sites_path"]:
                    if field in node_info and node_info.get(field):
                        setattr(existing_node, field, node_info.get(field))
                
                updated_count += 1
                node = existing_node
            else:
                # Create new node
                node = Node(
                    name=node_info.get("hostname") or f"Node-{ip_address.replace('.', '-')}",
                    ip_address=ip_address,
                    ssh_port=node_info.get("ssh_port") or 22,
                    ssh_user=username,  # Set default username if provided
                    ssh_password=password,  # Set default password if provided
                    ssh_key_path=key_path,  # Set default key path if provided
                    is_active=False,  # Nodes start as inactive until verified
                    is_discovered=True,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                
                # Set other fields from node_info if present
                if "nginx_conf_path" in node_info:
                    node.nginx_conf_path = node_info.get("nginx_conf_path")
                if "nginx_sites_path" in node_info:
                    node.nginx_sites_path = node_info.get("nginx_sites_path")
                
                db.session.add(node)
                added_count += 1
            
            # Auto-verify if requested
            if auto_verify:
                if not username:
                    # Skip verification if no username provided
                    continue
                
                # Use node's credentials or provided credentials
                node_username = node.ssh_user or username
                node_password = node.ssh_password or password
                node_key_path = node.ssh_key_path or key_path
                
                # Verify SSH access
                verification_result = NodeDiscoveryService.verify_ssh_access(
                    ip_address=node.ip_address,
                    port=node.ssh_port,
                    username=node_username,
                    password=node_password,
                    key_path=node_key_path
                )
                
                if verification_result.get("success"):
                    # Update node with verification information
                    node.is_active = True
                    node.verified_at = datetime.utcnow()
                    node.hostname = verification_result.get("hostname") or node.hostname
                    
                    # Update system information if available
                    system_info = verification_result.get("system_info") or {}
                    if system_info:
                        node.os_info = system_info.get("os")
                        
                        # Update Nginx information if available
                        if system_info.get("nginx_installed"):
                            node.nginx_version = system_info.get("nginx_version")
                            node.nginx_conf_path = verification_result.get("nginx_conf_path") or node.nginx_conf_path
                    
                    verified_count += 1
                else:
                    failed_count += 1
                    failures.append({
                        "node": node_info,
                        "reason": verification_result.get("message")
                    })
        
        # Commit changes to database
        try:
            db.session.commit()
            
            return {
                "success": True,
                "added": added_count,
                "updated": updated_count,
                "verified": verified_count,
                "failed": failed_count,
                "failures": failures
            }
        except Exception as e:
            db.session.rollback()
            log_activity('error', f"Error adding discovered nodes: {str(e)}")
            
            return {
                "success": False,
                "message": f"Error adding discovered nodes: {str(e)}"
            }
    
    @staticmethod
    def scan_local_network():
        """
        Scan the local network for nodes
        
        Returns:
            dict: Scan results
        """
        import socket
        import ipaddress
        
        # Get current host IP
        try:
            # Get the local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Calculate network range
            ip_obj = ipaddress.ip_address(local_ip)
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            network_range = str(network)
            
            log_activity('info', f"Scanning local network: {network_range}")
            
            # Discover nodes
            discovery_results = NodeDiscoveryService.discover_nodes(network_range)
            
            if not discovery_results.get("success"):
                return discovery_results
            
            nodes = discovery_results.get("nodes", [])
            
            return {
                "success": True,
                "local_ip": local_ip,
                "network_range": network_range,
                "nodes_found": len(nodes),
                "nodes": nodes
            }
            
        except Exception as e:
            log_activity('error', f"Error scanning local network: {str(e)}")
            
            return {
                "success": False,
                "message": f"Error scanning local network: {str(e)}"
            }
    
    @staticmethod
    def auto_configure_node(node_id):
        """
        Automatically configure a node for hosting
        
        Args:
            node_id: ID of the node to configure
            
        Returns:
            dict: Configuration result
        """
        from app.models.models import Node, db
        
        node = Node.query.get(node_id)
        if not node:
            return {
                "success": False,
                "message": f"Node ID {node_id} not found"
            }
        
        # Check if node is active
        if not node.is_active:
            return {
                "success": False,
                "message": f"Node {node.name} is not active. Verify SSH access first."
            }
        
        import paramiko
        import time
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Connect to the node
            if node.ssh_key_path:
                ssh.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    key_filename=node.ssh_key_path
                )
            else:
                ssh.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    password=node.ssh_password
                )
            
            # Check if Nginx is installed
            stdin, stdout, stderr = ssh.exec_command("which nginx || echo 'Not installed'")
            nginx_check = stdout.read().decode('utf-8').strip()
            
            if nginx_check == 'Not installed':
                # Install Nginx
                log_activity('info', f"Installing Nginx on node {node.name}")
                
                # Check OS to determine installation method
                stdin, stdout, stderr = ssh.exec_command(
                    "if [ -f /etc/debian_version ]; then "
                    "echo 'debian'; "
                    "elif [ -f /etc/redhat-release ]; then "
                    "echo 'redhat'; "
                    "elif [ -f /etc/alpine-release ]; then "
                    "echo 'alpine'; "
                    "else "
                    "echo 'unknown'; "
                    "fi"
                )
                os_type = stdout.read().decode('utf-8').strip()
                
                if os_type == 'debian':
                    stdin, stdout, stderr = ssh.exec_command(
                        "apt-get update && apt-get install -y nginx"
                    )
                elif os_type == 'redhat':
                    stdin, stdout, stderr = ssh.exec_command(
                        "yum install -y nginx"
                    )
                elif os_type == 'alpine':
                    stdin, stdout, stderr = ssh.exec_command(
                        "apk add --no-cache nginx"
                    )
                else:
                    ssh.close()
                    return {
                        "success": False,
                        "message": f"Unsupported OS type: {os_type}"
                    }
                
                # Wait for installation to complete
                exit_status = stdout.channel.recv_exit_status()
                
                if exit_status != 0:
                    error = stderr.read().decode('utf-8')
                    ssh.close()
                    return {
                        "success": False,
                        "message": f"Failed to install Nginx: {error}"
                    }
                
                # Check Nginx again
                stdin, stdout, stderr = ssh.exec_command("which nginx || echo 'Not installed'")
                nginx_check = stdout.read().decode('utf-8').strip()
                
                if nginx_check == 'Not installed':
                    ssh.close()
                    return {
                        "success": False,
                        "message": "Failed to install Nginx"
                    }
            
            # Get Nginx version
            stdin, stdout, stderr = ssh.exec_command("nginx -v 2>&1")
            nginx_version = stdout.read().decode('utf-8').strip()
            
            # Detect Nginx configuration paths
            stdin, stdout, stderr = ssh.exec_command("find /etc -name nginx.conf 2>/dev/null | head -1")
            nginx_conf = stdout.read().decode('utf-8').strip()
            
            nginx_conf_path = None
            nginx_sites_path = None
            
            if nginx_conf:
                nginx_conf_path = os.path.dirname(nginx_conf)
                
                # Check for common sites directories
                potential_sites_paths = [
                    f"{nginx_conf_path}/sites-available",
                    f"{nginx_conf_path}/conf.d",
                    f"{nginx_conf_path}/sites-enabled"
                ]
                
                for path in potential_sites_paths:
                    stdin, stdout, stderr = ssh.exec_command(f"test -d {path} && echo 'exists' || echo 'not found'")
                    if stdout.read().decode('utf-8').strip() == 'exists':
                        nginx_sites_path = path
                        break
                
                # If sites path not found, use conf.d
                if not nginx_sites_path:
                    # Create conf.d directory if it doesn't exist
                    nginx_sites_path = f"{nginx_conf_path}/conf.d"
                    stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {nginx_sites_path}")
            
            # Update node record
            if nginx_conf_path:
                node.nginx_conf_path = nginx_conf_path
            if nginx_sites_path:
                node.nginx_sites_path = nginx_sites_path
            
            # Get Nginx reload command
            stdin, stdout, stderr = ssh.exec_command("which systemctl >/dev/null 2>&1 && echo 'systemctl' || echo 'service'")
            service_manager = stdout.read().decode('utf-8').strip()
            
            if service_manager == 'systemctl':
                node.nginx_reload_command = "systemctl reload nginx"
            else:
                node.nginx_reload_command = "service nginx reload"
            
            # Create necessary directories for hosting
            stdin, stdout, stderr = ssh.exec_command("mkdir -p /var/www/html")
            
            # Create test file
            timestamp = int(time.time())
            test_content = f"Node {node.name} is ready for hosting. Configured at {timestamp}"
            
            stdin, stdout, stderr = ssh.exec_command(f"echo '{test_content}' > /var/www/html/cdntest.txt")
            
            # Make node active
            node.is_active = True
            node.auto_configured = True
            node.nginx_version = nginx_version
            node.updated_at = datetime.utcnow()
            
            db.session.commit()
            ssh.close()
            
            log_activity('info', f"Node {node.name} has been auto-configured for hosting")
            
            return {
                "success": True,
                "message": f"Node {node.name} has been auto-configured for hosting",
                "nginx_conf_path": nginx_conf_path,
                "nginx_sites_path": nginx_sites_path,
                "nginx_version": nginx_version,
                "test_file": "/var/www/html/cdntest.txt"
            }
            
        except Exception as e:
            db.session.rollback()
            log_activity('error', f"Error auto-configuring node {node.name}: {str(e)}")
            
            try:
                ssh.close()
            except:
                pass
                
            return {
                "success": False,
                "message": f"Error auto-configuring node: {str(e)}"
            }
    
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
            ssh_client = None
            
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
                            ssh_client = None
                            break
                            
                        except Exception as ssh_error:
                            connection_error = str(ssh_error)
                            if attempt < max_retries - 1:
                                time.sleep(retry_delay)
                            if ssh_client:
                                ssh_client.close()
                                ssh_client = None
                                
            except Exception as e:
                connection_error = str(e)
                if ssh_client:
                    ssh_client.close()
                    ssh_client = None
                
            finally:
                # Ensure ssh_client is closed in all cases
                if ssh_client:
                    ssh_client.close()
                    ssh_client = None
                    
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