import os
import re
import paramiko
import tempfile
from flask import current_app
from datetime import datetime
from app.models.models import db, Site, Node, SiteNode, DeploymentLog
from app.services.logger_service import log_activity

class NginxConfigParser:
    """Helper class to parse Nginx configuration files"""
    
    @staticmethod
    def extract_server_name(config_content):
        """Extract server_name from Nginx config content"""
        server_name_pattern = re.compile(r'server_name\s+([^;]+);')
        match = server_name_pattern.search(config_content)
        if match:
            return match.group(1).strip()
        return None
    
    @staticmethod
    def extract_listen_ports(config_content):
        """Extract listen ports from Nginx config content"""
        listen_pattern = re.compile(r'listen\s+(\d+)(?:\s+ssl)?;')
        return [int(port) for port in listen_pattern.findall(config_content)]
    
    @staticmethod
    def is_https_config(config_content):
        """Check if config uses HTTPS"""
        return 'ssl' in config_content and 'ssl_certificate' in config_content
    
    @staticmethod
    def extract_proxy_pass(config_content):
        """Extract proxy_pass target from config"""
        proxy_pattern = re.compile(r'proxy_pass\s+(\S+);')
        match = proxy_pattern.search(config_content)
        if match:
            proxy_url = match.group(1)
            # Parse protocol, address and port
            protocol_pattern = re.compile(r'^(https?):\/\/')
            protocol_match = protocol_pattern.search(proxy_url)
            protocol = protocol_match.group(1) if protocol_match else 'http'
            
            # Remove protocol
            url_without_protocol = re.sub(r'^https?:\/\/', '', proxy_url)
            
            # Extract address and port
            parts = url_without_protocol.split(':')
            address = parts[0]
            port = parts[1] if len(parts) > 1 else '80' if protocol == 'http' else '443'
            
            return {
                'protocol': protocol,
                'address': address,
                'port': port
            }
        return None
    
    @staticmethod
    def has_cache_config(config_content):
        """Check if config has caching enabled"""
        return 'proxy_cache_path' in config_content or 'proxy_cache ' in config_content
    
    @staticmethod
    def extract_custom_config(config_content):
        """Try to extract custom configuration sections"""
        # This is a simplified approach - in reality this would need to be more sophisticated
        sections = re.split(r'# Custom configuration', config_content)
        if len(sections) > 1:
            custom_config = sections[1].strip()
            # Remove the closing brackets and any common sections
            custom_config = re.sub(r'}\s*$', '', custom_config).strip()
            return custom_config
        return ""

def scan_node_for_configs(node):
    """
    Scan a node for existing Nginx configurations
    
    Args:
        node: Node object to scan
        
    Returns:
        list: List of dictionaries containing information about found configurations
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
                timeout=15
            )
        else:
            ssh_client.connect(
                hostname=node.ip_address,
                port=node.ssh_port,
                username=node.ssh_user,
                password=node.ssh_password,
                timeout=15
            )
        
        # Get list of config files in the Nginx sites directory
        sftp = ssh_client.open_sftp()
        configs = []
        
        try:
            # List files in the Nginx config directory
            for file_attr in sftp.listdir_attr(node.nginx_config_path):
                if file_attr.filename.endswith('.conf'):
                    remote_path = os.path.join(node.nginx_config_path, file_attr.filename)
                    
                    # Create a temporary file to store the config
                    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
                        temp_path = temp.name
                    
                    # Download the config file
                    sftp.get(remote_path, temp_path)
                    
                    # Read the config content
                    with open(temp_path, 'r') as f:
                        config_content = f.read()
                    
                    # Parse the config
                    domain = NginxConfigParser.extract_server_name(config_content)
                    is_https = NginxConfigParser.is_https_config(config_content)
                    ports = NginxConfigParser.extract_listen_ports(config_content)
                    proxy_info = NginxConfigParser.extract_proxy_pass(config_content)
                    has_cache = NginxConfigParser.has_cache_config(config_content)
                    custom_config = NginxConfigParser.extract_custom_config(config_content)
                    
                    # Only add if we have a valid domain
                    if domain:
                        configs.append({
                            'filename': file_attr.filename,
                            'domain': domain,
                            'is_https': is_https,
                            'ports': ports,
                            'proxy_info': proxy_info,
                            'has_cache': has_cache,
                            'custom_config': custom_config,
                            'full_config': config_content,
                            'remote_path': remote_path
                        })
                    
                    # Remove the temporary file
                    os.unlink(temp_path)
        except Exception as e:
            log_activity('error', f"Error listing configs on node {node.name}: {str(e)}")
        
        sftp.close()
        ssh_client.close()
        
        return configs
    
    except Exception as e:
        log_activity('error', f"Error connecting to node {node.name}: {str(e)}")
        return []

def import_configs_to_database(node_id, configs, user_id=None):
    """
    Import discovered configurations into the database
    
    Args:
        node_id: ID of the node
        configs: List of config dictionaries from scan_node_for_configs
        user_id: Optional ID of the user to assign sites to
        
    Returns:
        dict: Summary of import operation
    """
    node = Node.query.get(node_id)
    if not node:
        raise ValueError("Node not found")
    
    stats = {
        'imported': 0,
        'skipped': 0,
        'errors': 0,
        'details': []
    }
    
    for config in configs:
        # Check if the site already exists
        site = Site.query.filter_by(domain=config['domain']).first()
        
        if site:
            # Site exists, check if it's already deployed to this node
            site_node = SiteNode.query.filter_by(site_id=site.id, node_id=node_id).first()
            
            if site_node:
                stats['skipped'] += 1
                stats['details'].append({
                    'domain': config['domain'],
                    'action': 'skipped',
                    'reason': 'Already exists and deployed to this node'
                })
                continue
            else:
                # Create a new site_node relation
                try:
                    site_node = SiteNode(
                        site_id=site.id,
                        node_id=node_id,
                        status='discovered',
                        config_path=config['remote_path'],
                        discovered_at=datetime.utcnow()
                    )
                    db.session.add(site_node)
                    db.session.commit()
                    
                    stats['imported'] += 1
                    stats['details'].append({
                        'domain': config['domain'],
                        'action': 'linked',
                        'site_id': site.id
                    })
                except Exception as e:
                    stats['errors'] += 1
                    stats['details'].append({
                        'domain': config['domain'],
                        'action': 'error',
                        'reason': str(e)
                    })
        else:
            # Create a new site
            try:
                # Extract origin info
                protocol = 'https' if config['is_https'] else 'http'
                origin_protocol = config['proxy_info']['protocol'] if config['proxy_info'] else 'http'
                origin_address = config['proxy_info']['address'] if config['proxy_info'] else ''
                origin_port = config['proxy_info']['port'] if config['proxy_info'] else '80'
                
                # Create the site
                site = Site(
                    domain=config['domain'],
                    protocol=protocol,
                    origin_protocol=origin_protocol,
                    origin_address=origin_address,
                    origin_port=origin_port,
                    enable_cache=config['has_cache'],
                    custom_config=config['custom_config'],
                    user_id=user_id,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                    is_discovered=True
                )
                db.session.add(site)
                db.session.flush()  # Get the site ID without committing
                
                # Create site_node relation
                site_node = SiteNode(
                    site_id=site.id,
                    node_id=node_id,
                    status='discovered',
                    config_path=config['remote_path'],
                    discovered_at=datetime.utcnow()
                )
                db.session.add(site_node)
                
                # Create a deployment log
                log = DeploymentLog(
                    site_id=site.id,
                    node_id=node_id,
                    action='discovery',
                    status='success',
                    message=f"Discovered existing configuration for {site.domain}"
                )
                db.session.add(log)
                
                db.session.commit()
                
                stats['imported'] += 1
                stats['details'].append({
                    'domain': config['domain'],
                    'action': 'created',
                    'site_id': site.id
                })
            except Exception as e:
                db.session.rollback()
                stats['errors'] += 1
                stats['details'].append({
                    'domain': config['domain'],
                    'action': 'error',
                    'reason': str(e)
                })
    
    return stats

def verify_ssl_certificate(node, domain):
    """
    Verify that an SSL certificate is valid and installed correctly on a node
    
    Args:
        node: Node object
        domain: Domain to check certificate for
        
    Returns:
        dict: Certificate information including validity and expiry
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
        
        # Check if the certificate files exist
        cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
        
        stdin, stdout, stderr = ssh_client.exec_command(f"test -f {cert_path} && echo 'exists' || echo 'missing'")
        cert_exists = stdout.read().decode('utf-8').strip() == 'exists'
        
        stdin, stdout, stderr = ssh_client.exec_command(f"test -f {key_path} && echo 'exists' || echo 'missing'")
        key_exists = stdout.read().decode('utf-8').strip() == 'exists'
        
        if not cert_exists or not key_exists:
            ssh_client.close()
            return {
                'valid': False,
                'reason': 'Certificate or key file missing',
                'cert_path': cert_path,
                'key_path': key_path,
                'cert_exists': cert_exists,
                'key_exists': key_exists
            }
        
        # Check certificate expiry
        cmd = f"openssl x509 -in {cert_path} -noout -dates"
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        dates_output = stdout.read().decode('utf-8').strip().split('\n')
        
        # Parse dates
        not_before = None
        not_after = None
        for line in dates_output:
            if 'notBefore' in line:
                not_before = line.split('=')[1].strip()
            elif 'notAfter' in line:
                not_after = line.split('=')[1].strip()
        
        # Check if the certificate is for the correct domain
        cmd = f"openssl x509 -in {cert_path} -noout -text | grep -A1 'Subject Alternative Name'"
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        san_output = stdout.read().decode('utf-8').strip()
        
        # Extract domains from SAN output
        domains = []
        if 'DNS:' in san_output:
            dns_parts = san_output.split('DNS:')
            for part in dns_parts[1:]:
                domain_part = part.split(',')[0].strip()
                domains.append(domain_part)
        
        valid_domain = domain in domains or f"*.{domain.split('.', 1)[1]}" in domains
        
        # Certificate verification
        cmd = f"echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | openssl x509 -noout -checkend 0"
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        valid_cert = "Certificate will not expire" in stdout.read().decode('utf-8')
        
        ssh_client.close()
        
        return {
            'valid': valid_cert and valid_domain,
            'not_before': not_before,
            'not_after': not_after,
            'domains': domains,
            'valid_domain': valid_domain,
            'valid_cert': valid_cert
        }
        
    except Exception as e:
        return {
            'valid': False,
            'reason': str(e)
        }

import os
import re
import tempfile
import paramiko
from datetime import datetime
from app import db
from app.models.models import Node, Site, SiteNode, DeploymentLog, SystemLog
from app.services.logger_service import LoggerService

logger = LoggerService.get_logger(__name__)

class NodeInspectionService:
    """Service for inspecting Nginx configurations on nodes and importing them into the application"""
    
    @staticmethod
    def scan_node_for_configs(node_id):
        """
        Scan a node for existing Nginx site configurations
        
        Args:
            node_id (int): ID of the node to scan
            
        Returns:
            dict: Dictionary with status and results containing discovered configs
        """
        node = Node.query.get(node_id)
        if not node:
            return {"status": "error", "message": f"Node with ID {node_id} not found"}
        
        try:
            # Connect to the node
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect using either key or password
            if node.ssh_key_path:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    key_filename=node.ssh_key_path
                )
            else:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    password=node.ssh_password
                )
            
            # Get the nginx config path, default to /etc/nginx/conf.d
            config_path = node.nginx_config_path or "/etc/nginx/conf.d"
            
            # Find all .conf files in the config directory
            stdin, stdout, stderr = ssh_client.exec_command(f"find {config_path} -type f -name '*.conf'")
            config_files = stdout.read().decode('utf-8').strip().split('\n')
            
            discovered_configs = []
            
            for config_file in config_files:
                if not config_file:  # Skip empty lines
                    continue
                    
                # Read the config file
                stdin, stdout, stderr = ssh_client.exec_command(f"cat {config_file}")
                config_content = stdout.read().decode('utf-8')
                
                # Parse the config file to extract server_name
                domains = NodeInspectionService._extract_server_name(config_content)
                
                # Parse the config file to extract proxy_pass (origin)
                origin_info = NodeInspectionService._extract_proxy_pass(config_content)
                
                if domains and origin_info:
                    # For each domain in the server_name
                    for domain in domains:
                        discovered_configs.append({
                            "domain": domain,
                            "config_path": config_file,
                            "origin_protocol": origin_info.get("protocol", "http"),
                            "origin_address": origin_info.get("address", ""),
                            "origin_port": origin_info.get("port", 80),
                            "config_content": config_content,
                            "is_https": NodeInspectionService._is_https_config(config_content)
                        })
            
            ssh_client.close()
            
            return {
                "status": "success", 
                "results": discovered_configs
            }
        
        except Exception as e:
            logger.error(f"Error scanning node {node.name} ({node.ip_address}): {str(e)}")
            return {
                "status": "error", 
                "message": f"Error scanning node: {str(e)}"
            }
    
    @staticmethod
    def import_discovered_configs(node_id, configs_to_import):
        """
        Import discovered configurations into the application
        
        Args:
            node_id (int): ID of the node
            configs_to_import (list): List of config IDs to import from the discovered configs
            
        Returns:
            dict: Dictionary with status and results
        """
        node = Node.query.get(node_id)
        if not node:
            return {"status": "error", "message": f"Node with ID {node_id} not found"}
        
        try:
            discovered_configs = NodeInspectionService.scan_node_for_configs(node_id)
            
            if discovered_configs["status"] != "success":
                return discovered_configs
                
            configs = discovered_configs["results"]
            imported_count = 0
            
            for config_id in configs_to_import:
                if config_id < 0 or config_id >= len(configs):
                    continue
                    
                config = configs[config_id]
                
                # Check if site with this domain already exists
                existing_site = Site.query.filter_by(domain=config["domain"]).first()
                
                if existing_site:
                    # If site exists, just add the node to it if not already added
                    site_node = SiteNode.query.filter_by(
                        site_id=existing_site.id, 
                        node_id=node.id
                    ).first()
                    
                    if not site_node:
                        site_node = SiteNode(
                            site_id=existing_site.id,
                            node_id=node.id,
                            status="discovered",
                            config_path=config["config_path"],
                            discovered_at=datetime.utcnow()
                        )
                        db.session.add(site_node)
                        
                        # Log the discovery
                        log = DeploymentLog(
                            site_id=existing_site.id,
                            node_id=node.id,
                            action="discovery",
                            status="success",
                            message=f"Site configuration discovered on node {node.name}"
                        )
                        db.session.add(log)
                else:
                    # Create a new site
                    new_site = Site(
                        name=config["domain"],
                        domain=config["domain"],
                        protocol="https" if config["is_https"] else "http",
                        origin_protocol=config["origin_protocol"],
                        origin_address=config["origin_address"],
                        origin_port=config["origin_port"],
                        is_discovered=True,
                        custom_config=NodeInspectionService._extract_custom_config(config["config_content"])
                    )
                    db.session.add(new_site)
                    db.session.flush()  # To get the ID of the new site
                    
                    # Create site-node association
                    site_node = SiteNode(
                        site_id=new_site.id,
                        node_id=node.id,
                        status="discovered",
                        config_path=config["config_path"],
                        discovered_at=datetime.utcnow()
                    )
                    db.session.add(site_node)
                    
                    # Log the discovery
                    log = DeploymentLog(
                        site_id=new_site.id,
                        node_id=node.id,
                        action="discovery",
                        status="success",
                        message=f"New site discovered and imported from node {node.name}"
                    )
                    db.session.add(log)
                
                imported_count += 1
            
            # Add a system log
            system_log = SystemLog(
                action="node_inspection",
                level="info",
                message=f"Imported {imported_count} configurations from node {node.name}"
            )
            db.session.add(system_log)
            
            db.session.commit()
            
            return {
                "status": "success", 
                "message": f"Successfully imported {imported_count} configurations",
                "imported_count": imported_count
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error importing configs from node {node.name}: {str(e)}")
            return {
                "status": "error", 
                "message": f"Error importing configurations: {str(e)}"
            }
    
    @staticmethod
    def _extract_server_name(config_content):
        """Extract server_name from Nginx config"""
        server_name_pattern = r'server_name\s+([^;]+);'
        match = re.search(server_name_pattern, config_content)
        if match:
            domains = match.group(1).strip().split()
            # Filter out wildcard domains
            domains = [domain for domain in domains if not domain.startswith('*')]
            return domains
        return []
    
    @staticmethod
    def _extract_proxy_pass(config_content):
        """Extract proxy_pass from Nginx config to get origin"""
        proxy_pass_pattern = r'proxy_pass\s+(https?):\/\/([^:\/]+):?(\d*)'
        match = re.search(proxy_pass_pattern, config_content)
        if match:
            protocol = match.group(1)
            address = match.group(2)
            port = match.group(3) or ('443' if protocol == 'https' else '80')
            return {
                "protocol": protocol,
                "address": address,
                "port": int(port)
            }
        return {}
    
    @staticmethod
    def _is_https_config(config_content):
        """Check if the config is using HTTPS"""
        return 'listen 443 ssl' in config_content or 'ssl_certificate' in config_content
    
    @staticmethod
    def _extract_custom_config(config_content):
        """Extract custom configuration from Nginx config"""
        # Look for custom configuration section
        custom_config_pattern = r'# Custom configuration\s*\n(.*?)(?:\n\s*}|\n\s*#|$)'
        match = re.search(custom_config_pattern, config_content, re.DOTALL)
        if match and match.group(1).strip():
            return match.group(1).strip()
        return None
    
    @staticmethod
    def health_check_all_nodes():
        """
        Perform a health check on all active nodes
        
        Returns:
            dict: Health check results
        """
        nodes = Node.query.filter_by(is_active=True).all()
        
        results = {
            "total_nodes": len(nodes),
            "healthy_nodes": 0,
            "unhealthy_nodes": 0,
            "unreachable_nodes": 0,
            "node_results": []
        }
        
        for node in nodes:
            node_result = NodeInspectionService.health_check_node(node.id)
            results["node_results"].append(node_result)
            
            if node_result["status"] == "healthy":
                results["healthy_nodes"] += 1
            elif node_result["status"] == "unhealthy":
                results["unhealthy_nodes"] += 1
            else: # unreachable
                results["unreachable_nodes"] += 1
        
        # Add a system log entry
        system_log = SystemLog(
            action="health_check",
            level="info" if results["unreachable_nodes"] == 0 and results["unhealthy_nodes"] == 0 else "warning",
            message=f"Health check: {results['healthy_nodes']} healthy, {results['unhealthy_nodes']} unhealthy, {results['unreachable_nodes']} unreachable"
        )
        db.session.add(system_log)
        db.session.commit()
        
        return results
    
    @staticmethod
    def health_check_node(node_id):
        """
        Perform health check on a single node
        
        Args:
            node_id (int): ID of the node to check
            
        Returns:
            dict: Health check results for the node
        """
        node = Node.query.get(node_id)
        if not node:
            return {
                "node_id": node_id,
                "status": "error",
                "message": f"Node with ID {node_id} not found"
            }
        
        try:
            # Connect to the node
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Set a shorter timeout for unreachable nodes
            try:
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
            except (paramiko.SSHException, socket.timeout, socket.error) as e:
                # Node is unreachable
                logger.error(f"Node {node.name} ({node.ip_address}) is unreachable: {str(e)}")
                
                # Update node status
                node.last_health_check = datetime.utcnow()
                node.health_status = "unreachable"
                node.health_message = str(e)
                db.session.commit()
                
                return {
                    "node_id": node.id,
                    "node_name": node.name,
                    "ip_address": node.ip_address,
                    "status": "unreachable",
                    "message": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Check if Nginx is running
            stdin, stdout, stderr = ssh_client.exec_command("systemctl is-active nginx")
            nginx_status = stdout.read().decode('utf-8').strip()
            
            # Check if Nginx configuration is valid
            stdin, stdout, stderr = ssh_client.exec_command("nginx -t 2>&1")
            nginx_test = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
            nginx_config_valid = "test is successful" in nginx_test
            
            # Check system resources
            checks = [
                # Check CPU load
                {
                    "command": "cat /proc/loadavg | awk '{print $1}'",
                    "name": "cpu_load",
                    "threshold": 0.8 * multiprocessing.cpu_count() if hasattr(multiprocessing, 'cpu_count') else 3.0,
                    "compare": lambda val, threshold: float(val) > threshold,
                    "format": lambda val: float(val)
                },
                # Check memory usage
                {
                    "command": "free | grep Mem | awk '{print $3/$2 * 100.0}'",
                    "name": "memory_usage_percent",
                    "threshold": 90.0,
                    "compare": lambda val, threshold: float(val) > threshold,
                    "format": lambda val: float(val)
                },
                # Check disk space
                {
                    "command": "df / | tail -n 1 | awk '{print $5}' | sed 's/%//'",
                    "name": "disk_usage_percent",
                    "threshold": 90.0,
                    "compare": lambda val, threshold: float(val) > threshold,
                    "format": lambda val: float(val)
                },
                # Check if enough file descriptors are available
                {
                    "command": "cat /proc/sys/fs/file-nr | awk '{print $1/$3 * 100.0}'",
                    "name": "file_descriptors_percent",
                    "threshold": 90.0,
                    "compare": lambda val, threshold: float(val) > threshold,
                    "format": lambda val: float(val)
                },
                # Check for zombie processes
                {
                    "command": "ps aux | awk '{if ($8==\"Z\") print}' | wc -l",
                    "name": "zombie_processes",
                    "threshold": 5,
                    "compare": lambda val, threshold: int(val) > threshold,
                    "format": lambda val: int(val)
                }
            ]
            
            status_checks = {
                "nginx_running": nginx_status == "active",
                "nginx_config_valid": nginx_config_valid
            }
            
            resources = {}
            issues = []
            
            # Run resource checks
            for check in checks:
                try:
                    stdin, stdout, stderr = ssh_client.exec_command(check["command"])
                    value = stdout.read().decode('utf-8').strip()
                    
                    if value:
                        try:
                            formatted_value = check["format"](value)
                            resources[check["name"]] = formatted_value
                            
                            # Check if this is causing an issue
                            if check["compare"](formatted_value, check["threshold"]):
                                issues.append({
                                    "type": check["name"],
                                    "value": formatted_value,
                                    "threshold": check["threshold"],
                                    "message": f"{check['name']} is {formatted_value}, threshold is {check['threshold']}"
                                })
                        except (ValueError, TypeError):
                            resources[check["name"]] = value
                    else:
                        resources[check["name"]] = None
                except Exception as e:
                    resources[check["name"]] = f"Error: {str(e)}"
            
            # Check Nginx status issues
            if not status_checks["nginx_running"]:
                issues.append({
                    "type": "nginx_not_running",
                    "message": f"Nginx is not running. Status: {nginx_status}"
                })
                
            if not status_checks["nginx_config_valid"]:
                issues.append({
                    "type": "nginx_config_invalid",
                    "message": f"Nginx configuration is invalid: {nginx_test}"
                })
            
            # Get websites deployed on this node
            site_nodes = SiteNode.query.filter_by(node_id=node.id).all()
            sites = [Site.query.get(sn.site_id) for sn in site_nodes]
            
            # Determine overall status
            if issues:
                status = "unhealthy"
                message = f"Node has {len(issues)} health issues"
            else:
                status = "healthy"
                message = "All checks passed"
            
            # Update node status in database
            node.last_health_check = datetime.utcnow()
            node.health_status = status
            node.health_message = message
            db.session.commit()
            
            ssh_client.close()
            
            return {
                "node_id": node.id,
                "node_name": node.name,
                "ip_address": node.ip_address,
                "status": status,
                "message": message,
                "timestamp": datetime.utcnow().isoformat(),
                "checks": {
                    "nginx_running": status_checks["nginx_running"],
                    "nginx_config_valid": status_checks["nginx_config_valid"],
                    "resources": resources
                },
                "issues": issues,
                "sites_count": len(sites),
                "sites": [{"id": site.id, "domain": site.domain} for site in sites if site]
            }
            
        except Exception as e:
            logger.error(f"Error during health check of node {node.name}: {str(e)}")
            
            # Update node status
            node.last_health_check = datetime.utcnow()
            node.health_status = "error"
            node.health_message = str(e)
            db.session.commit()
            
            return {
                "node_id": node.id,
                "node_name": node.name,
                "ip_address": node.ip_address,
                "status": "error",
                "message": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }