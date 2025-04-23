import os
import socket
import json
import dns.resolver
import subprocess
import paramiko
import requests
import time
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from app.models.models import Site, Node, SiteNode, SSLCertificate, db
from app.services.logger_service import log_activity
from flask import current_app

class SSLCertificateService:
    """Service for managing SSL certificates"""
    
    @staticmethod
    def check_certificate_status(site_id, node_id=None):
        """
        Check the status of SSL certificates for a site on specific node(s)
        
        Args:
            site_id: ID of the site
            node_id: Optional ID of a specific node to check
            
        Returns:
            dict: Certificate status information
        """
        site = Site.query.get(site_id)
        if not site:
            return {"error": "Site not found"}
            
        domain = site.domain
        
        # Determine which nodes to check
        if node_id:
            nodes = [Node.query.get(node_id)]
            if not nodes[0]:
                return {"error": f"Node ID {node_id} not found"}
        else:
            # Check all nodes that have this site
            site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
            node_ids = [sn.node_id for sn in site_nodes]
            nodes = Node.query.filter(Node.id.in_(node_ids)).filter_by(is_active=True).all()
            
            if not nodes:
                return {"error": "No active nodes found for this site"}
        
        results = []
        cert_found = False
        
        for node in nodes:
            try:
                # Connect to node via SSH with timeout and retry logic
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                connection_attempts = 0
                max_attempts = 2
                connected = False
                
                while connection_attempts < max_attempts and not connected:
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
                        connected = True
                    except (paramiko.SSHException, socket.timeout, socket.error) as e:
                        connection_attempts += 1
                        if connection_attempts >= max_attempts:
                            raise
                        time.sleep(1)  # Short delay before retry
                
                # Check certificate paths
                cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
                key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
                
                # Also check for wildcard certificates which might be used by this domain
                # Extract the base domain (e.g., example.com from sub.example.com)
                domain_parts = domain.split('.')
                wildcard_cert_path = None
                if len(domain_parts) > 2:
                    base_domain = '.'.join(domain_parts[-2:])
                    wildcard_cert_path = f"/etc/letsencrypt/live/{base_domain}/fullchain.pem"
                
                # First check if the standard certificate exists
                stdin, stdout, stderr = ssh_client.exec_command(f"test -f {cert_path} && echo 'exists' || echo 'not found'")
                cert_exists = stdout.read().decode('utf-8').strip() == 'exists'
                
                # If standard cert doesn't exist, check for wildcard cert
                if not cert_exists and wildcard_cert_path:
                    stdin, stdout, stderr = ssh_client.exec_command(f"test -f {wildcard_cert_path} && echo 'exists' || echo 'not found'")
                    wildcard_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    if wildcard_exists:
                        cert_path = wildcard_cert_path
                        key_path = wildcard_cert_path.replace('fullchain.pem', 'privkey.pem')
                        cert_exists = True
                
                # Prepare the result object
                result = {
                    "node_id": node.id,
                    "node_name": node.name,
                    "ip_address": node.ip_address,
                    "checked_paths": [cert_path]
                }
                
                if wildcard_cert_path:
                    result["checked_paths"].append(wildcard_cert_path)
                
                if not cert_exists:
                    # Check for self-signed certificates
                    self_signed_paths = [
                        f"/etc/nginx/ssl/{domain}.crt",
                        f"/etc/nginx/ssl/self-signed/{domain}.crt",
                        f"/etc/nginx/conf.d/ssl/{domain}.crt"
                    ]
                    
                    for ss_path in self_signed_paths:
                        stdin, stdout, stderr = ssh_client.exec_command(f"test -f {ss_path} && echo 'exists' || echo 'not found'")
                        if stdout.read().decode('utf-8').strip() == 'exists':
                            cert_path = ss_path
                            key_path = ss_path.replace('.crt', '.key')
                            cert_exists = True
                            result["self_signed"] = True
                            break
                
                if cert_exists:
                    cert_found = True
                    # Get certificate information using OpenSSL
                    stdin, stdout, stderr = ssh_client.exec_command(f"openssl x509 -in {cert_path} -text -noout")
                    cert_output = stdout.read().decode('utf-8')
                    
                    # Extract certificate information
                    subject = re.search(r'Subject:.*CN\s*=\s*([^\s,]+)', cert_output)
                    issuer = re.search(r'Issuer:.*CN\s*=\s*([^\n]+)', cert_output)
                    not_before = re.search(r'Not Before\s*:\s*([^\n]+)', cert_output)
                    not_after = re.search(r'Not After\s*:\s*([^\n]+)', cert_output)
                    
                    # Parse dates and compute remaining days
                    valid_from = datetime.strptime(not_before.group(1).strip(), '%b %d %H:%M:%S %Y %Z') if not_before else None
                    valid_until = datetime.strptime(not_after.group(1).strip(), '%b %d %H:%M:%S %Y %Z') if not_after else None
                    now = datetime.utcnow()
                    days_remaining = (valid_until - now).days if valid_until else None
                    
                    # Check certificate status
                    is_self_signed = "self-signed" in cert_output.lower() or (issuer and subject and issuer.group(1) == subject.group(1))
                    is_expired = valid_until and now > valid_until
                    is_not_yet_valid = valid_from and now < valid_from
                    
                    # Determine status
                    if is_expired:
                        status = "expired"
                    elif is_not_yet_valid:
                        status = "not_yet_valid"
                    elif days_remaining is not None and days_remaining <= 30:
                        status = "expiring_soon"
                    else:
                        status = "valid"
                    
                    # Check if it's a wildcard certificate
                    is_wildcard = "Subject Alternative Name" in cert_output and "DNS:*." in cert_output
                    
                    # Verify certificate and key match
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f"openssl x509 -noout -modulus -in {cert_path} | openssl md5; " +
                        f"openssl rsa -noout -modulus -in {key_path} 2>/dev/null | openssl md5"
                    )
                    key_match_output = stdout.read().decode('utf-8').strip()
                    key_check_lines = key_match_output.split('\n')
                    key_matches = len(key_check_lines) >= 2 and key_check_lines[0] == key_check_lines[1]
                    
                    result["certificate"] = {
                        "exists": True,
                        "subject": subject.group(1) if subject else "Unknown",
                        "issuer": issuer.group(1) if issuer else "Unknown",
                        "valid_from": valid_from.strftime('%Y-%m-%d') if valid_from else "Unknown",
                        "valid_until": valid_until.strftime('%Y-%m-%d') if valid_until else "Unknown",
                        "days_remaining": days_remaining,
                        "status": status,
                        "is_self_signed": is_self_signed or result.get("self_signed", False),
                        "is_wildcard": is_wildcard,
                        "key_matches": key_matches,
                        "path": cert_path
                    }
                    
                    # Check auto-renewal configuration
                    stdin, stdout, stderr = ssh_client.exec_command("crontab -l 2>/dev/null | grep -q 'certbot renew' && echo 'configured' || echo 'not configured'")
                    renewal_status = stdout.read().decode('utf-8').strip()
                    result["certificate"]["auto_renewal"] = renewal_status == 'configured'
                    
                    # Check for chain issues
                    stdin, stdout, stderr = ssh_client.exec_command(f"openssl verify -untrusted {cert_path.replace('fullchain.pem', 'chain.pem')} {cert_path.replace('fullchain.pem', 'cert.pem')} 2>&1 || echo 'chain_error'")
                    chain_verify = stdout.read().decode('utf-8').strip()
                    result["certificate"]["chain_valid"] = "chain_error" not in chain_verify
                else:
                    result["certificate"] = {
                        "exists": False,
                        "message": "No SSL certificate found for this domain"
                    }
                
                ssh_client.close()
                results.append(result)
                
            except Exception as e:
                results.append({
                    "node_id": node.id,
                    "node_name": node.name,
                    "ip_address": node.ip_address,
                    "error": str(e)
                })
        
        return {
            "domain": domain,
            "results": results,
            "cert_found": cert_found
        }
    
    @staticmethod
    def check_domain_dns(domain):
        """
        Check DNS resolution for the domain and compare with CDN nodes
        
        Args:
            domain: Domain to check
            
        Returns:
            dict: DNS check results
        """
        try:
            # Get all active nodes' IPs
            nodes = Node.query.filter_by(is_active=True).all()
            node_ips = [node.ip_address for node in nodes if node.ip_address]
            
            # Get the domain's A records
            try:
                # Try to get A records
                dns_result = dns.resolver.resolve(domain, 'A')
                a_records = [rdata.address for rdata in dns_result]
            except dns.resolver.NoAnswer:
                a_records = []
            
            # Also try to get CNAME records
            cname_records = []
            try:
                cname_result = dns.resolver.resolve(domain, 'CNAME')
                cname_records = [rdata.target.to_text() for rdata in cname_result]
            except dns.resolver.NoAnswer:
                pass
            
            # Check if any of the domain's IPs match our node IPs
            matching_ips = [ip for ip in a_records if ip in node_ips]
            
            # Check if any CNAME target matches a hostname we recognize
            # (This would require additional logic to map hostnames to IP addresses)
            
            # Estimate DNS propagation status
            if matching_ips:
                dns_status = "ok"
                dns_message = f"Domain points to {len(matching_ips)} CDN nodes"
                matching_percentage = round((len(matching_ips) / len(node_ips)) * 100)
            elif len(a_records) > 0:
                dns_status = "incorrect"
                dns_message = "Domain points to non-CDN IPs"
                matching_percentage = 0
            elif len(cname_records) > 0:
                dns_status = "cname"
                dns_message = f"Domain has CNAME records: {', '.join(cname_records)}"
                matching_percentage = 0
            else:
                dns_status = "not_found"
                dns_message = "No DNS records found for domain"
                matching_percentage = 0
            
            return {
                "domain": domain,
                "dns_status": dns_status,
                "message": dns_message,
                "a_records": a_records,
                "cname_records": cname_records,
                "cdn_node_ips": node_ips,
                "matching_ips": matching_ips,
                "matching_percentage": matching_percentage
            }
            
        except Exception as e:
            return {
                "domain": domain,
                "dns_status": "error",
                "error": str(e)
            }
    
    @staticmethod
    def get_issuance_recommendations(site_id):
        """
        Generate recommendations for SSL certificate issuance based on domain and node status
        
        Args:
            site_id: ID of the site
            
        Returns:
            dict: SSL issuance recommendations
        """
        site = Site.query.get(site_id)
        if not site:
            return {"error": "Site not found"}
        
        # Check DNS status first
        dns_check = SSLCertificateService.check_domain_dns(site.domain)
        
        # Get all nodes for this site
        site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
        nodes = [Node.query.get(sn.node_id) for sn in site_nodes]
        
        # Check if domain has wildcard (*.example.com)
        domain_parts = site.domain.split('.')
        is_subdomain = len(domain_parts) > 2
        has_www = domain_parts[0] == 'www'
        base_domain = '.'.join(domain_parts[1:]) if is_subdomain else site.domain
        
        # Determine recommended validation method based on DNS status
        if dns_check['dns_status'] == 'ok' and dns_check['matching_percentage'] >= 80:
            # Domain is pointing to most of our nodes, HTTP validation is possible
            recommended_method = "http"
            method_reason = "Domain points to CDN nodes, making HTTP validation possible"
        elif dns_check['dns_status'] == 'ok' and dns_check['matching_percentage'] > 0:
            # Domain is pointing to some nodes, HTTP validation might work
            recommended_method = "http"
            method_reason = f"Domain points to {dns_check['matching_percentage']}% of CDN nodes. HTTP validation might work but DNS validation is more reliable."
        else:
            # Domain is not pointing to our nodes, use DNS validation
            recommended_method = "dns"
            method_reason = "Domain is not pointing to CDN nodes. DNS validation is required."
        
        # Determine if wildcard certificates might be useful
        should_use_wildcard = False
        wildcard_reason = None
        
        if is_subdomain and not has_www:
            # Check if there are sibling subdomains already configured
            other_subdomains = Site.query.filter(
                Site.domain.like(f"%.{base_domain}"),
                Site.id != site_id
            ).all()
            
            if len(other_subdomains) >= 2:
                should_use_wildcard = True
                wildcard_reason = f"Found {len(other_subdomains)} other subdomains of {base_domain}. A wildcard certificate would cover all current and future subdomains."
        
        # Check if certbot is installed on nodes
        certbot_status = []
        for node in nodes:
            try:
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
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
                
                # Check for certbot
                stdin, stdout, stderr = ssh_client.exec_command("which certbot 2>/dev/null || echo 'not found'")
                certbot_path = stdout.read().decode('utf-8').strip()
                
                # Check if Nginx has SSL module
                stdin, stdout, stderr = ssh_client.exec_command("nginx -V 2>&1 | grep -o with-http_ssl_module || echo 'not found'")
                ssl_module = stdout.read().decode('utf-8').strip()
                
                certbot_status.append({
                    "node_id": node.id,
                    "node_name": node.name,
                    "certbot_installed": certbot_path != 'not found',
                    "ssl_module_enabled": ssl_module != 'not found',
                    "certbot_path": certbot_path if certbot_path != 'not found' else None
                })
                
                ssh_client.close()
            except Exception as e:
                certbot_status.append({
                    "node_id": node.id,
                    "node_name": node.name,
                    "error": str(e)
                })
        
        # Generate recommended installation steps based on the validation method
        installation_steps = []
        
        if recommended_method == "http":
            installation_steps = [
                "Ensure the domain is correctly pointing to the CDN nodes (if not already)",
                "On each node, ensure the Nginx configuration includes the challenge path",
                "Request the certificate using the HTTP validation method",
                "Configure cron for automatic renewal"
            ]
        elif recommended_method == "dns":
            installation_steps = [
                "Gather API credentials for your DNS provider",
                "Install appropriate DNS plugin for certbot",
                "Request the certificate using the DNS validation method",
                "Configure cron for automatic renewal"
            ]
        
        # For nodes without certbot, add installation instructions
        nodes_missing_certbot = [node["node_name"] for node in certbot_status if not node.get("certbot_installed", False)]
        if nodes_missing_certbot:
            installation_steps.insert(0, f"Install certbot on nodes: {', '.join(nodes_missing_certbot)}")
        
        # For nodes without SSL module, add warning
        nodes_missing_ssl = [node["node_name"] for node in certbot_status if not node.get("ssl_module_enabled", False)]
        
        # Prepare the recommendations
        recommendations = {
            "site_id": site_id,
            "domain": site.domain,
            "dns_status": dns_check,
            "recommended_method": recommended_method,
            "method_reason": method_reason,
            "should_use_wildcard": should_use_wildcard,
            "wildcard_reason": wildcard_reason,
            "certbot_status": certbot_status,
            "installation_steps": installation_steps,
            "nodes_missing_certbot": nodes_missing_certbot,
            "nodes_missing_ssl": nodes_missing_ssl
        }
        
        return recommendations
    
    @staticmethod
    def request_certificate(site_id, node_id, email, challenge_type='http', dns_provider=None, dns_credentials=None, cert_type='standard'):
        """
        Request an SSL certificate from Let's Encrypt for a site on a node
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return {
                "success": False,
                "message": "Site or node not found"
            }
            
        domain = site.domain
        
        # For wildcard certificates, ensure domain is properly formatted
        if cert_type == 'wildcard':
            # Extract the base domain (e.g., example.com from sub.example.com)
            domain_parts = domain.split('.')
            if len(domain_parts) > 2:
                base_domain = '.'.join(domain_parts[-2:])
                wildcard_domain = f"*.{base_domain}"
                domains = [wildcard_domain, base_domain]
            else:
                wildcard_domain = f"*.{domain}"
                domains = [wildcard_domain, domain]
        else:
            # For standard certs, add www. variant if it doesn't start with www.
            if domain.startswith('www.'):
                domains = [domain]
            else:
                domains = [domain, f"www.{domain}"]
        
        try:
            # Connect to the node with retry logic
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Enhanced connection error handling
            connection_attempts = 0
            max_attempts = 3
            connection_error = None
            
            while connection_attempts < max_attempts:
                try:
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
                    # If we get here, connection succeeded
                    connection_error = None
                    break
                except Exception as e:
                    connection_error = str(e)
                    connection_attempts += 1
                    log_activity('warning', f"Connection attempt {connection_attempts} to node {node.name} failed: {str(e)}")
                    time.sleep(2)  # Short delay before retry
            
            if connection_error:
                return {
                    "success": False,
                    "message": f"Failed to connect to node after {max_attempts} attempts: {connection_error}"
                }
            
            # Check if certbot is installed
            stdin, stdout, stderr = ssh_client.exec_command("which certbot 2>/dev/null || echo 'not found'")
            certbot_path = stdout.read().decode('utf-8').strip()
            
            if certbot_path == 'not found':
                log_activity('info', f"Installing certbot on node {node.name}")
                
                # Try to determine OS and install certbot
                stdin, stdout, stderr = ssh_client.exec_command(
                    "if [ -f /etc/debian_version ]; then "
                    "apt-get update && apt-get install -y certbot python3-certbot-nginx; "
                    "elif [ -f /etc/redhat-release ]; then "
                    "yum install -y certbot python3-certbot-nginx; "
                    "elif [ -f /etc/alpine-release ]; then "
                    "apk add --no-cache certbot; "
                    "else "
                    "echo 'Unsupported OS'; "
                    "fi"
                )
                
                # Wait for installation to complete
                exit_status = stdout.channel.recv_exit_status()
                installation_output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                
                if exit_status != 0 or 'Unsupported OS' in installation_output:
                    # Try snap installation as a fallback
                    stdin, stdout, stderr = ssh_client.exec_command(
                        "which snap >/dev/null 2>&1 && "
                        "snap install certbot --classic || "
                        "echo 'Snap not available'"
                    )
                    exit_status = stdout.channel.recv_exit_status()
                    snap_output = stdout.read().decode('utf-8')
                    
                    if exit_status != 0 or 'Snap not available' in snap_output:
                        ssh_client.close()
                        return {
                            "success": False,
                            "message": f"Failed to install certbot: {installation_output}"
                        }
                
                # Verify certbot is now installed
                stdin, stdout, stderr = ssh_client.exec_command("which certbot")
                certbot_path = stdout.read().decode('utf-8').strip()
                
                if not certbot_path:
                    ssh_client.close()
                    return {
                        "success": False,
                        "message": "Failed to install certbot"
                    }
            
            # For HTTP validation, ensure the challenge directory exists
            if challenge_type == 'http':
                # Ensure webroot path for ACME challenge exists
                webroot_path = "/var/www/letsencrypt"
                stdin, stdout, stderr = ssh_client.exec_command(f"mkdir -p {webroot_path}/.well-known/acme-challenge")
                
                # Check if Nginx configuration has the ACME challenge location
                challenge_location = f"""
    # ACME challenge location for Let's Encrypt verification
    location /.well-known/acme-challenge/ {{
        root {webroot_path};
    }}"""
                
                # Check for this location in the site's Nginx config
                nginx_config_path = f"{node.nginx_config_path}/{domain}.conf"
                stdin, stdout, stderr = ssh_client.exec_command(f"grep -q '.well-known/acme-challenge' {nginx_config_path} || echo 'missing'")
                if stdout.read().decode('utf-8').strip() == 'missing':
                    # Add the challenge location to the Nginx config
                    # This is a basic approach - a more robust method would parse the config
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f"sed -i '/server_name/a\\{challenge_location}' {nginx_config_path} && "
                        f"{node.nginx_reload_command}"
                    )
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status != 0:
                        ssh_client.close()
                        return {
                            "success": False,
                            "message": f"Failed to update Nginx configuration: {stderr.read().decode('utf-8')}"
                        }
            
            # Build certbot command based on validation method
            certbot_cmd = [certbot_path, "certonly", "--non-interactive", "--agree-tos", "-m", email]
            
            # Add --staging flag for testing in development environments
            # Uncomment this line to use Let's Encrypt staging environment for testing
            # certbot_cmd.append("--staging")
            
            if challenge_type == 'http':
                certbot_cmd.extend(["--webroot", "-w", webroot_path])
                for domain in domains:
                    certbot_cmd.extend(["-d", domain])
            
            elif challenge_type == 'dns':
                if not dns_provider:
                    ssh_client.close()
                    return {
                        "success": False,
                        "message": "DNS provider is required for DNS validation"
                    }
                
                # Install DNS plugin if needed
                plugin_name = f"certbot-dns-{dns_provider}"
                stdin, stdout, stderr = ssh_client.exec_command(f"pip3 show {plugin_name} || echo 'not installed'")
                if "not installed" in stdout.read().decode('utf-8'):
                    # Install the plugin
                    stdin, stdout, stderr = ssh_client.exec_command(f"pip3 install {plugin_name}")
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status != 0:
                        ssh_client.close()
                        return {
                            "success": False,
                            "message": f"Failed to install {plugin_name}: {stderr.read().decode('utf-8')}"
                        }
                
                # Set up credentials file
                creds_dir = "/root/.secrets"
                creds_file = f"{creds_dir}/{dns_provider}_credentials.ini"
                
                stdin, stdout, stderr = ssh_client.exec_command(f"mkdir -p {creds_dir}")
                
                # Create credentials file content based on provider
                creds_content = ""
                if dns_provider == 'cloudflare':
                    creds_content = f"dns_cloudflare_api_token = {dns_credentials['token']}"
                elif dns_provider == 'route53':
                    creds_content = f"dns_route53_access_key = {dns_credentials['access_key']}\ndns_route53_secret_key = {dns_credentials['secret_key']}"
                elif dns_provider == 'digitalocean':
                    creds_content = f"dns_digitalocean_token = {dns_credentials['token']}"
                elif dns_provider == 'godaddy':
                    creds_content = f"dns_godaddy_key = {dns_credentials['key']}\ndns_godaddy_secret = {dns_credentials['secret']}"
                elif dns_provider == 'namecheap':
                    creds_content = f"dns_namecheap_username = {dns_credentials['username']}\ndns_namecheap_api_key = {dns_credentials['api_key']}"
                
                # Write the credentials file
                sftp = ssh_client.open_sftp()
                with sftp.file(creds_file, 'w') as f:
                    f.write(creds_content)
                sftp.close()
                
                # Secure the credentials file
                stdin, stdout, stderr = ssh_client.exec_command(f"chmod 600 {creds_file}")
                
                # Build the certbot command with DNS plugin
                certbot_cmd.extend([f"--dns-{dns_provider}", f"--dns-{dns_provider}-credentials", creds_file])
                for domain in domains:
                    certbot_cmd.extend(["-d", domain])
            
            elif challenge_type == 'manual-dns':
                # Manual DNS validation - we'll show the TXT records to create
                for domain in domains:
                    certbot_cmd.extend(["-d", domain])
                certbot_cmd.extend(["--manual", "--preferred-challenges", "dns", "--manual-public-ip-logging-ok"])
                
                # Execute certbot command and capture the output
                cmd_str = " ".join(certbot_cmd)
                stdin, stdout, stderr = ssh_client.exec_command(cmd_str)
                
                # Read the output to extract DNS challenge information
                certbot_output = ""
                dns_challenges = []
                
                for line in stdout:
                    certbot_output += line
                    # Look for DNS challenge information
                    if "_acme-challenge" in line and "IN TXT" in line:
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            record = parts[0]
                            value = parts[4].strip('"')
                            dns_challenges.append({"record": record, "value": value})
                
                # If we found DNS challenges, return them to the user
                if dns_challenges:
                    ssh_client.close()
                    return {
                        "success": False,
                        "manual_dns_required": True,
                        "dns_challenges": dns_challenges,
                        "message": "Please create these DNS TXT records and then run the complete_dns_challenge.py script"
                    }
                
                # If we didn't find DNS challenges but certbot still failed
                error_output = stderr.read().decode('utf-8')
                ssh_client.close()
                return {
                    "success": False,
                    "message": f"Failed to initiate DNS challenge: {error_output}"
                }
            
            # Execute certbot command (for non-manual methods)
            if challenge_type != 'manual-dns':
                cmd_str = " ".join(certbot_cmd)
                stdin, stdout, stderr = ssh_client.exec_command(cmd_str)
                exit_status = stdout.channel.recv_exit_status()
                
                certbot_output = stdout.read().decode('utf-8')
                certbot_error = stderr.read().decode('utf-8')
                
                if exit_status != 0:
                    # Check for specific error conditions
                    if "too many certificates already issued" in certbot_output + certbot_error:
                        ssh_client.close()
                        return {
                            "success": False,
                            "message": "Rate limit exceeded: too many certificates issued for this domain recently. Please try again later."
                        }
                    elif "DNS problem" in certbot_output + certbot_error:
                        ssh_client.close()
                        return {
                            "success": False,
                            "message": "DNS validation failed. Ensure your domain is correctly configured and try again, or use DNS validation."
                        }
                    else:
                        ssh_client.close()
                        return {
                            "success": False,
                            "message": f"Certbot command failed: {certbot_error or certbot_output}"
                        }
            
            # Setup auto-renewal via cron
            stdin, stdout, stderr = ssh_client.exec_command("crontab -l 2>/dev/null | grep -q 'certbot renew' || (crontab -l 2>/dev/null; echo '15 3 * * * certbot renew --quiet --post-hook \"systemctl reload nginx\"') | crontab -")
            
            # Update SSL certificate record in database
            # First check if the certificate exists
            cert_status = SSLCertificateService.check_certificate_status(site_id, node_id)
            
            ssh_client.close()
            
            return {
                "success": True,
                "message": f"Successfully issued {cert_type} certificate for {', '.join(domains)}",
                "domains": domains,
                "cert_type": cert_type,
                "validation_method": challenge_type
            }
            
        except Exception as e:
            # Log the exception
            log_activity('error', f"Failed to request certificate for {domain} on node {node.name}: {str(e)}")
            
            # Clean up resources
            if 'ssh_client' in locals() and ssh_client:
                ssh_client.close()
                
            return {
                "success": False,
                "message": f"Failed to request certificate: {str(e)}"
            }
    
    @staticmethod
    def revoke_certificate(site_id, node_id):
        """
        Revoke an SSL certificate for a site on a node
        
        Args:
            site_id: ID of the site
            node_id: ID of the node
            
        Returns:
            dict: Revocation result
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return {"success": False, "message": "Site or node not found"}
        
        try:
            # Connect to the node
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
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
            
            # Check if certificates exist
            cert_path = f"/etc/letsencrypt/live/{site.domain}/fullchain.pem"
            stdin, stdout, stderr = ssh_client.exec_command(f"test -f {cert_path} && echo 'exists' || echo 'not found'")
            cert_exists = stdout.read().decode('utf-8').strip() == 'exists'
            
            if not cert_exists:
                ssh_client.close()
                return {
                    "success": False,
                    "message": f"No certificate found for {site.domain} on this node"
                }
            
            # Revoke the certificate
            stdin, stdout, stderr = ssh_client.exec_command(f"certbot revoke --cert-path {cert_path} --delete-after-revoke --non-interactive")
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if exit_status != 0:
                ssh_client.close()
                return {
                    "success": False,
                    "message": f"Failed to revoke certificate: {error}",
                    "output": output,
                    "error": error
                }
            
            # Delete the certificate record from database
            cert_record = SSLCertificate.query.filter_by(
                site_id=site_id, 
                node_id=node_id
            ).first()
            
            if cert_record:
                db.session.delete(cert_record)
                db.session.commit()
            
            ssh_client.close()
            
            return {
                "success": True,
                "message": f"Successfully revoked certificate for {site.domain}",
                "output": output
            }
            
        except Exception as e:
            log_activity('error', f"Error revoking certificate for {site.domain} on node {node.name}: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to revoke certificate: {str(e)}"
            }
    
    @staticmethod
    def certificate_health_check():
        """
        Check the health of all SSL certificates across the system
        
        Returns:
            dict: Health check results
        """
        # Get all SSL certificates from database
        certs = SSLCertificate.query.all()
        
        expiring_soon = []
        expired = []
        healthy = []
        
        for cert in certs:
            site = Site.query.get(cert.site_id)
            node = Node.query.get(cert.node_id)
            
            if not site or not node:
                continue
                
            # Skip if not active or valid
            if cert.status not in ['valid', 'expiring soon']:
                continue
                
            cert_info = {
                "site_id": cert.site_id,
                "node_id": cert.node_id,
                "domain": site.domain,
                "node_name": node.name,
                "days_remaining": cert.days_remaining,
                "valid_until": cert.valid_until.strftime('%Y-%m-%d')
            }
            
            if cert.days_remaining <= 0:
                expired.append(cert_info)
            elif cert.days_remaining <= 7:
                expiring_soon.append(cert_info)
            else:
                healthy.append(cert_info)
        
        # Sort by days remaining
        expiring_soon.sort(key=lambda x: x['days_remaining'])
        healthy.sort(key=lambda x: x['days_remaining'])
        
        return {
            "total_certificates": len(certs),
            "healthy_count": len(healthy),
            "expiring_soon_count": len(expiring_soon),
            "expired_count": len(expired),
            "expiring_soon": expiring_soon,
            "expired": expired,
            "healthy": healthy
        }
    
    @staticmethod
    def get_supported_dns_providers():
        """
        Get a list of supported DNS providers for DNS validation
        
        Returns:
            list: Supported DNS providers
        """
        return [
            {
                "name": "Cloudflare",
                "id": "cloudflare",
                "description": "Cloudflare DNS API",
                "credentials": ["API Token"]
            },
            {
                "name": "Route 53",
                "id": "route53",
                "description": "Amazon Route 53 DNS API",
                "credentials": ["Access Key", "Secret Key"]
            },
            {
                "name": "DigitalOcean",
                "id": "digitalocean",
                "description": "DigitalOcean DNS API",
                "credentials": ["API Token"]
            },
            {
                "name": "GoDaddy",
                "id": "godaddy",
                "description": "GoDaddy DNS API",
                "credentials": ["API Key", "API Secret"]
            },
            {
                "name": "Namecheap",
                "id": "namecheap",
                "description": "Namecheap DNS API",
                "credentials": ["Username", "API Key"]
            },
            {
                "name": "Manual DNS",
                "id": "manual",
                "description": "Manual DNS validation (no API)",
                "credentials": []
            }
        ]
    
    @staticmethod
    def generate_self_signed_certificate(site_id, node_id, validity_days=365):
        """
        Generate a self-signed certificate for a site on a node
        
        Args:
            site_id: ID of the site
            node_id: ID of the node
            validity_days: Number of days the certificate should be valid
            
        Returns:
            dict: Certificate generation result
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return {"success": False, "message": "Site or node not found"}
        
        try:
            # Connect to the node
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
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
            
            domain = site.domain
            cert_dir = f"/etc/ssl/self-signed/{domain}"
            cert_path = f"{cert_dir}/fullchain.pem"
            key_path = f"{cert_dir}/privkey.pem"
            
            # Create directory for certificates
            stdin, stdout, stderr = ssh_client.exec_command(f"mkdir -p {cert_dir}")
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                ssh_client.close()
                return {
                    "success": False,
                    "message": f"Failed to create certificate directory: {stderr.read().decode('utf-8')}"
                }
            
            # Generate self-signed certificate with proper Subject Alternative Names (SANs)
            # We include both the domain and www.domain to match Let's Encrypt's behavior
            
            # Create a config file for OpenSSL with SAN extensions
            config_file = f"{cert_dir}/openssl.cnf"
            
            # Prepare SAN entries
            san_domains = [domain]
            if not domain.startswith('www.'):
                san_domains.append(f"www.{domain}")
            
            san_entries = ",".join([f"DNS:{d}" for d in san_domains])
            
            # Generate config file content
            config_content = f"""[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = {domain}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = {san_entries}
"""

            # Write the config file
            sftp = ssh_client.open_sftp()
            with sftp.file(config_file, 'w') as f:
                f.write(config_content)
            sftp.close()
            
            # Generate private key and certificate with SANs
            gen_cert_cmd = f"""
openssl req -x509 -nodes -days {validity_days} -newkey rsa:2048 \
-keyout {key_path} -out {cert_path} \
-config {config_file} -extensions v3_req
"""
            
            stdin, stdout, stderr = ssh_client.exec_command(gen_cert_cmd)
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                error = stderr.read().decode('utf-8')
                ssh_client.close()
                return {
                    "success": False,
                    "message": f"Failed to generate self-signed certificate: {error}"
                }
            
            # Set proper permissions
            stdin, stdout, stderr = ssh_client.exec_command(f"chmod 644 {cert_path} && chmod 600 {key_path}")
            
            # Create symbolic links in the expected Let's Encrypt location to avoid Nginx config changes
            # First ensure the directory exists
            le_dir = f"/etc/letsencrypt/live/{domain}"
            stdin, stdout, stderr = ssh_client.exec_command(f"mkdir -p {le_dir}")
            
            # Create the symlinks if they don't exist
            stdin, stdout, stderr = ssh_client.exec_command(f"""
if [ ! -f {le_dir}/fullchain.pem ]; then
    ln -sf {cert_path} {le_dir}/fullchain.pem
fi
if [ ! -f {le_dir}/privkey.pem ]; then
    ln -sf {key_path} {le_dir}/privkey.pem
fi
if [ ! -f {le_dir}/chain.pem ]; then
    ln -sf {cert_path} {le_dir}/chain.pem
fi
if [ ! -f {le_dir}/cert.pem ]; then
    ln -sf {cert_path} {le_dir}/cert.pem
fi
""")
            
            # Reload Nginx to apply the new certificate
            stdin, stdout, stderr = ssh_client.exec_command(node.nginx_reload_command)
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                error = stderr.read().decode('utf-8')
                ssh_client.close()
                return {
                    "success": False,
                    "message": f"Failed to reload Nginx: {error}"
                }
            
            # Create certificate record in database
            now = datetime.now()
            expiry_date = now + timedelta(days=validity_days)
            
            cert_record = SSLCertificate.query.filter_by(
                site_id=site_id, 
                node_id=node_id
            ).first()
            
            if cert_record:
                # Update existing record
                cert_record.domain = domain  # Ensure domain is set
                cert_record.issuer = domain
                cert_record.subject = domain
                cert_record.valid_from = now
                cert_record.valid_until = expiry_date
                cert_record.days_remaining = validity_days
                cert_record.status = "valid"
                cert_record.is_wildcard = False
                cert_record.is_self_signed = True
                cert_record.updated_at = now
            else:
                # Create new record
                cert_record = SSLCertificate(
                    site_id=site_id,
                    node_id=node_id,
                    domain=domain,  # Explicitly set the domain value
                    issuer=domain,
                    subject=domain,
                    valid_from=now,
                    valid_until=expiry_date,
                    days_remaining=validity_days,
                    status="valid",
                    is_wildcard=False,
                    is_self_signed=True,
                    created_at=now,
                    updated_at=now
                )
                db.session.add(cert_record)
            
            db.session.commit()
            
            ssh_client.close()
            
            log_activity('info', f"Generated self-signed certificate for {domain} on node {node.name}")
            
            return {
                "success": True,
                "message": f"Successfully generated self-signed certificate for {domain}",
                "certificate_path": cert_path,
                "key_path": key_path,
                "domain": domain,
                "valid_until": expiry_date.strftime('%Y-%m-%d'),
                "domains": san_domains,
                "is_self_signed": True
            }
            
        except Exception as e:
            log_activity('error', f"Error generating self-signed certificate for {site.domain} on node {node.name}: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to generate self-signed certificate: {str(e)}"
            }
    
    @staticmethod
    def replace_self_signed_with_real_certificate(site_id, node_id):
        """
        Replace a self-signed certificate with a real Let's Encrypt certificate
        
        Args:
            site_id: ID of the site
            node_id: ID of the node
            
        Returns:
            dict: Replacement result
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return {"success": False, "message": "Site or node not found"}
        
        domain = site.domain
        
        # Check if a self-signed certificate exists first
        cert_record = SSLCertificate.query.filter_by(
            site_id=site_id, 
            node_id=node_id,
            is_self_signed=True
        ).first()
        
        if not cert_record:
            return {"success": False, "message": "No self-signed certificate found to replace"}
        
        try:
            # Connect to the node
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
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
            
            # Check if real Let's Encrypt certificates exist
            le_cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
            le_key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
            
            stdin, stdout, stderr = ssh_client.exec_command(f"test -L {le_cert_path} && echo 'symlink' || echo 'not symlink'")
            is_symlink = stdout.read().decode('utf-8').strip() == 'symlink'
            
            stdin, stdout, stderr = ssh_client.exec_command(f"[ -f {le_cert_path} -a ! -L {le_cert_path} ] && echo 'real' || echo 'not real'")
            is_real_cert = stdout.read().decode('utf-8').strip() == 'real'
            
            if not is_real_cert:
                ssh_client.close()
                return {
                    "success": False,
                    "message": "No real Let's Encrypt certificate found. Request a certificate first."
                }
            
            # If the current certificate is a symlink, remove it
            if is_symlink:
                stdin, stdout, stderr = ssh_client.exec_command(f"rm -f {le_cert_path} {le_key_path}")
                exit_status = stdout.channel.recv_exit_status()
                
                if exit_status != 0:
                    error = stderr.read().decode('utf-8')
                    ssh_client.close()
                    return {
                        "success": False,
                        "message": f"Failed to remove symlink to self-signed certificate: {error}"
                    }
            
            # Update the certificate record
            cert_record.is_self_signed = False
            db.session.commit()
            
            # Reload Nginx to use the new certificate
            stdin, stdout, stderr = ssh_client.exec_command(node.nginx_reload_command)
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                error = stderr.read().decode('utf-8')
                ssh_client.close()
                return {
                    "success": False,
                    "message": f"Failed to reload Nginx: {error}"
                }
            
            ssh_client.close()
            
            log_activity('info', f"Replaced self-signed certificate with real certificate for {domain} on node {node.name}")
            
            return {
                "success": True,
                "message": f"Successfully replaced self-signed certificate with real Let's Encrypt certificate for {domain}"
            }
            
        except Exception as e:
            log_activity('error', f"Error replacing self-signed certificate for {site.domain} on node {node.name}: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to replace self-signed certificate: {str(e)}"
            }
    
    @staticmethod
    def auto_replace_self_signed_certificates():
        """
        Check for self-signed certificates that can be replaced with real Let's Encrypt certificates
        
        Returns:
            dict: Results of automatic replacement
        """
        # Get all self-signed certificates from database
        self_signed_certs = SSLCertificate.query.filter_by(is_self_signed=True).all()
        
        replaced_count = 0
        failed_replacements = []
        
        for cert in self_signed_certs:
            site = Site.query.get(cert.site_id)
            node = Node.query.get(cert.node_id)
            
            if not site or not node:
                continue
            
            # Check if real Let's Encrypt certificate exists
            try:
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
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
                
                le_cert_path = f"/etc/letsencrypt/live/{site.domain}/fullchain.pem"
                
                # Check if real certificate exists (not a symlink)
                stdin, stdout, stderr = ssh_client.exec_command(f"[ -f {le_cert_path} -a ! -L {le_cert_path} ] && echo 'real' || echo 'not real'")
                is_real_cert = stdout.read().decode('utf-8').strip() == 'real'
                
                ssh_client.close()
                
                if is_real_cert:
                    # Replace self-signed with real certificate
                    result = SSLCertificateService.replace_self_signed_with_real_certificate(cert.site_id, cert.node_id)
                    
                    if result.get("success", False):
                        replaced_count += 1
                    else:
                        failed_replacements.append({
                            "site_id": cert.site_id,
                            "node_id": cert.node_id,
                            "domain": site.domain,
                            "error": result.get("message", "Unknown error")
                        })
            
            except Exception as e:
                failed_replacements.append({
                    "site_id": cert.site_id,
                    "node_id": cert.node_id,
                    "domain": site.domain,
                    "error": str(e)
                })
        
        return {
            "self_signed_count": len(self_signed_certs),
            "replaced_count": replaced_count,
            "failed_count": len(failed_replacements),
            "failed_replacements": failed_replacements
        }
    
    @staticmethod
    def get_recommended_node(site_id):
        """
        Determine the best node for a new certificate based on load, availability, etc.
        
        Args:
            site_id: ID of the site needing a certificate
            
        Returns:
            Node: The recommended node or None if no suitable node found
        """
        # Get all active nodes
        nodes = Node.query.filter_by(is_active=True).all()
        if not nodes:
            return None
            
        # Get site-node relationships
        site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
        
        # If the site is already deployed on nodes, prefer those nodes
        deployed_nodes = [sn.node_id for sn in site_nodes if sn.status == 'deployed']
        if deployed_nodes:
            return Node.query.filter(Node.id.in_(deployed_nodes)).first()
            
        # Otherwise, find a node with fewest certificates (for load balancing)
        node_cert_counts = {}
        for node in nodes:
            cert_count = SSLCertificate.query.filter_by(node_id=node.id).count()
            node_cert_counts[node.id] = cert_count
            
        # Get node with the lowest certificate count
        if node_cert_counts:
            min_cert_node_id = min(node_cert_counts, key=node_cert_counts.get)
            return Node.query.get(min_cert_node_id)
            
        # Fallback to the first available node
        return nodes[0]
    
    @staticmethod
    def ensure_ssl_directories(site_id, node_id):
        """
        Ensure SSL directories exist on a node for a site to prevent Nginx from failing
        
        Args:
            site_id: ID of the site
            node_id: ID of the node
            
        Returns:
            dict: Result of the operation
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return {"success": False, "message": "Site or node not found"}
            
        try:
            # Connect to the node
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
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
            
            # Create all necessary directories with proper permissions
            domain = site.domain
            base_dir = "/etc/letsencrypt"
            archive_dir = f"{base_dir}/archive/{domain}"
            live_dir = f"{base_dir}/live/{domain}"
            
            # Create the directory structure with proper permissions
            mkdir_cmd = f"""
            mkdir -p {base_dir}
            mkdir -p {live_dir}
            mkdir -p {archive_dir}
            chmod 755 {base_dir}
            chmod 755 {live_dir}
            chmod 700 {archive_dir}
            """
            stdin, stdout, stderr = ssh_client.exec_command(mkdir_cmd)
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                error = stderr.read().decode('utf-8')
                ssh_client.close()
                return {
                    "success": False,
                    "message": f"Failed to create SSL certificate directories: {error}"
                }
                
            # Check if certificates already exist (either as real files or symlinks)
            stdin, stdout, stderr = ssh_client.exec_command(f"ls -la {live_dir}/fullchain.pem 2>/dev/null || echo 'missing'")
            cert_check = stdout.read().decode('utf-8').strip()
            cert_exists = 'missing' not in cert_check
            
            # If certificates don't exist, create self-signed placeholders
            if not cert_exists:
                # Generate a proper self-signed certificate to prevent Nginx from failing
                log_activity('info', f"Creating temporary self-signed certificate for {domain} on node {node.name}")
                
                # Create a minimal OpenSSL configuration
                openssl_config = f"""
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = {domain}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:{domain}, DNS:www.{domain}
"""
                
                # Write the configuration to a temporary file on the node
                sftp = ssh_client.open_sftp()
                temp_config_path = f"/tmp/{domain}_openssl.cnf"
                with sftp.file(temp_config_path, 'w') as f:
                    f.write(openssl_config)
                
                # Generate all required certificate files in the archive directory
                ssl_gen_cmd = f"""
                # Generate private key and certificate
                openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout {archive_dir}/privkey1.pem -out {archive_dir}/cert1.pem \
                -config {temp_config_path} -extensions v3_req
                
                # Create chain and fullchain
                cp {archive_dir}/cert1.pem {archive_dir}/chain1.pem
                cat {archive_dir}/cert1.pem {archive_dir}/chain1.pem > {archive_dir}/fullchain1.pem
                
                # Set correct permissions
                chmod 600 {archive_dir}/privkey1.pem
                chmod 644 {archive_dir}/cert1.pem {archive_dir}/chain1.pem {archive_dir}/fullchain1.pem
                
                # Create symlinks from live to archive
                ln -sf {archive_dir}/privkey1.pem {live_dir}/privkey.pem
                ln -sf {archive_dir}/cert1.pem {live_dir}/cert.pem
                ln -sf {archive_dir}/chain1.pem {live_dir}/chain.pem
                ln -sf {archive_dir}/fullchain1.pem {live_dir}/fullchain.pem
                
                # Clean up temporary file
                rm {temp_config_path}
                """
                
                stdin, stdout, stderr = ssh_client.exec_command(ssl_gen_cmd)
                exit_status = stdout.channel.recv_exit_status()
                cmd_output = stdout.read().decode('utf-8')
                cmd_error = stderr.read().decode('utf-8')
                
                if exit_status != 0:
                    ssh_client.close()
                    return {
                        "success": False,
                        "message": f"Failed to create temporary SSL certificate: {cmd_error}"
                    }
                
                # Verify that certificates are now in place
                stdin, stdout, stderr = ssh_client.exec_command(f"ls -la {live_dir}/fullchain.pem 2>/dev/null || echo 'still missing'")
                cert_check = stdout.read().decode('utf-8').strip()
                cert_exists = 'still missing' not in cert_check
                
                if not cert_exists:
                    ssh_client.close()
                    return {
                        "success": False,
                        "message": "Failed to verify SSL certificates after creation"
                    }
                
                # Create a database record for this self-signed certificate
                now = datetime.now()
                expiry_date = now + timedelta(days=365)
                
                cert_record = SSLCertificate.query.filter_by(
                    site_id=site_id, 
                    node_id=node_id
                ).first()
                
                if cert_record:
                    # Update existing record
                    cert_record.domain = domain  # Ensure domain is set
                    cert_record.issuer = f"Self-signed ({domain})"
                    cert_record.subject = domain
                    cert_record.valid_from = now
                    cert_record.valid_until = expiry_date
                    cert_record.days_remaining = 365
                    cert_record.status = "valid"
                    cert_record.is_wildcard = False
                    cert_record.is_self_signed = True
                    cert_record.updated_at = now
                else:
                    # Create new record
                    cert_record = SSLCertificate(
                        site_id=site_id,
                        node_id=node_id,
                        domain=domain,  # Explicitly set the domain value
                        issuer=f"Self-signed ({domain})",
                        subject=domain,
                        valid_from=now,
                        valid_until=expiry_date,
                        days_remaining=365,
                        status="valid",
                        is_wildcard=False,
                        is_self_signed=True,
                        created_at=now,
                        updated_at=now
                    )
                    db.session.add(cert_record)
                
                db.session.commit()
                
                log_activity('info', f"Created temporary self-signed certificate for {domain} on node {node.name}")
                
            ssh_client.close()
            
            return {
                "success": True,
                "message": f"SSL certificate directories and files are ready for {domain}",
                "certificate_exists": cert_exists
            }
            
        except Exception as e:
            log_activity('error', f"Error ensuring SSL directories for {site.domain} on node {node.name}: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to ensure SSL directories: {str(e)}"
            }
    
    @staticmethod
    def get_certificates_health_dashboard():
        """
        Generate a comprehensive dashboard of certificate health across all sites and nodes
        
        Returns:
            dict: Certificate health data categorized by status
        """
        # Get all certificates from database
        certificates = SSLCertificate.query.all()
        
        # Initialize dashboard data structure
        dashboard = {
            'total_certificates': len(certificates),
            'valid_certificates': 0,
            'expiring_soon': [],
            'expired': [],
            'self_signed': [],
            'by_node': {},
            'by_site': {},
            'renewal_status': {
                'configured': 0,
                'not_configured': 0
            }
        }
        
        # Process each certificate
        for cert in certificates:
            site = Site.query.get(cert.site_id)
            node = Node.query.get(cert.node_id)
            
            if not site or not node:
                continue
                
            # Add certificate to appropriate category
            if cert.is_self_signed:
                dashboard['self_signed'].append({
                    'domain': site.domain,
                    'site_id': site.id,
                    'node_id': node.id,
                    'node_name': node.name,
                    'valid_until': cert.valid_until,
                    'days_remaining': cert.days_remaining
                })
            elif cert.status == 'valid':
                dashboard['valid_certificates'] += 1
            elif cert.status == 'expiring_soon':
                dashboard['expiring_soon'].append({
                    'domain': site.domain,
                    'site_id': site.id,
                    'node_id': node.id,
                    'node_name': node.name,
                    'valid_until': cert.valid_until,
                    'days_remaining': cert.days_remaining,
                    'is_wildcard': cert.is_wildcard
                })
            elif cert.status == 'expired':
                dashboard['expired'].append({
                    'domain': site.domain,
                    'site_id': site.id,
                    'node_id': node.id,
                    'node_name': node.name,
                    'valid_until': cert.valid_until,
                    'days_remaining': cert.days_remaining,
                    'is_wildcard': cert.is_wildcard
                })
                
            # Group certificates by node
            if node.id not in dashboard['by_node']:
                dashboard['by_node'][node.id] = {
                    'node_name': node.name,
                    'total': 0,
                    'valid': 0,
                    'expiring_soon': 0,
                    'expired': 0,
                    'self_signed': 0
                }
                
            dashboard['by_node'][node.id]['total'] += 1
            
            if cert.is_self_signed:
                dashboard['by_node'][node.id]['self_signed'] += 1
            elif cert.status == 'valid':
                dashboard['by_node'][node.id]['valid'] += 1
            elif cert.status == 'expiring_soon':
                dashboard['by_node'][node.id]['expiring_soon'] += 1
            elif cert.status == 'expired':
                dashboard['by_node'][node.id]['expired'] += 1
                
            # Group certificates by site
            if site.id not in dashboard['by_site']:
                dashboard['by_site'][site.id] = {
                    'domain': site.domain,
                    'total': 0,
                    'valid': 0,
                    'expiring_soon': 0,
                    'expired': 0,
                    'self_signed': 0,
                    'nodes': []
                }
                
            if node.id not in dashboard['by_site'][site.id]['nodes']:
                dashboard['by_site'][site.id]['nodes'].append(node.id)
                
            dashboard['by_site'][site.id]['total'] += 1
            
            if cert.is_self_signed:
                dashboard['by_site'][site.id]['self_signed'] += 1
            elif cert.status == 'valid':
                dashboard['by_site'][site.id]['valid'] += 1
            elif cert.status == 'expiring_soon':
                dashboard['by_site'][site.id]['expiring_soon'] += 1
            elif cert.status == 'expired':
                dashboard['by_site'][site.id]['expired'] += 1
                
        # Check auto-renewal configuration
        for node_id in dashboard['by_node']:
            try:
                node = Node.query.get(node_id)
                if not node:
                    continue
                    
                # Connect to node
                import paramiko
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
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
                    
                # Check if certbot renewal is in crontab
                stdin, stdout, stderr = ssh_client.exec_command("crontab -l 2>/dev/null | grep 'certbot renew' || echo 'not configured'")
                renewal_configured = stdout.read().decode('utf-8').strip() != 'not configured'
                
                ssh_client.close()
                
                if renewal_configured:
                    dashboard['renewal_status']['configured'] += 1
                else:
                    dashboard['renewal_status']['not_configured'] += 1
                    
            except Exception:
                # If we can't connect, assume renewal is not configured
                dashboard['renewal_status']['not_configured'] += 1
                
        return dashboard
    
    @staticmethod
    def cleanup_dummy_certificates(node_id):
        """
        Clean up any temporary dummy certificates created for testing
        
        Args:
            node_id: ID of the node to clean up certificates on
            
        Returns:
            bool: Success indicator
        """
        node = Node.query.get(node_id)
        if not node:
            log_activity('error', f"Cannot clean up dummy certificates: Node {node_id} not found")
            return False
        
        ssh_client = None
        try:
            # Connect to the node
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect using key or password with proper error handling
            try:
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
            except Exception as conn_error:
                log_activity('error', f"Failed to connect to node {node.name} for dummy certificate cleanup: {str(conn_error)}")
                return False
            
            # Check if the dummy certificate directory exists
            dummy_dir = "/etc/nginx/ssl"
            stdin, stdout, stderr = ssh_client.exec_command(f"test -d {dummy_dir} && echo 'exists' || echo 'not found'")
            dir_exists = stdout.read().decode('utf-8').strip() == 'exists'
            
            if not dir_exists:
                # Nothing to clean up
                return True
            
            # Check for dummy certificate files
            dummy_files = [
                "dummy.crt", 
                "dummy.key", 
                "dummy-ca.crt", 
                "dummy-ca.key", 
                "dummy.csr",
                "dummy-chain.pem", 
                "dummy-fullchain.pem"
            ]
            
            # First, check if any of these files actually exist
            files_to_delete = []
            for file in dummy_files:
                file_path = f"{dummy_dir}/{file}"
                stdin, stdout, stderr = ssh_client.exec_command(f"test -f {file_path} && echo 'exists' || echo 'not found'")
                if stdout.read().decode('utf-8').strip() == 'exists':
                    files_to_delete.append(file_path)
            
            if not files_to_delete:
                # No files to clean up
                return True
            
            # Delete the dummy certificate files
            delete_cmd = f"sudo rm -f {' '.join(files_to_delete)}"
            stdin, stdout, stderr = ssh_client.exec_command(delete_cmd)
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                error = stderr.read().decode('utf-8')
                log_activity('warning', f"Error removing dummy certificate files on node {node.name}: {error}")
                return False
            
            log_activity('info', f"Successfully cleaned up {len(files_to_delete)} dummy certificate files on node {node.name}")
            return True
            
        except Exception as e:
            log_activity('error', f"Error cleaning up dummy certificates on node {node.name}: {str(e)}")
            return False
        
        finally:
            # Ensure SSH connection is always closed
            if ssh_client:
                ssh_client.close()