import os
import re
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
        if not domain:
            return {"error": "Site has no domain configured"}
            
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
        import re
        import socket
        import time
        
        for node in nodes:
            try:
                # Connect to node via SSH with timeout and retry logic
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Connection with proper retry logic
                max_connection_attempts = 3
                connection_retry_delay = 2  # seconds
                connected = False
                last_error = None
                
                for attempt in range(max_connection_attempts):
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
                        connected = True
                        break
                    except (paramiko.SSHException, socket.timeout, socket.error, Exception) as e:
                        last_error = str(e)
                        if attempt < max_connection_attempts - 1:
                            time.sleep(connection_retry_delay)
                            log_activity('warning', f"Connection attempt {attempt+1} to node {node.name} failed: {str(e)}. Retrying...")
                
                if not connected:
                    results.append({
                        "node_id": node.id,
                        "node_name": node.name,
                        "ip_address": node.ip_address,
                        "error": f"Failed to connect after {max_connection_attempts} attempts: {last_error}"
                    })
                    continue
                
                # Check certificate paths
                cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
                key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
                
                # Check for certificates in multiple locations
                potential_cert_paths = [
                    # Standard Let's Encrypt paths
                    f"/etc/letsencrypt/live/{domain}/fullchain.pem",
                    
                    # Self-signed certificates
                    f"/etc/nginx/ssl/{domain}.crt",
                    f"/etc/nginx/ssl/self-signed/{domain}.crt",
                    f"/etc/nginx/conf.d/ssl/{domain}.crt",
                    
                    # Common alternate locations
                    f"/etc/ssl/certs/{domain}.crt",
                    f"/etc/ssl/{domain}/fullchain.pem",
                    f"/etc/nginx/certificates/{domain}.crt"
                ]
                
                # Also check for wildcard certificates which might be used by this domain
                domain_parts = domain.split('.')
                
                # Build potential parent domains for wildcard certificate check
                potential_parent_domains = []
                
                # For subdomains like sub.example.com, check example.com wildcard cert
                if len(domain_parts) > 2:
                    # Check immediate parent domain (example.com for sub.example.com)
                    parent_domain = '.'.join(domain_parts[-2:])
                    potential_parent_domains.append(parent_domain)
                    
                    # For deep subdomains, also check intermediate levels
                    # For service.region.example.com, also check region.example.com
                    for i in range(1, len(domain_parts)-1):
                        if len(domain_parts) > i+1:
                            intermediate_domain = '.'.join(domain_parts[i:])
                            if intermediate_domain not in potential_parent_domains:
                                potential_parent_domains.append(intermediate_domain)
                
                # Add wildcard certificate paths for all potential parent domains
                for parent_domain in potential_parent_domains:
                    potential_cert_paths.append(f"/etc/letsencrypt/live/{parent_domain}/fullchain.pem")
                
                # Add paths for domain variations with and without www prefix
                if domain.startswith('www.'):
                    base_domain = domain[4:]  # Remove www.
                    potential_cert_paths.append(f"/etc/letsencrypt/live/{base_domain}/fullchain.pem")
                else:
                    www_domain = f"www.{domain}"
                    potential_cert_paths.append(f"/etc/letsencrypt/live/{www_domain}/fullchain.pem")
                
                # Prepare the result object
                result = {
                    "node_id": node.id,
                    "node_name": node.name,
                    "ip_address": node.ip_address,
                    "checked_paths": potential_cert_paths.copy()
                }
                
                # Search for certificates in all potential locations
                cert_exists = False
                actual_cert_path = None
                actual_key_path = None
                
                for cert_path in potential_cert_paths:
                    stdin, stdout, stderr = ssh_client.exec_command(f"test -f {cert_path} && echo 'exists' || echo 'not found'")
                    if stdout.read().decode('utf-8').strip() == 'exists':
                        cert_exists = True
                        actual_cert_path = cert_path
                        
                        # Determine the key path based on certificate location pattern
                        if 'fullchain.pem' in cert_path:
                            actual_key_path = cert_path.replace('fullchain.pem', 'privkey.pem')
                        elif '.crt' in cert_path:
                            actual_key_path = cert_path.replace('.crt', '.key')
                        
                        # Verify the key exists too
                        if actual_key_path:
                            stdin, stdout, stderr = ssh_client.exec_command(f"test -f {actual_key_path} && echo 'exists' || echo 'not found'")
                            if stdout.read().decode('utf-8').strip() != 'exists':
                                # Key not found, continue searching
                                cert_exists = False
                                actual_cert_path = None
                                actual_key_path = None
                                continue
                        
                        # Found valid cert and key
                        break
                
                if cert_exists and actual_cert_path:
                    cert_found = True
                    cert_path = actual_cert_path
                    key_path = actual_key_path
                    
                    # Get certificate information using OpenSSL with extended details
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
                    elif days_remaining is not None and days_remaining <= 7:
                        status = "critical"
                    elif days_remaining is not None and days_remaining <= 30:
                        status = "expiring_soon"
                    else:
                        status = "valid"
                    
                    # Check if it's a wildcard certificate
                    subject_alt_names = []
                    san_section = cert_output.split("X509v3 Subject Alternative Name:")[1].split("\n\n")[0] if "X509v3 Subject Alternative Name:" in cert_output else ""
                    is_wildcard = "DNS:*." in cert_output
                    
                    # Extract all SANs
                    if san_section:
                        san_entries = re.findall(r'DNS:([^,\s]+)', san_section)
                        subject_alt_names = san_entries
                    
                    # Verify certificate and key match
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f"openssl x509 -noout -modulus -in {cert_path} | openssl md5; " +
                        f"openssl rsa -noout -modulus -in {key_path} 2>/dev/null | openssl md5"
                    )
                    key_match_output = stdout.read().decode('utf-8').strip()
                    key_check_lines = key_match_output.split('\n')
                    key_matches = len(key_check_lines) >= 2 and key_check_lines[0] == key_check_lines[1]
                    
                    # Get certificate type (RSA, ECC) and strength
                    cert_type = "RSA"  # Default assumption
                    key_strength = "2048-bit"  # Default assumption
                    
                    if "Public Key Algorithm: id-ecPublicKey" in cert_output:
                        cert_type = "ECC"
                        # Extract ECC curve name
                        curve_match = re.search(r'ASN1 OID: ([^\n]+)', cert_output)
                        if curve_match:
                            key_strength = curve_match.group(1).strip()
                    else:
                        # Extract RSA key length
                        key_length_match = re.search(r'Public-Key: \((\d+) bit\)', cert_output)
                        if key_length_match:
                            key_strength = f"{key_length_match.group(1)}-bit"
                    
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
                        "subject_alt_names": subject_alt_names,
                        "key_matches": key_matches,
                        "path": cert_path,
                        "key_path": key_path,
                        "cert_type": cert_type,
                        "key_strength": key_strength
                    }
                    
                    # Check auto-renewal configuration
                    stdin, stdout, stderr = ssh_client.exec_command("crontab -l 2>/dev/null | grep -q 'certbot renew' && echo 'configured' || echo 'not configured'")
                    renewal_status = stdout.read().decode('utf-8').strip()
                    result["certificate"]["auto_renewal"] = renewal_status == 'configured'
                    
                    # Check for systemd timer as an alternative renewal method
                    stdin, stdout, stderr = ssh_client.exec_command("systemctl list-timers 2>/dev/null | grep -q 'certbot\\.timer' && echo 'timer_configured' || echo 'no_timer'")
                    timer_status = stdout.read().decode('utf-8').strip()
                    if timer_status == 'timer_configured':
                        result["certificate"]["auto_renewal"] = True
                        result["certificate"]["renewal_method"] = "systemd timer"
                    elif result["certificate"]["auto_renewal"]:
                        result["certificate"]["renewal_method"] = "cron"
                    
                    # Check for chain issues with better error handling
                    if '/etc/letsencrypt/live/' in cert_path:
                        chain_path = cert_path.replace('fullchain.pem', 'chain.pem')
                        cert_only_path = cert_path.replace('fullchain.pem', 'cert.pem')
                        
                        stdin, stdout, stderr = ssh_client.exec_command(f"test -f {chain_path} && test -f {cert_only_path} && echo 'files_exist' || echo 'missing_files'")
                        chain_files_exist = stdout.read().decode('utf-8').strip() == 'files_exist'
                        
                        if chain_files_exist:
                            # Check the certificate chain validity
                            stdin, stdout, stderr = ssh_client.exec_command(
                                f"timeout 10 openssl verify -untrusted {chain_path} {cert_only_path} 2>&1 || echo 'chain_error'"
                            )
                            chain_verify = stdout.read().decode('utf-8').strip()
                            result["certificate"]["chain_valid"] = "chain_error" not in chain_verify and ": OK" in chain_verify
                            
                            if not result["certificate"]["chain_valid"]:
                                result["certificate"]["chain_error"] = chain_verify
                        else:
                            result["certificate"]["chain_valid"] = None
                            result["certificate"]["chain_note"] = "Chain validation skipped - chain.pem or cert.pem not available"
                    else:
                        # For self-signed or non-Let's Encrypt certs
                        result["certificate"]["chain_valid"] = None
                        result["certificate"]["chain_note"] = "Chain validation not applicable for this certificate type"
                else:
                    result["certificate"] = {
                        "exists": False,
                        "message": "No SSL certificate found for this domain"
                    }
                
                # Close the SSH connection
                ssh_client.close()
                results.append(result)
                
            except Exception as e:
                error_message = str(e)
                
                # Provide more helpful information based on common SSH connection issues
                if isinstance(e, paramiko.ssh_exception.NoValidConnectionsError):
                    error_message = f"Cannot connect to {node.ip_address}:{node.ssh_port} - server may be down or port closed"
                elif isinstance(e, paramiko.ssh_exception.AuthenticationException):
                    error_message = f"SSH authentication failed for {node.ssh_user}@{node.ip_address} - check credentials"
                elif isinstance(e, paramiko.ssh_exception.SSHException) and "not found in known_hosts" in str(e):
                    error_message = f"Host key verification failed - consider adding server to known hosts"
                elif isinstance(e, socket.timeout):
                    error_message = f"Connection timed out to {node.ip_address}:{node.ssh_port} - check network or firewall"
                
                results.append({
                    "node_id": node.id,
                    "node_name": node.name,
                    "ip_address": node.ip_address,
                    "error": error_message
                })
        
        return {
            "domain": domain,
            "results": results,
            "cert_found": cert_found,
            "timestamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
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
                    creds_content = f"""
# Cloudflare API credentials for certbot
dns_cloudflare_api_token = {dns_credentials.get('api_token', '')}
"""
                elif dns_provider == 'route53':
                    creds_content = f"""
# AWS Route 53 credentials for certbot
dns_route53_access_key = {dns_credentials.get('access_key', '')}
dns_route53_secret_key = {dns_credentials.get('secret_key', '')}
"""
                elif dns_provider == 'digitalocean':
                    creds_content = f"""
# DigitalOcean API credentials for certbot
dns_digitalocean_token = {dns_credentials.get('api_token', '')}
"""
                elif dns_provider == 'godaddy':
                    creds_content = f"""
# GoDaddy API credentials for certbot
dns_godaddy_key = {dns_credentials.get('api_key', '')}
dns_godaddy_secret = {dns_credentials.get('api_secret', '')}
"""
                elif dns_provider == 'namecheap':
                    creds_content = f"""
# Namecheap API credentials for certbot
dns_namecheap_username = {dns_credentials.get('username', '')}
dns_namecheap_api_key = {dns_credentials.get('api_key', '')}
"""
                
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
        Automatically replace self-signed certificates with Let's Encrypt certificates
        if they already exist on the node
        
        Returns:
            dict: Results of the replacement operation
        """
        # Get all self-signed certificates
        self_signed_certs = SSLCertificate.query.filter_by(is_self_signed=True).all()
        
        results = {
            'self_signed_count': len(self_signed_certs),
            'replaced_count': 0,
            'failed_count': 0,
            'sites_checked': 0,
            'sites_updated': 0,
            'failed_replacements': [],
            'sites': []
        }
        
        replaced_count = 0
        failed_replacements = []
        
        # Get unique sites with self-signed certificates
        site_ids = set([cert.site_id for cert in self_signed_certs])
        sites = Site.query.filter(Site.id.in_(site_ids)).all()
        
        for site in sites:
            site_result = {
                'site_id': site.id,
                'domain': site.domain,
                'nodes': [],
                'status': 'skipped'
            }
            
            # Check each node for this site
            site_nodes = SiteNode.query.filter_by(site_id=site.id).all()
            for site_node in site_nodes:
                node = Node.query.get(site_node.node_id)
                if not node or not node.is_active:
                    continue
                    
                # Check if Let's Encrypt certificate exists
                ssh_client = None
                try:
                    import paramiko
                    
                    ssh_client = paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # Connect to node
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
                    
                    # Check if Let's Encrypt certificate exists
                    le_cert_path = f"/etc/letsencrypt/live/{site.domain}/fullchain.pem"
                    le_key_path = f"/etc/letsencrypt/live/{site.domain}/privkey.pem"
                    
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f"test -f {le_cert_path} && test -f {le_key_path} && echo 'exists' || echo 'not found'"
                    )
                    le_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    
                    if not le_exists:
                        # Also check for wildcard certificates
                        base_domain = '.'.join(site.domain.split('.')[-2:])  # e.g., example.com from sub.example.com
                        le_cert_path_wildcard = f"/etc/letsencrypt/live/{base_domain}/fullchain.pem"
                        
                        stdin, stdout, stderr = ssh_client.exec_command(
                            f"test -f {le_cert_path_wildcard} && echo 'exists' || echo 'not found'"
                        )
                        wildcard_exists = stdout.read().decode('utf-8').strip() == 'exists'
                        
                        if wildcard_exists:
                            le_exists = True
                            le_cert_path = le_cert_path_wildcard
                            le_key_path = le_cert_path_wildcard.replace('fullchain.pem', 'privkey.pem')
                    
                    # Find the Nginx configuration file for this site
                    nginx_site_conf = f"{node.nginx_config_path}/sites/{site.domain}.conf"
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f"test -f {nginx_site_conf} && echo 'exists' || echo 'not found'"
                    )
                    conf_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    
                    if not conf_exists:
                        # Try other common locations
                        potential_paths = [
                            f"{node.nginx_config_path}/{site.domain}.conf",
                            f"{node.nginx_config_path}/sites-enabled/{site.domain}.conf",
                            f"{node.nginx_config_path}/conf.d/{site.domain}.conf"
                        ]
                        
                        for path in potential_paths:
                            stdin, stdout, stderr = ssh_client.exec_command(
                                f"test -f {path} && echo 'exists' || echo 'not found'"
                            )
                            if stdout.read().decode('utf-8').strip() == 'exists':
                                nginx_site_conf = path
                                conf_exists = True
                                break
                    
                    if le_exists and conf_exists:
                        # Backup the current config
                        backup_path = f"{nginx_site_conf}.bak-{int(time.time())}"
                        stdin, stdout, stderr = ssh_client.exec_command(f"cp {nginx_site_conf} {backup_path}")
                        if stdout.channel.recv_exit_status() != 0:
                            raise Exception(f"Failed to create backup: {stderr.read().decode('utf-8')}")
                            
                        # Get current config
                        stdin, stdout, stderr = ssh_client.exec_command(f"cat {nginx_site_conf}")
                        current_config = stdout.read().decode('utf-8')
                        
                        # Check if it's using self-signed certs
                        ssl_cert_line = None
                        ssl_key_line = None
                        
                        for line in current_config.split('\n'):
                            if 'ssl_certificate ' in line and 'self-signed' in line:
                                ssl_cert_line = line.strip()
                            if 'ssl_certificate_key ' in line and 'self-signed' in line:
                                ssl_key_line = line.strip()
                        
                        if ssl_cert_line and ssl_key_line:
                            # Replace cert paths
                            new_config = current_config.replace(
                                ssl_cert_line,
                                f"    ssl_certificate {le_cert_path};"
                            ).replace(
                                ssl_key_line,
                                f"    ssl_certificate_key {le_key_path};"
                            )
                            
                            # Write updated config
                            stdin, stdout, stderr = ssh_client.exec_command(f"cat > {nginx_site_conf} << 'EOF'\n{new_config}\nEOF")
                            if stdout.channel.recv_exit_status() != 0:
                                raise Exception(f"Failed to update config: {stderr.read().decode('utf-8')}")
                                
                            # Test the Nginx config
                            stdin, stdout, stderr = ssh_client.exec_command("nginx -t")
                            nginx_test = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                            
                            if 'test is successful' in nginx_test or 'test successful' in nginx_test:
                                # Reload Nginx
                                stdin, stdout, stderr = ssh_client.exec_command(node.nginx_reload_command)
                                if stdout.channel.recv_exit_status() == 0:
                                    node_result = {
                                        'node_id': node.id,
                                        'node_name': node.name,
                                        'status': 'replaced',
                                        'from': ssl_cert_line,
                                        'to': le_cert_path
                                    }
                                    site_result['nodes'].append(node_result)
                                    site_result['status'] = 'replaced'
                                    results['replaced_count'] += 1
                                else:
                                    # Failed to reload, restore backup
                                    stdin, stdout, stderr = ssh_client.exec_command(f"cp {backup_path} {nginx_site_conf}")
                                    error = stderr.read().decode('utf-8')
                                    node_result = {
                                        'node_id': node.id,
                                        'node_name': node.name,
                                        'status': 'failed',
                                        'error': f"Nginx reload failed: {error}",
                                        'action': 'restored backup'
                                    }
                                    site_result['nodes'].append(node_result)
                                    site_result['status'] = 'failed'
                                    results['failed_count'] += 1
                            else:
                                # Config test failed, restore backup
                                stdin, stdout, stderr = ssh_client.exec_command(f"cp {backup_path} {nginx_site_conf}")
                                error = nginx_test
                                node_result = {
                                    'node_id': node.id,
                                    'node_name': node.name,
                                    'status': 'failed',
                                    'error': f"Nginx config test failed: {error}",
                                    'action': 'restored backup'
                                }
                                site_result['nodes'].append(node_result)
                                site_result['status'] = 'failed'
                                results['failed_count'] += 1
                        else:
                            # No self-signed cert detected in config
                            node_result = {
                                'node_id': node.id,
                                'node_name': node.name,
                                'status': 'skipped',
                                'reason': 'No self-signed certificate found in Nginx config'
                            }
                            site_result['nodes'].append(node_result)
                    else:
                        reason = []
                        if not le_exists:
                            reason.append("No Let's Encrypt certificate found")
                        if not conf_exists:
                            reason.append("No Nginx configuration found")
                            
                        node_result = {
                            'node_id': node.id,
                            'node_name': node.name,
                            'status': 'skipped',
                            'reason': ', '.join(reason)
                        }
                        site_result['nodes'].append(node_result)
                    
                except Exception as e:
                    node_result = {
                        'node_id': node.id,
                        'node_name': node.name,
                        'status': 'error',
                        'error': str(e)
                    }
                    site_result['nodes'].append(node_result)
                    site_result['status'] = 'failed'
                    results['failed_count'] += 1
                finally:
                    # Ensure the SSH client is properly closed
                    if ssh_client:
                        ssh_client.close()
            
            results['sites'].append(site_result)
            if site_result['status'] == 'replaced':
                results['sites_updated'] += 1
            results['sites_checked'] += 1
        
        return results
    
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
                openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
                -keyout {archive_dir}/privkey1.pem -out {archive_dir}/cert1.pem \\
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
                        port=node.ssh_port or 22,
                        username=node.ssh_user,
                        key_filename=node.ssh_key_path,
                        timeout=5
                    )
                else:
                    ssh_client.connect(
                        hostname=node.ip_address,
                        port=node.ssh_port or 22,
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

        # Add summary statistics
        dashboard['summary'] = {
            'total': len(certificates),
            'valid': dashboard['valid_certificates'],
            'expiring_soon': len(dashboard['expiring_soon']),
            'expired': len(dashboard['expired']),
            'self_signed': len(dashboard['self_signed']),
            'nodes_with_certs': len(dashboard['by_node']),
            'sites_with_certs': len(dashboard['by_site']),
            'renewal_configured_percent': (
                (dashboard['renewal_status']['configured'] / len(dashboard['by_node'])) * 100 
                if dashboard['by_node'] else 0
            )
        }
        
        return dashboard
    
    @staticmethod
    def auto_replace_self_signed_certificates():
        """
        Automatically replace self-signed certificates with Let's Encrypt certificates if available
        This is meant to be run as a scheduled task
        
        Returns:
            dict: Results of the replacement operation
        """
        from app.models.models import Site, Node, SiteNode
        
        results = {
            'checked': 0,
            'replaced': 0,
            'failed': 0,
            'sites': []
        }
        
        # Get all sites with self-signed certificates
        health_check = SSLCertificateService.certificate_health_check()
        self_signed_sites = set()
        
        for site_info in health_check.get('self_signed', []):
            self_signed_sites.add(site_info.get('site_id'))
        
        # For each site with self-signed certs, check if we can find a Let's Encrypt cert
        for site_id in self_signed_sites:
            site = Site.query.get(site_id)
            if not site:
                continue
                
            results['checked'] += 1
            site_result = {
                'site_id': site.id,
                'domain': site.domain,
                'nodes': [],
                'status': 'skipped'
            }
            
            # Check each node for this site
            site_nodes = SiteNode.query.filter_by(site_id=site.id).all()
            for site_node in site_nodes:
                node = Node.query.get(site_node.node_id)
                if not node or not node.is_active:
                    continue
                    
                # Check if Let's Encrypt certificate exists
                ssh_client = None
                try:
                    import paramiko
                    
                    ssh_client = paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # Connect to node
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
                    
                    # Check for Let's Encrypt certificate
                    le_cert_path = f"/etc/letsencrypt/live/{site.domain}/fullchain.pem"
                    le_key_path = f"/etc/letsencrypt/live/{site.domain}/privkey.pem"
                    
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f"test -f {le_cert_path} && test -f {le_key_path} && echo 'exists' || echo 'not found'"
                    )
                    le_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    
                    if not le_exists:
                        # Also check for wildcard certificates
                        base_domain = '.'.join(site.domain.split('.')[-2:])  # e.g., example.com from sub.example.com
                        le_cert_path_wildcard = f"/etc/letsencrypt/live/{base_domain}/fullchain.pem"
                        
                        stdin, stdout, stderr = ssh_client.exec_command(
                            f"test -f {le_cert_path_wildcard} && echo 'exists' || echo 'not found'"
                        )
                        wildcard_exists = stdout.read().decode('utf-8').strip() == 'exists'
                        
                        if wildcard_exists:
                            le_exists = True
                            le_cert_path = le_cert_path_wildcard
                            le_key_path = le_cert_path_wildcard.replace('fullchain.pem', 'privkey.pem')
                    
                    # Find the Nginx configuration file for this site
                    nginx_site_conf = f"{node.nginx_config_path}/sites/{site.domain}.conf"
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f"test -f {nginx_site_conf} && echo 'exists' || echo 'not found'"
                    )
                    conf_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    
                    if not conf_exists:
                        # Try other common locations
                        potential_paths = [
                            f"{node.nginx_config_path}/{site.domain}.conf",
                            f"{node.nginx_config_path}/sites-enabled/{site.domain}.conf",
                            f"{node.nginx_config_path}/conf.d/{site.domain}.conf"
                        ]
                        
                        for path in potential_paths:
                            stdin, stdout, stderr = ssh_client.exec_command(
                                f"test -f {path} && echo 'exists' || echo 'not found'"
                            )
                            if stdout.read().decode('utf-8').strip() == 'exists':
                                nginx_site_conf = path
                                conf_exists = True
                                break
                    
                    if le_exists and conf_exists:
                        # Backup the current config
                        backup_path = f"{nginx_site_conf}.bak-{int(time.time())}"
                        stdin, stdout, stderr = ssh_client.exec_command(f"cp {nginx_site_conf} {backup_path}")
                        if stdout.channel.recv_exit_status() != 0:
                            raise Exception(f"Failed to create backup: {stderr.read().decode('utf-8')}")
                            
                        # Get current config
                        stdin, stdout, stderr = ssh_client.exec_command(f"cat {nginx_site_conf}")
                        current_config = stdout.read().decode('utf-8')
                        
                        # Check if it's using self-signed certs
                        ssl_cert_line = None
                        ssl_key_line = None
                        
                        for line in current_config.split('\n'):
                            if 'ssl_certificate ' in line and 'self-signed' in line:
                                ssl_cert_line = line.strip()
                            if 'ssl_certificate_key ' in line and 'self-signed' in line:
                                ssl_key_line = line.strip()
                        
                        if ssl_cert_line and ssl_key_line:
                            # Replace cert paths
                            new_config = current_config.replace(
                                ssl_cert_line,
                                f"    ssl_certificate {le_cert_path};"
                            ).replace(
                                ssl_key_line,
                                f"    ssl_certificate_key {le_key_path};"
                            )
                            
                            # Write updated config
                            stdin, stdout, stderr = ssh_client.exec_command(f"cat > {nginx_site_conf} << 'EOF'\n{new_config}\nEOF")
                            if stdout.channel.recv_exit_status() != 0:
                                raise Exception(f"Failed to update config: {stderr.read().decode('utf-8')}")
                                
                            # Test the Nginx config
                            stdin, stdout, stderr = ssh_client.exec_command("nginx -t")
                            nginx_test = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                            
                            if 'test is successful' in nginx_test or 'test successful' in nginx_test:
                                # Reload Nginx
                                stdin, stdout, stderr = ssh_client.exec_command(node.nginx_reload_command)
                                if stdout.channel.recv_exit_status() == 0:
                                    node_result = {
                                        'node_id': node.id,
                                        'node_name': node.name,
                                        'status': 'replaced',
                                        'from': ssl_cert_line,
                                        'to': le_cert_path
                                    }
                                    site_result['nodes'].append(node_result)
                                    site_result['status'] = 'replaced'
                                    results['replaced'] += 1
                                else:
                                    # Failed to reload, restore backup
                                    stdin, stdout, stderr = ssh_client.exec_command(f"cp {backup_path} {nginx_site_conf}")
                                    error = stderr.read().decode('utf-8')
                                    node_result = {
                                        'node_id': node.id,
                                        'node_name': node.name,
                                        'status': 'failed',
                                        'error': f"Nginx reload failed: {error}",
                                        'action': 'restored backup'
                                    }
                                    site_result['nodes'].append(node_result)
                                    site_result['status'] = 'failed'
                                    results['failed'] += 1
                            else:
                                # Config test failed, restore backup
                                stdin, stdout, stderr = ssh_client.exec_command(f"cp {backup_path} {nginx_site_conf}")
                                error = nginx_test
                                node_result = {
                                    'node_id': node.id,
                                    'node_name': node.name,
                                    'status': 'failed',
                                    'error': f"Nginx config test failed: {error}",
                                    'action': 'restored backup'
                                }
                                site_result['nodes'].append(node_result)
                                site_result['status'] = 'failed'
                                results['failed'] += 1
                        else:
                            # No self-signed cert detected in config
                            node_result = {
                                'node_id': node.id,
                                'node_name': node.name,
                                'status': 'skipped',
                                'reason': 'No self-signed certificate found in Nginx config'
                            }
                            site_result['nodes'].append(node_result)
                    else:
                        reason = []
                        if not le_exists:
                            reason.append("No Let's Encrypt certificate found")
                        if not conf_exists:
                            reason.append("No Nginx configuration found")
                            
                        node_result = {
                            'node_id': node.id,
                            'node_name': node.name,
                            'status': 'skipped',
                            'reason': ', '.join(reason)
                        }
                        site_result['nodes'].append(node_result)
                    
                    ssh_client.close()
                    
                except Exception as e:
                    node_result = {
                        'node_id': node.id,
                        'node_name': node.name,
                        'status': 'error',
                        'error': str(e)
                    }
                    site_result['nodes'].append(node_result)
                    site_result['status'] = 'failed'
                    results['failed'] += 1
                finally:
                    # Ensure the SSH client is properly closed
                    if ssh_client:
                        ssh_client.close()
            
            results['sites'].append(site_result)
        
        # Log results
        log_activity(
            'info',
            f"Auto-replace self-signed certificates completed: "
            f"{results['replaced']} replaced, {results['failed']} failed out of {results['checked']} sites"
        )
        
        return results
    
    @staticmethod
    def ensure_all_ssl_directories_on_node(node_id):
        """
        Ensure SSL directories exist for all configured sites on a node.
        This helps prevent failures when one site's configuration requires certificates for another domain.
        
        Args:
            node_id: ID of the node
            
        Returns:
            dict: Result of the operation
        """
        node = Node.query.get(node_id)
        
        if not node:
            return {"success": False, "message": "Node not found"}
            
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
            
            # First, get all active sites that are deployed on this node
            site_nodes = SiteNode.query.filter_by(node_id=node_id).all()
            sites = []
            for site_node in site_nodes:
                site = Site.query.get(site_node.site_id)
                if site and site.protocol == 'https':
                    sites.append(site)
            
            # Gather all domain names
            domains = [site.domain for site in sites]
            
            # Also scan Nginx configs to find any extra domains referenced in SSL directives
            # This helps find cross-domain dependencies
            stdin, stdout, stderr = ssh_client.exec_command(f"grep -r 'ssl_certificate' {node.nginx_config_path}/*")
            ssl_cert_lines = stdout.read().decode('utf-8').strip().split('\n')
            
            for line in ssl_cert_lines:
                if 'ssl_certificate' in line and '/etc/letsencrypt/live/' in line:
                    # Extract domain from path like /etc/letsencrypt/live/example.com/fullchain.pem
                    domain_match = re.search(r'/etc/letsencrypt/live/([^/]+)/', line)
                    if domain_match:
                        domain = domain_match.group(1)
                        if domain not in domains:
                            domains.append(domain)
            
            # Create directories and dummy certificates for each domain
            created_domains = []
            failed_domains = []
            
            for domain in domains:
                # Create all necessary directories with proper permissions
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
                    failed_domains.append(domain)
                    continue
                
                # Check if certificates already exist
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
                    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
                    -keyout {archive_dir}/privkey1.pem -out {archive_dir}/cert1.pem \\
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
                    
                    if exit_status == 0:
                        created_domains.append(domain)
                    else:
                        failed_domains.append(domain)
                else:
                    # Certificate already exists
                    created_domains.append(domain)
            
            ssh_client.close()
            
            # Return the results
            return {
                "success": True,
                "message": f"SSL certificate directories prepared for {len(created_domains)} domains",
                "domains_processed": domains,
                "domains_created": created_domains,
                "domains_failed": failed_domains
            }
            
        except Exception as e:
            log_activity('error', f"Error ensuring SSL directories on node {node.name}: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to ensure SSL directories: {str(e)}"
            }
    
    @staticmethod
    def configure_automated_ssl_renewal_check():
        """
        Set up automated SSL certificate renewal check and send notifications for expiring certificates
        
        Returns:
            dict: Configuration result
        """
        # We'll add a cron job that checks for expiring certificates daily
        try:
            # Get email configuration from app config
            from flask import current_app
            admin_email = current_app.config.get('ADMIN_EMAIL', '')
            
            if not admin_email:
                log_activity('warning', "No admin email configured for SSL expiry notifications")
            
            # Create a script file to check certificates
            check_script = """#!/bin/bash
# Script to check SSL certificate expiry and send notifications

# Output file for results
output_file="/tmp/ssl_expiry_check.txt"
echo "SSL Certificate Expiry Check - $(date)" > $output_file

# Check for SSL certificates expiring in the next 30 days
for domain_dir in /etc/letsencrypt/live/*/; do
    domain=$(basename "$domain_dir")
    cert_file="${domain_dir}fullchain.pem"
    
    if [ -f "$cert_file" ]; then
        expiry_date=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
        expiry_epoch=$(date -d "$expiry_date" +%s)
        current_epoch=$(date +%s)
        seconds_until_expiry=$((expiry_epoch - current_epoch))
        days_until_expiry=$((seconds_until_expiry / 86400))
        
        echo "Domain: $domain, Expires in: $days_until_expiry days" >> $output_file
        
        if [ $days_until_expiry -le 30 ]; then
            echo "WARNING: Certificate for $domain expires in $days_until_expiry days" >> $output_file
            
            # Try to renew automatically
            certbot renew --cert-name "$domain" --quiet
            
            # Check if renewal was successful
            new_expiry_date=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
            new_expiry_epoch=$(date -d "$new_expiry_date" +%s)
            new_seconds_until_expiry=$((new_expiry_epoch - current_epoch))
            new_days_until_expiry=$((new_seconds_until_expiry / 86400))
            
            if [ $new_days_until_expiry -gt $days_until_expiry ]; then
                echo "SUCCESS: Certificate for $domain renewed successfully" >> $output_file
            else
                echo "FAILURE: Certificate for $domain could not be renewed" >> $output_file
                
                # Send notification email if configured
                if [ -n "$ADMIN_EMAIL" ]; then
                    echo "Certificate renewal for $domain failed. Please check manually." | mail -s "SSL Certificate Renewal Failed for $domain" $ADMIN_EMAIL
                fi
            fi
        fi
    fi
done

# Send summary if any certificates are expiring soon
if grep -q "WARNING" $output_file; then
    if [ -n "$ADMIN_EMAIL" ]; then
        cat $output_file | mail -s "SSL Certificate Expiry Warning" $ADMIN_EMAIL
    fi
fi
"""
            
            # Install the script on all active nodes
            nodes = Node.query.filter_by(is_active=True).all()
            results = []
            
            for node in nodes:
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
                    
                    # Create the script file
                    script_path = "/usr/local/bin/check_ssl_expiry.sh"
                    
                    # Replace placeholder with actual admin email
                    script_content = check_script.replace("$ADMIN_EMAIL", admin_email)
                    
                    # Write the script to the node
                    sftp = ssh_client.open_sftp()
                    with sftp.file(script_path, 'w') as f:
                        f.write(script_content)
                    sftp.close()
                    
                    # Make it executable
                    ssh_client.exec_command(f"chmod +x {script_path}")
                    
                    # Add cron job to run daily
                    cron_cmd = f"0 3 * * * {script_path} > /dev/null 2>&1"
                    ssh_client.exec_command(f"(crontab -l 2>/dev/null | grep -v check_ssl_expiry.sh; echo '{cron_cmd}') | crontab -")
                    
                    # Install mail utility if not present
                    ssh_client.exec_command("which mail >/dev/null || (apt-get update && apt-get install -y mailutils)")
                    
                    # Verify cron job was added
                    stdin, stdout, stderr = ssh_client.exec_command("crontab -l | grep check_ssl_expiry.sh")
                    verification = stdout.read().decode('utf-8').strip()
                    
                    node_result = {
                        "node_id": node.id,
                        "node_name": node.name,
                        "success": bool(verification),
                        "cron_job": verification if verification else None
                    }
                    
                    # Ensure renewal hook is setup
                    hook_path = "/etc/letsencrypt/renewal-hooks/post"
                    ssh_client.exec_command(f"mkdir -p {hook_path}")
                    
                    # Create a hook script to reload Nginx
                    hook_script = """#!/bin/bash
# Hook script to reload Nginx after certificate renewal
nginx -t && systemctl reload nginx || echo "Nginx reload failed"
"""
                    
                    hook_file = f"{hook_path}/reload-nginx.sh"
                    sftp = ssh_client.open_sftp()
                    with sftp.file(hook_file, 'w') as f:
                        f.write(hook_script)
                    sftp.close()
                    
                    # Make it executable
                    ssh_client.exec_command(f"chmod +x {hook_file}")
                    
                    ssh_client.close()
                    
                    results.append(node_result)
                    
                except Exception as e:
                    results.append({
                        "node_id": node.id,
                        "node_name": node.name,
                        "success": False,
                        "error": str(e)
                    })
            
            # Count successes and failures
            successes = sum(1 for result in results if result.get("success", False))
            failures = len(results) - successes
            
            log_activity('info', f"SSL renewal check configured on {successes} nodes, failed on {failures} nodes")
            
            return {
                "success": successes > 0,
                "message": f"SSL renewal check configured on {successes} nodes, failed on {failures} nodes",
                "configured_nodes": successes,
                "failed_nodes": failures,
                "results": results
            }
            
        except Exception as e:
            log_activity('error', f"Failed to configure SSL renewal check: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to configure SSL renewal check: {str(e)}"
            }
    
    @staticmethod
    def certificate_health_check(site_id=None):
        """
        Perform a comprehensive health check on SSL certificates across all or a specific site
        
        Args:
            site_id (int, optional): Specific site ID to check or None for all sites
            
        Returns:
            dict: Health check results with issues and summary
        """
        from app.models.models import Site, Node, SiteNode
        
        results = {
            'checked': 0,
            'healthy': 0,
            'issues': [],
            'expiring_soon': [],
            'expired': [],
            'self_signed': [],
            'missing': [],
            'chain_issues': [],
            'key_mismatch': [],
            'summary': {}
        }
        
        # Get sites to check
        if site_id:
            sites = [Site.query.get(site_id)]
            if not sites[0]:
                return {'error': f'Site ID {site_id} not found'}
        else:
            # Check all active sites
            sites = Site.query.filter_by(is_active=True).all()
            
        # Check each site
        for site in sites:
            result = SSLCertificateService.check_certificate_status(site.id)
            results['checked'] += 1
            
            # Analyze the certificate status for this site
            cert_found = result.get('cert_found', False)
            has_issues = False
            
            if not cert_found:
                has_issues = True
                results['missing'].append({
                    'site_id': site.id,
                    'domain': site.domain,
                    'nodes': len(result.get('results', []))
                })
                continue
            
            # Check each node's certificate
            for node_result in result.get('results', []):
                if 'error' in node_result:
                    has_issues = True
                    results['issues'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name'),
                        'issue': 'connection_error',
                        'details': node_result.get('error')
                    })
                    continue
                
                cert_info = node_result.get('certificate', {})
                if not cert_info.get('exists', False):
                    has_issues = True
                    results['missing'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name')
                    })
                    continue
                
                # Check various certificate issues
                if cert_info.get('status') == 'expired':
                    has_issues = True
                    results['expired'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name'),
                        'valid_until': cert_info.get('valid_until')
                    })
                
                if cert_info.get('status') in ['critical', 'expiring_soon'] and cert_info.get('days_remaining', 30) <= 30:
                    has_issues = True
                    results['expiring_soon'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name'),
                        'days_remaining': cert_info.get('days_remaining'),
                        'valid_until': cert_info.get('valid_until')
                    })
                
                if cert_info.get('is_self_signed', False):
                    has_issues = True
                    results['self_signed'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name')
                    })
                
                if cert_info.get('chain_valid') is False:
                    has_issues = True
                    results['chain_issues'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name'),
                        'error': cert_info.get('chain_error', 'Unknown chain validation error')
                    })
                
                if cert_info.get('key_matches') is False:
                    has_issues = True
                    results['key_mismatch'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name'),
                        'cert_path': cert_info.get('path'),
                        'key_path': cert_info.get('key_path')
                    })
            
            if not has_issues:
                results['healthy'] += 1
        
        # Generate summary statistics
        results['summary'] = {
            'total_checked': results['checked'],
            'healthy': results['healthy'],
            'with_issues': results['checked'] - results['healthy'],
            'issues_by_type': {
                'missing': len(results['missing']),
                'expired': len(results['expired']),
                'expiring_soon': len(results['expiring_soon']),
                'self_signed': len(results['self_signed']),
                'chain_issues': len(results['chain_issues']),
                'key_mismatch': len(results['key_mismatch'])
            }
        }
        
        # Log health check results
        log_activity(
            'info',
            f"SSL certificate health check completed: {results['healthy']} healthy, "
            f"{results['checked'] - results['healthy']} with issues out of {results['checked']} sites"
        )
        
        if results['checked'] - results['healthy'] > 0:
            log_activity(
                'warning',
                f"SSL certificate issues detected: {len(results['expired'])} expired, "
                f"{len(results['expiring_soon'])} expiring soon, {len(results['missing'])} missing"
            )
        
        return results
        
    @staticmethod
    def auto_replace_self_signed_certificates():
        """
        Automatically replace self-signed certificates with Let's Encrypt certificates if available
        This is meant to be run as a scheduled task
        
        Returns:
            dict: Results of the replacement operation
        """
        from app.models.models import Site, Node, SiteNode
        
        results = {
            'checked': 0,
            'replaced': 0,
            'failed': 0,
            'sites': []
        }
        
        # Get all sites with self-signed certificates
        health_check = SSLCertificateService.certificate_health_check()
        self_signed_sites = set()
        
        for site_info in health_check.get('self_signed', []):
            self_signed_sites.add(site_info.get('site_id'))
        
        # For each site with self-signed certs, check if we can find a Let's Encrypt cert
        for site_id in self_signed_sites:
            site = Site.query.get(site_id)
            if not site:
                continue
                
            results['checked'] += 1
            site_result = {
                'site_id': site.id,
                'domain': site.domain,
                'nodes': [],
                'status': 'skipped'
            }
            
            # Check each node for this site
            site_nodes = SiteNode.query.filter_by(site_id=site.id).all()
            for site_node in site_nodes:
                node = Node.query.get(site_node.node_id)
                if not node or not node.is_active:
                    continue
                    
                # Check if Let's Encrypt certificate exists
                ssh_client = None
                try:
                    import paramiko
                    
                    ssh_client = paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # Connect to node
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
                    
                    # Check for Let's Encrypt certificate
                    le_cert_path = f"/etc/letsencrypt/live/{site.domain}/fullchain.pem"
                    le_key_path = f"/etc/letsencrypt/live/{site.domain}/privkey.pem"
                    
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f"test -f {le_cert_path} && test -f {le_key_path} && echo 'exists' || echo 'not found'"
                    )
                    le_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    
                    if not le_exists:
                        # Also check for wildcard certificates
                        base_domain = '.'.join(site.domain.split('.')[-2:])  # e.g., example.com from sub.example.com
                        le_cert_path_wildcard = f"/etc/letsencrypt/live/{base_domain}/fullchain.pem"
                        
                        stdin, stdout, stderr = ssh_client.exec_command(
                            f"test -f {le_cert_path_wildcard} && echo 'exists' || echo 'not found'"
                        )
                        wildcard_exists = stdout.read().decode('utf-8').strip() == 'exists'
                        
                        if wildcard_exists:
                            le_exists = True
                            le_cert_path = le_cert_path_wildcard
                            le_key_path = le_cert_path_wildcard.replace('fullchain.pem', 'privkey.pem')
                    
                    # Find the Nginx configuration file for this site
                    nginx_site_conf = f"{node.nginx_config_path}/sites/{site.domain}.conf"
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f"test -f {nginx_site_conf} && echo 'exists' || echo 'not found'"
                    )
                    conf_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    
                    if not conf_exists:
                        # Try other common locations
                        potential_paths = [
                            f"{node.nginx_config_path}/{site.domain}.conf",
                            f"{node.nginx_config_path}/sites-enabled/{site.domain}.conf",
                            f"{node.nginx_config_path}/conf.d/{site.domain}.conf"
                        ]
                        
                        for path in potential_paths:
                            stdin, stdout, stderr = ssh_client.exec_command(
                                f"test -f {path} && echo 'exists' || echo 'not found'"
                            )
                            if stdout.read().decode('utf-8').strip() == 'exists':
                                nginx_site_conf = path
                                conf_exists = True
                                break
                    
                    if le_exists and conf_exists:
                        # Backup the current config
                        backup_path = f"{nginx_site_conf}.bak-{int(time.time())}"
                        stdin, stdout, stderr = ssh_client.exec_command(f"cp {nginx_site_conf} {backup_path}")
                        if stdout.channel.recv_exit_status() != 0:
                            raise Exception(f"Failed to create backup: {stderr.read().decode('utf-8')}")
                            
                        # Get current config
                        stdin, stdout, stderr = ssh_client.exec_command(f"cat {nginx_site_conf}")
                        current_config = stdout.read().decode('utf-8')
                        
                        # Check if it's using self-signed certs
                        ssl_cert_line = None
                        ssl_key_line = None
                        
                        for line in current_config.split('\n'):
                            if 'ssl_certificate ' in line and 'self-signed' in line:
                                ssl_cert_line = line.strip()
                            if 'ssl_certificate_key ' in line and 'self-signed' in line:
                                ssl_key_line = line.strip()
                        
                        if ssl_cert_line and ssl_key_line:
                            # Replace cert paths
                            new_config = current_config.replace(
                                ssl_cert_line,
                                f"    ssl_certificate {le_cert_path};"
                            ).replace(
                                ssl_key_line,
                                f"    ssl_certificate_key {le_key_path};"
                            )
                            
                            # Write updated config
                            stdin, stdout, stderr = ssh_client.exec_command(f"cat > {nginx_site_conf} << 'EOF'\n{new_config}\nEOF")
                            if stdout.channel.recv_exit_status() != 0:
                                raise Exception(f"Failed to update config: {stderr.read().decode('utf-8')}")
                                
                            # Test the Nginx config
                            stdin, stdout, stderr = ssh_client.exec_command("nginx -t")
                            nginx_test = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                            
                            if 'test is successful' in nginx_test or 'test successful' in nginx_test:
                                # Reload Nginx
                                stdin, stdout, stderr = ssh_client.exec_command(node.nginx_reload_command)
                                if stdout.channel.recv_exit_status() == 0:
                                    node_result = {
                                        'node_id': node.id,
                                        'node_name': node.name,
                                        'status': 'replaced',
                                        'from': ssl_cert_line,
                                        'to': le_cert_path
                                    }
                                    site_result['nodes'].append(node_result)
                                    site_result['status'] = 'replaced'
                                    results['replaced'] += 1
                                else:
                                    # Failed to reload, restore backup
                                    stdin, stdout, stderr = ssh_client.exec_command(f"cp {backup_path} {nginx_site_conf}")
                                    error = stderr.read().decode('utf-8')
                                    node_result = {
                                        'node_id': node.id,
                                        'node_name': node.name,
                                        'status': 'failed',
                                        'error': f"Nginx reload failed: {error}",
                                        'action': 'restored backup'
                                    }
                                    site_result['nodes'].append(node_result)
                                    site_result['status'] = 'failed'
                                    results['failed'] += 1
                            else:
                                # Config test failed, restore backup
                                stdin, stdout, stderr = ssh_client.exec_command(f"cp {backup_path} {nginx_site_conf}")
                                error = nginx_test
                                node_result = {
                                    'node_id': node.id,
                                    'node_name': node.name,
                                    'status': 'failed',
                                    'error': f"Nginx config test failed: {error}",
                                    'action': 'restored backup'
                                }
                                site_result['nodes'].append(node_result)
                                site_result['status'] = 'failed'
                                results['failed'] += 1
                        else:
                            # No self-signed cert detected in config
                            node_result = {
                                'node_id': node.id,
                                'node_name': node.name,
                                'status': 'skipped',
                                'reason': 'No self-signed certificate found in Nginx config'
                            }
                            site_result['nodes'].append(node_result)
                    else:
                        reason = []
                        if not le_exists:
                            reason.append("No Let's Encrypt certificate found")
                        if not conf_exists:
                            reason.append("No Nginx configuration found")
                            
                        node_result = {
                            'node_id': node.id,
                            'node_name': node.name,
                            'status': 'skipped',
                            'reason': ', '.join(reason)
                        }
                        site_result['nodes'].append(node_result)
                    
                    ssh_client.close()
                    
                except Exception as e:
                    node_result = {
                        'node_id': node.id,
                        'node_name': node.name,
                        'status': 'error',
                        'error': str(e)
                    }
                    site_result['nodes'].append(node_result)
                    site_result['status'] = 'failed'
                    results['failed'] += 1
                finally:
                    # Ensure the SSH client is properly closed
                    if ssh_client:
                        ssh_client.close()
            
            results['sites'].append(site_result)
        
        # Log results
        log_activity(
            'info',
            f"Auto-replace self-signed certificates completed: "
            f"{results['replaced']} replaced, {results['failed']} failed out of {results['checked']} sites"
        )
        
        return results
    
    @staticmethod
    def ensure_all_ssl_directories_on_node(node_id):
        """
        Ensure SSL directories exist for all configured sites on a node.
        This helps prevent failures when one site's configuration requires certificates for another domain.
        
        Args:
            node_id: ID of the node
            
        Returns:
            dict: Result of the operation
        """
        node = Node.query.get(node_id)
        
        if not node:
            return {"success": False, "message": "Node not found"}
            
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
            
            # First, get all active sites that are deployed on this node
            site_nodes = SiteNode.query.filter_by(node_id=node_id).all()
            sites = []
            for site_node in site_nodes:
                site = Site.query.get(site_node.site_id)
                if site and site.protocol == 'https':
                    sites.append(site)
            
            # Gather all domain names
            domains = [site.domain for site in sites]
            
            # Also scan Nginx configs to find any extra domains referenced in SSL directives
            # This helps find cross-domain dependencies
            stdin, stdout, stderr = ssh_client.exec_command(f"grep -r 'ssl_certificate' {node.nginx_config_path}/*")
            ssl_cert_lines = stdout.read().decode('utf-8').strip().split('\n')
            
            for line in ssl_cert_lines:
                if 'ssl_certificate' in line and '/etc/letsencrypt/live/' in line:
                    # Extract domain from path like /etc/letsencrypt/live/example.com/fullchain.pem
                    domain_match = re.search(r'/etc/letsencrypt/live/([^/]+)/', line)
                    if domain_match:
                        domain = domain_match.group(1)
                        if domain not in domains:
                            domains.append(domain)
            
            # Create directories and dummy certificates for each domain
            created_domains = []
            failed_domains = []
            
            for domain in domains:
                # Create all necessary directories with proper permissions
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
                    failed_domains.append(domain)
                    continue
                
                # Check if certificates already exist
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
                    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
                    -keyout {archive_dir}/privkey1.pem -out {archive_dir}/cert1.pem \\
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
                    
                    if exit_status == 0:
                        created_domains.append(domain)
                    else:
                        failed_domains.append(domain)
                else:
                    # Certificate already exists
                    created_domains.append(domain)
            
            ssh_client.close()
            
            # Return the results
            return {
                "success": True,
                "message": f"SSL certificate directories prepared for {len(created_domains)} domains",
                "domains_processed": domains,
                "domains_created": created_domains,
                "domains_failed": failed_domains
            }
            
        except Exception as e:
            log_activity('error', f"Error ensuring SSL directories on node {node.name}: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to ensure SSL directories: {str(e)}"
            }
    
    @staticmethod
    def certificate_health_check(site_id=None):
        """
        Perform a comprehensive health check on SSL certificates across all or a specific site
        
        Args:
            site_id (int, optional): Specific site ID to check or None for all sites
            
        Returns:
            dict: Health check results with issues and summary
        """
        from app.models.models import Site, Node, SiteNode
        
        results = {
            'checked': 0,
            'healthy': 0,
            'issues': [],
            'expiring_soon': [],
            'expired': [],
            'self_signed': [],
            'missing': [],
            'chain_issues': [],
            'key_mismatch': [],
            'summary': {}
        }
        
        # Get sites to check
        if site_id:
            sites = [Site.query.get(site_id)]
            if not sites[0]:
                return {'error': f'Site ID {site_id} not found'}
        else:
            # Check all active sites
            sites = Site.query.filter_by(is_active=True).all()
            
        # Check each site
        for site in sites:
            result = SSLCertificateService.check_certificate_status(site.id)
            results['checked'] += 1
            
            # Analyze the certificate status for this site
            cert_found = result.get('cert_found', False)
            has_issues = False
            
            if not cert_found:
                has_issues = True
                results['missing'].append({
                    'site_id': site.id,
                    'domain': site.domain,
                    'nodes': len(result.get('results', []))
                })
                continue
            
            # Check each node's certificate
            for node_result in result.get('results', []):
                if 'error' in node_result:
                    has_issues = True
                    results['issues'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name'),
                        'issue': 'connection_error',
                        'details': node_result.get('error')
                    })
                    continue
                
                cert_info = node_result.get('certificate', {})
                if not cert_info.get('exists', False):
                    has_issues = True
                    results['missing'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name')
                    })
                    continue
                
                # Check various certificate issues
                if cert_info.get('status') == 'expired':
                    has_issues = True
                    results['expired'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name'),
                        'valid_until': cert_info.get('valid_until')
                    })
                
                if cert_info.get('status') in ['critical', 'expiring_soon'] and cert_info.get('days_remaining', 30) <= 30:
                    has_issues = True
                    results['expiring_soon'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name'),
                        'days_remaining': cert_info.get('days_remaining'),
                        'valid_until': cert_info.get('valid_until')
                    })
                
                if cert_info.get('is_self_signed', False):
                    has_issues = True
                    results['self_signed'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name')
                    })
                
                if cert_info.get('chain_valid') is False:
                    has_issues = True
                    results['chain_issues'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name'),
                        'error': cert_info.get('chain_error', 'Unknown chain validation error')
                    })
                
                if cert_info.get('key_matches') is False:
                    has_issues = True
                    results['key_mismatch'].append({
                        'site_id': site.id,
                        'domain': site.domain,
                        'node_id': node_result.get('node_id'),
                        'node_name': node_result.get('node_name'),
                        'cert_path': cert_info.get('path'),
                        'key_path': cert_info.get('key_path')
                    })
            
            if not has_issues:
                results['healthy'] += 1
        
        # Generate summary statistics
        results['summary'] = {
            'total_checked': results['checked'],
            'healthy': results['healthy'],
            'with_issues': results['checked'] - results['healthy'],
            'issues_by_type': {
                'missing': len(results['missing']),
                'expired': len(results['expired']),
                'expiring_soon': len(results['expiring_soon']),
                'self_signed': len(results['self_signed']),
                'chain_issues': len(results['chain_issues']),
                'key_mismatch': len(results['key_mismatch'])
            }
        }
        
        # Log health check results
        log_activity(
            'info',
            f"SSL certificate health check completed: {results['healthy']} healthy, "
            f"{results['checked'] - results['healthy']} with issues out of {results['checked']} sites"
        )
        
        if results['checked'] - results['healthy'] > 0:
            log_activity(
                'warning',
                f"SSL certificate issues detected: {len(results['expired'])} expired, "
                f"{len(results['expiring_soon'])} expiring soon, {len(results['missing'])} missing"
            )
        
        return results
        
    @staticmethod
    def auto_replace_self_signed_certificates():
        """
        Automatically replace self-signed certificates with Let's Encrypt certificates if available
        This is meant to be run as a scheduled task
        
        Returns:
            dict: Results of the replacement operation
        """
        from app.models.models import Site, Node, SiteNode
        
        results = {
            'checked': 0,
            'replaced': 0,
            'failed': 0,
            'sites': []
        }
        
        # Get all sites with self-signed certificates
        health_check = SSLCertificateService.certificate_health_check()
        self_signed_sites = set()
        
        for site_info in health_check.get('self_signed', []):
            self_signed_sites.add(site_info.get('site_id'))
        
        # For each site with self-signed certs, check if we can find a Let's Encrypt cert
        for site_id in self_signed_sites:
            site = Site.query.get(site_id)
            if not site:
                continue
                
            results['checked'] += 1
            site_result = {
                'site_id': site.id,
                'domain': site.domain,
                'nodes': [],
                'status': 'skipped'
            }
            
            # Check each node for this site
            site_nodes = SiteNode.query.filter_by(site_id=site.id).all()
            for site_node in site_nodes:
                node = Node.query.get(site_node.node_id)
                if not node or not node.is_active:
                    continue
                    
                # Check if Let's Encrypt certificate exists
                ssh_client = None
                try:
                    import paramiko
                    
                    ssh_client = paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # Connect to node
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
                    
                    # Check for Let's Encrypt certificate
                    le_cert_path = f"/etc/letsencrypt/live/{site.domain}/fullchain.pem"
                    le_key_path = f"/etc/letsencrypt/live/{site.domain}/privkey.pem"
                    
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f"test -f {le_cert_path} && test -f {le_key_path} && echo 'exists' || echo 'not found'"
                    )
                    le_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    
                    if not le_exists:
                        # Also check for wildcard certificates
                        base_domain = '.'.join(site.domain.split('.')[-2:])  # e.g., example.com from sub.example.com
                        le_cert_path_wildcard = f"/etc/letsencrypt/live/{base_domain}/fullchain.pem"
                        
                        stdin, stdout, stderr = ssh_client.exec_command(
                            f"test -f {le_cert_path_wildcard} && echo 'exists' || echo 'not found'"
                        )
                        wildcard_exists = stdout.read().decode('utf-8').strip() == 'exists'
                        
                        if wildcard_exists:
                            le_exists = True
                            le_cert_path = le_cert_path_wildcard
                            le_key_path = le_cert_path_wildcard.replace('fullchain.pem', 'privkey.pem')
                    
                    # Find the Nginx configuration file for this site
                    nginx_site_conf = f"{node.nginx_config_path}/sites/{site.domain}.conf"
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f"test -f {nginx_site_conf} && echo 'exists' || echo 'not found'"
                    )
                    conf_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    
                    if not conf_exists:
                        # Try other common locations
                        potential_paths = [
                            f"{node.nginx_config_path}/{site.domain}.conf",
                            f"{node.nginx_config_path}/sites-enabled/{site.domain}.conf",
                            f"{node.nginx_config_path}/conf.d/{site.domain}.conf"
                        ]
                        
                        for path in potential_paths:
                            stdin, stdout, stderr = ssh_client.exec_command(
                                f"test -f {path} && echo 'exists' || echo 'not found'"
                            )
                            if stdout.read().decode('utf-8').strip() == 'exists':
                                nginx_site_conf = path
                                conf_exists = True
                                break
                    
                    if le_exists and conf_exists:
                        # Backup the current config
                        backup_path = f"{nginx_site_conf}.bak-{int(time.time())}"
                        stdin, stdout, stderr = ssh_client.exec_command(f"cp {nginx_site_conf} {backup_path}")
                        if stdout.channel.recv_exit_status() != 0:
                            raise Exception(f"Failed to create backup: {stderr.read().decode('utf-8')}")
                            
                        # Get current config
                        stdin, stdout, stderr = ssh_client.exec_command(f"cat {nginx_site_conf}")
                        current_config = stdout.read().decode('utf-8')
                        
                        # Check if it's using self-signed certs
                        ssl_cert_line = None
                        ssl_key_line = None
                        
                        for line in current_config.split('\n'):
                            if 'ssl_certificate ' in line and 'self-signed' in line:
                                ssl_cert_line = line.strip()
                            if 'ssl_certificate_key ' in line and 'self-signed' in line:
                                ssl_key_line = line.strip()
                        
                        if ssl_cert_line and ssl_key_line:
                            # Replace cert paths
                            new_config = current_config.replace(
                                ssl_cert_line,
                                f"    ssl_certificate {le_cert_path};"
                            ).replace(
                                ssl_key_line,
                                f"    ssl_certificate_key {le_key_path};"
                            )
                            
                            # Write updated config
                            stdin, stdout, stderr = ssh_client.exec_command(f"cat > {nginx_site_conf} << 'EOF'\n{new_config}\nEOF")
                            if stdout.channel.recv_exit_status() != 0:
                                raise Exception(f"Failed to update config: {stderr.read().decode('utf-8')}")
                                
                            # Test the Nginx config
                            stdin, stdout, stderr = ssh_client.exec_command("nginx -t")
                            nginx_test = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                            
                            if 'test is successful' in nginx_test or 'test successful' in nginx_test:
                                # Reload Nginx
                                stdin, stdout, stderr = ssh_client.exec_command(node.nginx_reload_command)
                                if stdout.channel.recv_exit_status() == 0:
                                    node_result = {
                                        'node_id': node.id,
                                        'node_name': node.name,
                                        'status': 'replaced',
                                        'from': ssl_cert_line,
                                        'to': le_cert_path
                                    }
                                    site_result['nodes'].append(node_result)
                                    site_result['status'] = 'replaced'
                                    results['replaced'] += 1
                                else:
                                    # Failed to reload, restore backup
                                    stdin, stdout, stderr = ssh_client.exec_command(f"cp {backup_path} {nginx_site_conf}")
                                    error = stderr.read().decode('utf-8')
                                    node_result = {
                                        'node_id': node.id,
                                        'node_name': node.name,
                                        'status': 'failed',
                                        'error': f"Nginx reload failed: {error}",
                                        'action': 'restored backup'
                                    }
                                    site_result['nodes'].append(node_result)
                                    site_result['status'] = 'failed'
                                    results['failed'] += 1
                            else:
                                # Config test failed, restore backup
                                stdin, stdout, stderr = ssh_client.exec_command(f"cp {backup_path} {nginx_site_conf}")
                                error = nginx_test
                                node_result = {
                                    'node_id': node.id,
                                    'node_name': node.name,
                                    'status': 'failed',
                                    'error': f"Nginx config test failed: {error}",
                                    'action': 'restored backup'
                                }
                                site_result['nodes'].append(node_result)
                                site_result['status'] = 'failed'
                                results['failed'] += 1
                        else:
                            # No self-signed cert detected in config
                            node_result = {
                                'node_id': node.id,
                                'node_name': node.name,
                                'status': 'skipped',
                                'reason': 'No self-signed certificate found in Nginx config'
                            }
                            site_result['nodes'].append(node_result)
                    else:
                        reason = []
                        if not le_exists:
                            reason.append("No Let's Encrypt certificate found")
                        if not conf_exists:
                            reason.append("No Nginx configuration found")
                            
                        node_result = {
                            'node_id': node.id,
                            'node_name': node.name,
                            'status': 'skipped',
                            'reason': ', '.join(reason)
                        }
                        site_result['nodes'].append(node_result)
                    
                    ssh_client.close()
                    
                except Exception as e:
                    node_result = {
                        'node_id': node.id,
                        'node_name': node.name,
                        'status': 'error',
                        'error': str(e)
                    }
                    site_result['nodes'].append(node_result)
                    site_result['status'] = 'failed'
                    results['failed'] += 1
                finally:
                    # Ensure the SSH client is properly closed
                    if ssh_client:
                        ssh_client.close()
            
            results['sites'].append(site_result)
        
        # Log results
        log_activity(
            'info',
            f"Auto-replace self-signed certificates completed: "
            f"{results['replaced']} replaced, {results['failed']} failed out of {results['checked']} sites"
        )
        
        return results
    
    @staticmethod
    def ensure_all_ssl_directories_on_node(node_id):
        """
        Ensure SSL directories exist for all configured sites on a node.
        This helps prevent failures when one site's configuration requires certificates for another domain.
        
        Args:
            node_id: ID of the node
            
        Returns:
            dict: Result of the operation
        """
        node = Node.query.get(node_id)
        
        if not node:
            return {"success": False, "message": "Node not found"}
            
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
            
            # First, get all active sites that are deployed on this node
            site_nodes = SiteNode.query.filter_by(node_id=node_id).all()
            sites = []
            for site_node in site_nodes:
                site = Site.query.get(site_node.site_id)
                if site and site.protocol == 'https':
                    sites.append(site)
            
            # Gather all domain names
            domains = [site.domain for site in sites]
            
            # Also scan Nginx configs to find any extra domains referenced in SSL directives
            # This helps find cross-domain dependencies
            stdin, stdout, stderr = ssh_client.exec_command(f"grep -r 'ssl_certificate' {node.nginx_config_path}/*")
            ssl_cert_lines = stdout.read().decode('utf-8').strip().split('\n')
            
            for line in ssl_cert_lines:
                if 'ssl_certificate' in line and '/etc/letsencrypt/live/' in line:
                    # Extract domain from path like /etc/letsencrypt/live/example.com/fullchain.pem
                    domain_match = re.search(r'/etc/letsencrypt/live/([^/]+)/', line)
                    if domain_match:
                        domain = domain_match.group(1)
                        if domain not in domains:
                            domains.append(domain)
            
            # Create directories and dummy certificates for each domain
            created_domains = []
            failed_domains = []
            
            for domain in domains:
                # Create all necessary directories with proper permissions
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
                    failed_domains.append(domain)
                    continue
                
                # Check if certificates already exist
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
                    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
                    -keyout {archive_dir}/privkey1.pem -out {archive_dir}/cert1.pem \\
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
                    
                    if exit_status == 0:
                        created_domains.append(domain)
                    else:
                        failed_domains.append(domain)
                else:
                    # Certificate already exists
                    created_domains.append(domain)
            
            ssh_client.close()
            
            # Return the results
            return {
                "success": True,
                "message": f"SSL certificate directories prepared for {len(created_domains)} domains",
                "domains_processed": domains,
                "domains_created": created_domains,
                "domains_failed": failed_domains
            }
            
        except Exception as e:
            log_activity('error', f"Error ensuring SSL directories on node {node.name}: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to ensure SSL directories: {str(e)}"
            }
    
    @staticmethod
    def test_certificate_challenge(site_id, test_method='http', user_id=None):
        """
        Test ACME challenge connection for a domain
        
        Args:
            site_id: ID of the site
            test_method: Challenge method to test ('http' or 'dns')
            user_id: ID of the user performing the test
            
        Returns:
            dict: Result of the test
        """
        site = Site.query.get(site_id)
        if not site:
            return {
                'success': False,
                'message': 'Site not found'
            }
        
        if test_method == 'http':
            # Test HTTP-01 challenge connectivity
            try:
                # Test the connection to the domain
                acme_url = f"http://{site.domain}/.well-known/acme-challenge/test-file"
                
                # Create a test file on an active node
                site_node = SiteNode.query.filter_by(site_id=site_id, status='active').first()
                if not site_node:
                    return {
                        'success': False,
                        'message': 'No active node found for this site'
                    }
                
                node = Node.query.get(site_node.node_id)
                
                with SSHConnectionService.get_connection(node) as ssh_client:
                    # Create test file
                    test_content = "This is a test file for ACME challenge validation"
                    SSHConnectionService.execute_command(
                        ssh_client, f"mkdir -p /var/www/letsencrypt/.well-known/acme-challenge"
                    )
                    SSHConnectionService.execute_command(
                        ssh_client, f"echo '{test_content}' > /var/www/letsencrypt/.well-known/acme-challenge/test-file"
                    )
                    
                    # Test with curl directly from the server
                    exit_code, stdout, stderr = SSHConnectionService.execute_command(
                        ssh_client, f"curl -s {acme_url}"
                    )
                    
                    server_accessible = test_content in stdout
                    
                    # Remove test file
                    SSHConnectionService.execute_command(
                        ssh_client, "rm -f /var/www/letsencrypt/.well-known/acme-challenge/test-file"
                    )
                
                # Check external connectivity
                try:
                    # Check if socket module is available for external test
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    s.connect((site.domain, 80))
                    externally_accessible = True
                    s.close()
                except:
                    externally_accessible = False
                
                return {
                    'success': server_accessible,
                    'message': 'HTTP challenge test completed',
                    'server_accessible': server_accessible,
                    'externally_accessible': externally_accessible,
                    'details': {
                        'challenge_url': acme_url,
                        'webroot_path': '/var/www/letsencrypt',
                        'challenge_path': '/var/www/letsencrypt/.well-known/acme-challenge'
                    }
                }
                
            except Exception as e:
                return {
                    'success': False,
                    'message': f"HTTP challenge test failed: {str(e)}"
                }
        elif test_method == 'dns':
            # Test DNS-01 challenge
            return {
                'success': True,
                'message': 'DNS challenge test requires manual verification',
                'details': {
                    'domain': site.domain,
                    'txt_record': f"_acme-challenge.{site.domain}",
                    'instructions': 'To test DNS challenge, you would need to add a TXT record to your DNS configuration'
                }
            }
        else:
            return {
                'success': False,
                'message': f"Unsupported challenge method: {test_method}"
            }