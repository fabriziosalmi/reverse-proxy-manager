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
        Check the status of SSL certificates for a site, optionally on a specific node
        
        Args:
            site_id: ID of the site to check
            node_id: Optional ID of a specific node to check
            
        Returns:
            dict: Certificate status information
        """
        site = Site.query.get(site_id)
        if not site:
            return {"error": "Site not found"}
        
        # Get all nodes serving this site or just the specified node
        if node_id:
            nodes = [Node.query.get(node_id)]
            if not nodes[0]:
                return {"error": f"Node with ID {node_id} not found"}
        else:
            site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
            nodes = [Node.query.get(sn.node_id) for sn in site_nodes]
        
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
                        key_filename=node.ssh_key_path
                    )
                else:
                    ssh_client.connect(
                        hostname=node.ip_address,
                        port=node.ssh_port,
                        username=node.ssh_user,
                        password=node.ssh_password
                    )
                
                # Define certificate paths based on site domain
                cert_path = f"/etc/letsencrypt/live/{site.domain}/fullchain.pem"
                key_path = f"/etc/letsencrypt/live/{site.domain}/privkey.pem"
                
                # Check if certificates exist
                stdin, stdout, stderr = ssh_client.exec_command(f"test -f {cert_path} && echo 'exists' || echo 'not found'")
                cert_exists = stdout.read().decode('utf-8').strip() == 'exists'
                
                stdin, stdout, stderr = ssh_client.exec_command(f"test -f {key_path} && echo 'exists' || echo 'not found'")
                key_exists = stdout.read().decode('utf-8').strip() == 'exists'
                
                node_result = {
                    "node_id": node.id,
                    "node_name": node.name,
                    "certificate_exists": cert_exists,
                    "key_exists": key_exists
                }
                
                # If certificates exist, get detailed information
                if cert_exists:
                    # Read the certificate
                    sftp = ssh_client.open_sftp()
                    temp_cert_path = tempfile.mktemp()
                    sftp.get(cert_path, temp_cert_path)
                    
                    with open(temp_cert_path, 'rb') as cert_file:
                        cert_data = cert_file.read()
                        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    
                    # Clean up temp file
                    os.unlink(temp_cert_path)
                    
                    # Parse certificate information
                    issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    valid_from = cert.not_valid_before
                    valid_until = cert.not_valid_after
                    days_remaining = (valid_until - datetime.now()).days
                    
                    # Get certificate fingerprint
                    fingerprint = cert.fingerprint(hashes.SHA256()).hex(':')
                    
                    # Check SAN (Subject Alternative Names)
                    san = []
                    try:
                        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        for name in ext.value:
                            if isinstance(name, x509.DNSName):
                                san.append(str(name.value))
                    except x509.extensions.ExtensionNotFound:
                        # No SAN extension
                        pass
                    
                    # Check if certificate matches domain
                    domain_match = site.domain in san or site.domain == subject or f"*.{site.domain.split('.', 1)[1]}" in san
                    
                    # Check if it's a wildcard certificate
                    is_wildcard = any(name.startswith('*.') for name in san)
                    
                    # Check certificate status (valid, expired, etc.)
                    now = datetime.now()
                    if now < valid_from:
                        status = "not yet valid"
                    elif now > valid_until:
                        status = "expired"
                    elif days_remaining < 7:
                        status = "expiring soon"
                    else:
                        status = "valid"
                    
                    certificate_info = {
                        "issuer": issuer,
                        "subject": subject,
                        "valid_from": valid_from.strftime('%Y-%m-%d'),
                        "valid_until": valid_until.strftime('%Y-%m-%d'),
                        "days_remaining": days_remaining,
                        "is_wildcard": is_wildcard,
                        "domain_match": domain_match,
                        "san": san,
                        "fingerprint": fingerprint,
                        "status": status
                    }
                    
                    # Add certificate info to node_result
                    node_result["certificate"] = certificate_info
                    
                    # Check if certificate is in the database and update if needed
                    cert_record = SSLCertificate.query.filter_by(
                        site_id=site_id, 
                        node_id=node.id
                    ).first()
                    
                    if cert_record:
                        # Update existing record
                        cert_record.issuer = issuer
                        cert_record.subject = subject
                        cert_record.valid_from = valid_from
                        cert_record.valid_until = valid_until
                        cert_record.days_remaining = days_remaining
                        cert_record.status = status
                        cert_record.is_wildcard = is_wildcard
                        cert_record.fingerprint = fingerprint
                        cert_record.updated_at = datetime.now()
                    else:
                        # Create new record
                        cert_record = SSLCertificate(
                            site_id=site_id,
                            node_id=node.id,
                            issuer=issuer,
                            subject=subject,
                            valid_from=valid_from,
                            valid_until=valid_until,
                            days_remaining=days_remaining,
                            status=status,
                            is_wildcard=is_wildcard,
                            fingerprint=fingerprint,
                            created_at=datetime.now(),
                            updated_at=datetime.now()
                        )
                        db.session.add(cert_record)
                    
                    db.session.commit()
                
                # Check if Let's Encrypt client (certbot) is installed
                stdin, stdout, stderr = ssh_client.exec_command("which certbot 2>/dev/null || echo 'not found'")
                certbot_path = stdout.read().decode('utf-8').strip()
                node_result["certbot_installed"] = certbot_path != 'not found'
                
                # Check if certificate renewal is configured in cron
                stdin, stdout, stderr = ssh_client.exec_command("crontab -l 2>/dev/null | grep 'certbot renew' || echo 'not found'")
                renewal_cron = stdout.read().decode('utf-8').strip()
                node_result["renewal_configured"] = renewal_cron != 'not found'
                
                # Close connection
                ssh_client.close()
                
                # Add to results
                results.append(node_result)
                
            except Exception as e:
                # Log exception
                log_activity('error', f"Error checking certificate for site {site.domain} on node {node.name}: {str(e)}")
                
                # Add error result
                results.append({
                    "node_id": node.id,
                    "node_name": node.name,
                    "error": str(e)
                })
        
        return {
            "site_id": site_id,
            "domain": site.domain,
            "results": results
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
        Request a new SSL certificate for a site on a specific node
        
        Args:
            site_id: ID of the site
            node_id: ID of the node to request certificate on
            email: Email address for Let's Encrypt notifications
            challenge_type: Type of challenge to use ('http', 'dns', 'manual-dns')
            dns_provider: DNS provider to use for DNS challenges (e.g., 'cloudflare')
            dns_credentials: Credentials for DNS API access
            cert_type: Type of certificate to issue ('standard' or 'wildcard')
            
        Returns:
            dict: Certificate request result
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return {"success": False, "message": "Site or node not found"}
        
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
            
            # Check if certbot is installed
            stdin, stdout, stderr = ssh_client.exec_command("which certbot")
            certbot_path = stdout.read().decode('utf-8').strip()
            
            if not certbot_path:
                # Install certbot if not present
                log_activity('info', f"Installing certbot on node {node.name}")
                
                # Try to determine OS and install certbot
                stdin, stdout, stderr = ssh_client.exec_command(
                    "if [ -f /etc/debian_version ]; then "
                    "apt-get update && apt-get install -y certbot python3-certbot-nginx; "
                    "elif [ -f /etc/redhat-release ]; then "
                    "yum install -y certbot python3-certbot-nginx; "
                    "else "
                    "echo 'Unsupported OS'; "
                    "fi"
                )
                
                # Wait for installation to complete
                exit_status = stdout.channel.recv_exit_status()
                installation_output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                
                if exit_status != 0 or 'Unsupported OS' in installation_output:
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
                certbot_cmd.extend(["--manual", "--preferred-challenges", "dns"])
                
                # Execute certbot in manual mode to get the DNS records
                cmd_str = " ".join(certbot_cmd)
                stdin, stdout, stderr = ssh_client.exec_command(cmd_str)
                
                # Buffer for storing output lines
                output_buffer = []
                txt_records = []
                
                # This will block until certbot asks for manual input or times out
                for line in stdout:
                    output_buffer.append(line.strip())
                    # Look for lines mentioning TXT records
                    if '_acme-challenge' in line and 'TXT record' in line:
                        txt_records.append(line.strip())
                
                # Get the full output including errors
                full_output = "\n".join(output_buffer)
                errors = stderr.read().decode('utf-8')
                
                # Manual DNS challenges require user action
                ssh_client.close()
                
                return {
                    "success": True,
                    "message": "Manual DNS challenge initiated. Please add the TXT records shown below.",
                    "txt_records": txt_records,
                    "instructions": "Add these TXT records to your DNS configuration, then wait for DNS propagation before continuing.",
                    "manual": True,
                    "output": full_output,
                    "errors": errors
                }
            
            # Run certbot command (for HTTP and DNS automated validations)
            cmd_str = " ".join(certbot_cmd)
            stdin, stdout, stderr = ssh_client.exec_command(cmd_str)
            
            # Wait for command to complete
            exit_status = stdout.channel.recv_exit_status()
            cmd_output = stdout.read().decode('utf-8')
            cmd_error = stderr.read().decode('utf-8')
            
            if exit_status != 0:
                ssh_client.close()
                return {
                    "success": False,
                    "message": f"Certificate request failed: {cmd_error}",
                    "output": cmd_output,
                    "error": cmd_error
                }
            
            # Check if certificates were created successfully
            stdin, stdout, stderr = ssh_client.exec_command(f"test -f /etc/letsencrypt/live/{domain}/fullchain.pem && echo 'success' || echo 'failed'")
            cert_check = stdout.read().decode('utf-8').strip()
            
            if cert_check != 'success':
                ssh_client.close()
                return {
                    "success": False,
                    "message": "Certificate was not generated properly",
                    "output": cmd_output,
                    "error": cmd_error
                }
            
            # Set up auto-renewal if not already configured
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
            log_activity('error', f"Error requesting certificate for {domain} on node {node.name}: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to request certificate: {str(e)}"
            }
    
    @staticmethod
    def setup_auto_renewal(node_id, renewal_days=30):
        """
        Set up automatic certificate renewal on a node
        
        Args:
            node_id: ID of the node
            renewal_days: Days before expiry to renew
            
        Returns:
            dict: Setup result
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
                    key_filename=node.ssh_key_path
                )
            else:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    password=node.ssh_password
                )
            
            # Check if certbot is installed
            stdin, stdout, stderr = ssh_client.exec_command("which certbot")
            certbot_path = stdout.read().decode('utf-8').strip()
            
            if not certbot_path:
                ssh_client.close()
                return {
                    "success": False,
                    "message": "Certbot is not installed on this node"
                }
            
            # Set up cron job for auto-renewal
            cron_cmd = f"0 3 * * * {certbot_path} renew --quiet --renew-hook 'systemctl reload nginx' --deploy-hook 'systemctl reload nginx'"
            
            # Check if cron job already exists
            stdin, stdout, stderr = ssh_client.exec_command("crontab -l 2>/dev/null | grep -q 'certbot renew' && echo 'exists' || echo 'not found'")
            cron_exists = stdout.read().decode('utf-8').strip() == 'exists'
            
            if cron_exists:
                # Update existing cron job
                stdin, stdout, stderr = ssh_client.exec_command(
                    "crontab -l | sed '/certbot renew/d' | (cat; echo '%s') | crontab -" % cron_cmd
                )
            else:
                # Add new cron job
                stdin, stdout, stderr = ssh_client.exec_command(
                    "(crontab -l 2>/dev/null; echo '%s') | crontab -" % cron_cmd
                )
            
            # Configure renewal days
            config_cmd = f"echo 'renew_before_expiry = {renewal_days} days' > /etc/letsencrypt/renewal-hooks/renew-days.conf"
            stdin, stdout, stderr = ssh_client.exec_command(config_cmd)
            
            # Verify cron job was added
            stdin, stdout, stderr = ssh_client.exec_command("crontab -l | grep 'certbot renew'")
            verification = stdout.read().decode('utf-8').strip()
            
            ssh_client.close()
            
            if not verification:
                return {
                    "success": False,
                    "message": "Failed to set up auto-renewal cron job"
                }
            
            return {
                "success": True,
                "message": f"Successfully set up auto-renewal {renewal_days} days before expiry",
                "cron_job": verification
            }
            
        except Exception as e:
            log_activity('error', f"Error setting up auto-renewal on node {node.name}: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to set up auto-renewal: {str(e)}"
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