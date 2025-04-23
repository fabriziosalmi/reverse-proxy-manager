import os
import paramiko
import tempfile
import time
import json
import socket
import dns.resolver
from datetime import datetime, timedelta
from app.models.models import db, Site, Node, SiteNode, DeploymentLog, SSLCertificate
from app.services.logger_service import log_activity
from flask import current_app

class SSLCertificateService:
    """Service for managing SSL certificates and Let's Encrypt integration"""
    
    # Supported DNS providers for DNS challenge
    DNS_PROVIDERS = {
        'cloudflare': {
            'plugin': 'certbot-dns-cloudflare',
            'credentials_format': 'dns_cloudflare_api_token = {token}'
        },
        'route53': {
            'plugin': 'certbot-dns-route53',
            'credentials_format': '''[default]
aws_access_key_id = {access_key}
aws_secret_access_key = {secret_key}'''
        },
        'digitalocean': {
            'plugin': 'certbot-dns-digitalocean',
            'credentials_format': 'dns_digitalocean_token = {token}'
        },
        'godaddy': {
            'plugin': 'certbot-dns-godaddy',
            'credentials_format': '''certbot_dns_godaddy:dns_godaddy_secret = {secret}
certbot_dns_godaddy:dns_godaddy_key = {key}'''
        },
        'namecheap': {
            'plugin': 'certbot-dns-namecheap',
            'credentials_format': '''dns_namecheap_api_key = {api_key}
dns_namecheap_username = {username}'''
        }
    }
    
    # SSL challenge types
    CHALLENGE_TYPES = ['http', 'dns', 'manual-dns']

    # Certificate types
    CERT_TYPES = ['standard', 'wildcard']
    
    @staticmethod
    def check_certificate_status(site_id, node_id=None):
        """
        Check the status of SSL certificates for a site on all nodes or a specific node
        
        Args:
            site_id: ID of the site to check
            node_id: Optional ID of specific node to check
            
        Returns:
            dict: Certificate status information
        """
        site = Site.query.get(site_id)
        if not site:
            return {"error": "Site not found"}
        
        if site.protocol != 'https':
            return {"error": "Site is not configured for HTTPS"}
        
        # Get nodes to check
        if node_id:
            nodes = [Node.query.get(node_id)]
            if not nodes[0]:
                return {"error": "Node not found"}
        else:
            # Get all nodes that have this site deployed
            site_nodes = SiteNode.query.filter_by(site_id=site_id, status='deployed').all()
            nodes = [Node.query.get(sn.node_id) for sn in site_nodes]
        
        results = []
        
        for node in nodes:
            try:
                cert_info = SSLCertificateService._get_certificate_info(node, site.domain)
                results.append({
                    "node_id": node.id,
                    "node_name": node.name,
                    "ip_address": node.ip_address,
                    "certificate": cert_info
                })
            except Exception as e:
                results.append({
                    "node_id": node.id,
                    "node_name": node.name,
                    "ip_address": node.ip_address,
                    "error": str(e)
                })
        
        # Add DNS resolution info
        dns_info = SSLCertificateService.check_domain_dns(site.domain)
        
        return {
            "site_id": site_id,
            "domain": site.domain,
            "dns_info": dns_info,
            "results": results
        }
    
    @staticmethod
    def _get_certificate_info(node, domain):
        """
        Get SSL certificate information for a domain on a node
        
        Args:
            node: Node object
            domain: Domain name
            
        Returns:
            dict: Certificate information
        """
        try:
            # Connect to the node via SSH
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
            
            # Check if certificate exists
            cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
            stdin, stdout, stderr = ssh_client.exec_command(f"test -f {cert_path} && echo 'exists' || echo 'not found'")
            result = stdout.read().decode('utf-8').strip()
            
            if result == 'not found':
                ssh_client.close()
                return {
                    "exists": False,
                    "message": f"Certificate not found at {cert_path}"
                }
            
            # Get certificate information using OpenSSL
            cmd = f"openssl x509 -in {cert_path} -noout -text | grep -A2 'Validity' | grep -v 'Validity'"
            stdin, stdout, stderr = ssh_client.exec_command(cmd)
            cert_dates = stdout.read().decode('utf-8').strip()
            
            # Get subject information (domain)
            cmd = f"openssl x509 -in {cert_path} -noout -subject"
            stdin, stdout, stderr = ssh_client.exec_command(cmd)
            subject = stdout.read().decode('utf-8').strip()
            
            # Get issuer information (Let's Encrypt, etc.)
            cmd = f"openssl x509 -in {cert_path} -noout -issuer"
            stdin, stdout, stderr = ssh_client.exec_command(cmd)
            issuer = stdout.read().decode('utf-8').strip()
            
            # Parse certificate expiration and calculate days remaining
            not_after_line = [line for line in cert_dates.split('\n') if "Not After" in line][0]
            # Extract date string
            date_str = not_after_line.split(':', 1)[1].strip()
            
            # Parse using OpenSSL directly to convert date to timestamp
            cmd = f"openssl x509 -in {cert_path} -noout -enddate | cut -d= -f2 | xargs -I{{}} date -d \"{{}}\" +%s"
            stdin, stdout, stderr = ssh_client.exec_command(cmd)
            expiry_timestamp = stdout.read().decode('utf-8').strip()
            
            if expiry_timestamp:
                try:
                    expiry_timestamp = int(expiry_timestamp)
                    current_timestamp = int(time.time())
                    days_remaining = (expiry_timestamp - current_timestamp) // (24 * 3600)
                except (ValueError, TypeError):
                    days_remaining = None
            else:
                days_remaining = None
            
            ssh_client.close()
            
            return {
                "exists": True,
                "subject": subject,
                "issuer": issuer,
                "validity": cert_dates,
                "expiry_date": date_str,
                "days_remaining": days_remaining,
                "status": "valid" if days_remaining and days_remaining > 0 else "expired"
            }
            
        except Exception as e:
            raise Exception(f"Error checking certificate: {str(e)}")
    
    @staticmethod
    def check_domain_dns(domain):
        """
        Check DNS resolution for a domain to help with SSL certificate setup
        
        Args:
            domain: Domain name to check
            
        Returns:
            dict: DNS resolution info
        """
        try:
            # Get A record
            a_records = []
            try:
                answers = dns.resolver.resolve(domain, 'A')
                for rdata in answers:
                    a_records.append(str(rdata))
            except Exception as e:
                a_records = [f"Error: {str(e)}"]
            
            # Get AAAA record (IPv6)
            aaaa_records = []
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                for rdata in answers:
                    aaaa_records.append(str(rdata))
            except Exception:
                aaaa_records = []  # No IPv6 records is common
                
            # Get CNAME record
            cname_records = []
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                for rdata in answers:
                    cname_records.append(str(rdata))
            except Exception:
                cname_records = []  # No CNAME is common
                
            # Get CAA records (Certificate Authority Authorization)
            caa_records = []
            try:
                # Try with base domain
                base_domain = '.'.join(domain.split('.')[-2:])
                answers = dns.resolver.resolve(base_domain, 'CAA')
                for rdata in answers:
                    property_tag = rdata.property.decode('utf-8')
                    value = rdata.value.decode('utf-8')
                    caa_records.append(f"{property_tag}: {value}")
            except Exception:
                caa_records = []  # No CAA records is common
                
            # Get node names from application database
            nodes = Node.query.filter_by(is_active=True).all()
            node_ips = [node.ip_address for node in nodes]
            
            # Check if domain resolves to any of our CDN nodes
            matching_nodes = []
            for ip in a_records:
                if ip in node_ips:
                    node = Node.query.filter_by(ip_address=ip).first()
                    if node:
                        matching_nodes.append({
                            "node_id": node.id,
                            "node_name": node.name,
                            "ip_address": node.ip_address
                        })
            
            # Is domain resolving correctly?
            domain_resolution_correct = len(matching_nodes) > 0
            
            return {
                "a_records": a_records,
                "aaaa_records": aaaa_records,
                "cname_records": cname_records,
                "caa_records": caa_records,
                "pointing_to_cdn": domain_resolution_correct,
                "matching_nodes": matching_nodes,
                "dns_status": "ok" if domain_resolution_correct else "warning"
            }
        except Exception as e:
            return {
                "error": str(e),
                "dns_status": "error"
            }
    
    @staticmethod
    def get_issuance_recommendations(site_id):
        """
        Provide recommendations for SSL certificate issuance methods based on domain/DNS configuration
        
        Args:
            site_id: ID of the site
            
        Returns:
            dict: Recommendations for SSL issuance
        """
        site = Site.query.get(site_id)
        if not site:
            return {"error": "Site not found"}
        
        if site.protocol != 'https':
            return {"error": "Site is not configured for HTTPS"}
        
        # Check DNS resolution
        dns_info = SSLCertificateService.check_domain_dns(site.domain)
        
        recommendations = {
            "domain": site.domain,
            "methods": [],
            "preferred_method": None,
            "notes": []
        }
        
        # HTTP-01 Challenge Validation
        http_method = {
            "type": "http",
            "name": "HTTP Challenge",
            "description": "Certbot places a token file in the /.well-known/acme-challenge/ directory which Let's Encrypt validates",
            "requirements": [
                "Domain must resolve to server IP",
                "Port 80 must be open and accessible from the internet",
                "No wildcard certificates"
            ],
            "suitable": dns_info.get("pointing_to_cdn", False)
        }
        recommendations["methods"].append(http_method)
        
        # DNS-01 Challenge with API
        dns_method = {
            "type": "dns",
            "name": "DNS API Challenge",
            "description": "Automatically creates TXT records with your DNS provider via API",
            "requirements": [
                "Supported DNS provider with API access",
                "API credentials for your DNS provider",
                "Supports wildcard certificates"
            ],
            "suitable": True,  # Always an option if credentials provided
            "providers": list(SSLCertificateService.DNS_PROVIDERS.keys())
        }
        recommendations["methods"].append(dns_method)
        
        # Manual DNS Challenge
        manual_dns_method = {
            "type": "manual-dns",
            "name": "Manual DNS Challenge",
            "description": "Manually create TXT records with your DNS provider",
            "requirements": [
                "Access to modify your domain's DNS settings",
                "Supports wildcard certificates",
                "More effort but works with any DNS provider"
            ],
            "suitable": True  # Always an option
        }
        recommendations["methods"].append(manual_dns_method)
        
        # Determine preferred method
        if dns_info.get("pointing_to_cdn", False):
            recommendations["preferred_method"] = "http"
            recommendations["notes"].append("HTTP validation is recommended since your domain is correctly pointed to the CDN.")
        else:
            recommendations["preferred_method"] = "dns"
            recommendations["notes"].append("DNS validation is recommended since your domain does not currently resolve to your CDN node.")
            recommendations["notes"].append("Consider using a DNS provider's API for automation or manual DNS validation.")
        
        # Check for wildcard certificate needs
        if site.domain.count('.') > 1:
            recommendations["notes"].append("For a wildcard certificate to cover all subdomains, you must use DNS validation.")
        
        return recommendations
    
    @staticmethod
    def request_certificate(site_id, node_id, email=None, challenge_type='http', 
                           dns_provider=None, dns_credentials=None, cert_type='standard'):
        """
        Request a new Let's Encrypt certificate for a site
        
        Args:
            site_id: ID of the site
            node_id: ID of the node to request the certificate on
            email: Email address for Let's Encrypt registration
            challenge_type: Type of challenge to use (http, dns, manual-dns)
            dns_provider: DNS provider for DNS challenge
            dns_credentials: Credentials for DNS provider
            cert_type: Type of certificate (standard or wildcard)
            
        Returns:
            dict: Result of the certificate request
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return {"error": "Site or node not found"}
            
        # Validate parameters
        if challenge_type not in SSLCertificateService.CHALLENGE_TYPES:
            return {"error": f"Invalid challenge type. Must be one of: {', '.join(SSLCertificateService.CHALLENGE_TYPES)}"}
            
        if cert_type not in SSLCertificateService.CERT_TYPES:
            return {"error": f"Invalid certificate type. Must be one of: {', '.join(SSLCertificateService.CERT_TYPES)}"}
            
        # If using DNS challenge, validate DNS provider
        if challenge_type == 'dns':
            if not dns_provider:
                return {"error": "DNS provider is required for DNS challenge"}
                
            if dns_provider not in SSLCertificateService.DNS_PROVIDERS:
                return {"error": f"Unsupported DNS provider. Supported providers: {', '.join(SSLCertificateService.DNS_PROVIDERS.keys())}"}
                
            if not dns_credentials:
                return {"error": "DNS credentials are required for DNS challenge"}
        
        # For wildcard certificates, force DNS challenge
        if cert_type == 'wildcard' and challenge_type not in ['dns', 'manual-dns']:
            return {"error": "Wildcard certificates require DNS challenge authentication"}
            
        try:
            # Connect to the node via SSH
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
            
            # Ensure certbot is installed
            stdin, stdout, stderr = ssh_client.exec_command("which certbot || echo 'not found'")
            result = stdout.read().decode('utf-8').strip()
            
            if result == 'not found':
                # Try to install certbot automatically
                ssh_client.exec_command("apt-get update && apt-get install -y certbot python3-certbot-nginx")
                
                # Check again
                stdin, stdout, stderr = ssh_client.exec_command("which certbot || echo 'not found'")
                result = stdout.read().decode('utf-8').strip()
                
                if result == 'not found':
                    ssh_client.close()
                    return {
                        "success": False,
                        "message": "Certbot not found and could not be installed automatically. Please install certbot manually."
                    }
            
            # If using DNS challenge with provider API, install required plugin
            credentials_file = None
            if challenge_type == 'dns' and dns_provider:
                # Install the DNS plugin
                plugin_package = SSLCertificateService.DNS_PROVIDERS[dns_provider]['plugin']
                ssh_client.exec_command(f"apt-get update && apt-get install -y {plugin_package}")
                
                # Check if plugin was installed successfully
                stdin, stdout, stderr = ssh_client.exec_command(f"pip3 list | grep {plugin_package} || echo 'not found'")
                result = stdout.read().decode('utf-8').strip()
                
                if "not found" in result:
                    # Try pip installation as fallback
                    ssh_client.exec_command(f"pip3 install {plugin_package}")
                    
                    # Check again
                    stdin, stdout, stderr = ssh_client.exec_command(f"pip3 list | grep {plugin_package} || echo 'not found'")
                    result = stdout.read().decode('utf-8').strip()
                    
                    if "not found" in result:
                        ssh_client.close()
                        return {
                            "success": False,
                            "message": f"Failed to install DNS plugin {plugin_package}. Please install it manually."
                        }
                
                # Format credentials for the specific DNS provider
                credentials_format = SSLCertificateService.DNS_PROVIDERS[dns_provider]['credentials_format']
                formatted_credentials = credentials_format
                
                # Replace placeholders with actual credentials
                for key, value in dns_credentials.items():
                    formatted_credentials = formatted_credentials.replace(f"{{{key}}}", value)
                
                # Create credentials directory if it doesn't exist
                credentials_dir = "/etc/letsencrypt/dns-credentials"
                ssh_client.exec_command(f"mkdir -p {credentials_dir} && chmod 700 {credentials_dir}")
                
                # Create credentials file
                credentials_file = f"{credentials_dir}/{dns_provider}.ini"
                ssh_client.exec_command(f"echo '{formatted_credentials}' > {credentials_file} && chmod 600 {credentials_file}")
            
            # Determine domain(s) to include in certificate request
            domains = []
            if cert_type == 'standard':
                domains.append(site.domain)
            elif cert_type == 'wildcard':
                # Extract base domain (e.g., from sub.example.com to example.com)
                if site.domain.count('.') > 1:
                    base_domain = '.'.join(site.domain.split('.')[-2:])
                else:
                    base_domain = site.domain
                    
                domains.append(site.domain)         # Include the specific domain
                domains.append(f"*.{base_domain}")  # Include wildcard domain
            
            domains_arg = " ".join([f"-d {domain}" for domain in domains])
            
            # Prepare the certbot command based on challenge type
            email_arg = f"--email {email}" if email else "--register-unsafely-without-email"
            
            if challenge_type == 'http':
                # Ensure the /var/www/letsencrypt directory exists for ACME challenges
                ssh_client.exec_command("mkdir -p /var/www/letsencrypt/.well-known/acme-challenge")
                certbot_cmd = f"certbot certonly --webroot -w /var/www/letsencrypt --agree-tos {email_arg} {domains_arg} --non-interactive"
            elif challenge_type == 'dns':  # Automated DNS challenge
                dns_plugin = dns_provider.replace('-', '_')
                certbot_cmd = f"certbot certonly --dns-{dns_plugin} --dns-{dns_plugin}-credentials {credentials_file} --agree-tos {email_arg} {domains_arg} --non-interactive"
            elif challenge_type == 'manual-dns':  # Manual DNS challenge
                # For manual DNS, we need to capture the output to show instructions to the user
                certbot_cmd = f"certbot certonly --manual --preferred-challenges dns --agree-tos {email_arg} {domains_arg} --manual-public-ip-logging-ok"
                
                # This will prompt for manual input, so we need special handling
                ssh_client.close()
                return {
                    "success": True,
                    "message": "Please use the manual token setup on the node directly",
                    "instructions": "Connect to the node and run the following command:\n" + certbot_cmd,
                    "node_ip": node.ip_address,
                    "challenge_type": "manual-dns"
                }
            
            # Run certbot
            stdin, stdout, stderr = ssh_client.exec_command(certbot_cmd)
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if exit_status != 0:
                # Log the failure
                log_activity('error', f"Failed to obtain certificate for {site.domain} on node {node.name}: {error}")
                
                # Create deployment log entry
                log = DeploymentLog(
                    site_id=site_id,
                    node_id=node_id,
                    action='ssl_request',
                    status='error',
                    message=f"Failed to obtain SSL certificate: {error}"
                )
                db.session.add(log)
                db.session.commit()
                
                ssh_client.close()
                return {
                    "success": False,
                    "message": f"Failed to obtain certificate: {error}"
                }
            
            # Check if certificate was actually issued
            primary_domain = site.domain
            cert_info = SSLCertificateService._get_certificate_info(node, primary_domain)
            
            if not cert_info.get("exists", False):
                ssh_client.close()
                return {
                    "success": False,
                    "message": "Certificate request appeared successful, but certificate file was not found."
                }
            
            # Store certificate information in database
            certificate = SSLCertificate.query.filter_by(site_id=site_id, domain=primary_domain).first()
            if not certificate:
                certificate = SSLCertificate(
                    site_id=site_id,
                    domain=primary_domain,
                    certificate_path=f"/etc/letsencrypt/live/{primary_domain}/cert.pem",
                    private_key_path=f"/etc/letsencrypt/live/{primary_domain}/privkey.pem",
                    fullchain_path=f"/etc/letsencrypt/live/{primary_domain}/fullchain.pem",
                    issuer="Let's Encrypt",
                    status='active'
                )
                db.session.add(certificate)
            else:
                certificate.status = 'active'
                certificate.updated_at = datetime.utcnow()
                
            # Try to parse the expiry date
            try:
                if cert_info.get("days_remaining"):
                    certificate.expires_at = datetime.utcnow() + timedelta(days=cert_info.get("days_remaining"))
            except:
                pass
                
            db.session.commit()
            
            # Log the success
            log_activity('info', f"Successfully obtained certificate for {site.domain} on node {node.name}")
            
            # Create deployment log entry
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action='ssl_request',
                status='success',
                message=f"Successfully obtained SSL certificate ({cert_type}) using {challenge_type} challenge"
            )
            db.session.add(log)
            db.session.commit()
            
            ssh_client.close()
            
            return {
                "success": True,
                "message": "Certificate successfully obtained",
                "certificate": cert_info,
                "certificate_type": cert_type,
                "challenge_type": challenge_type,
                "domains": domains
            }
            
        except Exception as e:
            # Log the error
            log_activity('error', f"Error requesting certificate for {site.domain} on node {node.name}: {str(e)}")
            
            # Create deployment log entry
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action='ssl_request',
                status='error',
                message=f"Error requesting certificate: {str(e)}"
            )
            db.session.add(log)
            db.session.commit()
            
            return {
                "success": False,
                "message": f"Error requesting certificate: {str(e)}"
            }
    
    @staticmethod
    def setup_auto_renewal(node_id, renewal_days=30, post_renewal_script=None):
        """
        Ensure automatic certificate renewal is properly configured on a node
        
        Args:
            node_id: ID of the node
            renewal_days: Days before expiry to renew certificates
            post_renewal_script: Custom script to run after renewal
            
        Returns:
            dict: Result of the setup
        """
        node = Node.query.get(node_id)
        
        if not node:
            return {"error": "Node not found"}
        
        try:
            # Connect to the node via SSH
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
            
            # Check if cron is installed
            stdin, stdout, stderr = ssh_client.exec_command("which crontab || echo 'not found'")
            result = stdout.read().decode('utf-8').strip()
            
            if result == 'not found':
                ssh_client.close()
                return {
                    "success": False,
                    "message": "Crontab not found. Please install cron."
                }
            
            # Check if certbot renew cron job already exists
            stdin, stdout, stderr = ssh_client.exec_command("crontab -l | grep certbot")
            cron_check = stdout.read().decode('utf-8').strip()
            
            if "certbot renew" in cron_check:
                # Cron job already exists, but we'll update it with our improved version
                ssh_client.exec_command("crontab -l | grep -v certbot | crontab -")
            
            # Create renewal hook scripts directory
            ssh_client.exec_command("mkdir -p /etc/letsencrypt/renewal-hooks/post")
            
            # Create a post-renewal script to reload Nginx and perform any custom actions
            post_hook_path = "/etc/letsencrypt/renewal-hooks/post/reload-nginx.sh"
            post_hook_script = "#!/bin/bash\n\n"
            post_hook_script += "# Reload Nginx to use new certificates\n"
            post_hook_script += "systemctl reload nginx\n\n"
            
            # Add any custom post-renewal actions
            if post_renewal_script:
                post_hook_script += "# Custom post-renewal actions\n"
                post_hook_script += f"{post_renewal_script}\n"
            
            # Create the script file and make it executable
            stdin, stdout, stderr = ssh_client.exec_command(f"echo '{post_hook_script}' > {post_hook_path} && chmod +x {post_hook_path}")
            
            # Create a script to handle certificate renewal reporting
            report_script_path = "/usr/local/bin/certbot-renewal-report.sh"
            report_script = """#!/bin/bash

# Run certbot renew with detailed output
certbot renew --days-before-expiry {renewal_days} --non-interactive

# Get status of certificates
CERT_STATUS=$(find /etc/letsencrypt/live -maxdepth 1 -type d | grep -v '^/etc/letsencrypt/live$' | while read -r CERT_DIR; do
    DOMAIN=$(basename "$CERT_DIR")
    CERT_FILE="$CERT_DIR/cert.pem"
    
    if [ -f "$CERT_FILE" ]; then
        EXPIRY=$(openssl x509 -in "$CERT_FILE" -noout -enddate | cut -d= -f2)
        EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))
        
        echo "$DOMAIN: $DAYS_LEFT days until expiry ($EXPIRY)"
    fi
done)

# Log the results
echo "$(date): Certificate renewal check completed" >> /var/log/certbot-renewal.log
echo "$CERT_STATUS" >> /var/log/certbot-renewal.log
echo "----------------------------------------" >> /var/log/certbot-renewal.log

# For certificates expiring soon (less than 15 days), log a warning
echo "$CERT_STATUS" | grep -E ': ([0-9]|1[0-4]) days' > /dev/null
if [ $? -eq 0 ]; then
    echo "WARNING: Some certificates are expiring soon!" >> /var/log/certbot-renewal.log
    EXPIRING_CERTS=$(echo "$CERT_STATUS" | grep -E ': ([0-9]|1[0-4]) days')
    echo "$EXPIRING_CERTS" >> /var/log/certbot-renewal.log
fi
""".replace("{renewal_days}", str(renewal_days))
            
            # Create the report script and make it executable
            stdin, stdout, stderr = ssh_client.exec_command(f"echo '{report_script}' > {report_script_path} && chmod +x {report_script_path}")
            
            # Add certbot renew job to crontab (run daily at 3:00 AM)
            cron_cmd = f'(crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/certbot-renewal-report.sh > /dev/null 2>&1") | crontab -'
            stdin, stdout, stderr = ssh_client.exec_command(cron_cmd)
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                error = stderr.read().decode('utf-8')
                ssh_client.close()
                return {
                    "success": False,
                    "message": f"Failed to configure auto-renewal: {error}"
                }
            
            # Verify the job was added
            stdin, stdout, stderr = ssh_client.exec_command("crontab -l | grep certbot")
            cron_verify = stdout.read().decode('utf-8').strip()
            
            ssh_client.close()
            
            if "/usr/local/bin/certbot-renewal-report.sh" in cron_verify:
                # Log the success
                log_activity('info', f"Successfully configured SSL auto-renewal on node {node.name}")
                
                return {
                    "success": True,
                    "message": "Certificate auto-renewal successfully configured",
                    "cron_entry": cron_verify,
                    "renewal_days": renewal_days
                }
            else:
                return {
                    "success": False,
                    "message": "Failed to configure auto-renewal: cron job verification failed"
                }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Error configuring auto-renewal: {str(e)}"
            }
    
    @staticmethod
    def get_supported_dns_providers():
        """
        Get list of supported DNS providers for DNS challenges
        
        Returns:
            list: List of supported DNS providers
        """
        return list(SSLCertificateService.DNS_PROVIDERS.keys())
    
    @staticmethod
    def revoke_certificate(site_id, node_id, domain=None):
        """
        Revoke an existing SSL certificate
        
        Args:
            site_id: ID of the site
            node_id: ID of the node where certificate is installed
            domain: Optional specific domain to revoke
            
        Returns:
            dict: Result of the revocation
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return {"error": "Site or node not found"}
            
        domain_to_revoke = domain or site.domain
        
        try:
            # Connect to the node via SSH
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
                
            # Check if certificate exists
            cert_info = SSLCertificateService._get_certificate_info(node, domain_to_revoke)
            
            if not cert_info.get("exists", False):
                return {
                    "success": False,
                    "message": f"No certificate found for {domain_to_revoke}"
                }
                
            # Revoke the certificate
            stdin, stdout, stderr = ssh_client.exec_command(f"certbot revoke --cert-name {domain_to_revoke} --non-interactive")
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if exit_status != 0:
                ssh_client.close()
                return {
                    "success": False,
                    "message": f"Failed to revoke certificate: {error}"
                }
                
            # Update the certificate status in the database
            certificate = SSLCertificate.query.filter_by(site_id=site_id, domain=domain_to_revoke).first()
            if certificate:
                certificate.status = 'revoked'
                certificate.updated_at = datetime.utcnow()
                db.session.commit()
                
            # Log the revocation
            log_activity('info', f"Certificate for {domain_to_revoke} has been revoked")
            
            ssh_client.close()
            
            return {
                "success": True,
                "message": f"Certificate for {domain_to_revoke} successfully revoked"
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Error revoking certificate: {str(e)}"
            }
    
    @staticmethod
    def certificate_health_check(days_warning=30):
        """
        Check all certificates across all nodes for expiration issues
        
        Args:
            days_warning: Days threshold for expiration warning
            
        Returns:
            dict: Health check results
        """
        certificates = SSLCertificate.query.filter_by(status='active').all()
        expiring_soon = []
        expired = []
        healthy = []
        
        # Check each certificate
        for cert in certificates:
            if not cert.expires_at:
                # Unknown expiry date
                expiring_soon.append({
                    'id': cert.id,
                    'domain': cert.domain,
                    'site_id': cert.site_id,
                    'status': 'unknown'
                })
                continue
                
            days_remaining = (cert.expires_at - datetime.utcnow()).days
            
            if days_remaining < 0:
                # Certificate has expired
                expired.append({
                    'id': cert.id,
                    'domain': cert.domain,
                    'site_id': cert.site_id,
                    'days_remaining': days_remaining,
                    'expires_at': cert.expires_at.isoformat()
                })
            elif days_remaining < days_warning:
                # Certificate expiring soon
                expiring_soon.append({
                    'id': cert.id,
                    'domain': cert.domain,
                    'site_id': cert.site_id,
                    'days_remaining': days_remaining,
                    'expires_at': cert.expires_at.isoformat()
                })
            else:
                # Healthy certificate
                healthy.append({
                    'id': cert.id,
                    'domain': cert.domain,
                    'site_id': cert.site_id,
                    'days_remaining': days_remaining,
                    'expires_at': cert.expires_at.isoformat()
                })
        
        return {
            'total_certificates': len(certificates),
            'healthy': healthy,
            'expiring_soon': expiring_soon,
            'expired': expired,
            'warning_threshold_days': days_warning
        }