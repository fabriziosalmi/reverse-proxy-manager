import os
import paramiko
import tempfile
import time
from datetime import datetime, timedelta
from app.models.models import db, Site, Node, SiteNode, DeploymentLog
from app.services.logger_service import log_activity
from flask import current_app

class SSLCertificateService:
    """Service for managing SSL certificates and Let's Encrypt integration"""
    
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
        
        return {
            "site_id": site_id,
            "domain": site.domain,
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
    def request_certificate(site_id, node_id, email=None):
        """
        Request a new Let's Encrypt certificate for a site
        
        Args:
            site_id: ID of the site
            node_id: ID of the node to request the certificate on
            email: Email address for Let's Encrypt registration
            
        Returns:
            dict: Result of the certificate request
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return {"error": "Site or node not found"}
        
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
            
            # Ensure the /var/www/letsencrypt directory exists for ACME challenges
            ssh_client.exec_command("mkdir -p /var/www/letsencrypt/.well-known/acme-challenge")
            
            # Prepare the certbot command
            email_arg = f"--email {email}" if email else "--register-unsafely-without-email"
            certbot_cmd = f"certbot certonly --webroot -w /var/www/letsencrypt --agree-tos {email_arg} -d {site.domain} --non-interactive"
            
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
            cert_info = SSLCertificateService._get_certificate_info(node, site.domain)
            
            if not cert_info.get("exists", False):
                ssh_client.close()
                return {
                    "success": False,
                    "message": "Certificate request appeared successful, but certificate file was not found."
                }
            
            # Log the success
            log_activity('info', f"Successfully obtained certificate for {site.domain} on node {node.name}")
            
            # Create deployment log entry
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action='ssl_request',
                status='success',
                message="Successfully obtained SSL certificate"
            )
            db.session.add(log)
            db.session.commit()
            
            ssh_client.close()
            
            return {
                "success": True,
                "message": "Certificate successfully obtained",
                "certificate": cert_info
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
    def setup_auto_renewal(node_id):
        """
        Ensure automatic certificate renewal is properly configured on a node
        
        Args:
            node_id: ID of the node
            
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
                # Cron job already exists
                ssh_client.close()
                return {
                    "success": True,
                    "message": "Certificate auto-renewal is already configured",
                    "cron_entry": cron_check
                }
            
            # Add certbot renew job to crontab
            cron_cmd = '(crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook \"systemctl reload nginx\") | crontab -'
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
            
            if "certbot renew" in cron_verify:
                # Log the success
                log_activity('info', f"Successfully configured SSL auto-renewal on node {node.name}")
                
                return {
                    "success": True,
                    "message": "Certificate auto-renewal successfully configured",
                    "cron_entry": cron_verify
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