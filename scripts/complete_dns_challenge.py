#!/usr/bin/env python
"""
Script to complete a manual DNS challenge for Let's Encrypt certificate issuance.
This script should be run after DNS TXT records have been created and propagated.
"""
import sys
import os
import argparse
import time

# Add the parent directory to sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models.models import Site, Node
from app.services.logger_service import log_activity

def complete_dns_challenge(domain, node_name=None, wait_time=0):
    """
    Complete a manual DNS challenge for a domain.
    
    Args:
        domain: Domain name for the certificate
        node_name: Name of the node where the challenge was started (optional)
        wait_time: Time to wait for DNS propagation in seconds
    """
    # Get environment from environment variable or default to development
    env = os.environ.get('FLASK_ENV', 'development')
    app = create_app(env)
    
    with app.app_context():
        # Get the site
        site = Site.query.filter_by(domain=domain).first()
        if not site:
            print(f"Error: Site '{domain}' not found in database")
            return False
            
        # Find the node
        if node_name:
            node = Node.query.filter_by(name=node_name, is_active=True).first()
        else:
            # Get any active node
            node = Node.query.filter_by(is_active=True).first()
        
        if not node:
            print("Error: No active node found")
            return False
            
        # Wait for DNS propagation if requested
        if wait_time > 0:
            print(f"Waiting {wait_time} seconds for DNS propagation...")
            time.sleep(wait_time)
            
        print(f"Completing DNS challenge for {domain} on node {node.name}...")
        
        # Import here to avoid circular imports
        from app.services.ssl_certificate_service import SSLCertificateService
        
        # Check if there's a pending manual DNS challenge
        # (This would typically require session storage of the challenge in a real app)
        # For now, we'll just try to complete it
        
        # SSH to the node and run the certbot command to complete the challenge
        try:
            # Connect to the node
            import paramiko
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
                
            # Run the certbot command to continue the challenge
            print("Running certbot to complete the DNS challenge...")
            stdin, stdout, stderr = ssh_client.exec_command("certbot certonly --manual --preferred-challenges dns --manual-auth-hook /usr/local/bin/dns-auth-hook.sh --non-interactive -d " + domain)
            
            # Stream the output
            while not stdout.channel.exit_status_ready():
                if stdout.channel.recv_ready():
                    output = stdout.channel.recv(1024).decode('utf-8')
                    print(output, end='')
                    
            # Get the final exit status
            exit_status = stdout.channel.recv_exit_status()
            remaining_output = stdout.read().decode('utf-8')
            errors = stderr.read().decode('utf-8')
            
            if exit_status == 0:
                print("DNS challenge completed successfully!")
                
                # Setup auto-renewal
                renewal_result = SSLCertificateService.setup_auto_renewal(node.id)
                if renewal_result.get('success', False):
                    print(f"Auto-renewal configured: {renewal_result.get('message', '')}")
                else:
                    print(f"Warning: Failed to configure auto-renewal: {renewal_result.get('message', '')}")
                    
                return True
            else:
                print(f"Error completing DNS challenge: {errors}")
                return False
                
        except Exception as e:
            print(f"Error during challenge completion: {str(e)}")
            return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Complete a manual DNS challenge for Let's Encrypt certificate issuance")
    parser.add_argument("domain", help="Domain name for the certificate")
    parser.add_argument("--node", help="Node name where the challenge was started")
    parser.add_argument("--wait", type=int, default=0, help="Time to wait for DNS propagation in seconds")
    
    args = parser.parse_args()
    
    complete_dns_challenge(args.domain, args.node, args.wait)