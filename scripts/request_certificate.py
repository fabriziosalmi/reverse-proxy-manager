#!/usr/bin/env python
"""
Script to request an SSL certificate for a site using the SSL Certificate Service.
This script properly initializes the Flask application context.
"""
import sys
import os
import argparse
import json

# Add the parent directory to sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models.models import Site, Node, SiteNode
from app.services.ssl_certificate_service import SSLCertificateService
from app.services.logger_service import log_activity

def request_certificate(domain, node_name=None, email="admin@example.com", 
                       challenge_type="http", cert_type="standard", 
                       dns_provider=None, dns_credentials=None):
    """
    Request an SSL certificate for a domain on the specified node.
    
    Args:
        domain: Domain name to request certificate for
        node_name: Name of the node to install the certificate on (optional)
        email: Email address for Let's Encrypt notifications
        challenge_type: Type of challenge for validation ("http", "dns", "manual-dns")
        cert_type: Type of certificate ("standard" or "wildcard")
        dns_provider: DNS provider for DNS challenge (if applicable)
        dns_credentials: Credentials for DNS provider API access (if applicable)
    """
    # Get environment from environment variable or default to development
    env = os.environ.get('FLASK_ENV', 'development')
    app = create_app(env)
    
    with app.app_context():
        site = Site.query.filter_by(domain=domain).first()
        if not site:
            print(f"Error: Site '{domain}' not found in database")
            return False

        # Find the node to deploy to
        if node_name:
            node = Node.query.filter_by(name=node_name, is_active=True).first()
        else:
            # Get the first active node that has this site
            site_node = SiteNode.query.filter_by(site_id=site.id).first()
            if site_node:
                node = Node.query.filter_by(id=site_node.node_id, is_active=True).first()
            else:
                # If no site_node exists, get any active node
                node = Node.query.filter_by(is_active=True).first()
        
        if not node:
            print("Error: No active node found to request certificate")
            return False
        
        print(f"Requesting {cert_type} certificate for {domain} on node {node.name} using {challenge_type} validation...")
        
        # Request the certificate
        result = SSLCertificateService.request_certificate(
            site_id=site.id,
            node_id=node.id,
            email=email,
            challenge_type=challenge_type,
            cert_type=cert_type,
            dns_provider=dns_provider,
            dns_credentials=dns_credentials
        )
        
        if result.get('success', False):
            print(f"Success: {result.get('message', 'Certificate requested successfully')}")
            
            # Check if this is a manual DNS challenge
            if challenge_type == 'manual-dns' and 'txt_records' in result:
                print("\nDNS Challenge Instructions:")
                print("Add the following TXT records to your DNS configuration:")
                for record in result.get('txt_records', []):
                    print(f"  {record}")
                print("\nAfter adding these records and waiting for DNS propagation, run the following command to complete the certificate issuance:")
                print(f"./scripts/complete_dns_challenge.py {domain} --node {node.name}")
            
            # Setup auto-renewal after successful certificate request
            if result.get('success', False) and challenge_type != 'manual-dns':
                renewal_result = SSLCertificateService.setup_auto_renewal(node.id)
                if renewal_result.get('success', False):
                    print(f"Auto-renewal configured: {renewal_result.get('message', '')}")
                else:
                    print(f"Warning: Failed to configure auto-renewal: {renewal_result.get('message', '')}")
            
            return True
        else:
            print(f"Error: {result.get('message', 'Unknown error occurred')}")
            return False

def generate_self_signed_certificate(domain, node_name=None, validity_days=365):
    """
    Generate a self-signed certificate for a domain on the specified node.
    
    Args:
        domain: Domain name to generate certificate for
        node_name: Name of the node to install the certificate on (optional)
        validity_days: Number of days the certificate should be valid
    """
    # Get environment from environment variable or default to development
    env = os.environ.get('FLASK_ENV', 'development')
    app = create_app(env)
    
    with app.app_context():
        site = Site.query.filter_by(domain=domain).first()
        if not site:
            print(f"Error: Site '{domain}' not found in database")
            return False

        # Find the node to deploy to
        if node_name:
            node = Node.query.filter_by(name=node_name, is_active=True).first()
        else:
            # Get the first active node that has this site
            site_node = SiteNode.query.filter_by(site_id=site.id).first()
            if site_node:
                node = Node.query.filter_by(id=site_node.node_id, is_active=True).first()
            else:
                # If no site_node exists, get any active node
                node = Node.query.filter_by(is_active=True).first()
        
        if not node:
            print("Error: No active node found to generate certificate")
            return False
        
        print(f"Generating self-signed certificate for {domain} on node {node.name} (valid for {validity_days} days)...")
        
        # Generate the certificate
        result = SSLCertificateService.generate_self_signed_certificate(
            site_id=site.id,
            node_id=node.id,
            validity_days=validity_days
        )
        
        if result.get('success', False):
            print(f"Success: {result.get('message', 'Self-signed certificate generated successfully')}")
            print(f"Certificate path: {result.get('certificate_path', '')}")
            print(f"Key path: {result.get('key_path', '')}")
            return True
        else:
            print(f"Error: {result.get('message', 'Unknown error occurred')}")
            return False

def setup_certificate_renewal(node_name=None, renewal_days=30):
    """
    Set up automatic certificate renewal on a node
    
    Args:
        node_name: Name of the node to set up renewal on (optional)
        renewal_days: Days before expiry to renew
    """
    # Get environment from environment variable or default to development
    env = os.environ.get('FLASK_ENV', 'development')
    app = create_app(env)
    
    with app.app_context():
        # Find the node to configure
        if node_name:
            node = Node.query.filter_by(name=node_name, is_active=True).first()
        else:
            # If no node specified, get the first active node
            node = Node.query.filter_by(is_active=True).first()
        
        if not node:
            print("Error: No active node found to set up certificate renewal")
            return False
        
        print(f"Setting up certificate auto-renewal on node {node.name} ({renewal_days} days before expiry)...")
        
        # Setup auto-renewal
        result = SSLCertificateService.setup_auto_renewal(node.id, renewal_days)
        
        if result.get('success', False):
            print(f"Success: {result.get('message', 'Auto-renewal configured successfully')}")
            print(f"Cron job: {result.get('cron_job', '')}")
            return True
        else:
            print(f"Error: {result.get('message', 'Unknown error occurred')}")
            return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Manage SSL certificates for domains")
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Request certificate command
    request_parser = subparsers.add_parser('request', help='Request a new certificate')
    request_parser.add_argument("domain", help="Domain name to request certificate for")
    request_parser.add_argument("--node", help="Node name to install certificate on")
    request_parser.add_argument("--email", default="admin@example.com", help="Email for Let's Encrypt notifications")
    request_parser.add_argument("--method", choices=["http", "dns", "manual-dns"], default="http", 
                       help="Challenge type for domain validation")
    request_parser.add_argument("--wildcard", action="store_true", help="Request wildcard certificate (requires DNS validation)")
    request_parser.add_argument("--dns-provider", choices=["cloudflare", "route53", "digitalocean", "godaddy"], 
                       help="DNS provider for DNS validation")
    request_parser.add_argument("--dns-credentials", type=str, help="JSON string or path to JSON file with DNS credentials")
    
    # Self-signed certificate command
    selfsigned_parser = subparsers.add_parser('self-signed', help='Generate a self-signed certificate')
    selfsigned_parser.add_argument("domain", help="Domain name to generate certificate for")
    selfsigned_parser.add_argument("--node", help="Node name to install certificate on")
    selfsigned_parser.add_argument("--days", type=int, default=365, help="Validity days for certificate")
    
    # Setup renewal command
    renewal_parser = subparsers.add_parser('setup-renewal', help='Set up automatic certificate renewal')
    renewal_parser.add_argument("--node", help="Node name to set up renewal on")
    renewal_parser.add_argument("--days", type=int, default=30, help="Days before expiry to renew certificates")
    
    args = parser.parse_args()
    
    if args.command == 'request':
        # Process DNS credentials if provided
        dns_credentials = None
        if args.dns_credentials:
            if os.path.isfile(args.dns_credentials):
                # Load from file
                try:
                    with open(args.dns_credentials, 'r') as f:
                        dns_credentials = json.load(f)
                except Exception as e:
                    print(f"Error loading DNS credentials from file: {e}")
                    sys.exit(1)
            else:
                # Try parsing as JSON string
                try:
                    dns_credentials = json.loads(args.dns_credentials)
                except Exception as e:
                    print(f"Error parsing DNS credentials JSON: {e}")
                    sys.exit(1)
        
        # If wildcard was requested but method isn't DNS, force DNS method
        if args.wildcard and args.method == "http":
            print("Warning: Wildcard certificates require DNS validation. Switching to DNS method.")
            args.method = "dns"
        
        # If DNS method but no provider specified
        if args.method in ["dns", "manual-dns"] and not args.dns_provider and args.method != "manual-dns":
            print("Warning: DNS validation requires a DNS provider. Switching to manual DNS method.")
            args.method = "manual-dns"
        
        cert_type = "wildcard" if args.wildcard else "standard"
        
        request_certificate(
            domain=args.domain,
            node_name=args.node,
            email=args.email,
            challenge_type=args.method,
            cert_type=cert_type,
            dns_provider=args.dns_provider,
            dns_credentials=dns_credentials
        )
        
    elif args.command == 'self-signed':
        generate_self_signed_certificate(
            domain=args.domain,
            node_name=args.node,
            validity_days=args.days
        )
        
    elif args.command == 'setup-renewal':
        setup_certificate_renewal(
            node_name=args.node,
            renewal_days=args.days
        )
        
    else:
        parser.print_help()