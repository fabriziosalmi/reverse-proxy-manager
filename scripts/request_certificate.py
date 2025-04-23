#!/usr/bin/env python
"""
Script to request an SSL certificate for a site using the SSL Certificate Service.
This script properly initializes the Flask application context.
"""
import sys
import os
import argparse

# Add the parent directory to sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models.models import Site, Node, SiteNode
from app.services.ssl_certificate_service import SSLCertificateService
from app.services.logger_service import log_activity

def request_certificate(domain, node_name=None, email="admin@example.com", 
                       challenge_type="http", cert_type="standard"):
    """
    Request an SSL certificate for a domain on the specified node.
    
    Args:
        domain: Domain name to request certificate for
        node_name: Name of the node to install the certificate on (optional)
        email: Email address for Let's Encrypt notifications
        challenge_type: Type of challenge for validation ("http", "dns", "manual-dns")
        cert_type: Type of certificate ("standard" or "wildcard")
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
            cert_type=cert_type
        )
        
        if result.get('success', False):
            print(f"Success: {result.get('message', 'Certificate requested successfully')}")
            return True
        else:
            print(f"Error: {result.get('message', 'Unknown error occurred')}")
            return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Request SSL certificate for a domain")
    parser.add_argument("domain", help="Domain name to request certificate for")
    parser.add_argument("--node", help="Node name to install certificate on")
    parser.add_argument("--email", default="admin@example.com", help="Email for Let's Encrypt notifications")
    parser.add_argument("--method", choices=["http", "dns", "manual-dns"], default="http", 
                       help="Challenge type for domain validation")
    parser.add_argument("--wildcard", action="store_true", help="Request wildcard certificate (requires DNS validation)")
    
    args = parser.parse_args()
    
    # If wildcard was requested but method isn't DNS, force DNS method
    if args.wildcard and args.method == "http":
        print("Warning: Wildcard certificates require DNS validation. Switching to DNS method.")
        args.method = "dns"
    
    cert_type = "wildcard" if args.wildcard else "standard"
    
    request_certificate(
        domain=args.domain,
        node_name=args.node,
        email=args.email,
        challenge_type=args.method,
        cert_type=cert_type
    )