import re
import os
import paramiko
import tempfile
import git
import time
from flask import current_app
from app.models.models import db, Site, Node, SiteNode, DeploymentLog
from datetime import datetime
from app.services.logger_service import log_activity

def generate_nginx_config(site):
    """
    Generate an Nginx configuration for a site.
    
    Args:
        site: Site object containing configuration details
        
    Returns:
        str: Nginx configuration file content
    """
    # If site is blocked, return a blocked site configuration
    if site.is_blocked:
        return generate_blocked_site_config(site)
        
    # Load the appropriate template
    template_path = os.path.join(
        current_app.config['NGINX_TEMPLATES_DIR'], 
        'https.conf' if site.protocol == 'https' else 'http.conf'
    )
    
    # If template doesn't exist, use a default one
    if not os.path.exists(template_path):
        # Create basic template
        if site.protocol == 'https':
            template = """
server {
    listen 443 ssl http2;
    server_name {{domain}};
    
    ssl_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{domain}}/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/{{domain}}/chain.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Cache configuration
    {{cache_config}}
    
    location / {
        proxy_pass {{origin_protocol}}://{{origin_address}}:{{origin_port}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Websocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Cache headers
        {{cache_proxy_config}}
    }
    
    # Static files caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
        proxy_pass {{origin_protocol}}://{{origin_address}}:{{origin_port}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Static file caching
        {{static_cache_config}}
        
        # No need to track these requests
        access_log off;
        log_not_found off;
    }
    
    # Custom configuration
    {{custom_config}}
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name {{domain}};
    
    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }
    
    location / {
        return 301 https://$host$request_uri;
    }
}
"""
        else:  # HTTP template
            # Check if we need to force HTTPS redirect for HTTP sites
            if site.force_https:
                template = """
# HTTP site with forced HTTPS redirect
server {
    listen 80;
    server_name {{domain}};
    
    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }
    
    location / {
        return 301 https://$host$request_uri;
    }
}
"""
            else:
                template = """
server {
    listen 80;
    server_name {{domain}};
    
    # Cache configuration
    {{cache_config}}
    
    location / {
        proxy_pass {{origin_protocol}}://{{origin_address}}:{{origin_port}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Websocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Cache headers
        {{cache_proxy_config}}
    }
    
    # Static files caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
        proxy_pass {{origin_protocol}}://{{origin_address}}:{{origin_port}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Static file caching
        {{static_cache_config}}
        
        # No need to track these requests
        access_log off;
        log_not_found off;
    }
    
    # Custom configuration
    {{custom_config}}
}
"""
    else:
        # Read template from file
        with open(template_path, 'r') as file:
            template = file.read()
    
    # Replace placeholders
    config = template.replace('{{domain}}', site.domain)
    config = config.replace('{{origin_protocol}}', site.protocol)
    config = config.replace('{{origin_address}}', site.origin_address)
    config = config.replace('{{origin_port}}', str(site.origin_port))
    
    # Add custom config if provided
    if site.custom_config:
        config = config.replace('{{custom_config}}', site.custom_config)
    else:
        config = config.replace('{{custom_config}}', '')
    
    # Add cache configuration
    if site.enable_cache:
        # Define the proxy cache configuration
        cache_config = f"""
    # Cache configuration
    proxy_cache_path /var/cache/nginx/{site.domain}_cache levels=1:2 keys_zone={site.domain}_cache:10m max_size=500m inactive=60m;
    proxy_cache_key "$scheme$host$request_uri";
    proxy_cache_valid 200 {site.cache_time}s;
    proxy_cache_bypass $http_pragma $http_cache_control;
    proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;
"""
        # Define cache headers for proxy
        cache_proxy_config = f"""
        # Cache control
        proxy_cache {site.domain}_cache;
        proxy_cache_valid 200 {site.cache_time}s;
        
        # Browser caching headers
        add_header Cache-Control "public, max-age={site.cache_browser_time}";
        expires {site.cache_browser_time}s;
"""
        # Static files cache directives
        static_cache_config = f"""
        # Static file caching
        proxy_cache {site.domain}_cache;
        proxy_cache_valid 200 {site.cache_static_time}s;
        add_header Cache-Control "public, max-age={site.cache_static_time}";
        expires {site.cache_static_time}s;
"""
        # If custom cache rules are provided, append them
        if site.custom_cache_rules:
            cache_config += f"\n    # Custom cache rules\n    {site.custom_cache_rules}\n"
    else:
        # If caching is disabled
        cache_config = """
    # Caching disabled
    add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate";
    add_header Pragma "no-cache";
    expires 0;
"""
        cache_proxy_config = """
        # Cache disabled
        add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate";
        add_header Pragma "no-cache";
        expires 0;
"""
        static_cache_config = """
        # Static file caching disabled
        add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate";
        add_header Pragma "no-cache";
        expires 0;
"""
    
    # Replace cache placeholders
    config = config.replace('{{cache_config}}', cache_config)
    config = config.replace('{{cache_proxy_config}}', cache_proxy_config)
    config = config.replace('{{static_cache_config}}', static_cache_config)
    
    # Add WAF configuration if needed
    if site.use_waf:
        # This is a placeholder for WAF integration (like CrowdSec)
        waf_config = """
    # WAF Configuration (CrowdSec)
    include /etc/nginx/crowdsec/crowdsec.conf;
"""
        config = config.replace('{{custom_config}}', waf_config + site.custom_config if site.custom_config else waf_config)
    
    # Save to Git repo
    save_config_to_git(site, config)
    
    return config

def generate_blocked_site_config(site):
    """
    Generate a configuration for a blocked site.
    
    Args:
        site: Site object containing configuration details
        
    Returns:
        str: Nginx configuration file content for a blocked site
    """
    # For HTTP sites
    if site.protocol == 'http':
        template = """
server {
    listen 80;
    server_name {{domain}};
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";
    
    # Return blocked message for all requests
    location / {
        return 403 '<!DOCTYPE html>
<html>
<head>
    <title>Site Blocked</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #d9534f;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Site Blocked</h1>
        <p>This site has been temporarily blocked by the administrator.</p>
        <p>Please contact the site owner for more information.</p>
    </div>
</body>
</html>';
        add_header Content-Type text/html;
    }
    
    # Allow ACME challenges for future SSL certificate renewal
    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }
}
"""
    # For HTTPS sites
    else:
        template = """
server {
    listen 443 ssl http2;
    server_name {{domain}};
    
    ssl_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{domain}}/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/{{domain}}/chain.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";
    
    # Return blocked message for all requests
    location / {
        return 403 '<!DOCTYPE html>
<html>
<head>
    <title>Site Blocked</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #d9534f;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Site Blocked</h1>
        <p>This site has been temporarily blocked by the administrator.</p>
        <p>Please contact the site owner for more information.</p>
    </div>
</body>
</html>';
        add_header Content-Type text/html;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name {{domain}};
    
    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }
    
    location / {
        return 301 https://$host$request_uri;
    }
}
"""
    
    # Replace domain placeholder
    config = template.replace('{{domain}}', site.domain)
    
    # Save to Git repo
    save_config_to_git(site, config)
    
    return config

def save_config_to_git(site, config_content):
    """
    Save the Nginx configuration to the Git repository
    
    Args:
        site: Site object
        config_content: Nginx configuration content
    """
    repo_path = current_app.config['NGINX_CONFIG_GIT_REPO']
    
    # Create repo if it doesn't exist
    if not os.path.exists(os.path.join(repo_path, '.git')):
        os.makedirs(repo_path, exist_ok=True)
        repo = git.Repo.init(repo_path)
    else:
        repo = git.Repo(repo_path)
    
    # Create site directory if it doesn't exist
    site_dir = os.path.join(repo_path, 'sites')
    os.makedirs(site_dir, exist_ok=True)
    
    # Write config file
    file_path = os.path.join(site_dir, f"{site.domain}.conf")
    with open(file_path, 'w') as f:
        f.write(config_content)
    
    # Add to Git
    repo.git.add(file_path)
    
    # Commit changes
    message = f"Updated config for {site.domain}"
    if not repo.head.is_valid() or len(repo.index.diff("HEAD")) > 0:
        repo.git.commit('-m', message)

def deploy_to_node(site_id, node_id, nginx_config, test_only=False):
    """
    Deploy a site configuration to a node
    
    Args:
        site_id: ID of the site
        node_id: ID of the node to deploy to
        nginx_config: The Nginx configuration content
        test_only: If True, only test the configuration without deploying
        
    Returns:
        If test_only=True: tuple (is_valid, warnings)
        Otherwise: True on success or raises an exception
    """
    site = Site.query.get(site_id)
    node = Node.query.get(node_id)
    
    if not site or not node:
        raise ValueError("Site or node not found")
    
    # Validate the configuration first
    from app.services.nginx_validation_service import NginxValidationService
    
    # Parse the domain name from the nginx_config (assumes server_name is present)
    domain_match = re.search(r'server_name\s+([^;]+);', nginx_config)
    domain = domain_match.group(1).strip() if domain_match else site.domain
    
    # Get deployment warnings (for SSL, security headers, etc.)
    warnings = []
    
    # Validate SSL configuration if HTTPS
    if site.protocol == 'https':
        _, ssl_warnings = NginxValidationService.validate_ssl_config(nginx_config)
        warnings.extend(ssl_warnings)
        
        # Check if SSL certificate files exist on node
        certificates_exist, missing_files, cert_warnings = NginxValidationService.check_ssl_certificate_paths(node_id, nginx_config)
        warnings.extend(cert_warnings)
        
        # If certificates don't exist and we're in test mode, record this issue
        if not certificates_exist and test_only:
            warnings.append("SSL certificates not found. You may need to request SSL certificates.")
            
            # Extract paths for user reference
            ssl_certificate, ssl_certificate_key = NginxValidationService.extract_ssl_file_paths(nginx_config)
            if ssl_certificate:
                warnings.append(f"Certificate path: {ssl_certificate}")
            if ssl_certificate_key:
                warnings.append(f"Certificate key path: {ssl_certificate_key}")

    # Validate security headers
    _, security_warnings = NginxValidationService.validate_security_headers(nginx_config)
    warnings.extend(security_warnings)
    
    # Test the configuration
    is_valid, error_message, ssl_details = NginxValidationService.test_config_on_node(node_id, nginx_config, domain)
    
    # Handle SSL details if available
    if ssl_details and ssl_details.get('is_https', False):
        if ssl_details.get('certificates_needed', False):
            warnings.append("SSL certificates need to be provisioned")
            if ssl_details.get('ssl_certificate'):
                warnings.append(f"Certificate path: {ssl_details['ssl_certificate']}")
            if ssl_details.get('ssl_certificate_key'):
                warnings.append(f"Certificate key path: {ssl_details['ssl_certificate_key']}")
    
    # Special handling for SSL certificate errors - they're expected if certs don't exist yet
    # We'll let the deployment proceed but warn the user
    if not is_valid and "SSL certificate" in error_message and "missing" in error_message:
        warnings.append("Configuration test passed with SSL warnings (certificates missing)")
        is_valid = True  # Allow deployment to proceed
    
    # For test_only mode, return validation results
    if test_only:
        if not is_valid:
            # Analyze the error and add suggestions
            error_analysis = NginxValidationService.analyze_validation_error(error_message)
            warnings.append(f"Configuration test failed: {error_message}")
            warnings.append(f"Suggestion: {error_analysis['suggestion']}")
            
            if error_analysis['error_type'] == 'ssl_certificate' and 'alternate_solution' in error_analysis:
                warnings.append(f"Alternative: {error_analysis['alternate_solution']}")
        
        return is_valid, warnings
    
    # If configuration is invalid, log and raise exception
    if not is_valid:
        error_analysis = NginxValidationService.analyze_validation_error(error_message)
        log = DeploymentLog(
            site_id=site_id,
            node_id=node_id,
            action="deploy",
            status="error",
            message=f"Configuration validation failed: {error_message}"
        )
        db.session.add(log)
        db.session.commit()
        
        raise ValueError(f"Configuration validation failed: {error_message}\nSuggestion: {error_analysis['suggestion']}")
    
    try:
        # Connect to the node
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
                time.sleep(2)  # Short delay before retry
        
        if connection_error:
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action="deploy",
                status="error", 
                message=f"Failed to connect to node after {max_attempts} attempts: {connection_error}"
            )
            db.session.add(log)
            db.session.commit()
            raise ValueError(f"Failed to connect to node: {connection_error}")
        
        # Ensure the nginx config directory exists
        stdin, stdout, stderr = ssh_client.exec_command(f"mkdir -p {node.nginx_config_path}")
        exit_status = stdout.channel.recv_exit_status()
        
        if exit_status != 0:
            error = stderr.read().decode('utf-8')
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action="deploy",
                status="error",
                message=f"Failed to create nginx config directory: {error}"
            )
            db.session.add(log)
            db.session.commit()
            ssh_client.close()
            raise ValueError(f"Failed to create nginx config directory: {error}")
        
        # Create the config file
        config_file_path = f"{node.nginx_config_path}/{domain}.conf"
        sftp = ssh_client.open_sftp()
        
        # Write to a temporary file first
        temp_file_path = f"{config_file_path}.tmp"
        with sftp.file(temp_file_path, 'w') as f:
            f.write(nginx_config)
        
        # Move the temporary file to the final location (atomic operation)
        ssh_client.exec_command(f"mv {temp_file_path} {config_file_path}")
        
        # Special handling for HTTPS sites - check and create SSL directories if needed
        if site.protocol == 'https':
            # Extract SSL certificate paths
            ssl_certificate, ssl_certificate_key = NginxValidationService.extract_ssl_file_paths(nginx_config)
            
            # If certificate paths exist, ensure their parent directories exist
            if ssl_certificate:
                cert_dir = os.path.dirname(ssl_certificate)
                stdin, stdout, stderr = ssh_client.exec_command(f"mkdir -p {cert_dir}")
            
            if ssl_certificate_key:
                key_dir = os.path.dirname(ssl_certificate_key)
                stdin, stdout, stderr = ssh_client.exec_command(f"mkdir -p {key_dir}")
            
            # Check if SSL certificates exist and log a warning if not
            all_exist, missing_files, _ = NginxValidationService.check_ssl_certificate_paths(node_id, nginx_config)
            if not all_exist:
                missing_files_str = ", ".join(missing_files)
                log_activity('warning', f"Deployed HTTPS site {domain} but SSL certificates are missing: {missing_files_str}")
                
                # Add to warnings but allow deployment to continue
                warnings.append(f"Deployed HTTPS site but SSL certificates are missing: {missing_files_str}")
        
        # Reload Nginx
        stdin, stdout, stderr = ssh_client.exec_command(node.nginx_reload_command)
        exit_status = stdout.channel.recv_exit_status()
        
        if exit_status != 0:
            error = stderr.read().decode('utf-8')
            # Check if it's an SSL certificate error during reload
            if "SSL" in error and "certificate" in error and "failed" in error:
                # For SSL certificate errors, log a warning but consider deployment partially successful
                log = DeploymentLog(
                    site_id=site_id,
                    node_id=node_id,
                    action="deploy",
                    status="warning",
                    message=f"Deployment completed but Nginx reload had SSL certificate warnings: {error}"
                )
                db.session.add(log)
                
                # Update site node status to reflect warning
                site_node = SiteNode.query.filter_by(site_id=site_id, node_id=node_id).first()
                if site_node:
                    site_node.status = "warning"
                    site_node.updated_at = datetime.utcnow()
                else:
                    # Create new site_node relationship with warning status
                    site_node = SiteNode(
                        site_id=site_id,
                        node_id=node_id,
                        status="warning",
                        created_at=datetime.utcnow(),
                        updated_at=datetime.utcnow()
                    )
                    db.session.add(site_node)
                
                db.session.commit()
                ssh_client.close()
                
                warning_message = f"Site configuration deployed but Nginx reload had SSL certificate warnings. You need to request SSL certificates for {domain}."
                warnings.append(warning_message)
                
                # Return success with warnings
                return True
            else:
                # For other errors, log and raise exception
                log = DeploymentLog(
                    site_id=site_id,
                    node_id=node_id,
                    action="deploy",
                    status="error",
                    message=f"Failed to reload nginx: {error}"
                )
                db.session.add(log)
                db.session.commit()
                ssh_client.close()
                raise ValueError(f"Failed to reload nginx: {error}")
        
        # Update or create the site_node relationship
        site_node = SiteNode.query.filter_by(site_id=site_id, node_id=node_id).first()
        if site_node:
            site_node.status = "deployed"
            site_node.updated_at = datetime.utcnow()
        else:
            site_node = SiteNode(
                site_id=site_id,
                node_id=node_id,
                status="deployed",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.session.add(site_node)
        
        # Log successful deployment
        log = DeploymentLog(
            site_id=site_id,
            node_id=node_id,
            action="deploy",
            status="success",
            message=f"Successfully deployed {site.domain} to {node.name}"
        )
        db.session.add(log)
        db.session.commit()
        
        # Version the configuration in git if configured
        from app.services.config_versioning_service import save_config_version
        # Get the username from session if available
        try:
            from flask import session
            from flask_login import current_user
            username = current_user.username if current_user and current_user.is_authenticated else "system"
        except:
            username = "system"
        
        try:
            save_config_version(site, nginx_config, username)
        except Exception as e:
            # Log but don't fail deployment if versioning fails
            log_activity('warning', f"Failed to save config version for {site.domain}: {str(e)}")
        
        ssh_client.close()
        return True
        
    except Exception as e:
        # Log the error
        log = DeploymentLog(
            site_id=site_id,
            node_id=node_id,
            action="deploy",
            status="error",
            message=f"Deployment error: {str(e)}"
        )
        db.session.add(log)
        db.session.commit()
        
        # Re-raise the exception
        raise

def get_node_stats(node):
    """
    Get real-time server statistics from a node via SSH
    
    Args:
        node: Node object to retrieve stats from
        
    Returns:
        dict: A dictionary containing server statistics
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
        
        # Get CPU usage - improved command that works across different Linux variants
        stdin, stdout, stderr = ssh_client.exec_command("top -bn1 | grep '%Cpu' | awk '{print $2+$4+$6}' | awk '{printf \"%.1f%%\", $1}'")
        cpu_usage = stdout.read().decode('utf-8').strip()
        # If the command didn't work, try alternative command
        if not cpu_usage:
            stdin, stdout, stderr = ssh_client.exec_command("mpstat 1 1 | grep -A 5 '%idle' | tail -n 1 | awk '{print 100-$NF\"%\"}' || echo 'N/A'")
            cpu_usage = stdout.read().decode('utf-8').strip()
        # If still not working, try yet another alternative
        if not cpu_usage or cpu_usage == 'N/A':
            stdin, stdout, stderr = ssh_client.exec_command("vmstat 1 2 | tail -1 | awk '{print 100-$15\"%\"}' || echo 'N/A'")
            cpu_usage = stdout.read().decode('utf-8').strip()
        
        # Get memory usage - fixed command with proper quotes
        stdin, stdout, stderr = ssh_client.exec_command("free -m | grep 'Mem:' | awk '{printf \"%d/%dMB (%d%%)\", $3, $2, int($3*100/$2)}'")
        memory_usage = stdout.read().decode('utf-8').strip()
        
        # Get disk usage - fixed command with proper quotes
        stdin, stdout, stderr = ssh_client.exec_command("df -h / | grep -v Filesystem | awk '{printf \"%s/%s (%s)\", $3, $2, $5}'")
        disk_usage = stdout.read().decode('utf-8').strip()
        
        # Get uptime
        stdin, stdout, stderr = ssh_client.exec_command("uptime -p 2>/dev/null || uptime | sed 's/.*up \\([^,]*\\),.*/\\1/' || echo 'N/A'")
        uptime = stdout.read().decode('utf-8').strip().replace('up ', '')
        
        # Get load average
        stdin, stdout, stderr = ssh_client.exec_command("cat /proc/loadavg | awk '{print $1\", \"$2\", \"$3}'")
        load_average = stdout.read().decode('utf-8').strip()
        
        # Get Nginx connection statistics
        stdin, stdout, stderr = ssh_client.exec_command("curl -s http://localhost/nginx_status 2>/dev/null || echo 'Nginx status not available'")
        nginx_status = stdout.read().decode('utf-8')
        
        total_connections = 0
        active_connections = 0
        requests_per_second = 0
        
        if 'Active connections' in nginx_status:
            # Parse nginx status output
            lines = nginx_status.strip().split('\n')
            if len(lines) >= 1:
                active_connections = int(lines[0].split(':')[1].strip())
            if len(lines) >= 3:
                accepts, handled, requests = map(int, lines[2].strip().split())
                requests_per_second = round(requests / 60, 1)  # Approximate RPS
        else:
            # Try alternative method to get connections
            stdin, stdout, stderr = ssh_client.exec_command("netstat -an | grep :80 | grep ESTABLISHED | wc -l")
            http_connections = stdout.read().decode('utf-8').strip()
            try:
                active_http = int(http_connections)
            except ValueError:
                active_http = 0
                
            stdin, stdout, stderr = ssh_client.exec_command("netstat -an | grep :443 | grep ESTABLISHED | wc -l")
            https_connections = stdout.read().decode('utf-8').strip()
            try:
                active_https = int(https_connections)
            except ValueError:
                active_https = 0
                
            active_connections = active_http + active_https
        
        # Simple estimation for HTTP vs HTTPS
        active_http = int(active_connections * 0.4)  # 40% HTTP (example estimation)
        active_https = active_connections - active_http
        
        # Get bandwidth usage (estimation based on network interface traffic)
        stdin, stdout, stderr = ssh_client.exec_command("cat /proc/net/dev | grep -v face | grep -v lo | sort | head -n 1 | awk '{print $2, $10}'")
        net_stats = stdout.read().decode('utf-8').strip().split()
        
        # Convert to MB/s (very rough estimate)
        if len(net_stats) >= 2:
            bytes_in = int(net_stats[0])
            bytes_out = int(net_stats[1])
            bandwidth_usage = f"{round((bytes_in + bytes_out) / 1024 / 1024, 2)} MB/s"
        else:
            bandwidth_usage = "N/A"
        
        ssh_client.close()
        
        # Return stats
        server_stats = {
            'cpu_usage': cpu_usage if cpu_usage else 'N/A',
            'memory_usage': memory_usage if memory_usage else 'N/A',
            'disk_usage': disk_usage if disk_usage else 'N/A',
            'uptime': uptime if uptime else 'N/A',
            'load_average': load_average if load_average else 'N/A'
        }
        
        connection_stats = {
            'total_connections': active_connections,
            'active_http': active_http,
            'active_https': active_https,
            'requests_per_second': requests_per_second,
            'bandwidth_usage': bandwidth_usage
        }
        
        return server_stats, connection_stats
        
    except Exception as e:
        # If there's an error, return default values with error information
        error_message = str(e)
        return {
            'cpu_usage': 'N/A',
            'memory_usage': 'N/A',
            'disk_usage': 'N/A',
            'uptime': 'N/A',
            'load_average': 'N/A',
            'error': error_message
        }, {
            'total_connections': 0,
            'active_http': 0,
            'active_https': 0,
            'requests_per_second': 0,
            'bandwidth_usage': 'N/A'
        }

def get_nginx_info(node):
    """
    Get detailed Nginx information from a node, including version, modules, and configuration
    
    Args:
        node: Node object to retrieve Nginx info from
        
    Returns:
        dict: A dictionary containing Nginx information
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
        
        # Use the detected nginx path if available
        nginx_path = node.detected_nginx_path if hasattr(node, 'detected_nginx_path') and node.detected_nginx_path else "nginx"
        
        # Get Nginx version
        stdin, stdout, stderr = ssh_client.exec_command(f"{nginx_path} -v 2>&1")
        version_output = stdout.read().decode('utf-8').strip() + stderr.read().decode('utf-8').strip()
        
        # Extract version number
        version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', version_output)
        nginx_version = version_match.group(1) if version_match else "Unknown"
        
        # Get Nginx configuration information
        stdin, stdout, stderr = ssh_client.exec_command(f"{nginx_path} -V 2>&1")
        config_output = stdout.read().decode('utf-8').strip() + stderr.read().decode('utf-8').strip()
        
        # Extract compiled modules
        modules = []
        if '--with-' in config_output or '--without-' in config_output:
            module_matches = re.findall(r'--with-([^\s]+)', config_output)
            modules = [module for module in module_matches if module]
        
        # Get compile flags
        compile_flags = None
        if 'configure arguments:' in config_output:
            compile_flags = config_output.split('configure arguments:')[1].strip()
        
        # Check if common modules are enabled
        has_http2 = 'http_v2_module' in config_output or 'with-http_v2_module' in config_output
        has_ssl = 'http_ssl_module' in config_output or 'with-http_ssl_module' in config_output
        has_gzip = 'http_gzip_module' in config_output or 'with-http_gzip_module' in config_output
        
        # Get Nginx configuration file locations
        stdin, stdout, stderr = ssh_client.exec_command(f"{nginx_path} -T 2>/dev/null | grep 'configuration file' | head -1 || echo 'Unknown'")
        config_file = stdout.read().decode('utf-8').strip()
        if 'configuration file' in config_file:
            config_file = config_file.split('configuration file')[1].strip()
        
        # Get Nginx process status
        stdin, stdout, stderr = ssh_client.exec_command("ps aux | grep '[n]ginx: master' || echo 'Not running'")
        process_status = stdout.read().decode('utf-8').strip()
        is_running = process_status != 'Not running'
        
        # Get Nginx master process PID
        pid = None
        if is_running:
            stdin, stdout, stderr = ssh_client.exec_command("ps aux | grep '[n]ginx: master' | awk '{print $2}' | head -1")
            pid_output = stdout.read().decode('utf-8').strip()
            try:
                pid = int(pid_output)
            except ValueError:
                pid = None
        
        # Get worker processes count
        worker_count = 0
        if is_running:
            stdin, stdout, stderr = ssh_client.exec_command("ps aux | grep '[n]ginx: worker' | wc -l")
            worker_count_output = stdout.read().decode('utf-8').strip()
            try:
                worker_count = int(worker_count_output)
            except ValueError:
                worker_count = 0
        
        # Get server OS information
        stdin, stdout, stderr = ssh_client.exec_command("lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d '\"' -f 2 || echo 'Unknown'")
        os_info = stdout.read().decode('utf-8').strip()
        
        # Get RAM and CPU info
        stdin, stdout, stderr = ssh_client.exec_command("grep 'model name' /proc/cpuinfo | uniq | cut -d ':' -f 2 | xargs || echo 'Unknown CPU'")
        cpu_info = stdout.read().decode('utf-8').strip()
        
        stdin, stdout, stderr = ssh_client.exec_command("grep MemTotal /proc/meminfo | awk '{print $2 / 1024 / 1024}' | xargs printf '%.1f GB' || echo 'Unknown RAM'")
        ram_info = stdout.read().decode('utf-8').strip()
        
        # Get configuration tree (basic structure)
        config_tree = None
        stdin, stdout, stderr = ssh_client.exec_command(f"{nginx_path} -T 2>/dev/null | grep -v '#' | grep -v '^$' | head -50 || echo 'Configuration not available'")
        config_tree_raw = stdout.read().decode('utf-8').strip()
        if config_tree_raw and config_tree_raw != 'Configuration not available':
            config_tree = config_tree_raw
            
        # Parse virtual hosts (server blocks)
        sites = []
        
        # First, get list of all config files
        stdin, stdout, stderr = ssh_client.exec_command(f"find {node.nginx_config_path} -type f -name '*.conf' | sort")
        config_files = stdout.read().decode('utf-8').strip().split('\n')
        
        for config_file in config_files:
            if not config_file:
                continue
                
            # Extract server_name and listen directives
            stdin, stdout, stderr = ssh_client.exec_command(f"grep -E 'server_name|listen' {config_file} | grep -v '#'")
            server_directives = stdout.read().decode('utf-8').strip()
            
            if 'server_name' in server_directives:
                server_blocks = server_directives.split('server_name')
                for i in range(1, len(server_blocks)):
                    server_name = server_blocks[i].split(';')[0].strip()
                    
                    # Find corresponding listen directive
                    listen_port = "80"  # Default
                    ssl_enabled = False
                    
                    # Look for listen directive in the current or previous block
                    if 'listen' in server_blocks[i-1] or (i < len(server_blocks)-1 and 'listen' in server_blocks[i]):
                        listen_block = server_blocks[i-1] if 'listen' in server_blocks[i-1] else server_blocks[i]
                        listen_match = re.search(r'listen\s+([^;]+);', listen_block)
                        if listen_match:
                            listen_port = listen_match.group(1).strip()
                            if 'ssl' in listen_port or '443' in listen_port:
                                ssl_enabled = True
                    
                    # Extract root directive
                    stdin, stdout, stderr = ssh_client.exec_command(f"grep -E 'root' {config_file} | grep -v '#' | head -1")
                    root_directive = stdout.read().decode('utf-8').strip()
                    root_path = None
                    if root_directive:
                        root_match = re.search(r'root\s+([^;]+);', root_directive)
                        if root_match:
                            root_path = root_match.group(1).strip()
                    
                    # Add to sites list
                    sites.append({
                        'server_name': server_name,
                        'listen': listen_port,
                        'ssl_enabled': ssl_enabled,
                        'root': root_path,
                        'config_file': os.path.basename(config_file)
                    })
        
        ssh_client.close()
        
        return {
            'version': nginx_version,
            'version_full': version_output,
            'is_running': is_running,
            'pid': pid,
            'worker_count': worker_count,
            'config_file': config_file,
            'modules': modules,
            'compile_flags': compile_flags,
            'has_http2': has_http2,
            'has_ssl': has_ssl,
            'has_gzip': has_gzip,
            'os_info': os_info,
            'cpu_info': cpu_info,
            'ram_info': ram_info,
            'config_tree': config_tree,
            'sites': sites
        }
        
    except Exception as e:
        return {
            'version': 'Unknown',
            'error': str(e),
            'is_running': False
        }