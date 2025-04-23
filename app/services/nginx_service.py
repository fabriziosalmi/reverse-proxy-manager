import os
import paramiko
import tempfile
import git
from flask import current_app
from app.models.models import db, Site, Node, SiteNode, DeploymentLog
from datetime import datetime

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
    Deploy Nginx configuration to a node
    
    Args:
        site_id: ID of the site being deployed
        node_id: ID of the node to deploy to
        nginx_config: Nginx configuration content
        test_only: If True, only test the configuration without applying it
        
    Returns:
        bool: Success or failure
    """
    site = Site.query.get(site_id)
    node = Node.query.get(node_id)
    
    if not site or not node:
        raise ValueError("Site or node not found")
    
    site_node = SiteNode.query.filter_by(site_id=site_id, node_id=node_id).first()
    if not site_node:
        site_node = SiteNode(site_id=site_id, node_id=node_id, status='pending')
        db.session.add(site_node)
    
    try:
        # First, validate the configuration locally
        from app.services.nginx_validation_service import NginxValidationService
        
        is_valid, error_message = NginxValidationService.validate_config_syntax(nginx_config)
        if not is_valid:
            raise ValueError(f"Invalid Nginx configuration: {error_message}")
        
        # Validate security best practices
        _, ssl_warnings = NginxValidationService.validate_ssl_config(nginx_config)
        _, security_warnings = NginxValidationService.validate_security_headers(nginx_config)
        
        # Test configuration on the node
        is_valid, test_output = NginxValidationService.test_config_on_node(node_id, nginx_config, site.domain)
        if not is_valid:
            raise ValueError(f"Nginx configuration test failed: {test_output}")
        
        # If test_only, we stop here after validation
        if test_only:
            # Log the successful test
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action='test',
                status='success',
                message=f"Configuration test successful for {site.domain}"
            )
            db.session.add(log)
            db.session.commit()
            
            # Return warnings about security best practices
            all_warnings = ssl_warnings + security_warnings
            return True, all_warnings
        
        # Connect to the node via SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect using key or password
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
        
        # Create a temporary local file with the Nginx config
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
            temp.write(nginx_config)
            temp_path = temp.name
        
        # Define the remote path
        remote_filename = f"{site.domain}.conf"
        remote_path = os.path.join(node.nginx_config_path, remote_filename)
        
        # Transfer the file
        sftp = ssh_client.open_sftp()
        sftp.put(temp_path, remote_path)
        sftp.close()
        
        # Remove the temporary local file
        os.unlink(temp_path)
        
        # Enhanced nginx executable discovery specifically for Ubuntu systems
        
        # First try standard environment PATH with a full env sourcing
        stdin, stdout, stderr = ssh_client.exec_command("bash -l -c 'which nginx' 2>/dev/null || echo 'not found'")
        result = stdout.read().decode('utf-8').strip()
        if result != 'not found' and 'nginx' in result:
            nginx_path = result
        else:
            # Try common Ubuntu/Debian installation paths
            nginx_paths = [
                "/usr/sbin/nginx",            # Standard Debian/Ubuntu location
                "/usr/bin/nginx",             # Alternative location
                "/usr/local/nginx/sbin/nginx", # Manual install common location
                "/usr/local/sbin/nginx",      # Some package managers
                "/usr/share/nginx/sbin/nginx", # Some package managers
                "/opt/nginx/sbin/nginx",      # Custom installs
                "/snap/bin/nginx"             # Snap installation
            ]
            
            # Try to find working nginx path
            nginx_path = None
            for path in nginx_paths:
                stdin, stdout, stderr = ssh_client.exec_command(f"test -x {path} && echo {path} || echo 'not found'")
                result = stdout.read().decode('utf-8').strip()
                if result != 'not found':
                    nginx_path = result
                    break
        
        # If nginx binary still not found, try active service detection
        if not nginx_path:
            # Check if nginx service is active and get its path
            stdin, stdout, stderr = ssh_client.exec_command("systemctl status nginx 2>/dev/null | grep 'Main PID' | awk '{print $3}' || echo 'not found'")
            result = stdout.read().decode('utf-8').strip()
            if result != 'not found' and result.isdigit():
                # Get the executable path from the process
                pid = result
                stdin, stdout, stderr = ssh_client.exec_command(f"readlink -f /proc/{pid}/exe 2>/dev/null || echo 'not found'")
                result = stdout.read().decode('utf-8').strip()
                if result != 'not found' and 'nginx' in result:
                    nginx_path = result
        
        # If still not found, try a comprehensive file search
        if not nginx_path:
            # Try finding executable with dpkg (Debian/Ubuntu package manager)
            stdin, stdout, stderr = ssh_client.exec_command("dpkg -l | grep nginx | awk '{print $2}' | grep -v lib | head -1 || echo 'not found'")
            result = stdout.read().decode('utf-8').strip()
            if result != 'not found':
                # If any package is found, try dpkg to find binary
                package_name = result
                stdin, stdout, stderr = ssh_client.exec_command(f"dpkg -L {package_name} | grep bin/nginx || echo 'not found'")
                result = stdout.read().decode('utf-8').strip()
                if result != 'not found' and 'nginx' in result:
                    # Take the first line as the binary path
                    nginx_path = result.split('\n')[0]
        
        # Last resort: deep file search
        if not nginx_path:
            # This might be slow but will find nginx in most cases
            stdin, stdout, stderr = ssh_client.exec_command("find /usr /etc /opt /snap -name nginx -type f -executable 2>/dev/null | head -1 || echo 'not found'")
            result = stdout.read().decode('utf-8').strip()
            if result != 'not found':
                nginx_path = result
        
        # If nginx binary still not found, provide installation instructions
        if not nginx_path:
            # Try to determine the OS for better help message
            stdin, stdout, stderr = ssh_client.exec_command("lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d '\"' -f 2 || echo 'Unknown'")
            os_info = stdout.read().decode('utf-8').strip()
            
            if "Ubuntu" in os_info or "Debian" in os_info:
                raise Exception(f"Could not find nginx executable on the server ({os_info}). Please install nginx using: sudo apt update && sudo apt install -y nginx")
            else:
                raise Exception(f"Could not find nginx executable on the server ({os_info}). Please check nginx installation.")
        
        # Store the detected nginx path in node properties for future use
        if hasattr(node, 'detected_nginx_path') and not node.detected_nginx_path == nginx_path:
            node.detected_nginx_path = nginx_path
            db.session.commit()
        
        # Get the custom reload command or use default with found nginx path
        if 'systemctl' in node.nginx_reload_command:
            reload_command = node.nginx_reload_command
        else:
            # If it's a custom command that might include nginx directly
            if nginx_path:
                # Replace 'nginx' with the full path
                reload_command = node.nginx_reload_command.replace('nginx', nginx_path)
            else:
                reload_command = node.nginx_reload_command
        
        # Reload Nginx to apply the changes
        stdin, stdout, stderr = ssh_client.exec_command(reload_command)
        exit_status = stdout.channel.recv_exit_status()
        
        if exit_status != 0:
            error_output = stderr.read().decode('utf-8')
            raise Exception(f"Failed to reload Nginx: {error_output}")
        
        # Update the site_node status
        site_node.status = 'deployed'
        site_node.config_path = remote_path
        site_node.deployed_at = datetime.utcnow()
        site_node.error_message = None
        
        # Create warning message if any security warnings
        warning_message = ""
        if ssl_warnings or security_warnings:
            warning_message = "Deployed with warnings: " + ", ".join(ssl_warnings + security_warnings)
        
        # Log the deployment
        log = DeploymentLog(
            site_id=site_id,
            node_id=node_id,
            action='deploy',
            status='success',
            message=f"Successfully deployed {site.domain} to {node.name}{' - ' + warning_message if warning_message else ''}"
        )
        db.session.add(log)
        db.session.commit()
        
        ssh_client.close()
        return True
        
    except Exception as e:
        # Handle errors
        site_node.status = 'error'
        site_node.error_message = str(e)
        
        # Log the error
        log = DeploymentLog(
            site_id=site_id,
            node_id=node_id,
            action='deploy' if not test_only else 'test',
            status='error',
            message=str(e)
        )
        db.session.add(log)
        db.session.commit()
        
        raise e

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