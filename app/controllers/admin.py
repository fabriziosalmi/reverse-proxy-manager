from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, abort, session
from flask_login import login_required, current_user
from app.models.models import db, User, Node, Site, SiteNode, DeploymentLog, ConfigVersion
from app.services.access_control import admin_required
from app.services.ssl_certificate_service import SSLCertificateService
from app.services.nginx_service import deploy_to_node, generate_nginx_config
from datetime import datetime, timedelta
import random
import string
import os
import tempfile
import paramiko
import re
from app.services.analytics_service import AnalyticsService

admin = Blueprint('admin', __name__)

# Helper function to generate a random password
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

@admin.route('/dashboard')
@login_required
@admin_required
def dashboard():
    # Statistics for the dashboard
    user_count = User.query.filter_by(role='client').count()
    node_count = Node.query.count()
    active_node_count = Node.query.filter_by(is_active=True).count()
    site_count = Site.query.count()
    active_site_count = Site.query.filter_by(is_active=True).count()
    
    # Get current time for the dashboard
    now = datetime.now()
    
    # Get error logs count for last 24h
    error_log_count = DeploymentLog.query.filter(
        DeploymentLog.status == 'error',
        DeploymentLog.created_at >= datetime.now() - timedelta(days=1)
    ).count()
    
    # Get SSL certificates expiring soon count
    from app.models.models import SSLCertificate
    ssl_expiring_count = SSLCertificate.query.filter(
        SSLCertificate.valid_until <= datetime.now() + timedelta(days=30)
    ).count()
    
    # Get the latest deployment logs
    latest_logs = DeploymentLog.query.order_by(DeploymentLog.created_at.desc()).limit(10).all()
    
    # Get nodes for nodes list
    nodes = Node.query.order_by(Node.name).limit(5).all()
    
    # Get recent sites for sites list
    sites = Site.query.order_by(Site.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', 
                           user_count=user_count,
                           node_count=node_count,
                           active_node_count=active_node_count,
                           site_count=site_count,
                           active_site_count=active_site_count,
                           latest_logs=latest_logs,
                           now=now,
                           error_log_count=error_log_count,
                           ssl_expiring_count=ssl_expiring_count,
                           nodes=nodes,
                           sites=sites)

# User Management
@admin.route('/users')
@login_required
@admin_required
def list_users():
    users = User.query.all()
    return render_template('admin/users/list.html', users=users)

@admin.route('/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_user():
    if request.method == 'GET':
        return render_template('admin/users/new.html')
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role', 'client')
        
        # Check if custom password was provided, otherwise generate one
        password = request.form.get('password')
        if not password:
            password = generate_random_password()
            generated_password = True
        else:
            generated_password = False
        
        # Validation
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('admin.new_user'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return redirect(url_for('admin.new_user'))
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password=password,
            role=role
        )
        
        db.session.add(user)
        db.session.commit()
        
        if generated_password:
            flash(f'User created successfully! Generated password: {password}', 'success')
        else:
            flash('User created successfully!', 'success')
            
        return redirect(url_for('admin.list_users'))

@admin.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'GET':
        return render_template('admin/users/edit.html', user=user)
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        is_active = 'is_active' in request.form
        
        # Check for username uniqueness if changed
        if username != user.username and User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('admin.edit_user', user_id=user_id))
            
        # Check for email uniqueness if changed
        if email != user.email and User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return redirect(url_for('admin.edit_user', user_id=user_id))
        
        # Update user
        user.username = username
        user.email = email
        user.role = role
        user.is_active = is_active
        
        # Change password if provided
        new_password = request.form.get('new_password')
        if new_password:
            user.set_password(new_password)
        
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin.list_users'))

@admin.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting yourself
    if user.id == current_user.id:
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('admin.list_users'))
    
    # Check if user has sites before deletion
    sites = Site.query.filter_by(user_id=user_id).all()
    if sites:
        flash('Cannot delete user with active sites. Please delete or reassign sites first.', 'error')
        return redirect(url_for('admin.list_users'))
    
    # Import logger service
    from app.services.logger_service import log_activity
    
    # Log the user deletion
    log_activity(
        category='admin',
        action='delete',
        resource_type='user',
        resource_id=user_id,
        details=f'Deleted user: {user.username} (ID: {user.id})'
    )
    
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin.list_users'))

# Node Management
@admin.route('/nodes')
@login_required
@admin_required
def list_nodes():
    nodes = Node.query.all()
    return render_template('admin/nodes/list.html', nodes=nodes)

@admin.route('/nodes/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_node():
    if request.method == 'GET':
        # Get supported proxy types for the form
        from app.services.proxy_service_factory import ProxyServiceFactory
        proxy_types = ProxyServiceFactory.get_supported_proxy_types()
        return render_template('admin/nodes/new.html', proxy_types=proxy_types)
    
    if request.method == 'POST':
        name = request.form.get('name')
        ip_address = request.form.get('ip_address')
        ssh_port = request.form.get('ssh_port', 22)
        ssh_user = request.form.get('ssh_user')
        ssh_key_path = request.form.get('ssh_key_path')
        ssh_password = request.form.get('ssh_password')
        proxy_type = request.form.get('proxy_type', 'nginx')
        
        # Get proxy-specific configuration paths
        if proxy_type == 'nginx':
            proxy_config_path = request.form.get('proxy_config_path', '/etc/nginx/conf.d')
            proxy_reload_command = request.form.get('proxy_reload_command', 'sudo systemctl reload nginx')
        elif proxy_type == 'caddy':
            proxy_config_path = request.form.get('proxy_config_path', '/etc/caddy')
            proxy_reload_command = request.form.get('proxy_reload_command', 'sudo systemctl reload caddy')
        elif proxy_type == 'traefik':
            proxy_config_path = request.form.get('proxy_config_path', '/etc/traefik/dynamic')
            proxy_reload_command = request.form.get('proxy_reload_command', 'sudo systemctl reload traefik')
        else:
            # Default to nginx if unsupported proxy type somehow got through
            proxy_type = 'nginx'
            proxy_config_path = request.form.get('proxy_config_path', '/etc/nginx/conf.d')
            proxy_reload_command = request.form.get('proxy_reload_command', 'sudo systemctl reload nginx')
        
        # Validation
        errors = []
        
        if not name or not name.strip():
            errors.append('Node name is required')
        elif Node.query.filter_by(name=name).first():
            errors.append('Node name already exists')
        
        # Validate IP address format
        import re
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not ip_address or not ip_pattern.match(ip_address):
            errors.append('Invalid IP address format')
        else:
            # Check if each octet is in valid range
            octets = ip_address.split('.')
            for octet in octets:
                if int(octet) > 255:
                    errors.append('Invalid IP address, octets must be between 0-255')
                    break
        
        # Validate SSH port
        try:
            ssh_port = int(ssh_port)
            if ssh_port < 1 or ssh_port > 65535:
                errors.append('SSH port must be between 1 and 65535')
        except (ValueError, TypeError):
            errors.append('Invalid SSH port number')
        
        # Validate username
        if not ssh_user or not ssh_user.strip():
            errors.append('SSH username is required')
        
        # Validate auth method - at least one of SSH key or password must be provided
        if not ssh_key_path and not ssh_password:
            errors.append('Either SSH key path or password must be provided')
        
        # Display errors if any
        if errors:
            for error in errors:
                flash(error, 'error')
            from app.services.proxy_service_factory import ProxyServiceFactory
            proxy_types = ProxyServiceFactory.get_supported_proxy_types()
            return render_template('admin/nodes/new.html', proxy_types=proxy_types)
        
        # Create new node
        node = Node(
            name=name,
            ip_address=ip_address,
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            ssh_key_path=ssh_key_path,
            ssh_password=ssh_password,
            proxy_type=proxy_type,
            proxy_config_path=proxy_config_path,
            proxy_reload_command=proxy_reload_command,
            is_active=True
        )
        
        db.session.add(node)
        db.session.commit()
        
        flash('Node added successfully', 'success')
        return redirect(url_for('admin.list_nodes'))

@admin.route('/nodes/<int:node_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_node(node_id):
    node = Node.query.get_or_404(node_id)
    
    if request.method == 'GET':
        # Get supported proxy types for the form
        from app.services.proxy_service_factory import ProxyServiceFactory
        proxy_types = ProxyServiceFactory.get_supported_proxy_types()
        return render_template('admin/nodes/edit.html', node=node, proxy_types=proxy_types)
    
    if request.method == 'POST':
        name = request.form.get('name')
        ip_address = request.form.get('ip_address')
        ssh_port = request.form.get('ssh_port')
        ssh_user = request.form.get('ssh_user')
        ssh_key_path = request.form.get('ssh_key_path')
        ssh_password = request.form.get('ssh_password')
        proxy_type = request.form.get('proxy_type', node.proxy_type)  # Use existing type if not provided
        proxy_config_path = request.form.get('proxy_config_path')
        proxy_reload_command = request.form.get('proxy_reload_command')
        is_active = 'is_active' in request.form
        
        # Validation
        errors = []
        
        if not name or not name.strip():
            errors.append('Node name is required')
        elif name != node.name and Node.query.filter_by(name=name).first():
            errors.append('Node name already exists')
        
        # Validate IP address format
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not ip_address or not ip_pattern.match(ip_address):
            errors.append('Invalid IP address format')
        else:
            # Check if each octet is in valid range
            octets = ip_address.split('.')
            for octet in octets:
                if int(octet) > 255:
                    errors.append('Invalid IP address, octets must be between 0-255')
                    break
        
        # Validate SSH port
        try:
            ssh_port = int(ssh_port)
            if ssh_port < 1 or ssh_port > 65535:
                errors.append('SSH port must be between 1 and 65535')
        except (ValueError, TypeError):
            errors.append('Invalid SSH port number')
        
        # Validate username
        if not ssh_user or not ssh_user.strip():
            errors.append('SSH username is required')
        
        # Display errors if any
        if errors:
            for error in errors:
                flash(error, 'error')
            # Get proxy types again for the form
            from app.services.proxy_service_factory import ProxyServiceFactory
            proxy_types = ProxyServiceFactory.get_supported_proxy_types()
            return render_template('admin/nodes/edit.html', node=node, proxy_types=proxy_types)
        
        # Update node
        node.name = name
        node.ip_address = ip_address
        node.ssh_port = ssh_port
        node.ssh_user = ssh_user
        
        if ssh_key_path:
            node.ssh_key_path = ssh_key_path
            
        if ssh_password:
            node.ssh_password = ssh_password
        
        # Update proxy type and related fields    
        node.proxy_type = proxy_type
        node.proxy_config_path = proxy_config_path
        node.proxy_reload_command = proxy_reload_command
        node.is_active = is_active
        node.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash('Node updated successfully', 'success')
        return redirect(url_for('admin.list_nodes'))

@admin.route('/nodes/<int:node_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_node(node_id):
    node = Node.query.get_or_404(node_id)
    
    # Check if node has sites before deletion
    site_nodes = SiteNode.query.filter_by(node_id=node_id).all()
    if site_nodes:
        flash('Cannot delete node with active sites. Please delete or relocate sites first.', 'error')
        return redirect(url_for('admin.list_nodes'))
    
    db.session.delete(node)
    db.session.commit()
    flash('Node deleted successfully', 'success')
    return redirect(url_for('admin.list_nodes'))

@admin.route('/nodes/<int:node_id>')
@login_required
@admin_required
def view_node(node_id):
    node = Node.query.get_or_404(node_id)
    
    # Get all sites deployed on this node
    site_nodes = SiteNode.query.filter_by(node_id=node_id).all()
    sites = [Site.query.get(sn.site_id) for sn in site_nodes]
    
    # Get recent deployment logs for this node
    deployment_logs = DeploymentLog.query.filter_by(node_id=node_id).order_by(DeploymentLog.created_at.desc()).limit(10).all()
    
    # Get real server stats and connection info
    from app.services.nginx_service import get_node_stats, get_nginx_info
    from app.services.nginx_validation_service import NginxValidationService
    
    # Check if Nginx is installed on the node
    nginx_missing = False
    nginx_missing_message = ""
    
    # Test Nginx with a simple config to check if it's installed
    test_config = "server { listen 80; server_name _; location / { return 200; } }"
    is_valid, error_message, _ = NginxValidationService.test_config_on_node(node_id, test_config, "test")
    
    # If Nginx is missing, we'll get a specific error message about it
    if not is_valid and "Could not find nginx executable on the server" in error_message:
        nginx_missing = True
        nginx_missing_message = error_message
    
    try:
        # Get server stats and connection info
        server_stats, connection_stats = get_node_stats(node)
        
        # Get Nginx version and configuration info
        nginx_info = get_nginx_info(node)
    except Exception as e:
        # Log the error
        from app.services.logger_service import log_activity
        log_activity(
            category='error',
            action='view_node',
            resource_type='node',
            resource_id=node.id,
            details=f"Error fetching node stats: {str(e)}"
        )
        
        # Fallback to mock data if real stats can't be retrieved
        server_stats = {
            'cpu_usage': '32%',
            'memory_usage': '4.2GB / 8GB (52%)',
            'disk_usage': '45GB / 100GB (45%)',
            'uptime': '14 days, 6 hours',
            'load_average': '0.74, 0.82, 0.76'
        }
        
        connection_stats = {
            'total_connections': 248,
            'active_http': 156,
            'active_https': 92,
            'requests_per_second': 42.7,
            'bandwidth_usage': '8.5 MB/s'
        }
        
        nginx_info = {
            'version': 'Unknown',
            'error': str(e),
            'is_running': False
        }
    
    return render_template('admin/nodes/view.html', 
                          node=node, 
                          sites=sites, 
                          site_nodes=site_nodes,
                          deployment_logs=deployment_logs,
                          server_stats=server_stats,
                          connection_stats=connection_stats,
                          nginx_missing=nginx_missing,
                          nginx_missing_message=nginx_missing_message,
                          nginx_info=nginx_info)

@admin.route('/nodes/<int:node_id>/toggle_active', methods=['POST'])
@login_required
@admin_required
def toggle_node_active(node_id):
    node = Node.query.get_or_404(node_id)
    node.is_active = not node.is_active
    db.session.commit()
    
    status = 'activated' if node.is_active else 'deactivated'
    flash(f'Node {status} successfully', 'success')
    return redirect(url_for('admin.view_node', node_id=node_id))

@admin.route('/nodes/bulk-toggle', methods=['POST'])
@login_required
@admin_required
def bulk_toggle_nodes():
    action = request.form.get('action')
    node_ids_str = request.form.get('node_ids', '')
    
    if not node_ids_str:
        flash('No nodes selected', 'error')
        return redirect(url_for('admin.list_nodes'))
    
    node_ids = [int(id) for id in node_ids_str.split(',')]
    
    # Set the active status based on the action
    is_active = action == 'activate'
    action_verb = 'activated' if is_active else 'deactivated'
    
    # Update all selected nodes
    for node_id in node_ids:
        node = Node.query.get(node_id)
        if node:
            node.is_active = is_active
    
    db.session.commit()
    
    flash(f'Successfully {action_verb} {len(node_ids)} nodes', 'success')
    return redirect(url_for('admin.list_nodes'))

@admin.route('/nodes/<int:node_id>/stats', methods=['GET'])
@login_required
@admin_required
def get_node_stats_ajax(node_id):
    """API endpoint to get node stats for AJAX refresh"""
    node = Node.query.get_or_404(node_id)
    
    # Get real server stats and connection info
    from app.services.nginx_service import get_node_stats
    
    try:
        server_stats, connection_stats = get_node_stats(node)
        return jsonify({
            'success': True,
            'serverStats': server_stats,
            'connectionStats': connection_stats
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@admin.route('/nodes/<int:node_id>/redeploy-all', methods=['POST'])
@login_required
@admin_required
def redeploy_all_sites(node_id):
    """Redeploy all sites on a specific node using the appropriate proxy service"""
    node = Node.query.get_or_404(node_id)
    
    # Get all sites deployed on this node
    site_nodes = SiteNode.query.filter_by(node_id=node_id).all()
    
    if not site_nodes:
        flash('No sites are currently deployed on this node', 'info')
        return redirect(url_for('admin.view_node', node_id=node_id))
    
    # Import the proxy service factory
    from app.services.proxy_service_factory import ProxyServiceFactory
    
    # Create the appropriate proxy service based on the node's proxy type
    proxy_service = ProxyServiceFactory.create_service(node.proxy_type)
    
    success_count = 0
    error_count = 0
    
    for site_node in site_nodes:
        site = Site.query.get(site_node.site_id)
        if not site:
            continue
        
        try:
            # Generate config using the appropriate proxy service
            config_content = proxy_service.generate_config(site)
            
            # Deploy to the node
            proxy_service.deploy_config(site.id, node_id, config_content)
            
            # Log the successful deployment
            log = DeploymentLog(
                site_id=site.id,
                node_id=node_id,
                user_id=current_user.id,
                action="redeploy",
                status="success",
                message=f"Successfully redeployed site during bulk operation using {node.proxy_type} proxy"
            )
            db.session.add(log)
            success_count += 1
            
        except Exception as e:
            # Log the error
            error_count += 1
            log = DeploymentLog(
                site_id=site.id,
                node_id=node_id,
                user_id=current_user.id,
                action="redeploy",
                status="error",
                message=f"Failed to redeploy: {str(e)}"
            )
            db.session.add(log)
    
    db.session.commit()
    
    if error_count > 0:
        flash(f'Redeployment completed with {success_count} successes and {error_count} failures. Check the logs for details.', 'warning')
    else:
        flash(f'Successfully redeployed all {success_count} sites on this node', 'success')
    
    return redirect(url_for('admin.view_node', node_id=node_id))

@admin.route('/nodes/<int:node_id>/install-nginx', methods=['POST'])
@login_required
@admin_required
def install_nginx(node_id):
    """Install Nginx on a node where it's missing"""
    node = Node.query.get_or_404(node_id)
    
    # Call the Node model's install_nginx method
    success, message = node.install_nginx(user_id=current_user.id)
    
    if success:
        flash(message, 'success')
    else:
        flash(message, 'error')
    
    return redirect(url_for('admin.view_node', node_id=node_id))

@admin.route('/nodes/<int:node_id>/check-external-ip', methods=['GET'])
@login_required
@admin_required
def check_external_ip(node_id):
    """Endpoint to check the external IP address of a node"""
    node = Node.query.get_or_404(node_id)
    
    try:
        # Use SSH to execute a command to check the external IP
        import paramiko
        
        # Create SSH client
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
        
        # Try multiple IP checking services in case one fails
        commands = [
            "curl -s https://ifconfig.me",
            "curl -s https://api.ipify.org",
            "curl -s https://ipinfo.io/ip",
            "wget -qO- https://ipecho.net/plain"
        ]
        
        external_ip = None
        for cmd in commands:
            try:
                stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=5)
                result = stdout.read().decode('utf-8').strip()
                
                # Validate that the result looks like an IP address
                if result and len(result) < 40 and '.' in result:
                    external_ip = result
                    break
            except:
                continue
                
        # Close the SSH connection
        ssh_client.close()
        
        if external_ip:
            return jsonify({
                'success': True,
                'external_ip': external_ip
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Could not determine external IP address'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Site Management (Admin View)
@admin.route('/sites')
@login_required
@admin_required
def list_sites():
    sites = Site.query.all()
    return render_template('admin/sites/list.html', sites=sites)

@admin.route('/sites/<int:site_id>')
@login_required
@admin_required
def view_site(site_id):
    site = Site.query.get_or_404(site_id)
    site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
    deployment_logs = DeploymentLog.query.filter_by(site_id=site_id).order_by(DeploymentLog.created_at.desc()).all()
    
    return render_template('admin/sites/view.html', 
                           site=site, 
                           site_nodes=site_nodes,
                           deployment_logs=deployment_logs)

@admin.route('/sites/<int:site_id>/toggle_active', methods=['POST'])
@login_required
@admin_required
def toggle_site_active(site_id):
    site = Site.query.get_or_404(site_id)
    site.is_active = not site.is_active
    db.session.commit()
    
    status = 'activated' if site.is_active else 'deactivated'
    flash(f'Site {status} successfully', 'success')
    return redirect(url_for('admin.list_sites'))

@admin.route('/sites/<int:site_id>/toggle_blocked', methods=['POST'])
@login_required
@admin_required
def toggle_site_blocked(site_id):
    site = Site.query.get_or_404(site_id)
    site.is_blocked = not site.is_blocked
    db.session.commit()
    
    status = 'blocked' if site.is_blocked else 'unblocked'
    
    # Get all nodes serving this site and update their configurations
    site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
    
    try:
        from app.services.nginx_service import generate_nginx_config, deploy_to_node
        
        # Generate updated Nginx configuration
        nginx_config = generate_nginx_config(site)
        
        # Deploy to each node
        for site_node in site_nodes:
            node_id = site_node.node_id
            deploy_to_node(site.id, node_id, nginx_config)
            
            # Log the action
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action=f"Update site {status} status",
                status="success",
                message=f"Site configuration updated to {status} status"
            )
            db.session.add(log)
        
        db.session.commit()
        flash(f'Site {status} successfully and configuration deployed', 'success')
    except Exception as e:
        flash(f'Site {status} but configuration deployment failed: {str(e)}', 'warning')
    
    return redirect(url_for('admin.list_sites'))

@admin.route('/sites/<int:site_id>/toggle_waf', methods=['POST'])
@login_required
@admin_required
def toggle_site_waf(site_id):
    site = Site.query.get_or_404(site_id)
    site.use_waf = not site.use_waf
    db.session.commit()
    
    status = 'enabled' if site.use_waf else 'disabled'
    
    # Get all nodes serving this site and update their configurations
    site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
    
    try:
        from app.services.nginx_service import generate_nginx_config, deploy_to_node
        
        # Generate updated Nginx configuration with WAF settings
        nginx_config = generate_nginx_config(site)
        
        # Deploy to each node
        for site_node in site_nodes:
            node_id = site_node.node_id
            deploy_to_node(site.id, node_id, nginx_config)
            
            # Log the action
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action=f"Update WAF status",
                status="success",
                message=f"Web Application Firewall {status} for this site"
            )
            db.session.add(log)
        
        db.session.commit()
        flash(f'WAF protection {status} successfully and configuration deployed', 'success')
    except Exception as e:
        flash(f'WAF protection {status} but configuration deployment failed: {str(e)}', 'warning')
    
    return redirect(url_for('admin.view_site', site_id=site_id))

@admin.route('/sites/<int:site_id>/toggle_force_https', methods=['POST'])
@login_required
@admin_required
def toggle_site_force_https(site_id):
    site = Site.query.get_or_404(site_id)
    site.force_https = not site.force_https
    db.session.commit()
    
    status = 'enabled' if site.force_https else 'disabled'
    
    # Get all nodes serving this site and update their configurations
    site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
    
    try:
        from app.services.nginx_service import generate_nginx_config, deploy_to_node
        
        # Generate updated Nginx configuration with force HTTPS settings
        nginx_config = generate_nginx_config(site)
        
        # Deploy to each node
        for site_node in site_nodes:
            node_id = site_node.node_id
            deploy_to_node(site.id, node_id, nginx_config)
            
            # Log the action
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action=f"Update Force HTTPS status",
                status="success",
                message=f"Force HTTPS {status} for this site"
            )
            db.session.add(log)
        
        db.session.commit()
        flash(f'Force HTTPS {status} successfully and configuration deployed', 'success')
    except Exception as e:
        flash(f'Force HTTPS setting {status} but configuration deployment failed: {str(e)}', 'warning')
    
    return redirect(url_for('admin.view_site', site_id=site_id))

@admin.route('/sites/bulk-toggle', methods=['POST'])
@login_required
@admin_required
def bulk_toggle_sites():
    action = request.form.get('action')
    site_ids_str = request.form.get('site_ids', '')
    
    if not site_ids_str:
        flash('No sites selected', 'error')
        return redirect(url_for('admin.list_sites'))
    
    site_ids = [int(id) for id in site_ids_str.split(',')]
    sites_count = len(site_ids)
    
    # Handle different actions
    try:
        if action == 'activate':
            for site_id in site_ids:
                site = Site.query.get(site_id)
                if site:
                    site.is_active = True
            
            db.session.commit()
            flash(f'Successfully activated {sites_count} sites', 'success')
            
        elif action == 'deactivate':
            for site_id in site_ids:
                site = Site.query.get(site_id)
                if site:
                    site.is_active = False
            
            db.session.commit()
            flash(f'Successfully deactivated {sites_count} sites', 'success')
            
        elif action == 'block' or action == 'unblock':
            # Import needed functions
            from app.services.nginx_service import generate_nginx_config, deploy_to_node
            
            is_blocked = action == 'block'
            status_verb = 'blocked' if is_blocked else 'unblocked'
            
            success_count = 0
            failed_count = 0
            
            for site_id in site_ids:
                site = Site.query.get(site_id)
                if not site:
                    continue
                
                site.is_blocked = is_blocked
                db.session.commit()
                
                # Get all nodes serving this site
                site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
                
                try:
                    # Generate updated Nginx configuration
                    nginx_config = generate_nginx_config(site)
                    
                    # Deploy to each node
                    for site_node in site_nodes:
                        node_id = site_node.node_id
                        deploy_to_node(site.id, node_id, nginx_config)
                        
                        # Log the action
                        log = DeploymentLog(
                            site_id=site_id,
                            node_id=node_id,
                            action=f"Update site {status_verb} status",
                            status="success",
                            message=f"Site configuration updated to {status_verb} status via bulk action"
                        )
                        db.session.add(log)
                    
                    success_count += 1
                except Exception as e:
                    # Log the failure
                    failed_count += 1
                    
                    for site_node in site_nodes:
                        log = DeploymentLog(
                            site_id=site_id,
                            node_id=site_node.node_id,
                            action=f"Update site {status_verb} status",
                            status="error",
                            message=f"Failed to update configuration: {str(e)}"
                        )
                        db.session.add(log)
            
            db.session.commit()
            
            if failed_count > 0:
                flash(f'Successfully {status_verb} {success_count} sites with {failed_count} failures', 'warning')
            else:
                flash(f'Successfully {status_verb} {sites_count} sites', 'success')
    
    except Exception as e:
        flash(f'Error processing bulk action: {str(e)}', 'error')
    
    return redirect(url_for('admin.list_sites'))

# Deployment Logs
@admin.route('/logs')
@login_required
@admin_required
def deployment_logs():
    logs = DeploymentLog.query.order_by(DeploymentLog.created_at.desc()).all()
    return render_template('admin/logs.html', logs=logs)

# API endpoints for admin actions
@admin.route('/api/users', methods=['GET'])
@login_required
@admin_required
def api_list_users():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users])

@admin.route('/api/nodes', methods=['GET'])
@login_required
@admin_required
def api_list_nodes():
    nodes = Node.query.all()
    return jsonify([node.to_dict() for node in nodes])

@admin.route('/api/sites', methods=['GET'])
@login_required
@admin_required
def api_list_sites():
    sites = Site.query.all()
    return jsonify([site.to_dict() for site in sites])

@admin.route('/system/reset', methods=['GET', 'POST'])
@login_required
@admin_required
def system_reset():
    """Reset functionality for admins to delete all sites and nodes (testing purposes)"""
    if request.method == 'GET':
        # Count entities to be deleted
        site_count = Site.query.count()
        node_count = Node.query.count()
        site_node_count = SiteNode.query.count()
        deployment_logs_count = DeploymentLog.query.count()
        
        return render_template('admin/reset.html', 
                              site_count=site_count, 
                              node_count=node_count,
                              site_node_count=site_node_count,
                              deployment_logs_count=deployment_logs_count)
    
    if request.method == 'POST':
        # Verify admin password for security
        password = request.form.get('password')
        if not current_user.check_password(password):
            flash('Invalid password. Reset operation canceled.', 'error')
            return redirect(url_for('admin.system_reset'))
        
        reset_type = request.form.get('reset_type', 'all')
        
        try:
            # Import logger service
            from app.services.logger_service import log_activity
            
            if reset_type in ['all', 'sites']:
                # Delete all deployments first (foreign key constraints)
                DeploymentLog.query.delete()
                
                # Delete all site nodes relationships
                SiteNode.query.delete()
                
                # Delete all sites
                site_count = Site.query.count()
                Site.query.delete()
                
                db.session.commit()
                
                # Log the reset action for sites
                log_activity(
                    category='admin',
                    action='reset',
                    resource_type='site',
                    details=f'Deleted all sites ({site_count}) and their deployments'
                )
                
            if reset_type in ['all', 'nodes']:
                # If sites weren't already deleted, we need to delete site_nodes
                if reset_type != 'all' and reset_type != 'sites':
                    SiteNode.query.delete()
                    DeploymentLog.query.delete()
                
                # Delete all nodes
                node_count = Node.query.count()
                Node.query.delete()
                
                db.session.commit()
                
                # Log the reset action for nodes
                log_activity(
                    category='admin',
                    action='reset',
                    resource_type='node',
                    details=f'Deleted all nodes ({node_count})'
                )
            
            flash('System reset completed successfully', 'success')
            
            # Add a special log entry for the complete reset
            if reset_type == 'all':
                log_activity(
                    category='admin',
                    action='reset',
                    resource_type='system',
                    details='Complete system reset executed'
                )
                
        except Exception as e:
            db.session.rollback()
            flash(f'Error during reset: {str(e)}', 'error')
            
            # Log the failed reset attempt
            log_activity(
                category='admin',
                action='reset_failed',
                resource_type='system',
                details=f'Reset operation failed: {str(e)}'
            )
            
        return redirect(url_for('admin.dashboard'))

@admin.route('/system/logs')
@login_required
@admin_required
def system_logs():
    """View all system logs (auth, admin, security, etc.)"""
    # Get filter parameters
    category = request.args.get('category')
    user_id = request.args.get('user_id')
    resource_type = request.args.get('resource_type')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    
    # Import SystemLog model
    from app.models.models import SystemLog
    
    # Base query
    query = SystemLog.query
    
    # Apply filters
    if category:
        query = query.filter(SystemLog.category == category)
    
    if user_id:
        query = query.filter(SystemLog.user_id == user_id)
    
    if resource_type:
        query = query.filter(SystemLog.resource_type == resource_type)
    
    if from_date:
        try:
            from_datetime = datetime.strptime(from_date, '%Y-%m-%d')
            query = query.filter(SystemLog.created_at >= from_datetime)
        except ValueError:
            pass
    
    if to_date:
        try:
            to_datetime = datetime.strptime(to_date, '%Y-%m-%d')
            # Set to end of day
            to_datetime = to_datetime.replace(hour=23, minute=59, second=59)
            query = query.filter(SystemLog.created_at <= to_datetime)
        except ValueError:
            pass
    
    # Fetch distinct filter options for dropdowns
    categories = db.session.query(SystemLog.category).distinct().all()
    resource_types = db.session.query(SystemLog.resource_type).distinct().all()
    users = User.query.all()
    
    # Get logs with pagination
    page = request.args.get('page', 1, type=int)
    logs = query.order_by(SystemLog.created_at.desc()).paginate(page=page, per_page=50)
    
    return render_template('admin/system_logs.html',
                          logs=logs,
                          categories=[c[0] for c in categories if c[0]],
                          resource_types=[r[0] for r in resource_types if r[0]],
                          users=users,
                          filters={
                              'category': category,
                              'user_id': user_id,
                              'resource_type': resource_type,
                              'from_date': from_date,
                              'to_date': to_date
                          })

@admin.route('/sites/<int:site_id>/versions')
@login_required
@admin_required
def site_config_versions(site_id):
    """View configuration version history for a site"""
    site = Site.query.get_or_404(site_id)
    
    # Get configuration versions from the service
    from app.services.config_versioning_service import get_config_versions
    versions = get_config_versions(site)
    
    # Get database versions
    db_versions = ConfigVersion.query.filter_by(site_id=site_id).order_by(ConfigVersion.created_at.desc()).all()
    
    # Map DB versions to Git commits for additional metadata
    version_map = {v.commit_hash: v for v in db_versions}
    
    # Enhance version data with DB info
    for version in versions:
        if version['commit_hash'] in version_map:
            db_version = version_map[version['commit_hash']]
            version['user'] = db_version.author
            
    return render_template('admin/sites/versions.html', site=site, versions=versions)

@admin.route('/sites/<int:site_id>/versions/<string:commit_hash>')
@login_required
@admin_required
def view_config_version(site_id, commit_hash):
    """View a specific configuration version"""
    site = Site.query.get_or_404(site_id)
    
    # Get the configuration content
    from app.services.config_versioning_service import get_config_content, get_config_versions
    content = get_config_content(site, commit_hash)
    
    if not content:
        flash('Configuration version not found', 'error')
        return redirect(url_for('admin.site_config_versions', site_id=site_id))
    
    # Get version details
    versions = get_config_versions(site)
    version = next((v for v in versions if v['commit_hash'] == commit_hash), None)
    
    return render_template('admin/sites/view_version.html', site=site, version=version, content=content)

@admin.route('/sites/<int:site_id>/versions/compare', methods=['GET', 'POST'])
@login_required
@admin_required
def compare_config_versions(site_id):
    """Compare two configuration versions"""
    site = Site.query.get_or_404(site_id)
    
    from app.services.config_versioning_service import get_config_versions, compare_configs
    
    # Get available versions for selection
    versions = get_config_versions(site)
    
    if request.method == 'POST':
        # Get selected versions for comparison
        version1 = request.form.get('version1')
        version2 = request.form.get('version2', None)
        
        # Get diff
        diff = compare_configs(site, version1, version2)
        
        # Format the diff for display
        formatted_diff = []
        if diff:
            for line in diff.split('\n'):
                if line.startswith('+'):
                    formatted_diff.append(('addition', line))
                elif line.startswith('-'):
                    formatted_diff.append(('deletion', line))
                else:
                    formatted_diff.append(('context', line))
                    
            # Get version details for display
            v1_details = next((v for v in versions if v['commit_hash'] == version1), None)
            v2_details = next((v for v in versions if v['commit_hash'] == version2), None) if version2 else {'short_hash': 'Current'}
            
            return render_template('admin/sites/compare_versions.html', 
                                  site=site, 
                                  versions=versions, 
                                  diff=formatted_diff,
                                  v1=v1_details,
                                  v2=v2_details)
        else:
            flash('Error comparing versions', 'error')
    
    # Initial version selection form
    return render_template('admin/sites/compare_versions.html', site=site, versions=versions, diff=None)

@admin.route('/sites/<int:site_id>/versions/<string:commit_hash>/rollback', methods=['POST'])
@login_required
@admin_required
def rollback_config_version(site_id, commit_hash):
    """Rollback to a specific configuration version"""
    site = Site.query.get_or_404(site_id)
    
    # Check if we should deploy the rolled back config
    deploy = request.form.get('deploy', 'false') == 'true'
    
    # Perform the rollback
    from app.services.config_versioning_service import rollback_config
    success = rollback_config(site, commit_hash, deploy, current_user.id)
    
    if success:
        if deploy:
            flash(f'Successfully rolled back and deployed configuration for {site.domain}', 'success')
        else:
            flash(f'Successfully rolled back configuration for {site.domain} (not deployed)', 'success')
    else:
        flash(f'Error rolling back configuration for {site.domain}', 'error')
    
    return redirect(url_for('admin.site_config_versions', site_id=site_id))

@admin.route('/sites/<int:site_id>/test-config', methods=['GET', 'POST'])
@login_required
@admin_required
def test_site_config(site_id):
    """Test a site configuration without deploying it"""
    site = Site.query.get_or_404(site_id)
    
    if request.method == 'POST':
        # Get the node to test on
        node_id = request.form.get('node_id')
        if not node_id:
            flash('Please select a node to test on', 'error')
            nodes = Node.query.filter_by(is_active=True).all()
            return render_template('admin/sites/test_config.html', site=site, nodes=nodes)
        
        # Generate configuration
        from app.services.nginx_service import generate_nginx_config, deploy_to_node
        config = generate_nginx_config(site)
        
        try:
            # Test the configuration (test_only=True)
            success, warnings = deploy_to_node(site.id, int(node_id), config, test_only=True)
            
            if success:
                flash('Configuration test successful', 'success')
                if warnings:
                    flash('Warnings: ' + '<br>'.join(warnings), 'warning')
            else:
                flash('Configuration test failed', 'error')
            
            return redirect(url_for('admin.view_site', site_id=site_id))
        except Exception as e:
            flash(f'Error testing configuration: {str(e)}', 'error')
    
    # Show test form
    nodes = Node.query.filter_by(is_active=True).all()
    return render_template('admin/sites/test_config.html', site=site, nodes=nodes)

@admin.route('/sites/<int:site_id>/ssl', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_ssl_certificates(site_id):
    """Manage SSL certificates for a site"""
    from flask import session as flask_session  # Import session with a different name to avoid shadowing
    
    site = Site.query.get_or_404(site_id)
    
    # Get all nodes serving this site
    site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
    nodes = [Node.query.get(sn.node_id) for sn in site_nodes]
    
    if request.method == 'POST':
        # Determine what action we're taking
        action = request.form.get('action')
        node_id = request.form.get('node_id')
        
        if not node_id and action not in ['check_dns', 'get_recommendations']:
            flash('Please select a node', 'error')
            return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
        
        from app.services.ssl_certificate_service import SSLCertificateService
        
        if action == 'check':
            # Check certificate status
            result = SSLCertificateService.check_certificate_status(site_id, node_id)
            
            if 'error' in result:
                flash(f"Error checking certificate: {result['error']}", 'error')
            
            # Store result in session for template rendering
            flask_session['cert_check_result'] = result
            
        elif action == 'request':
            # Request new certificate
            email = request.form.get('email')
            challenge_type = request.form.get('challenge_type', 'http')
            cert_type = request.form.get('cert_type', 'standard')
            dns_provider = request.form.get('dns_provider')
            
            # Validate email for certificate requests
            import re
            if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                flash('Please provide a valid email address for certificate notifications', 'error')
                return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
            
            # Validate DNS provider for DNS challenges
            if challenge_type == 'dns' and not dns_provider and dns_provider != 'manual':
                flash('Please select a DNS provider for DNS validation', 'error')
                return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
                
            # Process DNS credentials if provided
            dns_credentials = None
            if challenge_type == 'dns' and dns_provider:
                dns_credentials = {}
                if dns_provider == 'cloudflare':
                    dns_credentials['token'] = request.form.get('cf_token')
                    if not dns_credentials['token']:
                        flash('Please provide a Cloudflare API token', 'error')
                        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
                elif dns_provider == 'route53':
                    dns_credentials['access_key'] = request.form.get('aws_access_key')
                    dns_credentials['secret_key'] = request.form.get('aws_secret_key')
                    if not dns_credentials['access_key'] or not dns_credentials['secret_key']:
                        flash('Please provide both AWS Access Key and Secret Key', 'error')
                        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
                elif dns_provider == 'digitalocean':
                    dns_credentials['token'] = request.form.get('do_token')
                    if not dns_credentials['token']:
                        flash('Please provide a DigitalOcean API token', 'error')
                        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
                elif dns_provider == 'godaddy':
                    dns_credentials['key'] = request.form.get('godaddy_key')
                    dns_credentials['secret'] = request.form.get('godaddy_secret')
                    if not dns_credentials['key'] or not dns_credentials['secret']:
                        flash('Please provide both GoDaddy API Key and Secret', 'error')
                        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
                elif dns_provider == 'namecheap':
                    dns_credentials['username'] = request.form.get('namecheap_username')
                    dns_credentials['api_key'] = request.form.get('namecheap_api_key')
                    if not dns_credentials['username'] or not dns_credentials['api_key']:
                        flash('Please provide both Namecheap Username and API Key', 'error')
                        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
            
            # Request certificate
            result = SSLCertificateService.request_certificate(
                site_id=site_id, 
                node_id=node_id, 
                email=email,
                challenge_type=challenge_type,
                dns_provider=dns_provider,
                dns_credentials=dns_credentials,
                cert_type=cert_type
            )
            
            if result.get('success', False):
                if challenge_type == 'manual-dns':
                    # Special handling for manual DNS challenge
                    flask_session['manual_dns_instructions'] = result
                    flash(f'Follow the manual DNS challenge instructions. You will need to create DNS TXT records.', 'info')
                else:
                    cert_type_name = "wildcard" if cert_type == 'wildcard' else "standard"
                    flash(f'SSL {cert_type_name} certificate successfully requested and installed using {challenge_type} validation', 'success')
            else:
                flash(f"Failed to request SSL certificate: {result.get('message', 'Unknown error')}", 'error')
                
        elif action == 'generate_self_signed':
            # Generate self-signed certificate
            result = SSLCertificateService.generate_self_signed_certificate(site_id, node_id)
            
            if result.get('success'):
                flash('Self-signed certificate generated successfully.', 'success')
            else:
                flash(f"Self-signed certificate generation failed: {result.get('message', 'Unknown error')}", 'error')
        
        elif action == 'setup_renewal':
            # Setup auto renewal
            renewal_days = int(request.form.get('renewal_days', 30))
            result = SSLCertificateService.setup_auto_renewal(node_id, renewal_days)
            
            if result.get('success', False):
                flash('Certificate auto-renewal configured successfully', 'success')
            else:
                flash(f"Failed to configure certificate auto-renewal: {result.get('message', 'Unknown error')}", 'error')
        
        elif action == 'revoke':
            # Revoke certificate
            result = SSLCertificateService.revoke_certificate(site_id, node_id)
            
            if result.get('success', False):
                flash('Certificate successfully revoked', 'success')
            else:
                flash(f"Failed to revoke certificate: {result.get('message', 'Unknown error')}", 'error')
        
        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
    
    # Get certificate status from session if available
    cert_check_result = flask_session.pop('cert_check_result', None)
    dns_check_result = flask_session.pop('dns_check_result', None)
    ssl_recommendations = flask_session.pop('ssl_recommendations', None)
    manual_dns_instructions = flask_session.pop('manual_dns_instructions', None)
    
    # If HTTPS site and no other data is available, automatically do a DNS check
    if site.protocol == 'https' and not dns_check_result and not cert_check_result and not ssl_recommendations:
        from app.services.ssl_certificate_service import SSLCertificateService
        dns_check_result = SSLCertificateService.check_domain_dns(site.domain)
        # Also get recommendations
        ssl_recommendations = SSLCertificateService.get_issuance_recommendations(site_id)
    
    # If cert status isn't available, check it for HTTPS sites
    cert_status = None
    if site.protocol == 'https' and not cert_check_result:
        from app.services.ssl_certificate_service import SSLCertificateService
        cert_status = SSLCertificateService.check_certificate_status(site_id)
    else:
        cert_status = cert_check_result
    
    # Get list of supported DNS providers
    dns_providers = []
    if site.protocol == 'https':
        from app.services.ssl_certificate_service import SSLCertificateService
        dns_providers = SSLCertificateService.get_supported_dns_providers()
    
    # Check certificate health
    cert_health = None
    if site.protocol == 'https':
        from app.models.models import SSLCertificate
        ssl_certificates = SSLCertificate.query.filter_by(site_id=site_id).all()
    
    return render_template(
        'admin/sites/ssl_management.html',
        site=site,
        nodes=nodes,
        cert_status=cert_status,
        dns_check_result=dns_check_result,
        ssl_recommendations=ssl_recommendations,
        manual_dns_instructions=manual_dns_instructions,
        dns_providers=dns_providers,
        cert_health=cert_health,
        ssl_certificates=ssl_certificates if 'ssl_certificates' in locals() else []
    )

@admin.route('/ssl-dashboard')
@login_required
@admin_required
def ssl_dashboard():
    """Dashboard view for all SSL certificates across sites"""
    from app.services.ssl_certificate_service import SSLCertificateService
    
    try:
        # Get certificate health dashboard data
        cert_health = SSLCertificateService.get_certificates_health_dashboard()
        
        # Get sites with SSL certificates
        from app.models.models import SSLCertificate, Site
        sites_with_certs = db.session.query(Site).join(
            SSLCertificate, SSLCertificate.site_id == Site.id
        ).distinct().all()
        
        return render_template(
            'admin/ssl_dashboard.html',
            cert_health=cert_health,
            sites_with_certs=sites_with_certs
        )
    except Exception as e:
        # Log the error
        from app.services.logger_service import log_activity
        log_activity(
            category='error',
            action='view_ssl_dashboard',
            resource_type='ssl',
            details=f"Error loading SSL dashboard: {str(e)}"
        )
        
        # Show error to admin
        flash(f"Error loading SSL dashboard: {str(e)}", 'error')
        return redirect(url_for('admin.dashboard'))

@admin.route('/templates')
@login_required
@admin_required
def list_templates():
    """List nginx configuration templates"""
    from app.services.config_template_service import ConfigTemplateService
    
    templates = ConfigTemplateService.list_templates()
    presets = ConfigTemplateService.list_presets()
    
    return render_template('admin/templates/list.html', 
                          templates=templates,
                          presets=presets)

@admin.route('/templates/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_template():
    """Create a new nginx configuration template"""
    from app.services.config_template_service import ConfigTemplateService
    
    if request.method == 'POST':
        template_name = request.form.get('template_name')
        content = request.form.get('content')
        
        if not template_name or not content:
            flash('Template name and content are required', 'error')
            return redirect(url_for('admin.new_template'))
        
        # Add .conf extension if missing
        if not template_name.endswith('.conf'):
            template_name += '.conf'
        
        # Save the template
        success = ConfigTemplateService.save_template(template_name, content)
        
        if success:
            flash(f'Template {template_name} created successfully', 'success')
            return redirect(url_for('admin.list_templates'))
        else:
            flash(f'Failed to create template {template_name}. It may already exist.', 'error')
            return redirect(url_for('admin.new_template'))
    
    return render_template('admin/templates/new.html')

@admin.route('/templates/edit/<path:template_name>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_template(template_name):
    """Edit an existing nginx configuration template"""
    from app.services.config_template_service import ConfigTemplateService
    
    # Get the template content
    content = ConfigTemplateService.get_template_content(template_name)
    
    if not content:
        flash(f'Template {template_name} not found', 'error')
        return redirect(url_for('admin.list_templates'))
    
    if request.method == 'POST':
        new_content = request.form.get('content')
        
        if not new_content:
            flash('Template content is required', 'error')
            return render_template('admin/templates/edit.html', 
                                template_name=template_name,
                                content=content)
        
        # Save the updated template
        success = ConfigTemplateService.save_template(template_name, new_content, overwrite=True)
        
        if success:
            flash(f'Template {template_name} updated successfully', 'success')
            return redirect(url_for('admin.list_templates'))
        else:
            flash(f'Failed to update template {template_name}', 'error')
            return render_template('admin/templates/edit.html', 
                                template_name=template_name,
                                content=content)
    
    return render_template('admin/templates/edit.html', 
                          template_name=template_name,
                          content=content)

@admin.route('/templates/delete/<path:template_name>', methods=['POST'])
@login_required
@admin_required
def delete_template(template_name):
    """Delete a template"""
    from app.services.config_template_service import ConfigTemplateService
    
    success = ConfigTemplateService.delete_template(template_name)
    
    if success:
        flash(f'Template {template_name} deleted successfully', 'success')
    else:
        flash(f'Failed to delete template {template_name}. Default templates cannot be deleted.', 'error')
    
    return redirect(url_for('admin.list_templates'))

@admin.route('/presets/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_preset():
    """Create a new configuration preset"""
    if request.method == 'POST':
        from app.services.config_template_service import ConfigTemplateService
        
        preset_name = request.form.get('preset_name')
        description = request.form.get('description', '')
        preset_type = request.form.get('type', 'custom')
        
        # Parse the preset data from form fields
        preset_data = {
            'name': preset_name,
            'description': description,
            'type': preset_type,
            'created_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'created_by': current_user.username,
            'use_waf': request.form.get('use_waf') == 'on',
            'force_https': request.form.get('force_https') == 'on',
            'enable_cache': request.form.get('enable_cache') == 'on',
            'cache_time': int(request.form.get('cache_time', 3600)),
            'cache_browser_time': int(request.form.get('cache_browser_time', 3600)),
            'cache_static_time': int(request.form.get('cache_static_time', 86400))
        }
        
        # Add custom config if provided
        custom_config = request.form.get('custom_config', '').strip()
        if custom_config:
            preset_data['custom_config'] = custom_config
        
        # Add custom cache rules if provided
        custom_cache_rules = request.form.get('custom_cache_rules', '').strip()
        if custom_cache_rules:
            preset_data['custom_cache_rules'] = custom_cache_rules
        
        # Save the preset
        success = ConfigTemplateService.save_preset(preset_name, preset_data)
        
        if success:
            flash(f'Preset {preset_name} created successfully', 'success')
            return redirect(url_for('admin.list_templates'))
        else:
            flash(f'Failed to create preset {preset_name}. It may already exist.', 'error')
            return redirect(url_for('admin.new_preset'))
    
    return render_template('admin/templates/new_preset.html')

@admin.route('/presets/from_site/<int:site_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def preset_from_site(site_id):
    """Create a preset from a site's current configuration"""
    site = Site.query.get_or_404(site_id)
    
    if request.method == 'POST':
        from app.services.config_template_service import ConfigTemplateService
        
        preset_name = request.form.get('preset_name')
        description = request.form.get('description', f'Preset created from {site.domain}')
        
        if not preset_name:
            flash('Preset name is required', 'error')
            return redirect(url_for('admin.preset_from_site', site_id=site_id))
        
        # Create the preset
        success, message = ConfigTemplateService.create_preset_from_site(site_id, preset_name, description)
        
        if success:
            flash(message, 'success')
            return redirect(url_for('admin.list_templates'))
        else:
            flash(message, 'error')
            return redirect(url_for('admin.preset_from_site', site_id=site_id))
    
    return render_template('admin/templates/preset_from_site.html', site=site)

@admin.route('/presets/view/<path:preset_name>')
@login_required
@admin_required
def view_preset(preset_name):
    """View a configuration preset"""
    from app.services.config_template_service import ConfigTemplateService
    
    preset = ConfigTemplateService.get_preset(preset_name)
    
    if not preset:
        flash(f'Preset {preset_name} not found', 'error')
        return redirect(url_for('admin.list_templates'))
    
    return render_template('admin/templates/view_preset.html', preset=preset, preset_name=preset_name)

@admin.route('/presets/delete/<path:preset_name>', methods=['POST'])
@login_required
@admin_required
def delete_preset(preset_name):
    """Delete a preset"""
    from app.services.config_template_service import ConfigTemplateService
    
    success = ConfigTemplateService.delete_preset(preset_name)
    
    if success:
        flash(f'Preset {preset_name} deleted successfully', 'success')
    else:
        flash(f'Failed to delete preset {preset_name}', 'error')
    
    return redirect(url_for('admin.list_templates'))

@admin.route('/presets/apply/<path:preset_name>/<int:site_id>', methods=['POST'])
@login_required
@admin_required
def apply_preset(preset_name, site_id):
    """Apply a preset to a site"""
    from app.services.config_template_service import ConfigTemplateService
    
    site = Site.query.get_or_404(site_id)
    
    # Apply the preset
    success, message = ConfigTemplateService.apply_preset_to_site(site_id, preset_name)
    
    if success:
        flash(message, 'success')
        
        # Automatically redeploy the site to all nodes with new settings
        try:
            from app.services.nginx_service import generate_nginx_config, deploy_to_node
            
            # Generate updated Nginx configuration
            nginx_config = generate_nginx_config(site)
            
            # Deploy to each node
            site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
            deploy_errors = []
            
            for site_node in site_nodes:
                try:
                    # Deploy to node
                    deploy_to_node(site.id, site_node.node_id, nginx_config)
                except Exception as e:
                    deploy_errors.append(f"Error deploying to {site_node.node.name}: {str(e)}")
            
            if deploy_errors:
                error_message = "<br>".join(deploy_errors)
                flash(f'Preset applied, but there were deployment errors:<br>{error_message}', 'warning')
            else:
                flash('Preset applied and successfully deployed to all nodes.', 'success')
        except Exception as e:
            flash(f'Preset applied, but deployment failed: {str(e)}', 'warning')
    else:
        flash(message, 'error')
    
    # Redirect to appropriate page
    referrer = request.referrer
    if referrer and 'view_site' in referrer:
        return redirect(url_for('admin.view_site', site_id=site_id))
    else:
        return redirect(url_for('admin.view_preset', preset_name=preset_name))

# Country Blocking Management (Admin Level - iptables)
@admin.route('/nodes/<int:node_id>/country-blocking', methods=['GET', 'POST'])
@login_required
@admin_required
def node_country_blocking(node_id):
    """Manage iptables-level country blocking for a node (admin only)"""
    node = Node.query.get_or_404(node_id)
    
    from app.services.iptables_country_blocking_service import IptablesCountryBlockingService
    
    # Check if GeoIP module is installed and available
    geoip_status = IptablesCountryBlockingService.check_geoip_module(node)
    
    # Get current blocked countries
    blocked_countries = IptablesCountryBlockingService.get_blocked_countries(node)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'block':
            # Get countries to block
            countries = [c.strip() for c in request.form.get('countries', '').split(',') if c.strip()]
            
            if countries:
                success, message = IptablesCountryBlockingService.block_countries(node, countries, current_user.id)
                
                if success:
                    # Save rules to persist after reboot
                    IptablesCountryBlockingService.save_iptables_rules(node)
                    flash(message, 'success')
                else:
                    flash(message, 'error')
            else:
                flash('No countries specified', 'error')
                
        elif action == 'unblock':
            # Get countries to unblock
            countries = request.form.getlist('blocked_countries')
            
            if countries:
                success, message = IptablesCountryBlockingService.unblock_countries(node, countries, current_user.id)
                
                if success:
                    # Save rules to persist after reboot
                    IptablesCountryBlockingService.save_iptables_rules(node)
                    flash(message, 'success')
                else:
                    flash(message, 'error')
            else:
                flash('No countries selected for unblocking', 'error')
                
        elif action == 'install_geoip':
            # Install GeoIP module
            success, message = IptablesCountryBlockingService.install_geoip_module(node, current_user.id)
            
            if success:
                flash(message, 'success')
                # Refresh the GeoIP status
                geoip_status = IptablesCountryBlockingService.check_geoip_module(node)
            else:
                flash(message, 'error')
                
        # Refresh the blocked countries list
        blocked_countries = IptablesCountryBlockingService.get_blocked_countries(node)
        
    return render_template('admin/nodes/country_blocking.html', 
                           node=node, 
                           blocked_countries=blocked_countries,
                           geoip_status=geoip_status)

@admin.route('/sites/<int:site_id>/waf', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_site_waf(site_id):
    """Manage advanced WAF settings for a site"""
    site = Site.query.get_or_404(site_id)
    
    if request.method == 'POST':
        try:
            # Server-side validation
            errors = []
            
            # Basic validation - presence of required fields
            waf_rule_level = request.form.get('waf_rule_level', 'basic')
            if waf_rule_level not in ['basic', 'medium', 'strict']:
                errors.append('Invalid WAF rule level provided')
            
            # Validate max request size
            try:
                waf_max_request_size = int(request.form.get('waf_max_request_size', 1))
                if waf_max_request_size < 1 or waf_max_request_size > 100:
                    errors.append('Max request size must be between 1 and 100 MB')
            except ValueError:
                errors.append('Max request size must be a valid number')
            
            # Validate request timeout
            try:
                waf_request_timeout = int(request.form.get('waf_request_timeout', 60))
                if waf_request_timeout < 10 or waf_request_timeout > 300:
                    errors.append('Request timeout must be between 10 and 300 seconds')
            except ValueError:
                errors.append('Request timeout must be a valid number')
            
            # Validate rate limiting if enabled
            if 'waf_rate_limiting_enabled' in request.form:
                try:
                    waf_rate_limiting_requests = int(request.form.get('waf_rate_limiting_requests', 100))
                    if waf_rate_limiting_requests < 10 or waf_rate_limiting_requests > 10000:
                        errors.append('Requests per minute must be between 10 and 10000')
                except ValueError:
                    errors.append('Requests per minute must be a valid number')
                
                try:
                    waf_rate_limiting_burst = int(request.form.get('waf_rate_limiting_burst', 200))
                    if waf_rate_limiting_burst < 10 or waf_rate_limiting_burst > 20000:
                        errors.append('Burst size must be between 10 and 20000')
                except ValueError:
                    errors.append('Burst size must be a valid number')
            
            # OWASP CRS paranoia level validation
            if 'waf_use_owasp_crs' in request.form:
                try:
                    waf_owasp_crs_paranoia = int(request.form.get('waf_owasp_crs_paranoia', 1))
                    if waf_owasp_crs_paranoia < 1 or waf_owasp_crs_paranoia > 4:
                        errors.append('OWASP CRS paranoia level must be between 1 and 4')
                except ValueError:
                    errors.append('OWASP CRS paranoia level must be a valid number')
            
            # Validate disabled CRS rules format (comma-separated numbers or ranges)
            waf_disabled_crs_rules = request.form.get('waf_disabled_crs_rules', '')
            if waf_disabled_crs_rules.strip():
                import re
                rule_pattern = re.compile(r'^(\d+(-\d+)?)(,\s*\d+(-\d+)?)*$')
                if not rule_pattern.match(waf_disabled_crs_rules):
                    errors.append('Disabled CRS rule IDs must be in the format of comma-separated numbers or ranges (e.g., 123, 456-789)')
            
            # Validate custom rules for unmatched quotes or other syntax issues
            waf_custom_rules = request.form.get('waf_custom_rules', '')
            if waf_custom_rules.strip():
                # Count quotes to check for unmatched pairs
                single_quotes = waf_custom_rules.count("'")
                double_quotes = waf_custom_rules.count('"')
                
                if single_quotes % 2 != 0:
                    errors.append('Custom rules contain unmatched single quotes')
                
                if double_quotes % 2 != 0:
                    errors.append('Custom rules contain unmatched double quotes')
            
            # If any validation errors, raise Exception
            if errors:
                raise ValueError('\n'.join(errors))
                
            # If we get here, validation passed - update the site
            site.use_waf = 'use_waf' in request.form
            site.waf_rule_level = waf_rule_level
            site.waf_custom_rules = waf_custom_rules
            site.waf_max_request_size = waf_max_request_size
            site.waf_request_timeout = waf_request_timeout
            site.waf_block_tor_exit_nodes = 'waf_block_tor_exit_nodes' in request.form
            site.waf_rate_limiting_enabled = 'waf_rate_limiting_enabled' in request.form
            
            if 'waf_rate_limiting_enabled' in request.form:
                site.waf_rate_limiting_requests = waf_rate_limiting_requests
                site.waf_rate_limiting_burst = waf_rate_limiting_burst
            
            # OWASP ModSecurity Core Rule Set settings
            site.waf_use_owasp_crs = 'waf_use_owasp_crs' in request.form
            
            if 'waf_use_owasp_crs' in request.form:
                site.waf_owasp_crs_paranoia = waf_owasp_crs_paranoia
                site.waf_enabled_crs_rules = request.form.get('waf_enabled_crs_rules')
                site.waf_disabled_crs_rules = waf_disabled_crs_rules
            
            db.session.commit()
            
            # Get all nodes serving this site and update their configurations
            site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
            
            try:
                from app.services.nginx_service import generate_nginx_config, deploy_to_node
                
                # Generate updated Nginx configuration with WAF settings
                nginx_config = generate_nginx_config(site)
                
                # Deploy to each node
                for site_node in site_nodes:
                    node_id = site_node.node_id
                    deploy_to_node(site.id, node_id, nginx_config)
                    
                    # Log the action
                    log = DeploymentLog(
                        site_id=site_id,
                        node_id=node_id,
                        action="Update WAF settings",
                        status="success",
                        message="Advanced WAF settings updated and deployed"
                    )
                    db.session.add(log)
                
                db.session.commit()
                flash('WAF settings updated successfully and configuration deployed', 'success')
            except Exception as e:
                flash(f'WAF settings updated but configuration deployment failed: {str(e)}', 'warning')
                
        except ValueError as validation_error:
            flash(f'Validation errors: {str(validation_error)}', 'error')
            # Prepare WAF rule level options for template
            rule_levels = [
                {'value': 'basic', 'label': 'Basic Protection', 'description': 'Basic protection against common web attacks'},
                {'value': 'medium', 'label': 'Medium Protection', 'description': 'Enhanced protection with more strict rules'},
                {'value': 'strict', 'label': 'Strict Protection', 'description': 'Maximum protection with potential false positives'}
            ]
            return render_template('admin/sites/waf_settings.html', site=site, rule_levels=rule_levels)
        
        return redirect(url_for('admin.view_site', site_id=site_id))
    
    # Prepare WAF rule level options
    rule_levels = [
        {'value': 'basic', 'label': 'Basic Protection', 'description': 'Basic protection against common web attacks'},
        {'value': 'medium', 'label': 'Medium Protection', 'description': 'Enhanced protection with more strict rules'},
        {'value': 'strict', 'label': 'Strict Protection', 'description': 'Maximum protection with potential false positives'}
    ]
    
    return render_template('admin/sites/waf_settings.html', 
                           site=site,
                           rule_levels=rule_levels)

@admin.route('/analytics')
@login_required
@admin_required
def analytics_dashboard():
    """Admin analytics dashboard"""
    try:
        # Get analytics data with error handling
        analytics_data = AnalyticsService.get_admin_analytics()
        
        # Ensure we have all the required keys for the template
        required_keys = [
            'dates', 'bandwidth_data', 'requests_data', 'node_names', 
            'node_response_times', 'node_error_rates', 'status_distribution',
            'geo_distribution', 'total_bandwidth', 'total_requests', 
            'active_sites', 'total_sites', 'error_rate', 'total_errors',
            'bandwidth_change', 'requests_change', 'sites', 'top_errors'
        ]
        
        # Initialize missing keys with empty/default values
        for key in required_keys:
            if key not in analytics_data:
                if key in ['dates', 'bandwidth_data', 'requests_data', 'node_names', 
                          'node_response_times', 'node_error_rates', 'sites', 'top_errors']:
                    analytics_data[key] = []
                elif key == 'status_distribution':
                    analytics_data[key] = [0, 0, 0, 0]  # 2xx, 3xx, 4xx, 5xx
                elif key == 'geo_distribution':
                    analytics_data[key] = {}
                elif key in ['total_bandwidth', 'total_requests', 'active_sites', 
                            'total_sites', 'error_rate', 'total_errors']:
                    analytics_data[key] = 0
                elif key in ['bandwidth_change', 'requests_change']:
                    analytics_data[key] = 0.0
        
        # Use current date for date ranges if not provided
        if 'start_date' not in analytics_data:
            analytics_data['start_date'] = datetime.now() - timedelta(days=7)
        if 'end_date' not in analytics_data:
            analytics_data['end_date'] = datetime.now()
            
        return render_template('admin/analytics/dashboard.html', **analytics_data)
    
    except Exception as e:
        # Log the error
        from app.services.logger_service import log_activity
        log_activity(
            category='error',
            action='view_analytics',
            resource_type='analytics',
            details=f"Error loading analytics dashboard: {str(e)}"
        )
        
        # Show error to admin
        flash(f"Error loading analytics dashboard: {str(e)}", 'error')
        return redirect(url_for('admin.dashboard'))

@admin.route('/analytics/data')
@login_required
@admin_required
def analytics_data():
    """API endpoint for analytics data"""
    period = request.args.get('period', 'week')
    real_time = request.args.get('real_time', 'false').lower() == 'true'
    
    data = AnalyticsService.get_api_analytics_data(period=period, real_time=real_time)
    return jsonify(data)

@admin.route('/node-health/refresh')
@login_required
@admin_required
def refresh_node_health():
    """API endpoint to refresh node health status"""
    from app.services.nginx_service import get_node_stats
    from app.services.node_inspection_service import check_node_connectivity
    
    nodes = Node.query.filter_by(is_active=True).all()
    nodes_data = []
    
    for node in nodes:
        try:
            # Check if the node is reachable
            is_reachable = check_node_connectivity(node)
            
            if is_reachable:
                # Get real server stats if node is reachable
                server_stats, _ = get_node_stats(node)
                
                # Extract CPU load from server stats
                cpu_load = 0
                if 'cpu_usage' in server_stats:
                    # Extract percentage from string like "32%"
                    cpu_str = server_stats.get('cpu_usage', '0%')
                    cpu_load = int(cpu_str.strip('%').split()[0]) if '%' in cpu_str else 0
                
                # Extract memory usage from server stats
                memory_usage = 0
                if 'memory_usage' in server_stats:
                    # Extract percentage from string like "4.2GB / 8GB (52%)"
                    mem_str = server_stats.get('memory_usage', '0%')
                    if '%' in mem_str:
                        mem_percent = mem_str.split('(')[1].split(')')[0].strip('%') if '(' in mem_str else '0'
                        memory_usage = int(mem_percent)
                
                # Determine health status based on CPU and memory
                health_status = "healthy"
                if cpu_load > 90 or memory_usage > 90:
                    health_status = "unhealthy"
                elif cpu_load > 75 or memory_usage > 75:
                    health_status = "warning"
                
                node_data = {
                    "id": node.id,
                    "name": node.name,
                    "ip_address": node.ip_address,
                    "health_status": health_status,
                    "cpu_load": cpu_load,
                    "memory_usage": memory_usage,
                    "last_check": datetime.utcnow().strftime("%Y-%m-%d %H:%m")
                }
            else:
                # Node is unreachable
                node_data = {
                    "id": node.id,
                    "name": node.name,
                    "ip_address": node.ip_address,
                    "health_status": "unreachable",
                    "cpu_load": 0,
                    "memory_usage": 0,
                    "last_check": datetime.utcnow().strftime("%Y-%m-%d %H:%m")
                }
                
            nodes_data.append(node_data)
            
        except Exception as e:
            # Log error
            from app.services.logger_service import log_activity
            log_activity(
                category='error',
                action='check_node_health',
                resource_type='node',
                resource_id=node.id,
                details=f"Error checking node health: {str(e)}"
            )
            
            # Add node with error status
            node_data = {
                "id": node.id,
                "name": node.name,
                "ip_address": node.ip_address,
                "health_status": "error",
                "cpu_load": 0,
                "memory_usage": 0,
                "error": str(e),
                "last_check": datetime.utcnow().strftime("%Y-%m-%d %H:%m")
            }
            nodes_data.append(node_data)
    
    return jsonify({"nodes": nodes_data})

@admin.route('/sites/<int:site_id>/request-certificate', methods=['POST'])
@login_required
@admin_required
def request_certificate(site_id):
    """API endpoint to request a certificate for a site"""
    site = Site.query.get_or_404(site_id)
    
    # Get required parameters
    node_id = request.form.get('node_id')
    email = request.form.get('email')
    challenge_type = request.form.get('challenge_type', 'http')
    cert_type = request.form.get('cert_type', 'standard')
    
    if not node_id or not email:
        flash('Node ID and email address are required', 'error')
        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
    
    # Get DNS provider for DNS challenges
    dns_provider = None
    dns_credentials = None
    if challenge_type == 'dns':
        dns_provider = request.form.get('dns_provider')
        
        # Extract credentials if provided
        if dns_provider:
            dns_credentials = {}
            if dns_provider == 'cloudflare':
                dns_credentials['token'] = request.form.get('cf_token')
            elif dns_provider == 'route53':
                dns_credentials['access_key'] = request.form.get('aws_access_key')
                dns_credentials['secret_key'] = request.form.get('aws_secret_key')
            elif dns_provider == 'digitalocean':
                dns_credentials['token'] = request.form.get('do_token')
            elif dns_provider == 'godaddy':
                dns_credentials['key'] = request.form.get('godaddy_key')
                dns_credentials['secret'] = request.form.get('godaddy_secret')
            elif dns_provider == 'namecheap':
                dns_credentials['username'] = request.form.get('namecheap_username')
                dns_credentials['api_key'] = request.form.get('namecheap_api_key')
    
    # Call certificate service to request a certificate
    from app.services.ssl_certificate_service import SSLCertificateService
    result = SSLCertificateService.request_certificate(
        site_id=site_id,
        node_id=node_id,
        email=email,
        challenge_type=challenge_type,
        dns_provider=dns_provider,
        dns_credentials=dns_credentials,
        cert_type=cert_type
    )
    
    if result.get('success', False):
        if challenge_type == 'manual-dns':
            # Store DNS challenge information in session
            from flask import session as flask_session
            flask_session['manual_dns_instructions'] = result
            flash('Follow the DNS challenge instructions to complete certificate issuance', 'info')
        else:
            flash('Certificate requested successfully', 'success')
    else:
        flash(f"Failed to request certificate: {result.get('message', 'Unknown error')}", 'error')
    
    return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))

@admin.route('/request-certificate', methods=['GET', 'POST'])
@login_required
@admin_required
def initiate_certificate_request():
    """Route for initiating SSL certificate requests from the SSL dashboard"""
    # Get all sites with HTTPS protocol
    https_sites = Site.query.filter_by(protocol='https').all()
    
    # Get all active nodes
    nodes = Node.query.filter_by(is_active=True).all()
    
    # If no HTTPS sites exist, show a message
    if not https_sites:
        flash('No HTTPS sites found. Please create a site with HTTPS protocol first.', 'warning')
        return redirect(url_for('admin.ssl_dashboard'))
    
    # Get list of supported DNS providers
    from app.services.ssl_certificate_service import SSLCertificateService
    dns_providers = SSLCertificateService.get_supported_dns_providers()
    
    # Handle form submission
    if request.method == 'POST':
        site_id = request.form.get('site_id')
        node_id = request.form.get('node_id')
        email = request.form.get('email')
        challenge_type = request.form.get('challenge_type', 'http')
        cert_type = request.form.get('cert_type', 'standard')
        
        # Validate required fields
        if not site_id or not node_id or not email:
            flash('Site, node, and email are required fields', 'error')
            return render_template(
                'admin/sites/request_certificate.html',
                sites=https_sites,
                nodes=nodes,
                dns_providers=dns_providers
            )
        
        # Process DNS provider information if selected
        dns_provider = None
        dns_credentials = None
        if challenge_type == 'dns':
            dns_provider = request.form.get('dns_provider')
            
            # Extract credentials based on provider
            if dns_provider:
                dns_credentials = {}
                if dns_provider == 'cloudflare':
                    dns_credentials['token'] = request.form.get('cf_token')
                elif dns_provider == 'route53':
                    dns_credentials['access_key'] = request.form.get('aws_access_key')
                    dns_credentials['secret_key'] = request.form.get('aws_secret_key')
                elif dns_provider == 'digitalocean':
                    dns_credentials['token'] = request.form.get('do_token')
                elif dns_provider == 'godaddy':
                    dns_credentials['key'] = request.form.get('godaddy_key')
                    dns_credentials['secret'] = request.form.get('godaddy_secret')
                elif dns_provider == 'namecheap':
                    dns_credentials['username'] = request.form.get('namecheap_username')
                    dns_credentials['api_key'] = request.form.get('namecheap_api_key')
        
        # Request the certificate
        result = SSLCertificateService.request_certificate(
            site_id=site_id,
            node_id=node_id,
            email=email,
            challenge_type=challenge_type,
            dns_provider=dns_provider,
            dns_credentials=dns_credentials,
            cert_type=cert_type
        )
        
        # Handle the result
        if result.get('success', False):
            flash('Certificate requested successfully', 'success')
            return redirect(url_for('admin.ssl_dashboard'))
        else:
            flash(f"Failed to request certificate: {result.get('message', 'Unknown error')}", 'error')
            return render_template(
                'admin/sites/request_certificate.html',
                sites=https_sites,
                nodes=nodes,
                dns_providers=dns_providers
            )
    
    return render_template(
        'admin/sites/request_certificate.html',
        sites=https_sites,
        nodes=nodes,
        dns_providers=dns_providers
    )

@admin.route('/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def settings():
    """Admin settings page to manage system configurations"""
    from flask import current_app
    import os
    
    # Get application settings from config
    app_settings = {
        'app_name': current_app.config.get('APP_NAME', 'Reverse Proxy Manager'),
        'app_version': current_app.config.get('VERSION', '1.0.0'),
        'debug_mode': current_app.config.get('DEBUG', False),
        'maintenance_mode': current_app.config.get('MAINTENANCE_MODE', False),
        'allow_registration': current_app.config.get('ALLOW_REGISTRATION', True),
        'max_upload_size': current_app.config.get('MAX_UPLOAD_SIZE', 50),
        'session_timeout': current_app.config.get('PERMANENT_SESSION_LIFETIME', 30) // 60,  # Convert seconds to minutes
        'log_retention_days': current_app.config.get('LOG_RETENTION_DAYS', 30)
    }
    
    # Get email settings
    email_settings = {
        'smtp_server': current_app.config.get('MAIL_SERVER', ''),
        'smtp_port': current_app.config.get('MAIL_PORT', 587),
        'smtp_username': current_app.config.get('MAIL_USERNAME', ''),
        'smtp_from_address': current_app.config.get('MAIL_DEFAULT_SENDER', ''),
        'enable_ssl': current_app.config.get('MAIL_USE_SSL', True),
        'enable_notifications': current_app.config.get('MAIL_ENABLE_NOTIFICATIONS', False),
        'notification_events': current_app.config.get('NOTIFICATION_EVENTS', ['certificate_expiry', 'node_offline', 'failed_deployment'])
    }
    
    # Get backup settings
    backup_settings = {
        'backup_enabled': current_app.config.get('BACKUP_ENABLED', False),
        'backup_frequency': current_app.config.get('BACKUP_FREQUENCY', 'daily'),
        'backup_retention': current_app.config.get('BACKUP_RETENTION_DAYS', 7),
        'backup_destination': current_app.config.get('BACKUP_DESTINATION', 'local'),
        'backup_path': current_app.config.get('BACKUP_PATH', '/var/backups/proxy-manager'),
        'include_certificates': current_app.config.get('BACKUP_INCLUDE_CERTS', True),
        'include_logs': current_app.config.get('BACKUP_INCLUDE_LOGS', False)
    }
    
    # Get security settings
    security_settings = {
        'failed_login_limit': current_app.config.get('FAILED_LOGIN_LIMIT', 5),
        'password_expiry_days': current_app.config.get('PASSWORD_EXPIRY_DAYS', 90),
        'enforce_password_complexity': current_app.config.get('ENFORCE_PASSWORD_COMPLEXITY', True),
        'allowed_ip_ranges': current_app.config.get('ALLOWED_IP_RANGES', []),
        'api_rate_limit': current_app.config.get('API_RATE_LIMIT', 100)
    }
    
    # Calculate real system statistics
    try:
        # Get database size
        db_path = os.path.join(current_app.instance_path, 'app.db')
        database_size = os.path.getsize(db_path) / (1024 * 1024) if os.path.exists(db_path) else 0  # Convert to MB
        
        # Count config files
        nginx_configs_dir = os.path.join(current_app.root_path, '..', 'nginx_configs')
        config_files_count = sum(1 for _ in os.listdir(nginx_configs_dir)) if os.path.exists(nginx_configs_dir) else 0
        
        # Count log entries
        from app.models.models import DeploymentLog, SystemLog
        deployment_log_count = DeploymentLog.query.count()
        system_log_count = SystemLog.query.count()
        log_files_count = deployment_log_count + system_log_count
        
        # Calculate total size of config files
        config_files_size = 0
        if os.path.exists(nginx_configs_dir):
            for filename in os.listdir(nginx_configs_dir):
                file_path = os.path.join(nginx_configs_dir, filename)
                if os.path.isfile(file_path):
                    config_files_size += os.path.getsize(file_path)
        config_files_size = config_files_size / (1024 * 1024)  # Convert to MB
        
        # Calculate total disk usage
        disk_usage = f"{database_size + config_files_size:.2f} MB"
        
    except Exception as e:
        # If there's an error, use default values
        import logging
        logging.error(f"Error calculating system statistics: {str(e)}")
        database_size = 0
        config_files_count = 0
        log_files_count = 0
        disk_usage = "0 MB"
    
    if request.method == 'POST':
        # Process form data and update settings
        section = request.form.get('section')
        
        if section == 'application':
            app_settings['app_name'] = request.form.get('app_name')
            app_settings['debug_mode'] = 'debug_mode' in request.form
            app_settings['maintenance_mode'] = 'maintenance_mode' in request.form
            app_settings['allow_registration'] = 'allow_registration' in request.form
            
            # Handle potentially empty form values with proper defaults
            max_upload_size = request.form.get('max_upload_size', '')
            app_settings['max_upload_size'] = int(max_upload_size) if max_upload_size.strip() else 50
            
            session_timeout = request.form.get('session_timeout', '')
            app_settings['session_timeout'] = int(session_timeout) if session_timeout.strip() else 30
            
            log_retention_days = request.form.get('log_retention_days', '')
            app_settings['log_retention_days'] = int(log_retention_days) if log_retention_days.strip() else 30
            
            # Update config in database
            try:
                from app.models.models import SystemSetting
                for key, value in app_settings.items():
                    setting = SystemSetting.query.filter_by(key=f"app_{key}").first()
                    if setting:
                        setting.value = str(value)
                    else:
                        db.session.add(SystemSetting(key=f"app_{key}", value=str(value)))
                db.session.commit()
                flash('Application settings updated successfully', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error saving application settings: {str(e)}', 'error')
        
        elif section == 'email':
            email_settings['smtp_server'] = request.form.get('smtp_server')
            email_settings['smtp_port'] = int(request.form.get('smtp_port', 587))
            email_settings['smtp_username'] = request.form.get('smtp_username')
            email_settings['smtp_from_address'] = request.form.get('smtp_from_address')
            email_settings['enable_ssl'] = 'enable_ssl' in request.form
            email_settings['enable_notifications'] = 'enable_notifications' in request.form
            email_settings['notification_events'] = request.form.getlist('notification_events')
            
            # Save email settings to database
            try:
                from app.models.models import SystemSetting
                for key, value in email_settings.items():
                    if isinstance(value, list):
                        value = ','.join(value)
                    setting = SystemSetting.query.filter_by(key=f"email_{key}").first()
                    if setting:
                        setting.value = str(value)
                    else:
                        db.session.add(SystemSetting(key=f"email_{key}", value=str(value)))
                db.session.commit()
                
                if request.form.get('test_email'):
                    # Test email configuration
                    try:
                        from flask_mail import Mail, Message
                        mail = Mail(current_app)
                        msg = Message("Test Email from Reverse Proxy Manager",
                                    sender=email_settings['smtp_from_address'],
                                    recipients=[current_user.email])
                        msg.body = "This is a test email from your Reverse Proxy Manager instance."
                        mail.send(msg)
                        flash('Test email sent successfully', 'success')
                    except Exception as e:
                        flash(f'Failed to send test email: {str(e)}', 'error')
                else:
                    flash('Email settings updated successfully', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error saving email settings: {str(e)}', 'error')
        
        elif section == 'backup':
            backup_settings['backup_enabled'] = 'backup_enabled' in request.form
            backup_settings['backup_frequency'] = request.form.get('backup_frequency')
            backup_settings['backup_retention'] = int(request.form.get('backup_retention', 7))
            backup_settings['backup_destination'] = request.form.get('backup_destination')
            backup_settings['backup_path'] = request.form.get('backup_path')
            backup_settings['include_certificates'] = 'include_certificates' in request.form
            backup_settings['include_logs'] = 'include_logs' in request.form
            
            # Save backup settings to database
            try:
                from app.models.models import SystemSetting
                for key, value in backup_settings.items():
                    setting = SystemSetting.query.filter_by(key=f"backup_{key}").first()
                    if setting:
                        setting.value = str(value)
                    else:
                        db.session.add(SystemSetting(key=f"backup_{key}", value=str(value)))
                db.session.commit()
                
                if request.form.get('run_backup_now'):
                    # Trigger an immediate backup
                    try:
                        from app.services.scheduled_task_service import run_backup
                        success, message = run_backup()
                        if success:
                            flash('Backup started successfully', 'success')
                        else:
                            flash(f'Backup failed: {message}', 'error')
                    except Exception as e:
                        flash(f'Failed to start backup: {str(e)}', 'error')
                else:
                    flash('Backup settings updated successfully', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error saving backup settings: {str(e)}', 'error')
        
        elif section == 'security':
            security_settings['failed_login_limit'] = int(request.form.get('failed_login_limit', 5))
            security_settings['password_expiry_days'] = int(request.form.get('password_expiry_days', 90))
            security_settings['enforce_password_complexity'] = 'enforce_password_complexity' in request.form
            # Two-factor authentication option removed
            security_settings['allowed_ip_ranges'] = [range.strip() for range in request.form.get('allowed_ip_ranges', '').split(',') if range.strip()]
            security_settings['api_rate_limit'] = int(request.form.get('api_rate_limit', 100))
            
            # Save security settings to database
            try:
                from app.models.models import SystemSetting
                for key, value in security_settings.items():
                    if isinstance(value, list):
                        value = ','.join(value)
                    setting = SystemSetting.query.filter_by(key=f"security_{key}").first()
                    if setting:
                        setting.value = str(value)
                    else:
                        # Create new setting if it doesn't exist
                        new_setting = SystemSetting(key=f"security_{key}", value=str(value))
                        db.session.add(new_setting)
                db.session.commit()
                flash('Security settings updated successfully', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error saving security settings: {str(e)}', 'error')
            
        elif section == 'database':
            # Handle database maintenance operations
            action = request.form.get('action')
            
            if action == 'vacuum':
                try:
                    # Perform vacuum operation
                    db.session.execute("VACUUM")
                    db.session.commit()
                    flash('Database vacuum operation completed successfully', 'success')
                except Exception as e:
                    flash(f'Database vacuum failed: {str(e)}', 'error')
                    
            elif action == 'reindex':
                try:
                    # Perform reindex operation
                    db.session.execute("REINDEX")
                    db.session.commit()
                    flash('Database reindex operation completed successfully', 'success')
                except Exception as e:
                    flash(f'Database reindex failed: {str(e)}', 'error')
                    
            elif action == 'optimize':
                try:
                    # Perform optimize operation
                    db.session.execute("PRAGMA optimize")
                    db.session.commit()
                    flash('Database optimization completed successfully', 'success')
                except Exception as e:
                    flash(f'Database optimization failed: {str(e)}', 'error')
                    
        elif section == 'export':
            # Handle system data export
            try:
                import json
                from datetime import datetime
                
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                export_dir = os.path.join(current_app.root_path, '..', 'exports')
                
                # Create exports directory if it doesn't exist
                os.makedirs(export_dir, exist_ok=True)
                
                export_file = os.path.join(export_dir, f'system_export_{timestamp}.json')
                
                export_data = {}
                
                # Export config if selected
                if 'export_config' in request.form:
                    # Export system configuration
                    from app.models.models import SystemSetting
                    settings = SystemSetting.query.all()
                    export_data['config'] = {setting.key: setting.value for setting in settings}
                
                # Export sites data if selected
                if 'export_sites' in request.form:
                    sites = Site.query.all()
                    export_data['sites'] = [site.to_dict() for site in sites]
                
                # Export users data if selected
                if 'export_users' in request.form:
                    users = User.query.all()
                    # Remove sensitive information like passwords
                    export_data['users'] = [{
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'role': user.role,
                        'is_active': user.is_active,
                        'created_at': user.created_at.isoformat() if hasattr(user, 'created_at') else None
                    } for user in users]
                
                # Write export data to file
                with open(export_file, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                # Return the file as a download
                from flask import send_file
                return send_file(export_file, as_attachment=True, download_name=f'system_export_{timestamp}.json')
                
            except Exception as e:
                flash(f'Export failed: {str(e)}', 'error')
    
    return render_template('admin/settings.html',
                          app_settings=app_settings,
                          email_settings=email_settings,
                          backup_settings=backup_settings,
                          security_settings=security_settings,
                          database_size=database_size,
                          config_files_count=config_files_count,
                          log_files_count=log_files_count,
                          disk_usage=disk_usage)

@admin.route('/nodes/<int:node_id>/install-proxy', methods=['POST'])
@login_required
@admin_required
def install_proxy(node_id):
    """Install the appropriate proxy service on a node based on its proxy_type"""
    node = Node.query.get_or_404(node_id)
    
    # Import the proxy service factory
    from app.services.proxy_service_factory import ProxyServiceFactory
    
    # Create the appropriate proxy service based on the node's proxy type
    proxy_service = ProxyServiceFactory.create_service(node.proxy_type)
    
    # Install the service on the node
    success, message = proxy_service.install_service(node, user_id=current_user.id)
    
    if success:
        flash(message, 'success')
    else:
        flash(message, 'error')
    
    return redirect(url_for('admin.view_node', node_id=node_id))

@admin.route('/nodes/<int:node_id>/change-proxy-type', methods=['POST'])
@login_required
@admin_required
def change_node_proxy_type(node_id):
    """Change a node's proxy type and redeploy all sites with the new proxy type"""
    node = Node.query.get_or_404(node_id)
    
    # Get the new proxy type
    new_proxy_type = request.form.get('proxy_type')
    if not new_proxy_type or new_proxy_type == node.proxy_type:
        flash('No change in proxy type', 'info')
        return redirect(url_for('admin.view_node', node_id=node_id))
    
    # Get the available proxy types for validation
    from app.services.proxy_service_factory import ProxyServiceFactory
    available_types = ProxyServiceFactory.get_supported_proxy_types()
    
    if new_proxy_type not in available_types:
        flash(f'Invalid proxy type: {new_proxy_type}', 'error')
        return redirect(url_for('admin.view_node', node_id=node_id))
    
    # Update proxy configuration paths based on the new type
    if new_proxy_type == 'nginx':
        proxy_config_path = request.form.get('proxy_config_path', '/etc/nginx/conf.d')
        proxy_reload_command = request.form.get('proxy_reload_command', 'sudo systemctl reload nginx')
    elif new_proxy_type == 'caddy':
        proxy_config_path = request.form.get('proxy_config_path', '/etc/caddy')
        proxy_reload_command = request.form.get('proxy_reload_command', 'sudo systemctl reload caddy')
    elif new_proxy_type == 'traefik':
        proxy_config_path = request.form.get('proxy_config_path', '/etc/traefik/dynamic')
        proxy_reload_command = request.form.get('proxy_reload_command', 'sudo systemctl reload traefik')
    else:
        proxy_config_path = request.form.get('proxy_config_path')
        proxy_reload_command = request.form.get('proxy_reload_command')
    
    # Save the old proxy type for logging
    old_proxy_type = node.proxy_type
    
    # Update the node
    node.proxy_type = new_proxy_type
    node.proxy_config_path = proxy_config_path
    node.proxy_reload_command = proxy_reload_command
    
    # Save the changes
    db.session.commit()
    
    # Optional: Redeploy sites if requested
    should_redeploy = request.form.get('redeploy', 'false').lower() == 'true'
    
    if should_redeploy:
        # Get all sites deployed on this node
        site_nodes = SiteNode.query.filter_by(node_id=node_id).all()
        
        if not site_nodes:
            flash(f'Node proxy type changed from {old_proxy_type} to {new_proxy_type}. No sites to redeploy.', 'success')
            return redirect(url_for('admin.view_node', node_id=node_id))
        
        # Create the appropriate proxy service
        proxy_service = ProxyServiceFactory.create_service(new_proxy_type)
        
        success_count = 0
        error_count = 0
        
        for site_node in site_nodes:
            site = Site.query.get(site_node.site_id)
            if not site:
                continue
            
            try:
                # Generate config using the new proxy service
                config_content = proxy_service.generate_config(site)
                
                # Deploy to the node
                proxy_service.deploy_config(site.id, node_id, config_content)
                
                # Log the successful deployment
                log = DeploymentLog(
                    site_id=site.id,
                    node_id=node_id,
                    user_id=current_user.id,
                    action="redeploy_after_proxy_change",
                    status="success",
                    message=f"Successfully redeployed site after changing node proxy type from {old_proxy_type} to {new_proxy_type}"
                )
                db.session.add(log)
                success_count += 1
                
            except Exception as e:
                # Log the error
                error_count += 1
                log = DeploymentLog(
                    site_id=site.id,
                    node_id=node_id,
                    user_id=current_user.id,
                    action="redeploy_after_proxy_change",
                    status="error",
                    message=f"Failed to redeploy after proxy type change: {str(e)}"
                )
                db.session.add(log)
        
        db.session.commit()
        
        if error_count > 0:
            flash(f'Node proxy type changed from {old_proxy_type} to {new_proxy_type}. Redeployment completed with {success_count} successes and {error_count} failures. Check the logs for details.', 'warning')
        else:
            flash(f'Node proxy type changed from {old_proxy_type} to {new_proxy_type}. Successfully redeployed all {success_count} sites.', 'success')
    else:
        flash(f'Node proxy type changed from {old_proxy_type} to {new_proxy_type}. Sites were not redeployed.', 'info')
    
    return redirect(url_for('admin.view_node', node_id=node_id))

@admin.route('/sites/<int:site_id>/nodes/<int:node_id>/deploy', methods=['POST'])
@login_required
@admin_required
def deploy_site_to_node(site_id, node_id):
    """Deploy a site to a node using the appropriate proxy service based on node type"""
    site = Site.query.get_or_404(site_id)
    node = Node.query.get_or_404(node_id)
    
    # Import the proxy service factory
    from app.services.proxy_service_factory import ProxyServiceFactory
    
    try:
        # Create the appropriate proxy service based on the node's proxy type
        proxy_service = ProxyServiceFactory.create_service(node.proxy_type)
        
        # Generate configuration for the site
        config_content = proxy_service.generate_config(site)
        
        # Deploy the configuration to the node
        proxy_service.deploy_config(site_id, node_id, config_content)
        
        # Record the deployment in the log
        log = DeploymentLog(
            site_id=site_id,
            node_id=node_id,
            user_id=current_user.id,
            action=f"deploy_using_{node.proxy_type}",
            status="success",
            message=f"Successfully deployed site to node using {node.proxy_type} proxy"
        )
        db.session.add(log)
        db.session.commit()
        
        flash(f'Site successfully deployed to {node.name} using {node.proxy_type} proxy', 'success')
    except Exception as e:
        # Log the error
        log = DeploymentLog(
            site_id=site_id,
            node_id=node_id,
            user_id=current_user.id,
            action=f"deploy_using_{node.proxy_type}",
            status="error",
            message=f"Deployment failed: {str(e)}"
        )
        db.session.add(log)
        db.session.commit()
        
        flash(f'Deployment failed: {str(e)}', 'error')
    
    # Redirect to the appropriate page based on referrer
    referrer = request.referrer
    if referrer and 'view_site' in referrer:
        return redirect(url_for('admin.view_site', site_id=site_id))
    else:
        return redirect(url_for('admin.view_node', node_id=node_id))

@admin.route('/nodes/<int:node_id>/proxy-status')
@login_required
@admin_required
def check_proxy_status(node_id):
    """Check which proxy software is installed and running on a node"""
    node = Node.query.get_or_404(node_id)
    
    try:
        # Use the combined service to check available proxy services
        from app.services.proxy_compatibility_service import ProxyCompatibilityService
        
        proxy_status = ProxyCompatibilityService.check_installed_proxies(node)
        
        return jsonify({
            'success': True,
            'proxy_status': proxy_status
        })
    except Exception as e:
        # Log the error
        from app.services.logger_service import log_activity
        log_activity(
            category='error',
            action='check_proxy_status',
            resource_type='node',
            resource_id=node_id,
            details=f"Failed to check proxy status: {str(e)}"
        )
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@admin.route('/nodes/<int:node_id>/install-proxy/<string:proxy_type>', methods=['POST'])
@login_required
@admin_required
def install_proxy_software(node_id, proxy_type):
    """Install proxy software (nginx, caddy, traefik) on a node"""
    node = Node.query.get_or_404(node_id)
    
    # Validate proxy type
    valid_proxy_types = ['nginx', 'caddy', 'traefik']
    if proxy_type not in valid_proxy_types:
        return jsonify({
            'success': False,
            'error': f"Invalid proxy type. Supported types: {', '.join(valid_proxy_types)}"
        }), 400
    
    try:
        # Use the compatibility service to install the requested proxy
        from app.services.proxy_compatibility_service import ProxyCompatibilityService
        
        result = ProxyCompatibilityService.install_proxy(node, proxy_type, current_user.id)
        
        if result.get('success'):
            # If successful, update the node's proxy type in the database
            node.proxy_type = proxy_type
            
            # Set appropriate defaults for config path and reload command based on proxy type
            if proxy_type == 'nginx':
                node.proxy_config_path = '/etc/nginx/conf.d'
                node.proxy_reload_command = 'sudo systemctl reload nginx'
            elif proxy_type == 'caddy':
                node.proxy_config_path = '/etc/caddy'
                node.proxy_reload_command = 'sudo systemctl reload caddy'
            elif proxy_type == 'traefik':
                node.proxy_config_path = '/etc/traefik/dynamic'
                node.proxy_reload_command = 'sudo systemctl reload traefik'
                
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f"{proxy_type.capitalize()} installed successfully on {node.name}"
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('message', f"Failed to install {proxy_type}")
            }), 500
            
    except Exception as e:
        # Log the error
        from app.services.logger_service import log_activity
        log_activity(
            category='error',
            action='install_proxy',
            resource_type='node',
            resource_id=node_id,
            details=f"Failed to install {proxy_type}: {str(e)}"
        )
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@admin.route('/nodes/<int:node_id>/proxy/<string:proxy_type>/<string:action>', methods=['POST'])
@login_required
@admin_required
def toggle_proxy_service(node_id, proxy_type, action):
    """Start or stop proxy services on a node"""
    node = Node.query.get_or_404(node_id)
    
    # Validate proxy type
    valid_proxy_types = ['nginx', 'caddy', 'traefik']
    if proxy_type not in valid_proxy_types:
        return jsonify({
            'success': False,
            'error': f"Invalid proxy type. Supported types: {', '.join(valid_proxy_types)}"
        }), 400
    
    # Validate action
    valid_actions = ['start', 'stop', 'restart']
    if action not in valid_actions:
        return jsonify({
            'success': False,
            'error': f"Invalid action. Supported actions: {', '.join(valid_actions)}"
        }), 400
    
    try:
        # Use the compatibility service to control the proxy service
        from app.services.proxy_compatibility_service import ProxyCompatibilityService
        
        result = ProxyCompatibilityService.control_proxy_service(node, proxy_type, action)
        
        if result.get('success'):
            # Log the action
            from app.services.logger_service import log_activity
            log_activity(
                category='admin',
                action=f'{action}_proxy',
                resource_type='node',
                resource_id=node_id,
                user_id=current_user.id,
                details=f"Successfully {action}ed {proxy_type} on node {node.name}"
            )
            
            return jsonify({
                'success': True,
                'message': f"{proxy_type.capitalize()} {action}ed successfully on {node.name}"
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('message', f"Failed to {action} {proxy_type}")
            }), 500
            
    except Exception as e:
        # Log the error
        from app.services.logger_service import log_activity
        log_activity(
            category='error',
            action=f'{action}_proxy',
            resource_type='node',
            resource_id=node_id,
            user_id=current_user.id,
            details=f"Failed to {action} {proxy_type}: {str(e)}"
        )
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@admin.route('/nodes/<int:node_id>/update-proxy-type', methods=['POST'])
@login_required
@admin_required
def update_node_proxy_type(node_id):
    """Change the proxy type for a node (for sites already running with a different proxy)"""
    node = Node.query.get_or_404(node_id)
    
    new_proxy_type = request.form.get('proxy_type')
    new_config_path = request.form.get('proxy_config_path')
    new_reload_command = request.form.get('proxy_reload_command')
    
    # Validation
    if not new_proxy_type:
        flash('Proxy type is required', 'error')
        return redirect(url_for('admin.edit_node', node_id=node_id))
    
    valid_proxy_types = ['nginx', 'caddy', 'traefik']
    if new_proxy_type not in valid_proxy_types:
        flash(f"Invalid proxy type. Supported types: {', '.join(valid_proxy_types)}", 'error')
        return redirect(url_for('admin.edit_node', node_id=node_id))
    
    if not new_config_path:
        flash('Proxy configuration path is required', 'error')
        return redirect(url_for('admin.edit_node', node_id=node_id))
    
    if not new_reload_command:
        flash('Proxy reload command is required', 'error')
        return redirect(url_for('admin.edit_node', node_id=node_id))
    
    try:
        # Check if the proxy is actually installed
        from app.services.proxy_compatibility_service import ProxyCompatibilityService
        
        proxy_status = ProxyCompatibilityService.check_installed_proxies(node)
        installed_proxies = [p['type'] for p in proxy_status.get('installed_proxies', [])]
        
        if new_proxy_type not in installed_proxies:
            flash(f"{new_proxy_type.capitalize()} is not installed on this node. Please install it first.", 'error')
            return redirect(url_for('admin.view_node', node_id=node_id))
        
        # Update node configuration
        node.proxy_type = new_proxy_type
        node.proxy_config_path = new_config_path
        node.proxy_reload_command = new_reload_command
        node.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Log the change
        from app.services.logger_service import log_activity
        log_activity(
            category='admin',
            action='change_proxy_type',
            resource_type='node',
            resource_id=node_id,
            user_id=current_user.id,
            details=f"Changed proxy type to {new_proxy_type} on node {node.name}"
        )
        
        # Check if we need to update site configurations on this node
        site_nodes = SiteNode.query.filter_by(node_id=node_id).all()
        if site_nodes:
            flash(f"Node proxy type changed to {new_proxy_type}. You may need to redeploy sites to this node.", 'warning')
        else:
            flash(f"Node proxy type changed to {new_proxy_type}.", 'success')
        
        return redirect(url_for('admin.view_node', node_id=node_id))
        
    except Exception as e:
        db.session.rollback()
        
        # Log the error
        from app.services.logger_service import log_activity
        log_activity(
            category='error',
            action='change_proxy_type',
            resource_type='node',
            resource_id=node_id,
            user_id=current_user.id,
            details=f"Failed to change proxy type: {str(e)}"
        )
        
        flash(f"Error changing proxy type: {str(e)}", 'error')
        return redirect(url_for('admin.edit_node', node_id=node_id))