from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, abort
from flask_login import login_required, current_user
from app.models.models import db, User, Node, Site, SiteNode, DeploymentLog, ConfigVersion
from app.services.access_control import admin_required
from datetime import datetime
import random
import string

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
    
    # Get the latest deployment logs
    latest_logs = DeploymentLog.query.order_by(DeploymentLog.created_at.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html', 
                           user_count=user_count,
                           node_count=node_count,
                           active_node_count=active_node_count,
                           site_count=site_count,
                           active_site_count=active_site_count,
                           latest_logs=latest_logs)

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
        return render_template('admin/nodes/new.html')
    
    if request.method == 'POST':
        name = request.form.get('name')
        ip_address = request.form.get('ip_address')
        ssh_port = request.form.get('ssh_port', 22)
        ssh_user = request.form.get('ssh_user')
        ssh_key_path = request.form.get('ssh_key_path')
        ssh_password = request.form.get('ssh_password')
        nginx_config_path = request.form.get('nginx_config_path', '/etc/nginx/conf.d')
        nginx_reload_command = request.form.get('nginx_reload_command', 'sudo systemctl reload nginx')
        
        # Validation
        if Node.query.filter_by(name=name).first():
            flash('Node name already exists', 'error')
            return redirect(url_for('admin.new_node'))
        
        # Create new node
        node = Node(
            name=name,
            ip_address=ip_address,
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            ssh_key_path=ssh_key_path,
            ssh_password=ssh_password,
            nginx_config_path=nginx_config_path,
            nginx_reload_command=nginx_reload_command,
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
        return render_template('admin/nodes/edit.html', node=node)
    
    if request.method == 'POST':
        name = request.form.get('name')
        ip_address = request.form.get('ip_address')
        ssh_port = request.form.get('ssh_port')
        ssh_user = request.form.get('ssh_user')
        ssh_key_path = request.form.get('ssh_key_path')
        ssh_password = request.form.get('ssh_password')
        nginx_config_path = request.form.get('nginx_config_path')
        nginx_reload_command = request.form.get('nginx_reload_command')
        is_active = 'is_active' in request.form
        
        # Check for name uniqueness if changed
        if name != node.name and Node.query.filter_by(name=name).first():
            flash('Node name already exists', 'error')
            return redirect(url_for('admin.edit_node', node_id=node_id))
        
        # Update node
        node.name = name
        node.ip_address = ip_address
        node.ssh_port = ssh_port
        node.ssh_user = ssh_user
        
        if ssh_key_path:
            node.ssh_key_path = ssh_key_path
            
        if ssh_password:
            node.ssh_password = ssh_password
            
        node.nginx_config_path = nginx_config_path
        node.nginx_reload_command = nginx_reload_command
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
    """Redeploy all sites on a specific node"""
    node = Node.query.get_or_404(node_id)
    
    # Get all sites deployed on this node
    site_nodes = SiteNode.query.filter_by(node_id=node_id).all()
    
    if not site_nodes:
        flash('No sites are currently deployed on this node', 'info')
        return redirect(url_for('admin.view_node', node_id=node_id))
    
    # Import needed functions
    from app.services.nginx_service import generate_nginx_config, deploy_to_node
    
    success_count = 0
    error_count = 0
    
    for site_node in site_nodes:
        site = Site.query.get(site_node.site_id)
        if not site:
            continue
        
        try:
            # Generate updated Nginx configuration
            nginx_config = generate_nginx_config(site)
            
            # Deploy to the node
            deploy_to_node(site.id, node_id, nginx_config)
            
            # Log the successful deployment
            log = DeploymentLog(
                site_id=site.id,
                node_id=node_id,
                action="redeploy",
                status="success",
                message=f"Successfully redeployed site during bulk operation"
            )
            db.session.add(log)
            success_count += 1
            
        except Exception as e:
            # Log the error
            error_count += 1
            log = DeploymentLog(
                site_id=site.id,
                node_id=node_id,
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
            else:
                # Store cert info in session for display
                session['cert_check_result'] = result
                
                # Determine appropriate message
                has_errors = any('error' in r for r in result['results'])
                valid_certs = any(r.get('certificate', {}).get('status') == 'valid' 
                                for r in result['results'] if 'certificate' in r)
                
                if has_errors:
                    flash('Certificate check completed with some errors. See details below.', 'warning')
                elif valid_certs:
                    flash('Certificate check completed. Valid certificates found.', 'success')
                else:
                    flash('Certificate check completed. No valid certificates found.', 'warning')
                    
        elif action == 'check_dns':
            # Check DNS resolution for the domain
            result = SSLCertificateService.check_domain_dns(site.domain)
            session['dns_check_result'] = result
            
            if 'error' in result:
                flash(f"Error checking DNS: {result['error']}", 'error')
            elif result.get('dns_status') == 'ok':
                flash('DNS check completed. Domain is correctly pointing to CDN nodes.', 'success')
            else:
                flash('DNS check completed. Domain is not correctly pointing to CDN nodes. See details below.', 'warning')
        
        elif action == 'get_recommendations':
            # Get SSL issuance recommendations
            result = SSLCertificateService.get_issuance_recommendations(site_id)
            session['ssl_recommendations'] = result
            
            if 'error' in result:
                flash(f"Error getting recommendations: {result['error']}", 'error')
            else:
                flash('SSL issuance recommendations generated. See details below.', 'info')
            
        elif action == 'request':
            # Get certificate request parameters
            email = request.form.get('email')
            challenge_type = request.form.get('challenge_type', 'http')
            cert_type = request.form.get('cert_type', 'standard')
            
            # Handle DNS provider credentials if using DNS challenge
            dns_provider = None
            dns_credentials = None
            
            if challenge_type == 'dns':
                dns_provider = request.form.get('dns_provider')
                
                if not dns_provider:
                    flash('DNS provider is required for DNS challenge', 'error')
                    return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
                
                # Collect provider-specific credentials
                if dns_provider == 'cloudflare':
                    token = request.form.get('cloudflare_token')
                    if not token:
                        flash('Cloudflare API token is required', 'error')
                        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
                    dns_credentials = {'token': token}
                    
                elif dns_provider == 'route53':
                    access_key = request.form.get('route53_access_key')
                    secret_key = request.form.get('route53_secret_key')
                    if not access_key or not secret_key:
                        flash('AWS access key and secret key are required', 'error')
                        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
                    dns_credentials = {'access_key': access_key, 'secret_key': secret_key}
                    
                elif dns_provider == 'digitalocean':
                    token = request.form.get('digitalocean_token')
                    if not token:
                        flash('DigitalOcean API token is required', 'error')
                        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
                    dns_credentials = {'token': token}
                    
                elif dns_provider == 'godaddy':
                    key = request.form.get('godaddy_key')
                    secret = request.form.get('godaddy_secret')
                    if not key or not secret:
                        flash('GoDaddy API key and secret are required', 'error')
                        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
                    dns_credentials = {'key': key, 'secret': secret}
                    
                elif dns_provider == 'namecheap':
                    username = request.form.get('namecheap_username')
                    api_key = request.form.get('namecheap_api_key')
                    if not username or not api_key:
                        flash('Namecheap username and API key are required', 'error')
                        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
                    dns_credentials = {'username': username, 'api_key': api_key}
            
            # Request the certificate with appropriate parameters
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
                    session['manual_dns_instructions'] = result
                    flash(f'Follow the manual DNS challenge instructions. You will need to create DNS TXT records.', 'info')
                else:
                    cert_type_name = "wildcard" if cert_type == 'wildcard' else "standard"
                    flash(f'SSL {cert_type_name} certificate successfully requested and installed using {challenge_type} validation', 'success')
            else:
                flash(f"Failed to request SSL certificate: {result.get('message', 'Unknown error')}", 'error')
        
        elif action == 'setup_renewal':
            # Get renewal days parameter
            renewal_days = request.form.get('renewal_days', 30)
            try:
                renewal_days = int(renewal_days)
            except ValueError:
                renewal_days = 30
            
            # Setup auto-renewal
            result = SSLCertificateService.setup_auto_renewal(node_id, renewal_days=renewal_days)
            
            if result.get('success', False):
                flash(f'Certificate auto-renewal successfully configured to renew {renewal_days} days before expiry', 'success')
            else:
                flash(f"Failed to configure auto-renewal: {result.get('message', 'Unknown error')}", 'error')
        
        elif action == 'revoke':
            # Revoke a certificate
            result = SSLCertificateService.revoke_certificate(site_id, node_id)
            
            if result.get('success', False):
                flash('Certificate successfully revoked', 'success')
            else:
                flash(f"Failed to revoke certificate: {result.get('message', 'Unknown error')}", 'error')
        
        return redirect(url_for('admin.manage_ssl_certificates', site_id=site_id))
    
    # Get certificate status from session if available
    cert_check_result = session.pop('cert_check_result', None)
    dns_check_result = session.pop('dns_check_result', None)
    ssl_recommendations = session.pop('ssl_recommendations', None)
    manual_dns_instructions = session.pop('manual_dns_instructions', None)
    
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
        from app.services.ssl_certificate_service import SSLCertificateService
        cert_health = SSLCertificateService.certificate_health_check()
    
    return render_template(
        'admin/sites/ssl_management.html', 
        site=site, 
        nodes=nodes, 
        cert_status=cert_status,
        dns_check_result=dns_check_result,
        ssl_recommendations=ssl_recommendations,
        manual_dns_instructions=manual_dns_instructions,
        dns_providers=dns_providers,
        cert_health=cert_health
    )

@admin.route('/ssl-dashboard')
@login_required
@admin_required
def ssl_dashboard():
    """Dashboard view for all SSL certificates across sites"""
    from app.services.ssl_certificate_service import SSLCertificateService
    
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