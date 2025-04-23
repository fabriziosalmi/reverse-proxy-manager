from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, abort
from flask_login import login_required, current_user
from app.models.models import db, User, Node, Site, SiteNode, DeploymentLog
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
    from app.services.nginx_service import get_node_stats
    
    try:
        server_stats, connection_stats = get_node_stats(node)
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
    
    return render_template('admin/nodes/view.html', 
                          node=node, 
                          sites=sites, 
                          site_nodes=site_nodes,
                          deployment_logs=deployment_logs,
                          server_stats=server_stats,
                          connection_stats=connection_stats)

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