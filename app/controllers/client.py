from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, abort
from flask_login import login_required, current_user
from app.models.models import db, Site, Node, SiteNode, DeploymentLog, SSLCertificate
from app.services.access_control import client_required
from app.services.nginx_service import generate_nginx_config, deploy_to_node
from datetime import datetime

client = Blueprint('client', __name__)

@client.route('/dashboard')
@login_required
@client_required
def dashboard():
    # Statistics for the dashboard
    site_count = Site.query.filter_by(user_id=current_user.id).count()
    active_site_count = Site.query.filter_by(user_id=current_user.id, is_active=True).count()
    
    # Get the latest sites and deployment logs
    sites = Site.query.filter_by(user_id=current_user.id).order_by(Site.created_at.desc()).limit(5).all()
    
    # Get the latest deployment logs for this client's sites
    site_ids = [site.id for site in Site.query.filter_by(user_id=current_user.id).all()]
    latest_logs = DeploymentLog.query.filter(DeploymentLog.site_id.in_(site_ids)).order_by(DeploymentLog.created_at.desc()).limit(10).all() if site_ids else []
    
    return render_template('client/dashboard.html', 
                           site_count=site_count,
                           active_site_count=active_site_count,
                           sites=sites,
                           latest_logs=latest_logs)

# Site Management
@client.route('/sites')
@login_required
@client_required
def list_sites():
    sites = Site.query.filter_by(user_id=current_user.id).all()
    return render_template('client/sites/list.html', sites=sites)

@client.route('/sites/new', methods=['GET', 'POST'])
@login_required
@client_required
def new_site():
    if request.method == 'GET':
        # Get all active nodes for selection
        nodes = Node.query.filter_by(is_active=True).all()
        return render_template('client/sites/new.html', nodes=nodes)
    
    if request.method == 'POST':
        name = request.form.get('name')
        domain = request.form.get('domain')
        protocol = request.form.get('protocol', 'https')
        origin_address = request.form.get('origin_address')
        origin_port = request.form.get('origin_port')
        use_waf = 'use_waf' in request.form
        custom_config = request.form.get('custom_config')
        
        # Get selected nodes
        node_ids = request.form.getlist('nodes')
        
        # Validation
        if Site.query.filter_by(domain=domain).first():
            flash('Domain already exists', 'error')
            nodes = Node.query.filter_by(is_active=True).all()
            return render_template('client/sites/new.html', nodes=nodes)
        
        if not node_ids:
            flash('Please select at least one deployment node', 'error')
            nodes = Node.query.filter_by(is_active=True).all()
            return render_template('client/sites/new.html', nodes=nodes)
        
        # Create new site
        site = Site(
            name=name,
            domain=domain,
            protocol=protocol,
            origin_address=origin_address,
            origin_port=origin_port,
            user_id=current_user.id,
            use_waf=use_waf,
            custom_config=custom_config,
            is_active=True,
            # Cache configuration
            enable_cache='enable_cache' in request.form,
            cache_time=int(request.form.get('cache_time', 3600)),
            cache_static_time=int(request.form.get('cache_static_time', 86400)),
            cache_browser_time=int(request.form.get('cache_browser_time', 3600)),
            custom_cache_rules=request.form.get('custom_cache_rules')
        )
        
        db.session.add(site)
        db.session.commit()
        
        # Create site-node relationships and attempt deployment
        for node_id in node_ids:
            node = Node.query.get(node_id)
            if node and node.is_active:
                site_node = SiteNode(
                    site_id=site.id,
                    node_id=node_id,
                    status='pending'
                )
                db.session.add(site_node)
        
        db.session.commit()
        
        # Initiate deployment process for the new site on all selected nodes
        # This would typically be done asynchronously in a real application
        try:
            # Generate Nginx configuration
            nginx_config = generate_nginx_config(site)
            
            # Deploy to each node
            for node_id in node_ids:
                deploy_to_node(site.id, node_id, nginx_config)
            
            flash('Site created and deployment initiated', 'success')
        except Exception as e:
            flash(f'Site created but deployment failed: {str(e)}', 'warning')
        
        return redirect(url_for('client.list_sites'))

@client.route('/sites/<int:site_id>', methods=['GET'])
@login_required
@client_required
def view_site(site_id):
    site = Site.query.get_or_404(site_id)
    
    # Check if the site belongs to the current user
    if site.user_id != current_user.id:
        abort(403)
    
    site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
    deployment_logs = DeploymentLog.query.filter_by(site_id=site_id).order_by(DeploymentLog.created_at.desc()).all()
    ssl_certificates = SSLCertificate.query.filter_by(site_id=site_id).all()
    
    return render_template('client/sites/view.html', 
                           site=site, 
                           site_nodes=site_nodes,
                           deployment_logs=deployment_logs,
                           ssl_certificates=ssl_certificates)

@client.route('/sites/<int:site_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_site(site_id):
    # Check if site exists and belongs to the current user
    site = Site.query.filter_by(id=site_id, user_id=current_user.id).first_or_404()
    
    if request.method == 'POST':
        # Extract data from form
        name = request.form.get('name')
        protocol = request.form.get('protocol')
        origin_address = request.form.get('origin_address')
        origin_port = request.form.get('origin_port')
        use_waf = 'use_waf' in request.form
        custom_config = request.form.get('custom_config')
        node_ids = request.form.getlist('nodes')
        
        # Cache configuration
        enable_cache = 'enable_cache' in request.form
        cache_time = int(request.form.get('cache_time', 3600))
        cache_static_time = int(request.form.get('cache_static_time', 86400))
        cache_browser_time = int(request.form.get('cache_browser_time', 3600))
        custom_cache_rules = request.form.get('custom_cache_rules')
        
        # Update site in database
        site.name = name
        site.protocol = protocol
        site.origin_address = origin_address
        site.origin_port = origin_port
        site.use_waf = use_waf
        site.custom_config = custom_config
        
        # Update cache configuration
        site.enable_cache = enable_cache
        site.cache_time = cache_time
        site.cache_static_time = cache_static_time
        site.cache_browser_time = cache_browser_time
        site.custom_cache_rules = custom_cache_rules
        
        db.session.commit()
        
        # Handle node associations
        current_nodes = [sn.node_id for sn in site.site_nodes]
        nodes_to_add = [int(node_id) for node_id in node_ids if int(node_id) not in current_nodes]
        nodes_to_remove = [node_id for node_id in current_nodes if node_id not in [int(id) for id in node_ids]]
        
        # Remove nodes that are no longer selected
        for node_id in nodes_to_remove:
            SiteNode.query.filter_by(site_id=site_id, node_id=node_id).delete()
        
        # Add new nodes
        for node_id in nodes_to_add:
            site_node = SiteNode(site_id=site_id, node_id=node_id, status='pending')
            db.session.add(site_node)
        
        db.session.commit()
        
        # Regenerate Nginx configuration and redeploy to all nodes
        try:
            # Generate updated Nginx configuration
            nginx_config = generate_nginx_config(site)
            
            # Deploy to each node
            for node_id in node_ids:
                deploy_to_node(site.id, int(node_id), nginx_config)
            
            flash('Site updated and redeployment initiated', 'success')
        except Exception as e:
            flash(f'Site updated but redeployment failed: {str(e)}', 'warning')
        
        return redirect(url_for('client.list_sites'))
    
    # GET request handling
    all_nodes = Node.query.filter_by(is_active=True).all()
    assigned_node_ids = [sn.node_id for sn in SiteNode.query.filter_by(site_id=site_id).all()]
    
    return render_template('client/sites/edit.html', 
                           site=site, 
                           nodes=all_nodes, 
                           assigned_node_ids=assigned_node_ids)

@client.route('/sites/<int:site_id>/delete', methods=['POST'])
@login_required
@client_required
def delete_site(site_id):
    site = Site.query.get_or_404(site_id)
    
    # Check if the site belongs to the current user
    if site.user_id != current_user.id:
        abort(403)
    
    # Delete all site-node relationships
    SiteNode.query.filter_by(site_id=site_id).delete()
    
    # Delete all SSL certificates
    SSLCertificate.query.filter_by(site_id=site_id).delete()
    
    # Delete all deployment logs for this site
    DeploymentLog.query.filter_by(site_id=site_id).delete()
    
    # Delete the site
    db.session.delete(site)
    db.session.commit()
    
    flash('Site deleted successfully', 'success')
    return redirect(url_for('client.list_sites'))

@client.route('/sites/<int:site_id>/toggle_active', methods=['POST'])
@login_required
@client_required
def toggle_site_active(site_id):
    site = Site.query.get_or_404(site_id)
    
    # Check if the site belongs to the current user
    if site.user_id != current_user.id:
        abort(403)
    
    site.is_active = not site.is_active
    db.session.commit()
    
    status = 'activated' if site.is_active else 'deactivated'
    flash(f'Site {status} successfully', 'success')
    return redirect(url_for('client.list_sites'))

# API endpoints for client actions
@client.route('/api/sites', methods=['GET'])
@login_required
@client_required
def api_list_sites():
    sites = Site.query.filter_by(user_id=current_user.id).all()
    return jsonify([site.to_dict() for site in sites])

@client.route('/api/sites/<int:site_id>', methods=['GET'])
@login_required
@client_required
def api_get_site(site_id):
    site = Site.query.get_or_404(site_id)
    
    # Check if the site belongs to the current user
    if site.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify(site.to_dict())