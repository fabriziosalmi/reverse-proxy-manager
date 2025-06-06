from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, abort, session
from flask_login import login_required, current_user
from app.models.models import db, Site, Node, SiteNode, DeploymentLog, SSLCertificate
from app.services.access_control import client_required
from app.services.proxy_service_factory import ProxyServiceFactory
from app.services.proxy_compatibility_service import ProxyCompatibilityService
from datetime import datetime
from app.services.analytics_service import AnalyticsService

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
        
        # Pass proxy type information for the documentation link
        proxy_info = {
            'nginx': ProxyCompatibilityService.get_proxy_type_info('nginx'),
            'caddy': ProxyCompatibilityService.get_proxy_type_info('caddy'),
            'traefik': ProxyCompatibilityService.get_proxy_type_info('traefik')
        }
        
        return render_template('client/sites/new.html', nodes=nodes, proxy_info=proxy_info)
    
    if request.method == 'POST':
        name = request.form.get('name')
        domain = request.form.get('domain')
        protocol = request.form.get('protocol', 'https')
        origin_protocol = request.form.get('origin_protocol', 'http')
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
            origin_protocol=origin_protocol,
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
            custom_cache_rules=request.form.get('custom_cache_rules'),
            # GeoIP configuration
            use_geoip='use_geoip' in request.form,
            geoip_mode=request.form.get('geoip_mode', 'blacklist'),
            geoip_level=request.form.get('geoip_level', 'nginx'),
            geoip_countries=request.form.get('geoip_countries', '').strip()
        )
        
        # Check compatibility before saving
        node_ids = [int(nid) for nid in node_ids]
        compatibility = ProxyCompatibilityService.check_nodes_compatibility(site, node_ids)
        
        # If there are compatibility warnings but the site is still compatible, show warnings but continue
        if compatibility['warnings'] and compatibility['is_compatible']:
            for warning in compatibility['warnings']:
                flash(f"Compatibility warning: {warning}", 'warning')
        
        # If there are compatibility issues that make the site incompatible, alert the user
        elif not compatibility['is_compatible']:
            flash('The site configuration is not compatible with all selected nodes. Please review and adjust your settings.', 'error')
            for warning in compatibility['warnings']:
                flash(f"Compatibility error: {warning}", 'error')
            
            nodes = Node.query.filter_by(is_active=True).all()
            return render_template('client/sites/new.html', nodes=nodes, site=site, compatibility=compatibility)
        
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
        
        # Store compatibility info in session for access in deployment logs
        session['last_compatibility_check'] = {
            'site_id': site.id,
            'compatibility': compatibility
        }
        
        # Initiate deployment process for the new site on all selected nodes
        # This would typically be done asynchronously in a real application
        try:
            # Deploy to each node using the appropriate proxy service
            for node_id in node_ids:
                node = Node.query.get(node_id)
                if not node:
                    continue
                
                # Get the appropriate proxy service for this node
                proxy_service = ProxyServiceFactory.create_service(node.proxy_type)
                
                # Generate configuration for the specific proxy type
                config = proxy_service.generate_config(site)
                
                # Deploy to the node
                proxy_service.deploy_config(site.id, node.id, config)
            
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
@client_required
def edit_site(site_id):
    # Check if site exists and belongs to the current user
    site = Site.query.filter_by(id=site_id, user_id=current_user.id).first_or_404()
    
    if request.method == 'POST':
        # Extract data from form
        name = request.form.get('name')
        protocol = request.form.get('protocol')
        origin_protocol = request.form.get('origin_protocol', site.origin_protocol)
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
        
        # GeoIP configuration
        use_geoip = 'use_geoip' in request.form
        geoip_mode = request.form.get('geoip_mode', 'blacklist')
        geoip_level = request.form.get('geoip_level', 'nginx')
        geoip_countries = request.form.get('geoip_countries', '').strip()
        
        # Update site in memory (don't commit yet)
        site.name = name
        site.protocol = protocol
        site.origin_protocol = origin_protocol
        site.origin_address = origin_address
        site.origin_port = origin_port
        site.use_waf = use_waf
        site.custom_config = custom_config
        site.enable_cache = enable_cache
        site.cache_time = cache_time
        site.cache_static_time = cache_static_time
        site.cache_browser_time = cache_browser_time
        site.custom_cache_rules = custom_cache_rules
        site.use_geoip = use_geoip
        site.geoip_mode = geoip_mode
        site.geoip_level = geoip_level
        site.geoip_countries = geoip_countries
        
        # Check compatibility before saving changes
        node_ids = [int(nid) for nid in node_ids]
        compatibility = ProxyCompatibilityService.check_nodes_compatibility(site, node_ids)
        
        # If there are compatibility warnings but the site is still compatible, show warnings but continue
        if compatibility['warnings'] and compatibility['is_compatible']:
            for warning in compatibility['warnings']:
                flash(f"Compatibility warning: {warning}", 'warning')
        
        # If there are compatibility issues that make the site incompatible, alert the user
        elif not compatibility['is_compatible']:
            flash('The site configuration is not compatible with all selected nodes. Please review and adjust your settings.', 'error')
            for warning in compatibility['warnings']:
                flash(f"Compatibility error: {warning}", 'error')
            
            # Revert any changes we made to the site object
            db.session.refresh(site)
            
            all_nodes = Node.query.filter_by(is_active=True).all()
            assigned_node_ids = [sn.node_id for sn in SiteNode.query.filter_by(site_id=site_id).all()]
            
            return render_template(
                'client/sites/edit.html', 
                site=site, 
                nodes=all_nodes, 
                assigned_node_ids=assigned_node_ids,
                compatibility=compatibility
            )
        
        # Now commit the changes to the database
        db.session.commit()
        
        # Handle node associations
        current_nodes = [sn.node_id for sn in SiteNode.query.filter_by(site_id=site_id).all()]
        nodes_to_add = [int(node_id) for node_id in node_ids if int(node_id) not in current_nodes]
        nodes_to_remove = [node_id for node_id in current_nodes if node_id not in node_ids]
        
        # Remove nodes that are no longer selected
        for node_id in nodes_to_remove:
            SiteNode.query.filter_by(site_id=site_id, node_id=node_id).delete()
        
        # Add new nodes
        for node_id in nodes_to_add:
            site_node = SiteNode(site_id=site_id, node_id=node_id, status='pending')
            db.session.add(site_node)
        
        db.session.commit()
        
        # Store compatibility info in session for access in deployment logs
        session['last_compatibility_check'] = {
            'site_id': site.id,
            'compatibility': compatibility
        }
        
        # Generate configurations and deploy to all nodes
        try:
            # Deploy to each node using the appropriate proxy service
            for node_id in node_ids:
                node = Node.query.get(node_id)
                if not node:
                    continue
                
                # Get the appropriate proxy service for this node
                proxy_service = ProxyServiceFactory.create_service(node.proxy_type)
                
                # Generate configuration for the specific proxy type
                config = proxy_service.generate_config(site)
                
                # Deploy to the node
                proxy_service.deploy_config(site.id, node.id, config)
            
            flash('Site updated and redeployment initiated', 'success')
        except Exception as e:
            flash(f'Site updated but redeployment failed: {str(e)}', 'warning')
        
        return redirect(url_for('client.list_sites'))
    
    # GET request handling
    all_nodes = Node.query.filter_by(is_active=True).all()
    assigned_node_ids = [sn.node_id for sn in SiteNode.query.filter_by(site_id=site_id).all()]
    
    # Get proxy type information for the documentation link
    proxy_info = {
        'nginx': ProxyCompatibilityService.get_proxy_type_info('nginx'),
        'caddy': ProxyCompatibilityService.get_proxy_type_info('caddy'),
        'traefik': ProxyCompatibilityService.get_proxy_type_info('traefik')
    }
    
    # Get assigned nodes' proxy types for compatibility UI
    assigned_nodes = Node.query.filter(Node.id.in_(assigned_node_ids)).all()
    assigned_proxy_types = {node.proxy_type for node in assigned_nodes}
    
    # Check compatibility with currently assigned nodes
    if assigned_proxy_types:
        compatibility = ProxyCompatibilityService.check_nodes_compatibility(site, assigned_node_ids)
    else:
        compatibility = None
    
    return render_template('client/sites/edit.html', 
                           site=site, 
                           nodes=all_nodes, 
                           assigned_node_ids=assigned_node_ids,
                           proxy_info=proxy_info,
                           compatibility=compatibility,
                           assigned_proxy_types=assigned_proxy_types)

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

@client.route('/sites/<int:site_id>/ssl', methods=['GET', 'POST'])
@login_required
@client_required
def manage_ssl_certificates(site_id):
    """SSL certificate management for client sites"""
    site = Site.query.filter_by(id=site_id, user_id=current_user.id).first_or_404()
    
    # Get all nodes serving this site
    site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
    nodes = [Node.query.get(sn.node_id) for sn in site_nodes]
    
    if request.method == 'POST':
        # Determine what action we're taking
        action = request.form.get('action')
        node_id = request.form.get('node_id')
        
        if not node_id and action not in ['check_dns', 'get_recommendations']:
            flash('Please select a node', 'error')
            return redirect(url_for('client.manage_ssl_certificates', site_id=site_id))
        
        from app.services.ssl_certificate_service import SSLCertificateService
        
        if action == 'check':
            # Check certificate status
            result = SSLCertificateService.check_certificate_status(site_id, node_id)
            
            if 'error' in result:
                flash(f"Error checking certificate: {result['error']}", 'error')
            
            # Store result in session for template rendering
            from flask import session
            session['cert_check_result'] = result
            
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
                return redirect(url_for('client.manage_ssl_certificates', site_id=site_id))
            
            # Validate DNS provider for DNS challenges
            if challenge_type == 'dns' and not dns_provider and dns_provider != 'manual':
                flash('Please select a DNS provider for DNS validation', 'error')
                return redirect(url_for('client.manage_ssl_certificates', site_id=site_id))
                
            # Process DNS credentials if provided
            dns_credentials = None
            if challenge_type == 'dns' and dns_provider:
                dns_credentials = {}
                if dns_provider == 'cloudflare':
                    dns_credentials['token'] = request.form.get('cf_token')
                    if not dns_credentials['token']:
                        flash('Please provide a Cloudflare API token', 'error')
                        return redirect(url_for('client.manage_ssl_certificates', site_id=site_id))
                elif dns_provider == 'route53':
                    dns_credentials['access_key'] = request.form.get('aws_access_key')
                    dns_credentials['secret_key'] = request.form.get('aws_secret_key')
                    if not dns_credentials['access_key'] or not dns_credentials['secret_key']:
                        flash('Please provide both AWS Access Key and Secret Key', 'error')
                        return redirect(url_for('client.manage_ssl_certificates', site_id=site_id))
                elif dns_provider == 'digitalocean':
                    dns_credentials['token'] = request.form.get('do_token')
                    if not dns_credentials['token']:
                        flash('Please provide a DigitalOcean API token', 'error')
                        return redirect(url_for('client.manage_ssl_certificates', site_id=site_id))
                elif dns_provider == 'godaddy':
                    dns_credentials['key'] = request.form.get('godaddy_key')
                    dns_credentials['secret'] = request.form.get('godaddy_secret')
                    if not dns_credentials['key'] or not dns_credentials['secret']:
                        flash('Please provide both GoDaddy API Key and Secret', 'error')
                        return redirect(url_for('client.manage_ssl_certificates', site_id=site_id))
                elif dns_provider == 'namecheap':
                    dns_credentials['username'] = request.form.get('namecheap_username')
                    dns_credentials['api_key'] = request.form.get('namecheap_api_key')
                    if not dns_credentials['username'] or not dns_credentials['api_key']:
                        flash('Please provide both Namecheap Username and API Key', 'error')
                        return redirect(url_for('client.manage_ssl_certificates', site_id=site_id))
            
            # Request certificate with appropriate validation method
            result = SSLCertificateService.request_certificate(
                site_id, 
                node_id, 
                email, 
                challenge_type=challenge_type,
                dns_provider=dns_provider,
                dns_credentials=dns_credentials,
                cert_type=cert_type
            )
            
            if result.get('success'):
                flash('Certificate request initiated. Please check status in a few minutes.', 'success')
                
                # If manual DNS challenge, display information
                if challenge_type == 'manual-dns' and 'txt_records' in result:
                    from flask import session
                    session['dns_challenge'] = {
                        'txt_records': result.get('txt_records', []),
                        'instructions': result.get('instructions', '')
                    }
            else:
                flash(f"Certificate request failed: {result.get('message', 'Unknown error')}", 'error')
        
        elif action == 'generate_self_signed':
            # Generate self-signed certificate
            result = SSLCertificateService.generate_self_signed_certificate(site_id, node_id)
            
            if result.get('success'):
                flash('Self-signed certificate generated successfully.', 'success')
            else:
                flash(f"Self-signed certificate generation failed: {result.get('message', 'Unknown error')}", 'error')
        
        elif action == 'setup_renewal':
            # Setup auto renewal
            result = SSLCertificateService.setup_auto_renewal(node_id)
            
            if result.get('success'):
                flash('Certificate auto-renewal configured successfully.', 'success')
            else:
                flash(f"Failed to set up auto-renewal: {result.get('message', 'Unknown error')}", 'error')
        
        elif action == 'revoke':
            # Revoke certificate
            result = SSLCertificateService.revoke_certificate(site_id, node_id)
            
            if result.get('success'):
                flash('Certificate revoked successfully.', 'success')
            else:
                flash(f"Failed to revoke certificate: {result.get('message', 'Unknown error')}", 'error')
                
        elif action == 'check_dns':
            # Check DNS settings for the domain
            result = SSLCertificateService.check_domain_dns(site.domain)
            
            # Store result in session for template rendering
            from flask import session
            session['dns_check_result'] = result
        
        elif action == 'get_recommendations':
            # Get certificate issuance recommendations
            result = SSLCertificateService.get_issuance_recommendations(site_id)
            
            # Store result in session for template rendering
            from flask import session
            session['cert_recommendations'] = result
        
        return redirect(url_for('client.manage_ssl_certificates', site_id=site_id))
    
    # Get existing certificates
    ssl_certificates = SSLCertificate.query.filter_by(site_id=site_id).all()
    
    # Get supported DNS providers
    from app.services.ssl_certificate_service import SSLCertificateService
    dns_providers = SSLCertificateService.get_supported_dns_providers()
    
    return render_template(
        'client/sites/ssl_management.html',
        site=site,
        nodes=nodes,
        ssl_certificates=ssl_certificates,
        dns_providers=dns_providers
    )

@client.route('/ssl-dashboard')
@login_required
@client_required
def ssl_dashboard():
    """SSL certificate dashboard showing all sites and their certificate status"""
    # Get all sites owned by the current user
    user = current_user
    sites = Site.query.filter_by(user_id=user.id).all()
    
    # Get certificate health status
    certificates = []
    expiring_soon = []
    expired = []
    
    for site in sites:
        # Get all certificates for this site
        site_certs = SSLCertificate.query.filter_by(site_id=site.id).all()
        
        for cert in site_certs:
            node = Node.query.get(cert.node_id)
            if not node:
                continue
                
            cert_info = {
                'site_id': site.id,
                'domain': site.domain,
                'node_id': node.id,
                'node_name': node.name,
                'status': cert.status,
                'issuer': cert.issuer,
                'valid_until': cert.valid_until,
                'days_remaining': cert.days_remaining,
                'is_self_signed': cert.is_self_signed
            }
            
            certificates.append(cert_info)
            
            if cert.status == 'expired':
                expired.append(cert_info)
            elif cert.status == 'expiring_soon':
                expiring_soon.append(cert_info)
    
    # Sort by days remaining
    certificates.sort(key=lambda x: (x['status'] != 'expired', x['status'] != 'expiring_soon', x['days_remaining'] if x['days_remaining'] is not None else 999))
    
    return render_template('client/ssl_dashboard.html', 
                          sites=sites,
                          certificates=certificates,
                          expired=expired,
                          expiring_soon=expiring_soon)

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

@client.route('/analytics')
@login_required
def analytics_dashboard():
    """Client analytics dashboard"""
    # Get site_id from query parameter if specified
    site_id = request.args.get('site_id', None)
    
    # Get analytics data for the user's sites
    analytics_data = AnalyticsService.get_client_analytics(
        user_id=current_user.id, 
        site_id=site_id
    )
    
    return render_template('client/analytics/dashboard.html', **analytics_data)

@client.route('/analytics/data')
@login_required
def analytics_data():
    """API endpoint for client analytics data"""
    site_id = request.args.get('site_id', None)
    period = request.args.get('period', 'week')
    
    data = AnalyticsService.get_api_analytics_data(
        period=period,
        site_id=site_id
    )
    
    return jsonify(data)