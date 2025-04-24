from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from app.models.models import db, Site, Node, SiteNode, User, DeploymentLog
from app.services.access_control import admin_required
import datetime
from flask_wtf.csrf import validate_csrf, CSRFError
import re
from functools import wraps
import time
from flask import current_app, g

api = Blueprint('api', __name__)

# Simple API rate limiter
class RateLimiter:
    """Basic rate limiter to prevent API abuse"""
    
    def __init__(self, max_calls=100, period=60, cleanup_interval=300):
        self.max_calls = max_calls  # Max calls allowed in the period
        self.period = period  # Period in seconds
        self.cache = {}  # Store client IP and their call timestamps
        self.last_cleanup = time.time()  # Last cache cleanup time
        self.cleanup_interval = cleanup_interval  # Cleanup every 5 minutes by default
    
    def is_allowed(self, client_ip):
        """Check if client is allowed to make another request"""
        now = time.time()
        
        # Periodically clean up expired entries to prevent memory leaks
        if now - self.last_cleanup > self.cleanup_interval:
            self._cleanup_expired_entries(now)
            self.last_cleanup = now
        
        # Create new entry for new clients
        if client_ip not in self.cache:
            self.cache[client_ip] = [now]
            return True
        
        # Get existing timestamps for this client
        timestamps = self.cache[client_ip]
        
        # Remove timestamps older than the period
        cutoff = now - self.period
        self.cache[client_ip] = [ts for ts in timestamps if ts > cutoff]
        
        # Add current timestamp
        self.cache[client_ip].append(now)
        
        # Check if client exceeded max calls in the period
        return len(self.cache[client_ip]) <= self.max_calls
    
    def _cleanup_expired_entries(self, current_time):
        """Remove expired entries from the cache to prevent memory leaks"""
        cutoff = current_time - self.period
        expired_ips = []
        
        # Find expired entries
        for ip, timestamps in self.cache.items():
            # Keep only timestamps within the rate limit period
            valid_timestamps = [ts for ts in timestamps if ts > cutoff]
            
            if valid_timestamps:
                # Update with only valid timestamps
                self.cache[ip] = valid_timestamps
            else:
                # If no valid timestamps, mark for removal
                expired_ips.append(ip)
        
        # Remove expired entries
        for ip in expired_ips:
            del self.cache[ip]

# Create rate limiter instance
rate_limiter = RateLimiter(max_calls=100, period=60)

# Rate limiter middleware
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get client IP address
        client_ip = request.remote_addr
        
        # Check if client is allowed
        if not rate_limiter.is_allowed(client_ip):
            # Return 429 Too Many Requests if rate limit exceeded
            return jsonify({
                "error": "Rate limit exceeded. Please try again later.",
                "retry_after": "60 seconds"
            }), 429
        
        # Proceed with the request
        return f(*args, **kwargs)
    
    return decorated_function

# API Error Responses
def error_response(message, status_code=400):
    return jsonify({"error": message}), status_code

# API Success Responses
def success_response(data, message="Success", status_code=200):
    return jsonify({"message": message, "data": data}), status_code

# Validate domain name format
def is_valid_domain(domain):
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_regex.match(domain))

# Health check endpoint (no auth required)
@api.route('/health', methods=['GET'])
@rate_limit
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.datetime.utcnow().isoformat()}), 200

# API endpoints that require authentication
@api.route('/status', methods=['GET'])
@login_required
@rate_limit
def api_status():
    role = 'admin' if current_user.is_admin() else 'client'
    return jsonify({
        "authenticated": True,
        "user": current_user.username,
        "role": role,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }), 200

# Admin-only API endpoints
@api.route('/admin/users', methods=['GET'])
@login_required
@admin_required
@rate_limit
def list_users():
    users = User.query.all()
    return success_response([user.to_dict() for user in users])

@api.route('/admin/nodes', methods=['GET'])
@login_required
@admin_required
@rate_limit
def list_nodes():
    nodes = Node.query.all()
    return success_response([node.to_dict() for node in nodes])

@api.route('/admin/sites', methods=['GET'])
@login_required
@admin_required
@rate_limit
def list_all_sites():
    sites = Site.query.all()
    return success_response([site.to_dict() for site in sites])

@api.route('/admin/logs', methods=['GET'])
@login_required
@admin_required
@rate_limit
def list_logs():
    logs = DeploymentLog.query.order_by(DeploymentLog.created_at.desc()).limit(100).all()
    return success_response([log.to_dict() for log in logs])

# Node-specific API endpoints
@api.route('/admin/nodes/<int:node_id>/sites', methods=['GET'])
@login_required
@admin_required
@rate_limit
def list_node_sites(node_id):
    # Get all site IDs for this node
    site_nodes = SiteNode.query.filter_by(node_id=node_id).all()
    site_ids = [site_node.site_id for site_node in site_nodes]
    
    # Get all sites
    sites = Site.query.filter(Site.id.in_(site_ids)).all()
    return success_response([site.to_dict() for site in sites])

# User-specific API endpoints
@api.route('/sites', methods=['GET'])
@login_required
@rate_limit
def list_user_sites():
    sites = Site.query.filter_by(user_id=current_user.id).all()
    return success_response([site.to_dict() for site in sites])

@api.route('/sites/<int:site_id>', methods=['GET'])
@login_required
@rate_limit
def get_site(site_id):
    site = Site.query.get_or_404(site_id)
    
    # Check if the user is an admin or the owner of the site
    if not current_user.is_admin() and site.user_id != current_user.id:
        return error_response("Unauthorized", 403)
    
    return success_response(site.to_dict())

@api.route('/sites/<int:site_id>/nodes', methods=['GET'])
@login_required
@rate_limit
def get_site_nodes(site_id):
    site = Site.query.get_or_404(site_id)
    
    # Check if the user is an admin or the owner of the site
    if not current_user.is_admin() and site.user_id != current_user.id:
        return error_response("Unauthorized", 403)
    
    site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
    return success_response([site_node.to_dict() for site_node in site_nodes])

@api.route('/api/deployments/recent', methods=['GET'])
@login_required
@rate_limit
def api_recent_deployments():
    """Get recent deployment logs for AJAX updates on dashboards"""
    # Get user ID for filtering if not admin
    user_id = current_user.id if not current_user.is_admin() else None
    
    # If client user, only show their sites' logs
    if user_id and not current_user.is_admin():
        site_ids = [site.id for site in Site.query.filter_by(user_id=user_id).all()]
        if site_ids:
            logs = DeploymentLog.query.filter(DeploymentLog.site_id.in_(site_ids)).order_by(
                DeploymentLog.created_at.desc()
            ).limit(20).all()
        else:
            logs = []
    else:
        # For admins, show all logs
        logs = DeploymentLog.query.order_by(DeploymentLog.created_at.desc()).limit(20).all()
    
    return jsonify({
        'success': True,
        'logs': [log.to_dict() for log in logs]
    })

@api.route('/sites/<int:site_id>/waf', methods=['GET'])
@login_required
@rate_limit
def get_site_waf(site_id):
    """Get WAF settings for a site"""
    site = Site.query.get_or_404(site_id)
    
    # Check if the user is an admin or the owner of the site
    if not current_user.is_admin() and site.user_id != current_user.id:
        return error_response("Unauthorized", 403)
    
    # Return WAF configuration details
    waf_config = {
        'use_waf': site.use_waf,
        'waf_rule_level': site.waf_rule_level,
        'waf_max_request_size': site.waf_max_request_size,
        'waf_request_timeout': site.waf_request_timeout,
        'waf_block_tor_exit_nodes': site.waf_block_tor_exit_nodes,
        'waf_rate_limiting_enabled': site.waf_rate_limiting_enabled,
        'waf_rate_limiting_requests': site.waf_rate_limiting_requests,
        'waf_rate_limiting_burst': site.waf_rate_limiting_burst,
        'waf_custom_rules': site.waf_custom_rules
    }
    
    return success_response(waf_config)

@api.route('/sites/<int:site_id>/waf', methods=['PUT'])
@login_required
@rate_limit
def update_site_waf(site_id):
    """Update WAF settings for a site"""
    site = Site.query.get_or_404(site_id)
    
    # Check if the user is an admin or the owner of the site
    if not current_user.is_admin() and site.user_id != current_user.id:
        return error_response("Unauthorized", 403)
    
    # Get JSON data
    data = request.get_json()
    if not data:
        return error_response("Invalid JSON data")
    
    # Validate CSRF token
    try:
        csrf_token = data.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not csrf_token:
            return error_response("Missing CSRF token", 400)
        validate_csrf(csrf_token)
    except CSRFError:
        return error_response("Invalid CSRF token", 400)
    
    # Update WAF settings
    if 'use_waf' in data:
        site.use_waf = bool(data['use_waf'])
    
    if 'waf_rule_level' in data:
        rule_level = data['waf_rule_level']
        if rule_level not in ['basic', 'medium', 'strict']:
            return error_response("Invalid value for waf_rule_level. Must be one of: basic, medium, strict")
        site.waf_rule_level = rule_level
    
    if 'waf_max_request_size' in data:
        try:
            size = int(data['waf_max_request_size'])
            if size < 1 or size > 100:
                return error_response("waf_max_request_size must be between 1 and 100 MB")
            site.waf_max_request_size = size
        except ValueError:
            return error_response("waf_max_request_size must be an integer")
    
    if 'waf_request_timeout' in data:
        try:
            timeout = int(data['waf_request_timeout'])
            if timeout < 10 or timeout > 300:
                return error_response("waf_request_timeout must be between 10 and 300 seconds")
            site.waf_request_timeout = timeout
        except ValueError:
            return error_response("waf_request_timeout must be an integer")
    
    if 'waf_block_tor_exit_nodes' in data:
        site.waf_block_tor_exit_nodes = bool(data['waf_block_tor_exit_nodes'])
    
    if 'waf_rate_limiting_enabled' in data:
        site.waf_rate_limiting_enabled = bool(data['waf_rate_limiting_enabled'])
    
    if 'waf_rate_limiting_requests' in data:
        try:
            requests = int(data['waf_rate_limiting_requests'])
            if requests < 10 or requests > 10000:
                return error_response("waf_rate_limiting_requests must be between 10 and 10000")
            site.waf_rate_limiting_requests = requests
        except ValueError:
            return error_response("waf_rate_limiting_requests must be an integer")
    
    if 'waf_rate_limiting_burst' in data:
        try:
            burst = int(data['waf_rate_limiting_burst'])
            if burst < 10 or burst > 20000:
                return error_response("waf_rate_limiting_burst must be between 10 and 20000")
            site.waf_rate_limiting_burst = burst
        except ValueError:
            return error_response("waf_rate_limiting_burst must be an integer")
    
    if 'waf_custom_rules' in data:
        site.waf_custom_rules = data['waf_custom_rules']
    
    # Save changes to database
    db.session.commit()
    
    # If auto-deploy is requested, update configs on all nodes
    if data.get('deploy', False):
        try:
            from app.services.nginx_service import generate_nginx_config, deploy_to_node
            
            # Generate updated Nginx configuration with WAF settings
            nginx_config = generate_nginx_config(site)
            
            # Deploy to each node
            site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
            deployment_results = []
            
            for site_node in site_nodes:
                try:
                    deploy_to_node(site.id, site_node.node_id, nginx_config)
                    deployment_results.append({
                        'node_id': site_node.node_id,
                        'success': True
                    })
                    
                    # Log the action
                    log = DeploymentLog(
                        site_id=site_id,
                        node_id=site_node.node_id,
                        user_id=current_user.id,
                        action="Update WAF settings",
                        status="success",
                        message="WAF settings updated via API"
                    )
                    db.session.add(log)
                except Exception as e:
                    deployment_results.append({
                        'node_id': site_node.node_id,
                        'success': False,
                        'error': str(e)
                    })
                    
                    # Log the error
                    log = DeploymentLog(
                        site_id=site_id,
                        node_id=site_node.node_id,
                        user_id=current_user.id,
                        action="Update WAF settings",
                        status="error",
                        message=f"Error updating WAF settings: {str(e)}"
                    )
                    db.session.add(log)
            
            db.session.commit()
            
            return success_response({
                'waf_settings_updated': True,
                'deployments': deployment_results
            })
        except Exception as e:
            db.session.rollback()
            return error_response(f"WAF settings updated but deployment failed: {str(e)}")
    
    return success_response({'waf_settings_updated': True})