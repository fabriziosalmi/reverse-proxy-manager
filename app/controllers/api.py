from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from app.models.models import db, Site, Node, SiteNode, User, DeploymentLog
from app.services.access_control import admin_required
import datetime

api = Blueprint('api', __name__)

# API Error Responses
def error_response(message, status_code=400):
    return jsonify({"error": message}), status_code

# API Success Responses
def success_response(data, message="Success", status_code=200):
    return jsonify({"message": message, "data": data}), status_code

# Health check endpoint (no auth required)
@api.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.datetime.utcnow().isoformat()}), 200

# API endpoints that require authentication
@api.route('/status', methods=['GET'])
@login_required
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
def list_users():
    users = User.query.all()
    return success_response([user.to_dict() for user in users])

@api.route('/admin/nodes', methods=['GET'])
@login_required
@admin_required
def list_nodes():
    nodes = Node.query.all()
    return success_response([node.to_dict() for node in nodes])

@api.route('/admin/sites', methods=['GET'])
@login_required
@admin_required
def list_all_sites():
    sites = Site.query.all()
    return success_response([site.to_dict() for site in sites])

@api.route('/admin/logs', methods=['GET'])
@login_required
@admin_required
def list_logs():
    logs = DeploymentLog.query.order_by(DeploymentLog.created_at.desc()).limit(100).all()
    return success_response([log.to_dict() for log in logs])

# Node-specific API endpoints
@api.route('/admin/nodes/<int:node_id>/sites', methods=['GET'])
@login_required
@admin_required
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
def list_user_sites():
    sites = Site.query.filter_by(user_id=current_user.id).all()
    return success_response([site.to_dict() for site in sites])

@api.route('/sites/<int:site_id>', methods=['GET'])
@login_required
def get_site(site_id):
    site = Site.query.get_or_404(site_id)
    
    # Check if the user is an admin or the owner of the site
    if not current_user.is_admin() and site.user_id != current_user.id:
        return error_response("Unauthorized", 403)
    
    return success_response(site.to_dict())

@api.route('/sites/<int:site_id>/nodes', methods=['GET'])
@login_required
def get_site_nodes(site_id):
    site = Site.query.get_or_404(site_id)
    
    # Check if the user is an admin or the owner of the site
    if not current_user.is_admin() and site.user_id != current_user.id:
        return error_response("Unauthorized", 403)
    
    site_nodes = SiteNode.query.filter_by(site_id=site_id).all()
    return success_response([site_node.to_dict() for site_node in site_nodes])