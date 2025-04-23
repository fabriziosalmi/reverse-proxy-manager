import datetime
from flask import request, has_request_context, current_app
from app.models.models import db, SystemLog
from flask_login import current_user

def log_activity(category, action, resource_type=None, resource_id=None, details=None, user_id=None):
    """
    Log system activity with detailed information
    
    Args:
        category: Category of the log (auth, admin, system, security, etc.)
        action: Action performed (login, logout, create, delete, etc.)
        resource_type: Type of resource affected (user, node, site, etc.)
        resource_id: ID of the affected resource
        details: Additional details about the action
        user_id: ID of the user performing the action (if different from current_user)
    
    Returns:
        SystemLog: The created log entry
    """
    try:
        # Get user ID from current_user if authenticated, or from the parameter
        if user_id is None and current_user and current_user.is_authenticated:
            user_id = current_user.id
            
        # Get IP address if in request context
        ip_address = None
        if has_request_context():
            ip_address = request.remote_addr
            
            # Handle proxy headers if applicable
            if 'X-Forwarded-For' in request.headers:
                ip_address = request.headers.getlist('X-Forwarded-For')[0].split(',')[0].strip()
        
        # Create log entry
        log = SystemLog(
            user_id=user_id,
            category=category,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
        )
        
        db.session.add(log)
        db.session.commit()
        
        return log
    except Exception as e:
        if current_app:
            current_app.logger.error(f"Failed to log activity: {str(e)}")
        return None