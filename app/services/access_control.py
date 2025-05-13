from functools import wraps
from flask import current_app, flash, redirect, url_for, abort, request, g, make_response, jsonify
from flask_login import current_user
from app.services.rate_limiter import api_rate_limiter, auth_rate_limiter, ssl_cert_rate_limiter, rate_limit_request
import time
import functools

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        if not current_user.is_admin():
            flash('You need admin privileges to access this page.', 'error')
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

def client_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        if not current_user.is_client():
            flash('This page is available only for client users.', 'error')
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_api(limiter=None):
    """
    Decorator for rate limiting API endpoints
    
    Args:
        limiter: RateLimiter instance to use (defaults to api_rate_limiter)
        
    Returns:
        Function: Decorator function
    """
    if limiter is None:
        limiter = api_rate_limiter
    
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            # Get client identifier (IP address)
            client_id = request.remote_addr
            
            # Apply rate limiting
            is_allowed, headers = rate_limit_request(limiter, client_id)
            
            if not is_allowed:
                # Create rate limit exceeded response
                response = make_response(jsonify({
                    'error': 'Rate limit exceeded',
                    'message': 'Too many requests, please try again later'
                }), 429)
                
                # Add rate limit headers
                for header, value in headers.items():
                    response.headers[header] = value
                
                # Add retry-after header
                response.headers['Retry-After'] = headers['X-RateLimit-Reset']
                
                return response
            
            # Call the original function
            response = f(*args, **kwargs)
            
            # Add rate limit headers to the response
            if hasattr(response, 'headers'):
                for header, value in headers.items():
                    response.headers[header] = value
            
            return response
        return wrapped
    return decorator