from functools import wraps
from flask import flash, redirect, url_for, current_app, request, jsonify
from flask_login import current_user

def admin_required(f):
    """
    Decorator that checks if the current user is an admin.
    If not, redirects to the login page or returns a 403 error for API endpoints.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'message': 'Authentication required'
                }), 401
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url))
        
        if not current_user.is_admin:
            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'message': 'Admin privileges required'
                }), 403
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('client.dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

def client_required(f):
    """
    Decorator that checks if the current user is authenticated.
    If not, redirects to the login page or returns a 401 for API endpoints.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'message': 'Authentication required'
                }), 401
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url))
            
        return f(*args, **kwargs)
    return decorated_function

def api_key_required(f):
    """
    Decorator that checks if the request contains a valid API key.
    If not, returns a 401 error.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get the API key from the request
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({
                'success': False,
                'message': 'API key is required'
            }), 401
        
        # Check if the API key is valid (from app.models.models import APIKey)
        from app.models.models import APIKey
        key = APIKey.query.filter_by(key=api_key, is_active=True).first()
        
        if not key:
            return jsonify({
                'success': False,
                'message': 'Invalid API key'
            }), 401
        
        # Check if the API key has the required permissions
        # This will be implemented in the future when we add permission-based API keys
        
        return f(*args, **kwargs)
    return decorated_function

def rate_limited(limit=60, period=60):
    """
    Decorator that limits the rate at which a function can be called.
    
    Args:
        limit: Maximum number of requests allowed in the period
        period: Time period in seconds
        
    Returns:
        Decorated function with rate limiting
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from app.services.rate_limiter import RateLimiter
            
            # Get client identifier (IP or user ID if authenticated)
            if current_user.is_authenticated:
                client_id = f"user:{current_user.id}"
            else:
                client_id = f"ip:{request.remote_addr}"
            
            # Check rate limit
            rate_limiter = RateLimiter()
            allowed, remaining, reset_time = rate_limiter.check_rate_limit(
                client_id, 
                request.endpoint, 
                limit, 
                period
            )
            
            if not allowed:
                # If we're handling an API request, return JSON
                if request.path.startswith('/api/'):
                    response = jsonify({
                        'success': False,
                        'message': 'Rate limit exceeded',
                        'rate_limit': {
                            'limit': limit,
                            'remaining': remaining,
                            'reset': reset_time
                        }
                    })
                    response.status_code = 429
                    response.headers['X-RateLimit-Limit'] = str(limit)
                    response.headers['X-RateLimit-Remaining'] = str(remaining)
                    response.headers['X-RateLimit-Reset'] = str(reset_time)
                    response.headers['Retry-After'] = str(reset_time - int(time.time()))
                    return response
                else:
                    # For regular requests, show an error message
                    flash('You have made too many requests. Please try again later.', 'danger')
                    return redirect(url_for('client.dashboard'))
            
            # Update headers for API requests
            if request.path.startswith('/api/'):
                response = f(*args, **kwargs)
                
                # Only modify response if it's a tuple with a response object or a Response object
                if isinstance(response, tuple) and len(response) >= 1:
                    actual_response = response[0]
                    if hasattr(actual_response, 'headers'):
                        actual_response.headers['X-RateLimit-Limit'] = str(limit)
                        actual_response.headers['X-RateLimit-Remaining'] = str(remaining)
                        actual_response.headers['X-RateLimit-Reset'] = str(reset_time)
                        return response
                elif hasattr(response, 'headers'):
                    response.headers['X-RateLimit-Limit'] = str(limit)
                    response.headers['X-RateLimit-Remaining'] = str(remaining)
                    response.headers['X-RateLimit-Reset'] = str(reset_time)
                    
                return response
            else:
                return f(*args, **kwargs)
                
        return decorated_function
    return decorator