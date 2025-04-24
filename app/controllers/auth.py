from flask import Blueprint, flash, render_template, redirect, url_for, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app.models.models import User, db, ActivityLog
from datetime import datetime
from app.services.access_control import admin_required
from app.services.rate_limiter import auth_rate_limiter, rate_limit_request
import time

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    # Redirect if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('client.dashboard'))
    
    if request.method == 'POST':
        # Apply rate limiting based on IP address
        client_ip = request.remote_addr
        is_allowed, headers = rate_limit_request(auth_rate_limiter, client_ip)
        
        if not is_allowed:
            flash('Too many login attempts. Please try again later.', 'error')
            
            # Create a response with rate limit headers
            response = redirect(url_for('auth.login'))
            for header, value in headers.items():
                response.headers[header] = value
            
            # Add retry-after header
            response.headers['Retry-After'] = headers['X-RateLimit-Reset']
            
            return response
        
        username = request.form.get('username')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        # Validate login credentials
        user = User.query.filter_by(username=username).first()
        
        if user and user.verify_password(password):
            # Successfully authenticated
            login_user(user, remember=remember)
            
            # Log the successful login
            log = ActivityLog(
                user_id=user.id,
                action='login',
                ip_address=request.remote_addr,
                details='Successful login'
            )
            db.session.add(log)
            db.session.commit()
            
            # Reset rate limiter for this IP since login was successful
            auth_rate_limiter.reset(client_ip)
            
            # Redirect based on user role
            if user.is_admin():
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
        else:
            # Log failed login attempt
            details = f"Failed login attempt for username: {username}"
            
            if user:
                log = ActivityLog(
                    user_id=user.id,
                    action='login_failed',
                    ip_address=request.remote_addr,
                    details=details
                )
            else:
                log = ActivityLog(
                    user_id=None,
                    action='login_failed',
                    ip_address=request.remote_addr,
                    details=details
                )
            
            db.session.add(log)
            db.session.commit()
            
            flash('Invalid username or password', 'error')
    
    return render_template('auth/login.html')

@auth.route('/logout', methods=['GET'])
@login_required
def logout():
    """Handle user logout"""
    # Log the logout activity
    log = ActivityLog(
        user_id=current_user.id,
        action='logout',
        ip_address=request.remote_addr,
        details='User logged out'
    )
    db.session.add(log)
    db.session.commit()
    
    # Perform the actual logout
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.login'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration"""
    # Check if user registration is enabled
    if not current_app.config.get('ALLOW_REGISTRATION', False):
        flash('User registration is currently disabled.', 'error')
        return redirect(url_for('auth.login'))
    
    # Redirect if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('client.dashboard'))
    
    if request.method == 'POST':
        # Apply rate limiting based on IP address to prevent registration attacks
        client_ip = request.remote_addr
        is_allowed, headers = rate_limit_request(auth_rate_limiter, client_ip)
        
        if not is_allowed:
            flash('Too many registration attempts. Please try again later.', 'error')
            
            # Create a response with rate limit headers
            response = redirect(url_for('auth.register'))
            for header, value in headers.items():
                response.headers[header] = value
                
            return response
        
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate form input
        error = None
        
        if not username:
            error = 'Username is required.'
        elif not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'
        elif password != confirm_password:
            error = 'Passwords do not match.'
        
        # Check if username or email already exists
        if not error:
            if User.query.filter_by(username=username).first():
                error = 'Username already exists.'
            elif User.query.filter_by(email=email).first():
                error = 'Email already exists.'
        
        if error:
            flash(error, 'error')
        else:
            # Create new user
            user = User(
                username=username,
                email=email,
                role='client',  # Default role for new users
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            user.set_password(password)
            
            # Add user to database
            db.session.add(user)
            
            # Log the registration
            log = ActivityLog(
                user_id=None,  # User ID not yet known
                action='register',
                ip_address=request.remote_addr,
                details=f"New user registration: {username}"
            )
            db.session.add(log)
            
            db.session.commit()
            
            # Update log with actual user ID
            log.user_id = user.id
            db.session.commit()
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html')

@auth.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Handle user profile view and updates"""
    if request.method == 'POST':
        # Apply rate limiting based on IP address
        client_ip = request.remote_addr
        is_allowed, headers = rate_limit_request(auth_rate_limiter, client_ip)
        
        if not is_allowed:
            flash('Too many profile update attempts. Please try again later.', 'error')
            
            # Create a response with rate limit headers
            response = redirect(url_for('auth.profile'))
            for header, value in headers.items():
                response.headers[header] = value
                
            return response
        
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate form input
        error = None
        
        # Update email if provided
        if email and email != current_user.email:
            # Check if email already exists
            if User.query.filter_by(email=email).first():
                error = 'Email already exists.'
            else:
                current_user.email = email
        
        # Update password if provided
        if current_password and new_password:
            if not current_user.verify_password(current_password):
                error = 'Current password is incorrect.'
            elif new_password != confirm_password:
                error = 'New passwords do not match.'
            else:
                current_user.set_password(new_password)
        
        if error:
            flash(error, 'error')
        else:
            # Update user
            current_user.updated_at = datetime.utcnow()
            
            # Log the profile update
            log = ActivityLog(
                user_id=current_user.id,
                action='profile_update',
                ip_address=request.remote_addr,
                details='User profile updated'
            )
            db.session.add(log)
            
            db.session.commit()
            
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('auth.profile'))
    
    # Get user's recent activity
    activities = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.created_at.desc()).limit(10).all()
    
    return render_template('auth/profile.html', user=current_user, activities=activities)

@auth.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    """Handle password reset request"""
    # Redirect if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('client.dashboard'))
    
    if request.method == 'POST':
        # Apply rate limiting based on IP address
        client_ip = request.remote_addr
        is_allowed, headers = rate_limit_request(auth_rate_limiter, client_ip)
        
        if not is_allowed:
            flash('Too many password reset attempts. Please try again later.', 'error')
            
            # Create a response with rate limit headers
            response = redirect(url_for('auth.reset_password_request'))
            for header, value in headers.items():
                response.headers[header] = value
                
            return response
        
        email = request.form.get('email')
        
        if not email:
            flash('Email is required.', 'error')
        else:
            user = User.query.filter_by(email=email).first()
            
            if user:
                # Generate password reset token
                token = user.generate_reset_token()
                
                # In a real app, send an email with the token
                # For now, just store it in the session for testing
                session['reset_token'] = token
                session['reset_email'] = email
                
                # Log the password reset request
                log = ActivityLog(
                    user_id=user.id,
                    action='password_reset_request',
                    ip_address=request.remote_addr,
                    details=f"Password reset requested for: {email}"
                )
                db.session.add(log)
                db.session.commit()
                
                flash('A password reset link has been sent to your email.', 'success')
                return redirect(url_for('auth.reset_password', token=token))
            else:
                # Even if user doesn't exist, show success message to prevent user enumeration
                flash('If an account exists with that email, a password reset link has been sent.', 'success')
    
    return render_template('auth/reset_password_request.html')

@auth.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handle password reset with token"""
    # Redirect if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('client.dashboard'))
    
    # In a real app, verify the token
    # For testing, compare with the token stored in the session
    if token != session.get('reset_token'):
        flash('Invalid or expired password reset token.', 'error')
        return redirect(url_for('auth.reset_password_request'))
    
    if request.method == 'POST':
        # Apply rate limiting based on IP address
        client_ip = request.remote_addr
        is_allowed, headers = rate_limit_request(auth_rate_limiter, client_ip)
        
        if not is_allowed:
            flash('Too many password reset attempts. Please try again later.', 'error')
            
            # Create a response with rate limit headers
            response = redirect(url_for('auth.reset_password', token=token))
            for header, value in headers.items():
                response.headers[header] = value
                
            return response
        
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password:
            flash('Password is required.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        else:
            # Get the user from the email stored in the session
            email = session.get('reset_email')
            user = User.query.filter_by(email=email).first()
            
            if user:
                # Update the password
                user.set_password(password)
                user.updated_at = datetime.utcnow()
                
                # Log the password reset
                log = ActivityLog(
                    user_id=user.id,
                    action='password_reset',
                    ip_address=request.remote_addr,
                    details='Password reset completed'
                )
                db.session.add(log)
                
                db.session.commit()
                
                # Clear session data
                session.pop('reset_token', None)
                session.pop('reset_email', None)
                
                flash('Your password has been reset successfully! You can now log in.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash('Invalid user.', 'error')
    
    return render_template('auth/reset_password.html')