from functools import wraps
from flask import current_app, flash, redirect, url_for, abort
from flask_login import current_user

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash('You need admin privileges to access this page.', 'error')
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

def client_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_client():
            flash('This page is available only for client users.', 'error')
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function