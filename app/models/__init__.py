from flask_login import UserMixin
from app import login_manager
from app.models.models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Add UserMixin to User class to implement Flask-Login methods
User.__bases__ = (UserMixin,) + User.__bases__