from flask_login import UserMixin
from app import login_manager
from app.models.models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# UserMixin is already part of User class definition in models.py, no need to add it again
# User.__bases__ = (UserMixin,) + User.__bases__