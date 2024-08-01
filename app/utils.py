from functools import wraps
from flask_jwt_extended import get_jwt_identity
from app.models import User, UserRole
from flask_smorest import abort

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        if not current_user or current_user.role != UserRole.ADMIN:
            abort(403, message="Admin access required")
        return fn(*args, **kwargs)
    return wrapper