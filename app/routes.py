from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app import db, bcrypt
from app.models import User, UserRole
from app.schemas import UserSchema, LoginSchema, PasswordResetSchema
from app.utils import admin_required
from sqlalchemy.exc import SQLAlchemyError
from flask import request, jsonify, current_app
import logging

bp = Blueprint('users', __name__, description='User management operations')

# @bp.route('/register')
# class Register(MethodView):
#     @bp.arguments(UserSchema)
#     @bp.response(201, UserSchema, description="User registered successfully")
#     @bp.response(400, description="Bad request")
#     @bp.response(409, description="User already exists")
#     @bp.response(422, description="Validation error")
#     def post(self, user_data):
#         logging.info(f"Register route called with data: {user_data}")
#         try:
#             if User.query.filter_by(username=user_data['username']).first():
#                 logging.warning(f"Registration attempt with existing username: {user_data['username']}")
#                 abort(409, message="Username already exists")
#             if User.query.filter_by(email=user_data['email']).first():
#                 logging.warning(f"Registration attempt with existing email: {user_data['email']}")
#                 abort(409, message="Email already exists")
            
#             role = user_data.get('role', 'User')
#             if role not in UserRole.__members__:
#                 logging.warning(f"Registration attempt with invalid role: {role}")
#                 abort(400, message="Invalid role")
#             role_enum = UserRole[role]
            
#             hashed_password = bcrypt.generate_password_hash(user_data['password']).decode('utf-8')
#             new_user = User(
#                 username=user_data['username'],
#                 first_name=user_data['first_name'],
#                 last_name=user_data['last_name'],
#                 password=hashed_password,
#                 email=user_data['email'],
#                 role=role_enum
#             )
#             db.session.add(new_user)
#             db.session.commit()
#             logging.info(f"User created successfully: {new_user.username}")
#             return new_user, 201
#         except SQLAlchemyError as e:
#             db.session.rollback()
#             logging.error(f"Database error during user registration: {str(e)}")
#             abort(500, message="An error occurred while accessing the database")
#         except Exception as e:
#             logging.error(f"Unexpected error in register route: {str(e)}")
#             abort(500, message="An unexpected error occurred")

@bp.route('/register')
class Register(MethodView):
    def post(self):
        user_data = request.get_json()
        
        # Create new user with given data
        hashed_password = bcrypt.generate_password_hash(user_data['password']).decode('utf-8')
        new_user = User(
            username=user_data['username'],
            first_name=user_data['first_name'],
            last_name=user_data['last_name'],
            password=hashed_password,
            email=user_data['email'],
            role=UserRole[user_data.get('role', 'User')]  # Default to 'User' role if not provided
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            return jsonify({"message": "User registered successfully"}), 201
        except SQLAlchemyError:
            db.session.rollback()
            return jsonify({"message": "Database error occurred"}), 500
        except Exception:
            return jsonify({"message": "Unexpected error occurred"}), 500

@bp.route('/login')
class Login(MethodView):
    @bp.arguments(LoginSchema)
    @bp.response(200, description="Login successful")
    def post(self, login_data):
        user = User.query.filter_by(username=login_data['username']).first()
        if user and bcrypt.check_password_hash(user.password, login_data['password']):
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}
        abort(401, message="Invalid username or password")

@bp.route('/users')
class Users(MethodView):
    @jwt_required()
    @admin_required
    #@bp.response(200, UserSchema(many=True))
    def get(self):
        return User.query.all()

@bp.route('/users/<int:user_id>')
class UserResource(MethodView):
    @jwt_required()
    @admin_required
    @bp.arguments(UserSchema)
    @bp.response(200, UserSchema)
    def put(self, user_data, user_id):
        user = User.query.get_or_404(user_id)
        for key, value in user_data.items():
            setattr(user, key, value)
        db.session.commit()
        return user

    @jwt_required()
    @admin_required
    @bp.response(200, description="User deleted successfully")
    def delete(self, user_id):
        user_to_delete = User.query.get_or_404(user_id)
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        if user_to_delete.role == UserRole.ADMIN:
            abort(403, message="Admin cannot delete another admin user")
        
        if current_user.id == user_to_delete.id:
            abort(403, message="Admin cannot delete themselves")
        
        db.session.delete(user_to_delete)
        db.session.commit()
        return {"message": "User deleted successfully"}

@bp.route('/reset-password')
class PasswordReset(MethodView):
    @bp.arguments(PasswordResetSchema)
    @bp.response(200, description="Password reset successfully")
    def post(self, reset_data):
        user = User.query.filter_by(email=reset_data['email']).first()
        if user:
            hashed_password = bcrypt.generate_password_hash(reset_data['new_password']).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            return {"message": "Password reset successfully"}
        abort(404, message="User not found")