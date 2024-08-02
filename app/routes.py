from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app import db, bcrypt
from app.models import User, UserRole
from app.schemas import UserSchema, LoginSchema, PasswordResetSchema
from app.utils import admin_required 
from flask import jsonify

bp = Blueprint('users', __name__, description='User management operations')

@bp.route('/register')
class Register(MethodView):
    @bp.arguments(UserSchema)
    @bp.response(201, UserSchema, description="User created", example={"message":"User created Successfully"}) 
    @bp.response(409, UserSchema, description="Username or Email already exists", example={"message":"Email already exists"}) 
    def post(self, user_data):
        if User.query.filter_by(username=user_data['username']).first():
            abort(409, message="Username already exists")
        if User.query.filter_by(email=user_data['email']).first():
            abort(409, message="Email already exists")

        hashed_password = bcrypt.generate_password_hash(user_data['password']).decode('utf-8')
        new_user = User(
            username=user_data['username'],
            first_name=user_data['first_name'],
            last_name=user_data['last_name'],
            email=user_data['email'],
            password=hashed_password,
            role=UserRole[user_data.get('role', 'USER')]
        )

        db.session.add(new_user)
        db.session.commit()

        response = {"message": "User Created Successfully"}
        return jsonify(response), 201

@bp.route('/login')
class Login(MethodView):
    @bp.arguments(LoginSchema)
    @bp.response(200, description="Login successful")
    @bp.response(401, description="Invalid username or password", example={"message":"Invalid username or password"}) 
    def post(self, login_data):
        user = User.query.filter_by(username=login_data['username']).first()
        if user and bcrypt.check_password_hash(user.password, login_data['password']):
            access_token = create_access_token(identity=user.id)
            return {"message":"Login successful","access_token": access_token},200
        abort(401, message="Invalid username or password")

@bp.route('/users')
class Users(MethodView):
    @jwt_required()
    @admin_required
    @bp.response(200, UserSchema(many=True))
    @bp.response(401, description="Authorization Header Missing", example={"message":"Missing Authorization Header"})
    @bp.response(422, description="Signature verification failed", example={"message":"Unauthorized token"})
    def get(self):
        return User.query.all()

#update user or delete user
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