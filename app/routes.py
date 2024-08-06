from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app import db, bcrypt
from app.models import User, UserRole
from app.schemas import UserSchema, LoginSchema,UserUpdateSchema,ResetPasswordSchema
from app.utils import admin_required 
from flask import jsonify 
import re  
from datetime import datetime, timedelta
from app import db, bcrypt 
import secrets
from sqlalchemy.exc import SQLAlchemyError
from .models import  PasswordHistory
from urllib.parse import urlparse, parse_qs

bp = Blueprint('users', __name__, description='User management operations')

@bp.route('/register')
class Register(MethodView):
    @bp.doc(
        summary="Create a new user",
        description="""\n
        This API endpoint allows user creation without a JWT. Admins can create new admin users by setting 
        the role to "ADMIN," requiring an existing admin JWT. Usernames and emails must be unique, with 
        usernames having a minimum length of 3 characters and passwords at least 8 characters long.\n""",
    ) 
    @bp.arguments(UserSchema, description="Create user object")
    @bp.response(201, description="User created") 
    @bp.alt_response(401, description="Token has expired")
    @bp.alt_response(403, description="Admin token required to create admin user") 
    @bp.alt_response(409, description="Username or Email already exists")
    @bp.alt_response(400, description="BAD REQUEST - Invalid json body")
    def post(self, user_data):
        if user_data.get('role') == 'ADMIN':
            @jwt_required()
            def create_admin_user():
                current_user_id = get_jwt_identity()
                current_user = User.query.get(current_user_id)
                if not current_user or current_user.role != UserRole.ADMIN:
                    abort(403, message="Admin token required to create admin user")
                return self.create_user(user_data)
            return create_admin_user()
        else:
            return self.create_user(user_data)

    def create_user(self, user_data):
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
    @bp.doc(
        summary="Logs user into the system",
        description="""\n
        This endpoint issues a JWT token to the user upon successful login.
        \n""",
    ) 
    @bp.arguments(LoginSchema)
    @bp.response(200, description="Login successful")
    @bp.response(401, description="Invalid username or password" ) 
    @bp.response(401, description="Bad Request - Invalid json body" ) 
    def post(self, login_data):
        user = User.query.filter_by(username=login_data['username']).first()
        if user and bcrypt.check_password_hash(user.password, login_data['password']):
            access_token = create_access_token(identity=user.id)
            return {"message":"Login successful","access_token": access_token},200
        abort(401, message="Invalid username or password")

    # login api completely tested everything works ***note - need to do detailed documentation for this

@bp.route('/users')
class Users(MethodView):
    @bp.doc(
        summary="Lists all the users (ADMIN only)",
        description="""\n
        This endpoint allows an admin to view a list of users.
        \n"""
    ) 
    @jwt_required()
    @admin_required
    @bp.response(200, UserSchema(many=True),description="Successfull")
    @bp.response(401, description="Authorization Header Missing" )
    @bp.response(403, description="Admin access required" )
    @bp.response(422, description="Signature verification failed" )
    def get(self):
        users = User.query.all()
        user_schema = UserSchema(many=True)
        return jsonify(user_schema.dump(users))
    
    # get all user works fine
     

@bp.route('/user/<string:identifier>')
class UserSearch(MethodView):
    @bp.doc(
        summary="Search for a specific user by their ID, email, or username (ADMIN only)",
        description="""\n
        This endpoint allows an admin to search for a specific user by ID, email, or username.
        \n""",
    ) 
    @jwt_required()
    @admin_required
    @bp.response(200, UserSchema)
    @bp.alt_response(404, description="User not found",example={"message":"User not found"}) 
    @bp.alt_response(422, description="Signature verification failed",example={"message":"Signature verification failed"}) 
    def get(self, identifier):
        user = self.get_user(identifier)

        if not user:
            abort(404, message="User not found")
        
        return user
    
    def get_user(self, identifier):
        if identifier.isdigit():
            return User.query.get(int(identifier))
        elif '@' in identifier:
            return User.query.filter_by(email=identifier).first()
        else:
            return User.query.filter_by(username=identifier).first()
# get user by unique identifier email or username works fine ***note - thinking about addidng the search by id feature

#update user or delete user
@bp.route('/users/<string:identifier>')
class UserResource(MethodView):
    @bp.doc(
        summary="Update a user",
        description="""\n
        This endpoint allows users to update their own account and admins to update any accounts, 
        including their own, using their JWT. However, one admin cannot update another admin's account.
        \n""",
    ) 
    @jwt_required()
    @bp.arguments(UserUpdateSchema)
    @bp.response(200, UserSchema)
    @bp.alt_response(401, description="Missing Authorization Header or expired token")
    @bp.alt_response(403, description="Only admins can change user roles")
    @bp.alt_response(404, description="User not found")
    @bp.alt_response(405, description="Admin cannot update another admin's information")
    @bp.alt_response(406, description="You can only update your own information")
    @bp.alt_response(409, description="Username or email already exists")
    def put(self, user_data, identifier):
        current_user_id = get_jwt_identity()
        current_user = User.query.get_or_404(current_user_id)

        user_to_update = self.get_user(identifier)
        if not user_to_update:
                abort(404, message="User not found")

        if  identifier in (str(current_user.id), current_user.username, current_user.email):
            # User is updating their own information
            user_to_update = current_user
        elif current_user.role == UserRole.ADMIN:
            # Admin is updating another user's information
            user_to_update = self.get_user(identifier)
            if not user_to_update:
                abort(404, message="User not found")
            if user_to_update.role == UserRole.ADMIN:
                abort(405, message="Admin cannot update another admin's information")
        else:
            # Regular user trying to update someone else's information
            abort(406, message="You can only update your own information")

        if User.query.filter_by(username=user_data['username']).first():
            abort(409, message="Username already exists use another username")
        if User.query.filter_by(email=user_data['email']).first():
            abort(409, message="Email already exists use another email")

        # Update user information
        for key, value in user_data.items():
            if key == 'role' and current_user.role != UserRole.ADMIN and current_user.role!=UserRole.USER:
                abort(403, message="Only admins can change user roles")
            setattr(user_to_update, key, value)

        db.session.commit()
        return user_to_update
    
    # need to add the functionality where users cannot change name to existing uesrname or email

    @jwt_required()
    @bp.doc(
        summary="DELETE a user ",
        description="""\n
        This endpoint allows users to delete their own account and admins to delete any accounts, 
        including their own, using their JWT. However, one admin cannot delete another admin's account.
        \n""",
    ) 
    @bp.response(200, description="User deleted successfully")
    @bp.alt_response(401, description="Invalid or expired token")
    @bp.alt_response(403, description="Unauthorized to delete this user")
    @bp.alt_response(404, description="User not found")
    @bp.alt_response(409, description="Admin cannot delete another admin")
    def delete(self, identifier):
        user_to_delete = self.get_user(identifier)
        if not user_to_delete:
            abort(404, message="User not found")
        
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        if current_user is None:
            abort(401,message="Invalid token")

        # Check if the current user has permission to delete the target user
        if user_to_delete.role == UserRole.ADMIN and current_user.role == user_to_delete.role:
            abort(409, message="Admin cannot delete another admin user")

        if not self.can_delete_user(current_user, user_to_delete):
            abort(403, message="Unauthorized to delete this user")
        
        db.session.delete(user_to_delete)
        db.session.commit()
        return {"message": "User deleted successfully"}
        
         

    def get_user(self, identifier):
        if identifier.isdigit():
            return User.query.get(int(identifier))
        elif '@' in identifier:
            return User.query.filter_by(email=identifier).first()
        else:
            return User.query.filter_by(username=identifier).first()

    def can_delete_user(self, current_user, user_to_delete):
        # Admins can delete any non-admin user, but not other admins
        if current_user.role == UserRole.ADMIN:
            if user_to_delete.role == UserRole.ADMIN and current_user.id != user_to_delete.id:
                return False  # Admin cannot delete another admin
            return True
        
        # Non-admin users can only delete their own account
        return current_user.id == user_to_delete.id
    

    # delete and update works (kind of) need intense testing 





@bp.route("/forget-password/<string:identifier>")
class ForgetPassword(MethodView):
    @bp.doc(
        summary="Forget password api",
        description="""\n
        This endpoint allows users to reset their forgotten password using their username or email as a slug. 
        It generates a token and returns a reset link, which the user can use to reset their password.
        \n""",
    ) 
    @bp.response(200, description="Password reset link generated successfully")
    @bp.alt_response(404, description="Invalid or expired token")
    @bp.alt_response(405, description="User not found")
    @bp.alt_response(500, description="An error occurred while generating the reset token.")
    def get(self, identifier):
        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        if not user:
            abort(405, message="User not found")
        
        # Generate a secure random token
        token = secrets.token_hex(16)  # 32 character string
        
        # Store the token and its expiry (e.g., 1 hour from now) in the user's record
        user.reset_token = token
        user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
        
        try:
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            abort(500, message="An error occurred while generating the reset token.")
        
        # Generate the reset link
        reset_link = f"/reset-password?token={token}"
        
        return {"message": "Password reset link generated successfully", "reset_link": reset_link}

@bp.route("/reset-password")
class ResetPassword(MethodView):
    @bp.doc(
        summary="Reset password",
        description="""\n
        This endpoint allows users to reset their password using a "forgot password" link. 
        The new password must be at least 8 characters long and must not match any of the 
        user's last five passwords. The full reset link should be provided in the request body.
        \n""",
    ) 
    @bp.arguments(ResetPasswordSchema)
    @bp.response(200, description="Password reset successfully")
    @bp.alt_response(400, description="Invalid link or password")
    @bp.alt_response(404, description="User not found or token expired")
    def post(self, reset_password_data):
        reset_link = reset_password_data['reset_link']
        new_password = reset_password_data['new_password']
        
        # Extract token from the reset link
        parsed_url = urlparse(reset_link)
        token = parse_qs(parsed_url.query).get('token', [None])[0]
        
        if not token:
            abort(400, message="Invalid reset link")
        
        user = User.query.filter_by(reset_token=token).first()
        if not user or user.reset_token_expiry < datetime.utcnow():
            abort(404, message="Invalid or expired token")
        
        # Check password history
        if self.is_password_used(user, new_password):
            abort(400, message="Password has been used recently. Please choose a different password.")
        
        # Update password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        user.reset_token = None
        user.reset_token_expiry = None
        
        # Add to password history
        self.add_to_password_history(user, hashed_password)
        
        try:
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            abort(500, message="An error occurred while resetting the password.")
        
        return {"message": "Password reset successfully"}
    
    def is_password_used(self, user, new_password):
        # Check the last 5 passwords
        recent_passwords = PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.created_at.desc()).limit(5).all()
        return any(bcrypt.check_password_hash(history.password, new_password) for history in recent_passwords)
    
    def add_to_password_history(self, user, hashed_password):
        new_history = PasswordHistory(user_id=user.id, password=hashed_password)
        db.session.add(new_history)

# Note: Ensure to handle these cases in your frontend:
# - When token mismatches, return not found
# - When using the same password, return bad request
 
# @bp.route("/forget-password")
# class ForgetPassword(MethodView):
#     @bp.doc(
#         summary="Forget password api",
#         description="""\n
#         This endpoint allows users to reset their forgotten password using their username or email. 
#         It generates a token, which the user must use along with a new password to change their 
#         password by hitting the reset password API.
#         \n""",
#     ) 
#     @bp.arguments(ForgetPasswordSchema)
#     @bp.response(200, description="Password reset link generated successfully")
#     @bp.alt_response(404, description="User not found")
#     def post(self, forget_password_data):
#         identifier = forget_password_data['identifier']
#         user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
#         if not user:
#             abort(404, message="User not found")
        
#         # Generate a secure random token
#         token = secrets.token_hex(16)  # 32 character string
        
#         # Store the token and its expiry (e.g., 1 hour from now) in the user's record
#         user.reset_token = token
#         user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
        
#         try:
#             db.session.commit()
#         except SQLAlchemyError as e:
#             db.session.rollback()
#             abort(500, message="An error occurred while generating the reset token.")
        
#         # Return the token directly
#         return {"message": "Password reset link generated successfully", "reset_token": token}

# @bp.route("/reset-password")
# class ResetPassword(MethodView):
#     @bp.doc(
#         summary="Reset passoword",
#         description="""\n
#         This endpoint allows users to reset their password using a "forgot password" token. 
#         The new password must be at least 8 characters long and must not match any of the 
#         user's last five passwords.
#         \n""",
#     ) 
#     @bp.arguments(ResetPasswordSchema)
#     @bp.response(200, description="Password reset successfully")
#     @bp.alt_response(400, description="Invalid token or password")
#     @bp.alt_response(404, description="User not found or token expired")
#     def post(self, reset_password_data):
#         token = reset_password_data['token']
#         new_password = reset_password_data['new_password']
        
#         user = User.query.filter_by(reset_token=token).first()
#         if not user or user.reset_token_expiry < datetime.utcnow():
#             abort(404, message="Invalid or expired token")
        
#         # Check password history
#         if self.is_password_used(user, new_password):
#             abort(400, message="Password has been used recently. Please choose a different password.")
        
#         # Update password
#         hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
#         user.password = hashed_password
#         user.reset_token = None
#         user.reset_token_expiry = None
        
#         # Add to password history
#         self.add_to_password_history(user, hashed_password)
        
#         try:
#             db.session.commit()
#         except SQLAlchemyError as e:
#             db.session.rollback()
#             abort(500, message="An error occurred while resetting the password.")
        
#         return {"message": "Password reset successfully"}
    
#     def is_password_used(self, user, new_password):
#         # Check the last 5 passwords
#         recent_passwords = PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.created_at.desc()).limit(5).all()
#         return any(bcrypt.check_password_hash(history.password, new_password) for history in recent_passwords)
    
#     def add_to_password_history(self, user, hashed_password):
#         new_history = PasswordHistory(user_id=user.id, password=hashed_password)
#         db.session.add(new_history)

        # when token missmatch returns not found
        # when use same password returns bad request