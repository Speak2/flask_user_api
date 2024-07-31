from flask import Blueprint, request, jsonify
from app import db, bcrypt
from app.models import User, UserRole
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app.utils import admin_required
import logging

bp = Blueprint('api', __name__)

@bp.route('/register', methods=['POST'])
def register():
    logging.info("Register route called")
    data = request.get_json()
    logging.info(f"Received data: {data}")
    try:
        if User.query.filter_by(username=data['username']).first():
            return jsonify({"message": "Username already exists"}), 400
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"message": "Email already exists"}), 400
        role = data.get('role', 'User')
        if role not in UserRole.__members__:
            return jsonify({"message": "Invalid role"}), 400
        role_enum = UserRole[role]
        
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        new_user = User(username=data['username'], first_name=data['first_name'], last_name=data['last_name'],
                        password=hashed_password, email=data['email'], role=role_enum)
        db.session.add(new_user)
        db.session.commit()
        logging.info("User created successfully")
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        logging.error(f"Error in register route: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500

@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify({"message": "Invalid username or password"}), 401

@bp.route('/users', methods=['GET'])
@jwt_required()
@admin_required
def get_users():
    users = User.query.all()
    return jsonify([{"id": user.id, "username": user.username, "email": user.email, "role": user.role.value} for user in users]), 200


    # Api tested till here all working 

@bp.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    user.username = data.get('username', user.username)
    user.email = data.get('email', user.email)
    user.active = data.get('active', user.active)
    db.session.commit()
    return jsonify({"message": "User updated successfully"}), 200

@bp.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200

@bp.route('/reset-password', methods=['POST'])
def reset_password():
    # In a real application, you would send an email with a reset link
    # For this example, we'll just update the password directly
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user:
        hashed_password = bcrypt.generate_password_hash(data['new_password']).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        return jsonify({"message": "Password reset successfully"}), 200
    return jsonify({"message": "User not found"}), 404