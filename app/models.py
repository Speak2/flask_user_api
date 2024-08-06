from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database
from datetime import datetime
from sqlalchemy import Enum as SQLAlchemyEnum 
from enum import Enum
from werkzeug.security import check_password_hash


db = SQLAlchemy()

class UserRole(str, Enum):
    
    USER = 'USER'
    ADMIN = 'ADMIN'

    def __str__(self):
        return self.value

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    first_name = db.Column(db.String(64), nullable=False)
    last_name = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(SQLAlchemyEnum(UserRole), nullable=False, default=UserRole.USER)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True, onupdate=datetime.utcnow)
    active = db.Column(db.Boolean, nullable=False, default=True)
    reset_token = db.Column(db.String(32), unique=True, nullable=True)  # new field added for reset and forget password feature
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'
    
    ## added the password history checker model
class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
   
    

def init_db(app):
    with app.app_context():
        engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
        if not database_exists(engine.url):
            create_database(engine.url)
            print(f"Created database: {app.config['DB_NAME']}")
            db.create_all()
            print("Created database tables")
            return True
        return False