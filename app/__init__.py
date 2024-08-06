from flask import Flask
from flask.json.provider import DefaultJSONProvider
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_smorest import Api
from config import Config
from app.models import db, init_db, UserRole,User
import click

migrate = Migrate()
jwt = JWTManager()
bcrypt = Bcrypt()
api = Api()

class EnumAwareJSONProvider(DefaultJSONProvider):
    def default(self, obj):
        if isinstance(obj, UserRole):
            return obj.value
        return super().default(obj)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.json = EnumAwareJSONProvider(app)
 
    db.init_app(app) 
    migrate.init_app(app, db)
    
    jwt.init_app(app)
    bcrypt.init_app(app)
    api.init_app(app)

    from app.routes import bp
    api.register_blueprint(bp)

    # Initialize database and check if it's a new creation
    is_new_db = init_db(app)

    # Register the CLI command
    from app.cli import create_admin_command, create_admin_user
    app.cli.add_command(create_admin_command)
 

    if is_new_db:
        with app.app_context():
            if User.query.filter_by(role=UserRole.ADMIN).first() is None:
                click.echo("No admin user found. Let's create one!")
                username = click.prompt("Enter admin username")
                email = click.prompt("Enter admin email")
                password = click.prompt("Enter admin password",hide_input=True,confirmation_prompt=True)
                first_name = click.prompt("Enter admin first name")
                last_name = click.prompt("Enter admin last name")
                create_admin_user(username, email, password, first_name, last_name)

    return app