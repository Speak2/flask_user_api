import click
from flask.cli import with_appcontext
from app.models import User, UserRole
from app import db, bcrypt

def create_admin_user(username, email, password, first_name, last_name):
    if User.query.filter_by(username=username).first():
        click.echo('Error: Username already exists')
        return False

    if User.query.filter_by(email=email).first():
        click.echo('Error: Email already exists')
        return False

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_admin = User(
        username=username,
        email=email,
        password=hashed_password,
        first_name=first_name,
        last_name=last_name,
        role=UserRole.ADMIN
    )

    db.session.add(new_admin)
    db.session.commit()

    click.echo(f'Admin user {username} created successfully!')
    return True

@click.command('create-admin')
@click.option('--username', prompt=True, help='The username of the admin user')
@click.option('--email', prompt=True, help='The email of the admin user')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='The password for the admin user')
@click.option('--first-name', prompt=True, help='The first name of the admin user')
@click.option('--last-name', prompt=True, help='The last name of the admin user')
@with_appcontext
def create_admin_command(username, email, password, first_name, last_name):
    """Create a new admin user."""
    create_admin_user(username, email, password, first_name, last_name)