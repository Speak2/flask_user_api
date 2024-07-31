# Flask User API

This is a RESTful API built with Flask, SQLAlchemy, and PostgreSQL for user management.

## Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd flask_user_api
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up the PostgreSQL database and update the `SQLALCHEMY_DATABASE_URI` in `config.py` with your database credentials.
   ```python
   'postgresql://username:password@localhost/dbname'
   ```

5. Initialize the database:
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

6. Set the FLASK_APP environment variable:
   ```bash
    export FLASK_APP=run.py  # on linux or mac os
    set FLASK_APP=run.py     # on windows 
   ```
7. Run the application:
   ```bash
   python run.py  # without export path
   flask run      # for export path
   ```

## API Documentation

### Register a new user
- URL: `/register`
- Method: POST
- Body: 
  ```json
  {
    "username": "string",
    "first_name": "string",
    "last_name": "string",
    "password": "string",
    "email": "string"
    // role is set to user by default
    // "role"="ADMIN" to specifically set to ADMIN ***strictly uppercase***
    I need to check this part again
  }
  ```

### Login
- URL: `/login`
- Method: POST
- Body:
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```

### Get all users (Admin only)
- URL: `/users`
- Method: GET
- Headers: 
  - Authorization: Bearer <access_token>

### Update a user (Admin only)
- URL: `/users/<user_id>`
- Method: PUT
- Headers:
  - Authorization: Bearer <access_token>
- Body:
  ```json
  {
    "username": "string",
    "first_name":"string",
    "last_name": "string",
    "email": "string",
    "active": boolean,     
    "password": "string",
    "role":"enum"     // strictly follow 'Admin' or 'User' (case sensitive)
  }
  ```

### Delete a user (Admin only)
- URL: `/users/<user_id>`
- Method: DELETE
- Headers:
  - Authorization: Bearer <access_token>

### Reset password
- URL: `/reset-password`
- Method: POST
- Body:
  ```json
  {
    "email": "string",
    "new_password": "string"
  }
  ```

## Note
This is a basic implementation. In a production environment, you would need to add more security measures, error handling, and possibly email functionality for features like password reset.
