# User Management API

This is a Flask-based User Management API that provides functionality for user registration, authentication, and management. It uses Flask-SMOREST for API documentation and Swagger UI integration.

## Features

- User registration
- User login with JWT authentication
- Password reset
- User management (for admin users)
- Swagger UI for API documentation and testing

## Technologies Used

- Flask
- Flask-SQLAlchemy
- Flask-Migrate
- Flask-JWT-Extended
- Flask-Bcrypt
- Flask-SMOREST
- PostgreSQL

## Setup and Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd user-management-api
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

4. Set up the PostgreSQL database and update the `SQLALCHEMY_DATABASE_URI` in `config.py` if necessary.

5. Set environment variables (optional):
   ```
   export SECRET_KEY=your_secret_key
   export JWT_SECRET_KEY=your_jwt_secret_key
   export DATABASE_URL=your_database_url
   ```

6. Initialize the database:
   ```
   flask db init
   flask db migrate
   flask db upgrade
   ```

7. Run the application:
   ```
   flask run
   ```

The API will be available at `http://localhost:5000`, and the Swagger UI will be accessible at `http://localhost:5000/swagger-ui`.

## API Endpoints

- `POST /register`: Register a new user
- `POST /login`: Authenticate a user and receive a JWT
- `GET /users`: Get all users (admin only)
- `PUT /users/<user_id>`: Update a user (admin only)
- `DELETE /users/<user_id>`: Delete a user (admin only)
- `POST /reset-password`: Reset a user's password

For detailed information about request/response formats and authentication requirements, please refer to the Swagger UI documentation.

## Authentication

This API uses JWT (JSON Web Tokens) for authentication. To access protected endpoints, include the JWT in the Authorization header of your requests:

```
Authorization: Bearer <your_jwt_token>
```

## Development

To run the application in development mode with debug enabled, use:

```
flask run --debug
```

## Testing

(Add information about running tests once you have implemented them)

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
