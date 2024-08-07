# Flask User API

This is a RESTful API built with Flask, SQLAlchemy, and PostgreSQL for user management. This is a Flask-based User Management API that provides functionality for user registration, authentication, and management. It uses Flask-SMOREST for API documentation and Swagger UI integration.

## Features

- ADMIN user registration upon first-time running the application
- Manual admin user registration using CLI command
- User registration for both admin user (existing admin JWT required) and regular user
- User login (provides JWT token)
- Search users (admin only, using JWT token)
- Search for specific users (admin only)
- Update users
- Delete users
- Forgot password
- Reset password
- Password history of the last 5 passwords used
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

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Speak2/flask_user_api
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

4. Set up the PostgreSQL database and update the database credentials in `config.py` with your database credentials for config file reference use the `config-sample.txt` file. copy paste the config-sample.txt file into config.py and use your own credentials. note: kindly use a new database it will automatically generate the database and tables
   ```python
   # Database configuration
    DB_HOST = os.environ.get('DB_HOST') or 'localhost'
    DB_USER = os.environ.get('DB_USER') or 'database-username'
    DB_PASSWORD = os.environ.get('DB_PASSWORD') or 'user-password'
    DB_NAME = os.environ.get('DB_NAME') or 'database-name'
   ```

5. Set the FLASK_APP environment variable:
   ```bash
    export FLASK_APP=run.py  # on linux or mac os
    set FLASK_APP=run.py     # on windows 
   ```
6. Run the application:
   ```bash
   python run.py  # without export path
   flask run      # for export path
   ```
7. Upon running the application, if no database is found, the database and tables are created, and the first admin user is registered by default.
8. Admin users can be added manually later using the CLI command:
   ```bash
   flask create-admin
   ```
9. Admin users can also be created via the registration API using another admin's JWT and explicitly setting the role to "ADMIN".
10. The Swagger UI implementation can be accessed at the following link: 
http://127.0.0.1:5000/swagger-ui

## API Endpoints

- `POST /register`: Register a new user
- `POST /login`: Authenticate a user and receive a JWT
- `GET /users`: Get all users (admin only)
- `GET /users`: Get specific users by their email or username (admin only)
- `PUT /users/<user_id>`: Update a user
- `DELETE /users/<user_id>`: Delete a user 
- `POST /forget-password`: Generates reset password link
- `POST /reset-password`: Reset a user's password

For detailed information about request/response formats and authentication requirements, please refer to the Swagger UI documentation.

## Authentication

This API uses JWT (JSON Web Tokens) for authentication. To access protected endpoints, include the JWT in the Authorization header of your requests:

```
Authorization: Bearer <your_jwt_token>
```

## API Documentation

This API endpoint allows user creation without a JWT. Admins can create new admin users by setting the role to "ADMIN," requiring an existing admin JWT. Usernames and emails must be unique, with usernames having a minimum length of 3 characters and passwords at least 8 characters long.

## Table of Contents

1. [Register User](#register-user)
2. [Login](#login)
3. [Get All Users](#get-all-users)
4. [Search User](#search-user)
5. [Update User](#update-user)
6. [Delete User](#delete-user)
7. [Forget Password](#forget-password)
8. [Reset Password](#reset-password)

### Register a new user
- URL: `/register`
- Method: POST
- Auth required: No ( JWT required for admin user creation )
- Body: 

  ```json
  {
    "username": "string",
    "first_name": "string",
    "last_name": "string",
    "password": "string",
    "email": "string",
    "role": "string" (optional, defaults to "USER" or can set to "ADMIN")
  }
  ```

### Success Response

- **Code**: 201 Created
- **Content**: `{"message": "User Created Successfully"}`
  
  
### Error Responses

1. **Code**: 401 Error: UNAUTHORIZED
- **Content**: `{"message": "Token has expired"}`

  ```json
  { "msg": "Token has expired"}
  ```

2. **Code**: 409 Conflict
- **Content**: `{"message": "Username already exists"}` or `{"message": "Email already exists"}`

  ```json
  {
    "code": 409,
    "message": "Username already exists",
    "status": "Conflict"
  }
  ```
3. **Code**: 403 Forbidden
- **Content**: `{"message": "Admin token required to create admin user"}`

  ```json
  {
    "code": 403,
    "message": "Admin token required to create admin user",
    "status": "Forbidden"
  }
  ```
4. **Code**: 422 Error: UNPROCESSABLE ENTITY
  - This error response indicates that some required data is missing.
5. **Code**: 400 Error: BAD REQUEST
  - This error is due to an invalid JSON body.
  - **Content**: `{"message": "Invalid JSON body."}`

    ```json
    {
      "code": 400,
      "errors": {
        "json": [ 
          "Invalid JSON body."
        ]
      },
      "status": "Bad Request"
    }
    ```

### Login

This endpoint issues a JWT token to the user upon successful login.

- URL: `/login`
- Method: POST
- Auth required: No
- Body:

  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
### Success Response

- **Code**: 200 OK
- **Content**: `{"message": "Login successful", "access_token": "string"}`

  ```json
  {
    "message": "Login successful", 
    "access_token": "string"
  }
  ```
### Error Response

1. **Code**: 401 Unauthorized
- **Content**: `{"message": "Invalid username or password"}`

  ```json
  {
    "code": 401,
    "message": "Invalid username or password",
    "status": "Unauthorized"
  }
  ```
2. **Code**: 400 Bad Request
- **Content**: `{"message": "Invalid JSON body."}`

  ```json
  {
    "code": 400,
    "errors": {
      "json": [ 
        "Invalid JSON body."
      ]
    },
    "status": "Bad Request"
  }
  ```

## Get All Users

Retrieve a list of all users. Admin only.

- **URL**: `/users`
- **Method**: `GET`
- **Auth required**: Yes (Admin JWT)

### Success Response

- **Code**: 200 OK
- **Content**: Array of user objects
  ```json
  [
    {
      "id": 0,
      "username": "string",
      "first_name": "string",
      "last_name": "string",
      "email": "user@example.com",
      "role": "USER",
      "created_at": "2024-08-05T08:25:29.950Z",
      "updated_at": "2024-08-05T08:25:29.950Z",
      "active": true
    }
  ]
  ```

### Error Responses

- **Code**: 401 Unauthorized
- when the authorization header is missing or hit with expired token
- **Content**: `{"message": "Missing Authorization Header"}`
  ```json
  {
    "code": 401,
    "message": "Missing Authorization Header",
    "status": "Conflict"
  }
  ```
- **Code**: 403 Error: FORBIDDEN
- when the api is hit with the user role jwt
- **Content**: `{"message": "Admin access required"}`

  ```json
  {
    "code": 403,
    "message": "Admin access required",
    "status": "Forbidden"
  }
  ```

- **Code**: 422 Unprocessable Entity
- when the jwt token does not maching any real jwt token
- **Content**: `{"message": "Signature verification failed"}`

  ```json
  { "message": "Signature verification failed" }
  ```


## Search User

Search for a user by email or username. Admin only.

- **URL**: `/user/<string:identifier>`
- **Method**: `GET`
- **Auth required**: Yes (Admin JWT)

### Success Response

- **Code**: 200 OK
- **Content**: User object

  ```json
  {
    "id": 0,
    "username": "string",
    "first_name": "string",
    "last_name": "string",
    "email": "user@example.com",
    "role": "USER",
    "created_at": "2024-08-05T08:25:29.950Z",
    "updated_at": "2024-08-05T08:25:29.950Z",
    "active": true
  }
  ```

### Error Response

- **Code**: 401 UNAUTHORIZED
- when hitting the api without any token or expired token
- **Content**: `{"message": "Missing Authorization Header"}`

  ```json
  { "msg": "Missing Authorization Header" }
  ```

- **Code**: 403 FORBIDDEN
- when hitting the api with user jwt token
- **Content**: `{"message": "Admin access required"}`

  ```json
  {
    "code": 403,
    "message": "Admin access required",
    "status": "Forbidden"
  }
  ```

- **Code**: 404 Not Found
- **Content**: `{"message": "User not found"}`

  ```json
  {
    "code": 404,
    "message": "User not found",
    "status": "Conflict"
  }
  ```
- **Code**: 422 UNPROCESSABLE ENTITY
- **Content**: `{"message": "Signature verification failed"}`

  ```json
  {"message": "Signature verification failed"}
  ```

## Update User

Users can update their own information, while admins can update any non-admin user's information. Any or all of the following fields can be modified.Users can update their own information using their own JWT, while admins can update any user's information using an admin JWT.

- **URL**: `/users/<string:identifier>`
- **Method**: `PUT`
- **Auth required**: Yes (User JWT or Admin JWT)

- Request Body

  ```json
  {
    "username": "string" (optional),
    "first_name": "string" (optional),
    "last_name": "string" (optional),
    "email": "string" (optional),
    "role": "string" (optional, admin only)
  }
  ```

### Success Response

- **Code**: 200 OK
- **Content**: Updated user object

### Error Responses

- **Code**: 401 UNAUTHORIZED
- when hitting the api without any token or expired token
- **Content**: `{"message": "Missing Authorization Header"}` or `{"message": "expired token"}`

  ```json
  { "msg": "Missing Authorization Header" }
  ```

- **Code**: 403 Forbidden
- **Content**:  or `{"message": "Admin cannot update another admin's information"}`

  ```json
  {
    "code": 403,
    "message": "You can only update your own information",
    "status": "Forbidden"
  }
  ```

- **Code**: 404 Not Found
- **Content**: `{"message": "User not found"}`

  ```json
  {
    "code": 404,
    "message": "User not found",
    "status": "Not Found"
  }
  ```

- **Code**: 406 Forbidden
- User cannot update another users information
- **Content**: `{"message": "You can only update your own information"}`

  ```json
  {
    "code": 406,
    "message": "You can only update your own information",
    "status": "Forbidden"
  }

- **Code**: 409 CONFLICT
- when updating the user information with existing username or email
- **Content**: `{"message": "Username already exists"}` or `{"message": "Email already exists"}`

  ```json
  {
    "code": 409,
    "message": "Username already exists",
    "status": "Conflict"
  }
  ```

## Delete User

Users can delete their own account using their own JWT, while admins can delete any non-admin user, including their own account, using their admin JWT. An admin account cannot delete another admin account. To delete a user, an identifier is required, which can be either the user ID, username, or email.

- **URL**: `/users/<string:identifier>`
- **Method**: `DELETE`
- **Auth required**: Yes (User JWT or Admin JWT)

### Success Response

- **Code**: 200 OK
- **Content**: `{"message": "User deleted successfully"}`

  ```json
  { "message": "User deleted successfully" }
  ```

### Error Responses

- **Code**: 401 UNAUTHORIZED
- **Content**: `{"message": "Invalid token"}` or `{"message": "token has expired"}`

  ```json
  {
    "code": 401,
    "message": "Invalid token",
    "status": "Unauthorized"
  }
  ```

- **Code**: 404 Not Found
- **Content**: `{"message": "User not found"}`

  ```json
  {
    "code": 404,
    "message": "User not found",
    "status": "Not Found"
  }
  ```

- **Code**: 403 Forbidden
- **Content**: `{"message": "Unauthorized to delete this user"}`

  ```json
  {
    "code": 403,
    "message": "Unauthorized to delete this user",
    "status": "Not Found"
  }
  ```

- **Code**: 409 Conflict
- **Content**: `{"message": "Admin cannot delete another admin user"}`

  ```json
  {
    "code": 409,
    "message": "Admin cannot delete another admin user",
    "status": "Not Found"
  }
  ```

## Forget Password

Generate a password reset token.

- **URL**: `/forget-password/<string:identifier>`
- **Method**: `POST`
- **Auth required**: No

 

### Success Response

- **Code**: 200 OK
- **Content**: `{"message": "Password reset link generated successfully", "reset_token": "string"}`

  ```json
  {
    "message": "Password reset link generated successfully",
    "reset_token": "string"
  }
  ```


### Error Response

- **Code**: 404 Not Found
- **Content**: `{"message": "Invalid or expired token"}`

  ```json
  {
    "code": 404,
    "message": "Invalid or expired token",
    "status": "Not Found"
  }
  ```

- **Code**: 405 Not Found
- **Content**: `{"message": "User not found"}`

  ```json
  {
    "code": 405,
    "message": "User not found",
    "status": "Not Found"
  }
  ```

- **Code**: 500 Not Found
- **Content**: `{"message": "An error occurred while generating the reset token."}`

  ```json
  {
    "code": 500,
    "message": "An error occurred while generating the reset token.",
    "status": "Error"
  }
  ```

## Reset Password

Reset a user's password using a reset link.
It checks the new password with the last 5 passwords used(excluding the first password to set up the account).User cannot change the password to last 5 password used.

- **URL**: `/reset-password`
- **Method**: `POST`
- **Auth required**: No

### Request Body

```json
{
  "token": "string",
  "new_password": "string"
}
```

### Success Response

- **Code**: 200 OK
- **Content**: `{"message": "Password reset successfully"}`

### Error Responses


- **Code**: 400 Bad Request
- **Content**: `{"message": "Invalid link."}`


- **Code**: 401 Not Found
- **Content**: `{"message": "Password must be at least 8 characters long."}`

```json
{ "message": "Password must be at least 8 characters long." }
```

- **Code**: 402 Bad Request
- **Content**: `{"message": "Password has been used recently. Please choose a different password."}`

```json
{ "message": "Password has been used recently. Please choose a different password." }
```

- **Code**: 404 Not Found
- **Content**: `{"message": "User not found"}`

```json
{
  "code": 404,
  "message": "User not found",
  "status": "Not Found"
}
```


- **Code**: 405 Not Found
- **Content**: `{"message": "Invalid or expired token"}`

```json
{
  "code": 405,
  "message": "Invalid or expired token",
  "status": "Not Found"
}
```


Note: All endpoints may return a 500 Internal Server Error if there's an unexpected issue with the server or database operations.


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


## Note
This is a basic implementation. In a production environment, you would need to add more security measures, error handling, and possibly email functionality for features like password reset.
