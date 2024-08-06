# User Management API Documentation

This document provides an overview of the User Management API endpoints, their functionalities, required parameters, and expected responses.



## Register User

Create a new user account.

- **URL**: `/register`
- **Method**: `POST`


### Request Body

```json
{
  "username": "string",
  "first_name": "string",
  "last_name": "string",
  "password": "string",
  "email": "string",
  "role": "string" (optional, defaults to "USER")
}
```

### Success Response

- **Code**: 201 Created
- **Content**: `{"message": "User Created Successfully"}`

### Error Responses

- **Code**: 409 Conflict
- **Content**: `{"message": "Username already exists"}` or `{"message": "Email already exists"}`

- **Code**: 403 Forbidden
- **Content**: `{"message": "Admin token required to create admin user"}`

## Login

Authenticate a user and receive an access token.

- **URL**: `/login`
- **Method**: `POST`
- **Auth required**: No

### Request Body

```json
{
  "username": "string",
  "password": "string"
}
```

### Success Response

- **Code**: 200 OK
- **Content**: `{"message": "Login successful", "access_token": "string"}`

### Error Response

- **Code**: 401 Unauthorized
- **Content**: `{"message": "Invalid username or password"}`

## Get All Users

Retrieve a list of all users. Admin only.

- **URL**: `/users`
- **Method**: `GET`
- **Auth required**: Yes (Admin JWT)

### Success Response

- **Code**: 200 OK
- **Content**: Array of user objects

### Error Responses

- **Code**: 401 Unauthorized
- **Content**: `{"message": "Missing Authorization Header"}`

- **Code**: 422 Unprocessable Entity
- **Content**: `{"message": "Unauthorized token"}`

## Search User

Search for a user by email or username. Admin only.

- **URL**: `/user/<string:identifier>`
- **Method**: `GET`
- **Auth required**: Yes (Admin JWT)

### Success Response

- **Code**: 200 OK
- **Content**: User object

### Error Response

- **Code**: 404 Not Found
- **Content**: `{"message": "User not found"}`

## Update User

Update user information. Users can update their own info, admins can update any non-admin user.

- **URL**: `/users/<string:identifier>`
- **Method**: `PUT`
- **Auth required**: Yes (User JWT or Admin JWT)

### Request Body

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

- **Code**: 404 Not Found
- **Content**: `{"message": "User not found"}`

- **Code**: 403 Forbidden
- **Content**: `{"message": "You can only update your own information"}` or `{"message": "Admin cannot update another admin's information"}`

## Delete User

Delete a user account. Users can delete their own account, admins can delete any non-admin user.

- **URL**: `/users/<string:identifier>`
- **Method**: `DELETE`
- **Auth required**: Yes (User JWT or Admin JWT)

### Success Response

- **Code**: 200 OK
- **Content**: `{"message": "User deleted successfully"}`

### Error Responses

- **Code**: 404 Not Found
- **Content**: `{"message": "User not found"}`

- **Code**: 403 Forbidden
- **Content**: `{"message": "Unauthorized to delete this user"}`

- **Code**: 409 Conflict
- **Content**: `{"message": "Admin cannot delete another admin user"}`

## Forget Password

Generate a password reset token.

- **URL**: `/forget-password`
- **Method**: `POST`
- **Auth required**: No

### Request Body

```json
{
  "identifier": "string" (email or username)
}
```

### Success Response

- **Code**: 200 OK
- **Content**: `{"message": "Password reset link generated successfully", "reset_token": "string"}`

### Error Response

- **Code**: 404 Not Found
- **Content**: `{"message": "User not found"}`

## Reset Password

Reset a user's password using a reset token.

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

- **Code**: 404 Not Found
- **Content**: `{"message": "Invalid or expired token"}`

- **Code**: 400 Bad Request
- **Content**: `{"message": "Password has been used recently. Please choose a different password."}`

---

Note: All endpoints may return a 500 Internal Server Error if there's an unexpected issue with the server or database operations.
