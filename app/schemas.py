from marshmallow import Schema, fields, validates, ValidationError, validate
from .models import UserRole

class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True, validate=validate.Length(min=3, max=64))
    first_name = fields.Str(required=True, validate=validate.Length(min=1, max=64))
    last_name = fields.Str(required=True, validate=validate.Length(min=1, max=64))
    email = fields.Email(required=True)
    password = fields.Str(required=True, load_only=True, validate=validate.Length(min=8))
    role = fields.Str(validate=validate.OneOf([role.name for role in UserRole]))
    active = fields.Bool(dump_only=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)

class LoginSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)

class PasswordResetSchema(Schema):
    email = fields.Email(required=True)
    new_password = fields.Str(required=True)

