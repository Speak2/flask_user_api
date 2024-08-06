from marshmallow import Schema, fields, validate,ValidationError
from .models import UserRole

class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True, validate=validate.Length(min=3, max=64))
    first_name = fields.Str(required=True, validate=validate.Length(min=1, max=64))
    last_name = fields.Str(required=True, validate=validate.Length(min=1, max=64))
    password = fields.Str(required=True, validate=validate.Length(min=8, max=128), load_only=True)
    email = fields.Email(required=True)
    role = fields.Str(validate=validate.OneOf([ UserRole.USER,UserRole.ADMIN]))
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)
    active = fields.Boolean(dump_only=True)
    

class LoginSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)


class UserUpdateSchema(Schema):
    username = fields.Str(validate=validate.Length(min=3, max=64))
    first_name = fields.Str(validate=validate.Length(min=1, max=64))
    last_name = fields.Str(validate=validate.Length(min=1, max=64))
    email = fields.Email()
    role = fields.Str(validate=validate.OneOf([UserRole.USER.value, UserRole.ADMIN.value]))
    password = fields.Str(validate=validate.Length(min=8, max=128), load_only=True)

    # Ensure at least one field is provided
    def validate(self, data, **kwargs):
        if not data:
            raise ValidationError("At least one field must be provided for update.")
        return data
    
 
class ResetPasswordSchema(Schema):
    reset_link = fields.String(required=True)
    new_password = fields.String(required=True,validate=validate.Length(min=8))

 

