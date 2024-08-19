from marshmallow import Schema, fields, validate, ValidationError
import re

def validate_password(password):
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long")
    if not re.search("[a-z]", password):
        raise ValidationError("Password must contain at least one lowercase letter")
    if not re.search("[A-Z]", password):
        raise ValidationError("Password must contain at least one uppercase letter")
    if not re.search("[0-9]", password):
        raise ValidationError("Password must contain at least one digit")
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValidationError("Password must contain at least one speicial character")
    if re.search("\s", password):
        raise ValidationError("Password must not contain spaces")


class UserSchema(Schema):
    id = fields.UUID(dump_only=True)  # UUID will be generated automatically, so it's read-only
    username = fields.String(required=True, validate=validate.Length(min=1, max=50))
    email = fields.Email(required=True, validate=validate.Email(error="Invalid email format."))
    password = fields.String(required=True, validate=validate.And(
        validate.Length(min=8),
        validate_password
    ))
    first_name = fields.String(validate=validate.Length(max=50))
    last_name = fields.String(validate=validate.Length(max=50))
    date_created = fields.DateTime(dump_only=True)  # Read-only, auto generated
    last_login_time = fields.DateTime(dump_only=True)  # Read-only, will be updated on login
    reset_token = fields.String(dump_only=True)
    token_expiry = fields.DateTime(dump_only=True)
    isActive = fields.Boolean(dump_only=True)

