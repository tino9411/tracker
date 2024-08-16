from marshmallow import Schema, fields, validate


class UserSchema(Schema):
    id = fields.UUID(dump_only=True)  # UUID will be generated automatically, so it's read-only
    username = fields.String(required=True, validate=validate.Length(min=1, max=50))
    email = fields.String(required=True)
    password = fields.String(required=True, validate=validate.Length(min=8))
    first_name = fields.String(validate=validate.Length(max=50))
    last_name = fields.String(validate=validate.Length(max=50))
    date_created = fields.DateTime(dump_only=True)  # Read-only, auto generated
    last_login_time = fields.DateTime(dump_only=True)  # Read-only, will be updated on login
