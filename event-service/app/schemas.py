from marshmallow import Schema, fields, validate, ValidationError

class EventSchema(Schema):
    id = fields.UUID(dump_only=True)
    event_type = fields.String(required=True, validate=validate.Length(min=1, max=100))
    aggregate_id = fields.UUID(required=True)
    aggregate_type = fields.String(required=True, validate=validate.Length(min=1, max=100))
    payload = fields.Dict(required=True)
    date_created = fields.DateTime(required=True)
    event_metadata = fields.Dict()