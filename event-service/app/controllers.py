from sqlalchemy.future import select
from quart import jsonify, request
from .models import Event
from .database import get_db_session
from .schemas import EventSchema
from .utils import ( api_response, handle_exceptions, get_entity_by_field, get_events, ingest_event_data)
from quart_jwt_extended import (create_access_token, create_refresh_token, 
                                set_refresh_cookies, unset_jwt_cookies, 
                                get_jwt_identity, set_access_cookies)
from marshmallow import ValidationError
import uuid
from datetime import datetime, timezone, timedelta
from quart_rate_limiter import rate_limit
from .kafka import (send_kafka_message, start_kafka_producer, 
                    stop_kafka_producer)
import logging


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@handle_exceptions
async def ingest_event():
    event_data = await request.get_json()
    await ingest_event_data(event_data)
    return api_response(message="Event ingested successfully", status_code=201)


@handle_exceptions
async def ingest_bulk_events():
    event_data = await request.get_json()
    await ingest_event_data(event_data)
    return api_response(message="Bulk events ingested successfully", status_code=201)


@handle_exceptions
async def get_events_by_aggregate(aggregate_id):
    events, error_reponse = await get_entity_by_field(entity_value=aggregate_id, filter_field='aggregate_id')
    if error_reponse:
        return error_reponse
    # Serialise the event data using Marshmallow
    events_data = EventSchema(many=True).dump(events)
   
    return api_response(data=events_data, message='Events fetched successfully', status_code=200)


@handle_exceptions
async def get_events_by_type(event_type):

    events, error_reponse = await get_entity_by_field(entity_value=event_type, filter_field='event_type')
    if error_reponse:
        return error_reponse
    # Serialise the event data using Marshmallow
    events_json = EventSchema(many=True).dump(events)
    return api_response(data=events_json, message='Events fetched successfully', status_code=200)

@handle_exceptions
async def get_events_by_timestamp():
    pass


@handle_exceptions
async def get_all_events():
    events = await get_events()
    if not events:
            return jsonify({'error': 'No events found'}), 404
    events_json = EventSchema(many=True).dump(events)
    return api_response(data=events_json, message='Events fetched successfully', status_code=200)


@handle_exceptions
async def replay_events_by_aggregate(aggregate_id):
    pass


@handle_exceptions
async def replay_events_by_type(event_type):
    pass



@handle_exceptions
async def replay_events_by_timestamp():
    pass


@handle_exceptions
async def get_event_metadata(event_id):
    pass


@handle_exceptions
async def search_events_by_metadata():
    pass


@handle_exceptions
async def check_health():
    pass

@handle_exceptions
async def get_metrics():
    pass


@handle_exceptions
async def purge_events():
    pass

@handle_exceptions
async def rebuild_read_models():
    pass