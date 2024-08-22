from sqlalchemy.future import select
from quart import jsonify, request
from .models import Event
from .database import get_db_session
from .schemas import EventSchema
from .utils import ( api_response, handle_exceptions, get_entity_by_field, get_events, ingest_event_data, query_by_timestamp)
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
    """
    Ingest a single event into the event store.

    - Expects a JSON payload containing the event data.
    - The event data is processed and stored in the event store.
    
    Returns:
        JSON response indicating the success of the ingestion process.
    """
    event_data = await request.get_json()
    await ingest_event_data(event_data)
    return api_response(message="Event ingested successfully", status_code=201)


@handle_exceptions
async def ingest_bulk_events():
    """
    Ingest multiple events into the event store in bulk.

    - Expects a JSON payload containing an array of event data.
    - The event data is processed and stored in the event store.
    
    Returns:
        JSON response indicating the success of the bulk ingestion process.
    """
    event_data = await request.get_json()
    await ingest_event_data(event_data)
    return api_response(message="Bulk events ingested successfully", status_code=201)


@handle_exceptions
async def get_events_by_aggregate(aggregate_id):
    """
    Retrieve all events associated with a specific aggregate ID.

    - Validates the provided aggregate ID.
    - Queries the event store for events related to the aggregate ID.
    
    Args:
        aggregate_id (str): The UUID of the aggregate.
    
    Returns:
        JSON response containing the events or an error message.
    """
    events, error_reponse = await get_entity_by_field(entity_value=aggregate_id, filter_field='aggregate_id')
    if error_reponse:
        return error_reponse
    # Serialise the event data using Marshmallow
    events_data = EventSchema(many=True).dump(events)
   
    return api_response(data=events_data, message='Events fetched successfully', status_code=200)


@handle_exceptions
async def get_events_by_type(event_type):
    """
    Retrieve all events of a specific event type.

    - Validates the provided event type.
    - Queries the event store for events of the given type.
    
    Args:
        event_type (str): The type of events to retrieve.
    
    Returns:
        JSON response containing the events or an error message.
    """

    events, error_reponse = await get_entity_by_field(entity_value=event_type, filter_field='event_type')
    if error_reponse:
        return error_reponse
    # Serialise the event data using Marshmallow
    events_json = EventSchema(many=True).dump(events)
    return api_response(data=events_json, message='Events fetched successfully', status_code=200)


@handle_exceptions
async def get_events_by_timestamp():
    """
    Retrieve all events that occurred within a specific timestamp range.

    - Expects query parameters for the start and end timestamps.
    - Queries the event store for events within the given time range.
    
    Returns:
        JSON response containing the events or an error message.
    """
    # Get query parameters
    start_time_str = request.args.get('start_time')
    end_time_str = request.args.get('end_time')

    events = await query_by_timestamp(start_time_str, end_time_str)

    if events is None:
        return jsonify({'error': 'No event found or invalid time range provided'}), 404
        
    # Serialise the events
    events_json = EventSchema(many=True).dump(events)
    return api_response(data=events_json, message='Events fetched successfully', status_code=200)



@handle_exceptions
async def get_all_events():
    """
    Retrieve all events from the event store.

    - Queries the event store for all events.
    
    Returns:
        JSON response containing all events or an error message.
    """
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