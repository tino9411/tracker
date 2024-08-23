from sqlalchemy.future import select
from quart import jsonify, request
from .database import get_db_session, check_database_health
from .schemas import EventSchema
from .utils import ( api_response, handle_exceptions, get_entity_by_field, get_events, 
                    ingest_event_data, query_by_timestamp, apply_event_to_aggregate,
                    query_events_by_metadata, get_database_metrics,)
from quart_jwt_extended import (create_access_token, create_refresh_token, 
                                set_refresh_cookies, unset_jwt_cookies, 
                                get_jwt_identity, set_access_cookies)
from marshmallow import ValidationError
import uuid
from datetime import datetime, timezone, timedelta
from quart_rate_limiter import rate_limit
from .kafka import (check_kafka_health, get_kafka_metrics)
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
    success, errors = await ingest_event_data(event_data)
    if not success:
        return jsonify({"errors": errors}), 400
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
    return api_response(message="Bulk events ingested successfully",
                        status_code=201)


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
    events, error_reponse = await get_entity_by_field(
                    entity_value=aggregate_id,
                    filter_field='aggregate_id')
    if error_reponse:
        return error_reponse
    # Serialise the event data using Marshmallow
    events_data = EventSchema(many=True).dump(events)
    return api_response(data=events_data,
                        message='Events fetched successfully', status_code=200)


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
    return api_response(data=events_json,
                        message='Events fetched successfully', status_code=200)


@handle_exceptions
async def replay_events_by_aggregate(aggregate_id):
    """
    Replay all events for a given aggregate ID to rebuild its state.

    Args:
        aggregate_id (str): The UUID of the aggregate.

    Returns:
        JSON response indicating the success or failure of the replay.
    """
    # Fetch all events associated with the aggregate_id
    events, error_response = await get_entity_by_field(entity_value=aggregate_id, filter_field='aggregate_id')
    if error_response:
        return error_response

    if not events:
        return jsonify(
           {'error': 'No events found for the specified aggregate ID'}), 404

    # Initialize the aggregate state
    aggregate_state = {}

    # Replay the events to rebuild the state
    for event in events:
        # Apply each event to the aggregate state
        aggregate_state = apply_event_to_aggregate(event, aggregate_state)

    return api_response(data=aggregate_state,
                        message="Events replayed successfully",
                        status_code=200)


@handle_exceptions
async def replay_events_by_type(event_type):
    """
    Replay all events of a specific type to rebuild the state.

    Args:
        event_type (str): The type of events to replay.

    Returns:
        JSON response indicating the success or failure of the replay.
    """
    # Fetch all events associated with the event_type
    events, error_response = await get_entity_by_field(entity_value=event_type,
                                                       filter_field='event_type')
    if error_response:
        return error_response

    if not events:
        return jsonify(
            {'error': f'No events found for the event type: {event_type}'}
        ), 404

    # Replay the events to rebuild the state
    aggregate_state = {}
    for event in events:
        aggregate_state = apply_event_to_aggregate(event, aggregate_state)

    # The `aggregate_state` now represents the state after applying all relevant events
    return api_response(data=aggregate_state,
                        message="Events replayed successfully",
                        status_code=200)


@handle_exceptions
async def replay_events_by_timestamp():
    """
    Replay all events within a specific timestamp range to rebuild the state.

    Args:
        None (timestamps are provided via query parameters).

    Returns:
        JSON response indicating the success or failure of the replay.
    """
    # Extract start_time and end_time from query parameters
    start_time_str = request.args.get('start_time')
    end_time_str = request.args.get('end_time')

    # Fetch all events within the specified timestamp range
    events = await query_by_timestamp(start_time_str, end_time_str)
    if events is None:
        return jsonify(
            {'error': 'No events found for the specified timestamp range'}
        ), 404

    # Replay the events to rebuild the state
    aggregate_state = {}
    for event in events:
        aggregate_state = apply_event_to_aggregate(event, aggregate_state)

    # The `aggregate_state` now represents the state after applying all relevant events
    return api_response(data=aggregate_state,
                        message="Events replayed successfully",
                        status_code=200)


@handle_exceptions
async def get_event_metadata(event_id):
    """
    Retrieve the metadata for a specific event.

    Args:
        event_id (str): The UUID of the event.

    Returns:
        JSON response with the event metadata.
    """
    event, error_response = await get_entity_by_field(entity_value=event_id, filter_field='id')
    if error_response:
        return error_response
    # Extract metadata
    metadata = event.metadata
    if not metadata:
        return jsonify({'error': 'No metadata found for the specified event'}), 404

    return api_response(data=metadata, message='Event metadata fetched successfully', status_code=200)


@handle_exceptions
async def search_events_by_metadata():
    """
    Search for events that match specific metadata criteria.

    Args:
        None (criteria are provided via JSON body).

    Returns:
        JSON response with the list of matching events.
    """
    metadata_criteria = await request.get_json()
    if not metadata_criteria:
        return jsonify(
            {'error': 'No metadata criteria provided'}
        ), 400

    events = await query_events_by_metadata(metadata_criteria)
    if not events:
        return jsonify(
            {'error': 'No events found matching the metadata criteria'}
        ), 404

    events_json = EventSchema(many=True).dump(events)
    return api_response(data=events_json,
                        message='Events matching metadata fetched successfully',
                        status_code=200)


@handle_exceptions
async def check_health():
    """
    Check the health of the event service.

    Returns:
        JSON response indicating the health status.
    """
    db_healthy = await check_database_health()
    kafka_healthy = check_kafka_health()

    if db_healthy and kafka_healthy:
        return api_response(message='Service is healthy', status_code=200)
    else:
        return api_response(message='Service is unhealthy', status_code=500)


@handle_exceptions
async def get_metrics():
    """
    Retrieve metrics related to the event service.

    Returns:
        JSON response with the metrics.
    """
    db_metrics = await get_database_metrics()
    kafka_metrics = get_kafka_metrics()

    metrics = {
        "database": db_metrics,
        "kafka": kafka_metrics,
    }

    return api_response(data=metrics, message='Service metrics fetched successfully', status_code=200)


@handle_exceptions
async def purge_events():
    """
    Purge events from the event store based on criteria (e.g., timestamp).

    Returns:
        JSON response indicating the success or failure of the purge operation.
    """
    data = await request.get_json()
    start_time_str = data.get('start_time')
    end_time_str = data.get('end_time')

    if not start_time_str and not end_time_str:
        return jsonify({'error': 'No purge criteria provided'}), 400
    events_to_purge = await query_by_timestamp(start_time_str, end_time_str)

    if not events_to_purge:
        return jsonify({'error': 'No events found to purge'}), 404

    async with get_db_session() as session:
        for event in events_to_purge:
            await session.delete(event)
        await session.commit()

    return api_response(message="Events purged successfully", status_code=200)


@handle_exceptions
async def rebuild_read_models():
    """
    Rebuild the read models from the event store.

    Returns:
        JSON response indicating the success or failure of the rebuild operation.
    """
    events = await get_events()
    if not events:
        return jsonify(
            {'error': 'No events found to rebuild read models'}
        ), 404

    aggregate_state = {}
    for event in events:
        aggregate_state = apply_event_to_aggregate(event, aggregate_state)

    # The `aggregate_state` now represents the fully rebuilt state
    # In practice, you would update your read models with this state
    return api_response(message="Read models rebuilt successfully", status_code=200)

