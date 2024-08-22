from quart import request, jsonify
import logging
from marshmallow import ValidationError
from .models import Event
from .schemas import EventSchema
import uuid
from .database import async_session, get_db_session
from sqlalchemy.future import select
from datetime import datetime, timezone, timedelta
from typing import List, Optional

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)



# Consistent response function
def api_response(data=None, message=None, status_code=200):
    response = {
        'status': 'success' if status_code < 400 else 'error',
        'message': message,
        'data': data
    }
    return jsonify(response), status_code


# Error handling decorator
def handle_exceptions(func):
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except ValidationError as err:
            return api_response(message=err.messages, status_code=400)
        except Exception as e:
            logger.error(f"Unhandled exception in {func.__name__}: {str(e)}", exc_info=True)
            return api_response(message=str(e), status_code=500)
    return wrapper
    

async def get_entity_by_field(entity_value, filter_field, entity_class=Event):
    """
    General utility function to query an entity based on a specific field.

    :param entity_value: The value to search for (e.g., UUID, event type).
    :param filter_field: The field to filter by (e.g., 'id', 'aggregate_id', 'event_type').
    :param entity_class: The class of the entity to query (default is Event).
    :return: Tuple of (entity or entities, error_response)
    """
    if filter_field in ['id', 'aggregate_id']:
        try:
            uuid_obj = uuid.UUID(entity_value)
        except ValueError:
            return None, jsonify({'error': f'Invalid {filter_field} ID format'}), 400
        
        async with get_db_session() as session:
            result = await session.execute(select(entity_class).filter_by(**{filter_field: uuid_obj}))
            entities = result.scalars().all() if filter_field == 'aggregate_id' else result.scalars().first()
            return entities, None
    else:
       async with get_db_session() as session:
        # Query the 'event_type' from the database
        result = await session.execute(select(entity_class)).filter_by(**{filter_field: filter_field})
        entities = result.scalar().all()
        if not entities:
            return None, jsonify({'error': f'{entity_class.__name__}(s) not found'}), 404
        return entities, None
       

async def get_events():
    async with get_db_session() as session:
        result = await session.execute(select(Event))
        events = result.scalars().all()
    return events if events else []


async def ingest_event_from_kafka(event_data):
    """
    Ingest an event received from Kafka into the event store.

    :param event_data: The event data received from Kafka.
    """
    # Validate the Event Data using Marshmallow Schema
    try:
        event_data = EventSchema().load(event_data)
    except ValidationError as err:
        logger.error(f"Validation error: {err.messages}")
        return

    # Persist the Event in the Database
    new_event = Event(**event_data)
    async with get_db_session() as session:
        session.add(new_event)
        await session.commit()
    logger.info(f"Event {new_event.id} ingested successfully")


async def ingest_event_data(event_data):
    """
    Ingest event(s) into the event store.

    :param event_data: The event data or list of event data to ingest.
    """
    if isinstance(event_data, list):
        events = []
        for data in event_data:
            try:
                validated_data = EventSchema().load(data)
                events.append(Event(**validated_data))
            except ValidationError as err:
                logger.error(f"Validation error for event: {err.messages}")
                continue  # Skip the invalid event and proceed with others

        async with get_db_session() as session:
            session.add_all(events)
            await session.commit()
        logger.info(f"{len(events)} events ingested successfully")
    else:
        # Handle single event ingestion
        try:
            validated_data = EventSchema().load(event_data)
            new_event = Event(**validated_data)
            async with get_db_session() as session:
                session.add(new_event)
                await session.commit()
            logger.info(f"Event {new_event.id} ingested successfully")
        except ValidationError as err:
            logger.error(f"Validation error: {err.messages}")

async def query_by_timestamp(start_time_str: Optional[str] = None, 
                             end_time_str: Optional[str] = None) -> Optional[List[Event]]:

    ## Parse timestamps
    try: 
        start_time = datetime.fromisoformat(start_time_str) if start_time_str else None
        end_time = datetime.fromisoformat(end_time_str) if end_time_str else None
    except ValueError:
        return None
    
    # Validate that at least one timestamp is provided
    if not start_time and not end_time:
        return None
    
    # Query the database for events within the time range
    async with get_db_session() as session:
        query = select(Event)
        if start_time:
            query = query.filter(Event.date_created >= start_time)
        if end_time:
            query = query.filter(Event.date_created <= end_time)

        result = await session.execute(query)
        events = result.scalars().all()

    return events if events else None # Return NOne if no events found