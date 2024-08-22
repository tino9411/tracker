from quart import Blueprint
from quart_jwt_extended import jwt_required, jwt_refresh_token_required
from .controllers import (ingest_event, ingest_bulk_events, get_events_by_aggregate,
                          get_events_by_type, get_events_by_timestamp, get_all_events,
                          replay_events_by_aggregate, replay_events_by_type, replay_events_by_timestamp,
                          get_event_metadata, search_events_by_metadata, check_health, get_metrics, 
                          purge_events, rebuild_read_models)


event = Blueprint('event', __name__)

@event.route('/events', methods=['POST'])
@jwt_required
async def ingest_event_route():
    return await ingest_event()


@event.route('/events/bulk', methods=['POST'])
@jwt_required
async def ingest_bulk_events_route():
    return await ingest_bulk_events()


@event.route('/events/aggregate/<aggregate_id>', methods=['GET'])
@jwt_required
async def get_events_by_aggregate_route(aggregate_id):
    return await get_events_by_aggregate(aggregate_id)


@event.route('/events/type/<event_type>', methods=['GET'])
@jwt_required
async def get_events_by_type_route(event_type):
    return await get_events_by_type(event_type)


@event.route('/events/timestamp', methods=['GET'])
@jwt_required
async def get_events_by_timestamp_route():
    return await get_events_by_timestamp()


@event.route('/events', methods=['GET'])
@jwt_required
async def get_all_events_route():
    return await get_all_events()


@event.route('/events/replay/aggregate/<aggregate_id>', methods=['POST'])
@jwt_required
async def replay_events_by_aggregate_route(aggregate_id):
    return await replay_events_by_aggregate(aggregate_id)


@event.route('/events/replay/type/<event_type>', methods=['POST'])
@jwt_required
async def replay_events_by_type_route(event_type):
    return await replay_events_by_type(event_type)



@event.route('/events/replay/timestamp', methods=['POST'])
@jwt_required
async def replay_events_by_timestamp_route():
    return await replay_events_by_timestamp()


@event.route('/events/<event_id>/metadata', methods=['GET'])
@jwt_required
async def get_event_metadata_route(event_id):
    return await get_event_metadata(event_id)


@event.route('/events/metadata/search', methods=['GET'])
@jwt_required
async def search_events_by_metadata_route():
    return await search_events_by_metadata()


@event.route('/events/health', methods=['GET'])
async def check_health_route():
    return await check_health()


@event.route('/events/metrics', methods=['GET'])
@jwt_required
async def get_metrics_route():
    return await get_metrics()


@event.route('/events/purge', methods=['DELETE'])
@jwt_required
async def purge_events_route():
    return await purge_events()


@event.route('/read-models/rebuild', methods=['POST'])
@jwt_required
async def rebuild_read_models_route():
    return await rebuild_read_models()