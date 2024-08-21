from quart import request, jsonify
import logging
from marshmallow import ValidationError
import logging

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