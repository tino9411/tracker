from quart import request, jsonify
from flask_mail import Message
from .mail import mail_instance
from .models import User, Role
from quart_jwt_extended import get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
import logging
import uuid
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from marshmallow import ValidationError
from .database import async_session

async def check_user_role(user_id, role_name, session):
    """
    Check if a user has a specific role.

    Args:
        user_id (str): The UUID of the user to check.
        role_name (str): The name of the role to check for.
        session (AsyncSession): The database session to use for queries.

    Returns:
        bool: True if the user has the role, False otherwise.
    """
    result = await session.execute(
        select(User).
        filter(User.id == user_id).
        filter(User.roles.any(Role.name == role_name))
    )
    user = result.scalars().first()
    return user is not None


def hash_password(password):
    """
    Hashes a plain text password using the PBKDF2 algorithm with SHA-256.

    This function takes a plain text password and returns a securely hashed version 
    of it, using the PBKDF2 algorithm with the SHA-256 hashing method. The resulting 
    hash can be safely stored in a database and used to verify the password later.

    Args:
        password (str): The plain text password to be hashed.

    Returns:
        str: The securely hashed password, which includes the hashing algorithm 
             used, the salt, and the hash itself.

    Example:
        Given the password "mysecretpassword", the function might return a string 
        like:
        "pbkdf2:sha256:260000$e9qNwHgM$91e7f3b9a8ff5020df64850de63f22fa4c2f8d35a46a9b57a61ff908df4f3b4b"
    """
    return generate_password_hash(password, method='pbkdf2:sha256')


def check_password(hashed_password, current_password):
    """
    Checks if the current_password matches the hashed_password.

    :param hashed_password: The hashed password stored in the database.
    :param current_password: The plain text password provided by the user.
    :return: True if the password matches, otherwise False.
    """
    return check_password_hash(hashed_password, current_password)


async def generate_reset_link(user):
    """
    Generates a password reset link for the given user.

    This function creates a full URL for the password reset process by dynamically 
    retrieving the base URL from the current request context and appending the 
    reset token as a query parameter.

    Args:
        user (User): The user object containing the reset token.

    Returns:
        str: A full URL string that the user can use to reset their password.
             The URL includes the reset token as a query parameter.

    Example:
        If the base URL is "http://localhost:5100" and the user's reset token is 
        "abc123", the generated link would look like:
        "http://localhost:5100/reset_password?token=abc123"
    """
    # Use request.host_url to dynamically get the base URL
    base_url = request.host_url.rstrip('/')
    return f"{base_url}/reset_password?token={user.reset_token}"


async def send_email(subject, recipients, body):
    """
    Sends an email using the Flask-Mail extension.

    :param  subject: Subject of the email:
    :param recipients: List of recipient email addresses
    :param body: The plain text body of the email
    """
    try:
        msg = Message(
            subject,
            recipients=recipients,
            body=body
        )
        await mail_instance.send(msg)
        logging.info(f"Email sent successfully to {recipients}")
        return True
    except Exception as e:
        # Log the exception or handle it as needed
        logging.error(f"Failed to send email: {e}")
        return False
    

async def get_user_by_uuid(user_id):
    """
    Validate UUID, query the user, and check if the user exists.
    
    :param user_id: The UUID of the user.
    :return: Tuple of (user, error_response)
    """
    try:
        uuid_obj = uuid.UUID(user_id)
    except ValueError:
        return None, jsonify({'error': 'Invalid user ID format'}), 400

    async with async_session() as session:
        result = await session.execute(select(User).filter_by(id=uuid_obj))
        user = result.scalars().first()

    if not user:
        return None, jsonify({'error': 'User not found'}), 404
    
    return user, None


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
            print(f"Unhandled exception in {func.__name__}: {str(e)}")
            return api_response(message='An unexpected error occurred', status_code=500)
    return wrapper