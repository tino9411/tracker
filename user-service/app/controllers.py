from sqlalchemy.future import select
from quart import jsonify, request
from .models import User, Role, user_roles
from .database import get_db_session
from .schemas import UserSchema, RoleSchema
from .utils import (hash_password, check_password, generate_reset_link, 
                    send_email, check_user_role, get_user_by_uuid, api_response, handle_exceptions)
from quart_jwt_extended import create_access_token, create_refresh_token, set_refresh_cookies, unset_jwt_cookies, get_jwt_identity, set_access_cookies
from sqlalchemy.exc import IntegrityError
from marshmallow import ValidationError
import uuid
from datetime import datetime, timezone, timedelta
from quart_rate_limiter import rate_limit
import secrets as secrets
from .kafka import get_kafka_producer
import json


@handle_exceptions
async def create_user():
    """
    Create a new user and assign the default "user" role.

    - Validates the input data using Marshmallow.
    - Hashes the user's password.
    - Assigns the "user" role to the new user.
    - Saves the user in the database.

    Returns:
        JSON response containing the created user or an error message.
    """
    data = await request.get_json()
    # Validate and deserialize input
    try:
        user_data = UserSchema().load(data)
    except ValidationError as err:
        return jsonify(err.messages), 400
    # Hash the password after validation
    user_data['password'] = hash_password(data['password'])
    # Create a new User instance
    new_user = User(**user_data)
    async for session in get_db_session():
        # Query the "user" role from the database
        result = await session.execute(select(Role).filter_by(name='user'))
        user_role = result.scalars().first()
        if not user_role:
            return api_response(data=user_data, message='Default user role not found', status_code=500)
            # Assign the "user" role to the new user
        new_user.roles.append(user_role)
        # Add the new user to the session and commit the transaction
        session.add(new_user)
        await session.commit()
        # Serialize the user object using UserSchema
        user_json = UserSchema().dump(new_user)
        producer = get_kafka_producer()
        message = {
            "user_id": str(new_user.id),  # Include the user's ID
            "status": "user_created"
        } 
        producer.send('user-events', value=message)
        producer.flush()
        return api_response(data=user_json, message='User created successfully', status_code=201)


@handle_exceptions
async def get_user(user_id):
    """
    Retrieve a user by their ID.

    - Validates the user ID format.
    - Queries the database for the user.
    - Returns the user data if found, or a 404 error if not found.

    Args:
        user_id (str): The UUID of the user.

    Returns:
        JSON response containing the user data or an error message.
    """
    
    # Assuming get_user_by_uuid is now an async function
    user, error_response = await get_user_by_uuid(user_id)
    if error_response:
        return error_response
    # Serialize the user data using Marshmallow
    user_data = UserSchema().dump(user)

    producer = get_kafka_producer()
    message = {"user_id": user_id, "status": "user_fetched"}
    producer.send('user-events', value=message)
    producer.flush()
    return api_response(data=user_data, message='User retrieved successfully', status_code=201)
   

@handle_exceptions
async def update_user(user_id):
    user, error_response = await get_user_by_uuid(user_id)
    if error_response:
        return error_response
    data = await request.get_json()
    user_data = UserSchema().load(data, partial=True)
    for key, value in user_data.items():
        setattr(user, key, value)
    async for session in get_db_session():
        session.add(user)
        await session.commit()
        updated_user = UserSchema().dump(user)

        producer = get_kafka_producer()
        message = {"user_id": user_id, "status": "user_updated"}
        producer.send('user-events', value=message)
        producer.flush()
        
        return api_response(data=updated_user, message='User updated successfully')


@handle_exceptions
async def delete_user(user_id):
    """
    Delete a user from the system.

    This function handles the deletion of a user account. It performs the following steps:
    1. Retrieves the user based on the provided user_id.
    2. Checks if the current user has permission to delete the account (either their own or as an admin).
    3. Deletes the user from the database if permissions are valid.
    4. Sends a Kafka message to notify about the user deletion.

    Args:
        user_id (str): The UUID of the user to be deleted.

    Returns:
        dict: A JSON response containing:
            - message (str): A description of the action taken.
            - status_code (int): HTTP status code (200 for success, 403 for forbidden, 404 for not found).

    Raises:
        Exception: Any unexpected errors during the deletion process.

    Notes:
        - This function requires a valid JWT token in the request for authentication.
        - Only the user themselves or an admin can delete a user account.
        - If the user deletes their own account, their session will be invalidated.

    Example:
        Response for successful deletion:
        {
            "message": "User has been deleted",
            "status_code": 200
        }

        Response for unauthorized deletion attempt:
        {
            "message": "You do not have permission to delete other users",
            "status_code": 403
        }
    """
    user, error_response = await get_user_by_uuid(user_id)
    if error_response:
        return error_response
    
    current_user_id = get_jwt_identity()
    
    async for session in get_db_session():
        try:
            # Check if the current user is the user being deleted or an admin
            if str(current_user_id) != str(user_id):
                is_admin = await check_user_role(current_user_id, 'admin', session)
                if not is_admin:
                    return api_response(message='You do not have permission to delete other users', status_code=403)
            
            # First, remove all role associations
            await session.execute(user_roles.delete().where(user_roles.c.user_id == user.id))
            
            # Then, delete the user
            await session.delete(user)
            await session.commit()

            producer = get_kafka_producer()
            message = {"user_id": user_id, "status": "user_deleted"}
            producer.send('user-events', value=message)
            producer.flush()
            
            if str(current_user_id) == str(user_id):
                return api_response(message='Your account has been deleted')
            else:
                return api_response(message='User has been deleted')
    
        except Exception as e:
            await session.rollback()
            print(f"Unexpected error during user deletion: {str(e)}")
            return api_response(message='An unexpected error occurred', status_code=500)


@handle_exceptions
async def update_password(user_id):
    """
    Update a user's password.

    - Validates the user ID format.
    - Checks the current password.
    - Hashes the new password and updates it in the database.

    Args:
        user_id (str): The UUID of the user.

    Returns:
        JSON response indicating the success or failure of the password update.
    """
   
    user, error_response = await get_user_by_uuid(user_id)
    if error_response:
        return error_response

    data = await request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not current_password or not new_password:
        return api_response(message='Current and new passwords are required', status_code=400)

    if not check_password(user.password, current_password):
        return api_response(message='Incorrect current password', status_code=400)

    hashed_new_password = hash_password(new_password)

    async for session in get_db_session():
        user.password = hashed_new_password
        session.add(user)
        await session.commit()

        # TODO: Invalidate active session
    producer = get_kafka_producer()
    message = {"user_id": user_id, "status": "password_updated"}
    producer.send('user-events', value=message)
    producer.flush()
    return api_response(message='Password updated successfully')


@handle_exceptions
@rate_limit(3, timedelta(minutes=15))  # Limit to 3 requests per 15 minutes
async def reset_password():
    """
    Initiate the password reset process.

    - Validates the user's email.
    - Generates a reset token and sends it via email.

    Returns:
        JSON response indicating the success or failure of the reset request.
    """
    data = await request.get_json()
    email = data.get('email')

    if not email:
        return api_response(message='Email is required', status_code=400)

    async for session in get_db_session():
        result = await session.execute(select(User).filter_by(email=email))
        user = result.scalars().first()

        if not user:
            return api_response(message='User not found', status_code=404)

        reset_token = secrets.token_urlsafe(32)
        token_expiry = datetime.now(timezone.utc) + timedelta(hours=1)

        user.reset_token = reset_token
        user.token_expiry = token_expiry

        session.add(user)
        await session.commit()

        reset_link = await generate_reset_link(user)
        email_sent = await send_email(
            subject="Password Reset Request",
            recipients=[user.email],
            body=f"To reset your password, click the following link: {reset_link}\n\n"
                 f"If you did not request this, please ignore this email."
        )

        if not email_sent:
            return api_response(message='Failed to send email', status_code=500)

    return api_response(message='Password reset email sent')


@handle_exceptions
async def reset_password_with_token():
    """
    Reset a user's password using a reset token.

    - Validates the reset token and new password.
    - Updates the user's password if the token is valid and not expired.

    Returns:
        JSON response indicating the success or failure of the password reset.
    """
    data = await request.get_json()
    reset_token = data.get('token')
    new_password = data.get('new_password')

    if not reset_token or not new_password:
        return api_response(message='Token and new password are required', status_code=400)

    async for session in get_db_session():
        result = await session.execute(select(User).filter_by(reset_token=reset_token))
        user = result.scalars().first()

        if not user:
            return api_response(message='Invalid or expired token', status_code=400)

        if user.token_expiry.tzinfo is None:
            user.token_expiry = user.token_expiry.replace(tzinfo=timezone.utc)

        current_time = datetime.now(timezone.utc)
        if current_time > user.token_expiry:
            return api_response(message='Token has expired', status_code=400)

        hashed_new_password = hash_password(new_password)

        user.password = hashed_new_password
        user.reset_token = None
        user.token_expiry = None

        session.add(user)
        await session.commit()

    return api_response(message='Password has been reset successfully')


@handle_exceptions
@rate_limit(1, timedelta(seconds=10))  # Limit to 1 request per 10 seconds
async def login():
    """
    Authenticate a user and return JWT tokens.

    - Validates the user's email and password.
    - Reactivates the user if they were deactivated.
    - Generates and returns JWT access and refresh tokens.

    Returns:
        JSON response containing the JWT tokens or an error message.
    """
    data = await request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return api_response(message='Email and password are required', status_code=400)
    async for session in get_db_session():
        result = await session.execute(select(User).filter_by(email=email))
        user = result.scalars().first()
        if not user or not check_password(user.password, password):
            return api_response(message='Invalid email or password', status_code=401)
        if not user.isActive:
            user.isActive = True
            session.add(user)
            await session.commit()
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        response = api_response(data={'access_token': access_token}, message='Login successful')
        set_access_cookies(response[0], access_token)
        set_refresh_cookies(response[0], refresh_token)
        return response
    

@handle_exceptions
async def logout():
    """
    Log out the current user.

    - Clears the JWT cookies.

    Returns:
        JSON response indicating the success of the logout.
    """
    response = api_response(message="Successfully logged out")
    unset_jwt_cookies(response[0])
    return response
    

@handle_exceptions
async def refresh():
    """
    Refresh the JWT access token.

    - Generates a new access token using the current refresh token.

    Returns:
        JSON response containing the new access token.
    """
    current_user_id = await get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)
    return api_response(data={'access_token': new_access_token}, message='Token refreshed successfully')


@handle_exceptions
async def deactivate(user_id):
    """
    Deactivate a user's account.

    - Validates the user ID format.
    - Deactivates the user's account if it is not already deactivated.

    Args:
        user_id (str): The UUID of the user.

    Returns:
        JSON response containing the updated user data or an error message.
    """
    user, error_response = await get_user_by_uuid(user_id)
    if error_response:
        return error_response

    async for session in get_db_session():
        if not user.isActive:
            return api_response(message='User is already deactivated', status_code=400)
        
        user.isActive = False
        session.add(user)
        await session.commit()

        updated_user = UserSchema().dump(user)
    
    producer = get_kafka_producer()
    message = {"user_id": user_id, "status": "user_deactivated"}
    producer.send('user-events', value=message)
    producer.flush()

    return api_response(data=updated_user, message='User deactivated successfully')
    
    
@handle_exceptions
async def reactivate(user_id):
    """
    Reactivate a user's account.

    - Validates the user ID format.
    - Reactivates the user's account if it is not already activated.

    Args:
        user_id (str): The UUID of the user.

    Returns:
        JSON response containing the updated user data or an error message.
    """
    user, error_response = await get_user_by_uuid(user_id)
    if error_response:
        return error_response

    async for session in get_db_session():
        if user.isActive:
            return api_response(message='User is already activated', status_code=400)
        
        user.isActive = True
        session.add(user)
        await session.commit()

        updated_user = UserSchema().dump(user)

        producer = get_kafka_producer()
        message = {"user_id": user_id, "status": "user_reactivated"}
        producer.send('user-events', value=message)
        producer.flush()

        return api_response(data=updated_user, message='User reactivated successfully')


@handle_exceptions
async def assign_role_to_user(user_id, role_id):
    """
    Assign a role to a user.

    - Validates the UUID format for user and role.
    - Assigns the specified role to the user if not already assigned.

    Args:
        user_id (str): The UUID of the user.
        role_id (str): The UUID of the role.

    Returns:
        JSON response indicating the success or failure of the role assignment.
    """
    try:
        uuid_user = uuid.UUID(user_id)
        uuid_role = uuid.UUID(role_id)
    except ValueError:
        return api_response(message='Invalid ID format', status_code=400)

    async for session in get_db_session():
        user_result = await session.execute(select(User).filter_by(id=uuid_user))
        user = user_result.scalars().first()

        role_result = await session.execute(select(Role).filter_by(id=uuid_role))
        role = role_result.scalars().first()

        if not user:
            return api_response(message='User not found', status_code=404)
        
        if not role:
            return api_response(message='Role not found', status_code=404)
        
        if role in user.roles:
            return api_response(message='Role already assigned to user', status_code=400)
        
        user.roles.append(role)
        session.add(user)
        await session.commit()
        producer = get_kafka_producer()
        message = {
            "user_id": user_id,  # Include the user's ID
            "status": "role_assigned_to_user",
            "role_id": role_id
        } 
        producer.send('user-events', value=message)
        producer.flush()
        return api_response(message=f'Role {role.name} assigned to user {user.username} successfully')


@handle_exceptions
async def create_role():
    """
    Create a new role.

    - Validates and deserializes input data.
    - Saves the new role in the database.

    Returns:
        JSON response containing the created role or an error message.
    """
    data = await request.get_json()
    role_data = RoleSchema().load(data)
    new_role = Role(**role_data)

    async for session in get_db_session():
        session.add(new_role)
        await session.commit()
    
    role_json = RoleSchema().dump(new_role)
    return api_response(data=role_json, message='Role created successfully', status_code=201)


@handle_exceptions
async def get_roles():
    """
    Retrieve all roles.

    - Queries the database for all roles.

    Returns:
        JSON response containing the list of roles.
    """
    async for session in get_db_session():
        result = await session.execute(select(Role))
        roles = result.scalars().all()

    roles_json = RoleSchema(many=True).dump(roles)
    return api_response(data=roles_json, message='Roles retrieved successfully')


@handle_exceptions
async def update_role(role_id):
    """
    Update a role's name.

    - Validates the role ID format.
    - Updates the role's name in the database.

    Args:
        role_id (str): The UUID of the role.

    Returns:
        JSON response containing the updated role data or an error message.
    """
    data = await request.get_json()
    try:
        uuid_obj = uuid.UUID(role_id)
    except ValueError:
        return api_response(message='Invalid role ID format', status_code=400)

    async for session in get_db_session():
        result = await session.execute(select(Role).filter_by(id=uuid_obj))
        role = result.scalars().first()

        if not role:
            return api_response(message='Role not found', status_code=404)

        role.name = data.get('name', role.name)
        session.add(role)
        await session.commit()

        return api_response(data=RoleSchema().dump(role), message='Role updated successfully')


@handle_exceptions
async def delete_role(role_id):
    """
    Delete a role from the system.

    - Validates the role ID format.
    - Deletes the role from the database.

    Args:
        role_id (str): The UUID of the role.

    Returns:
        JSON response indicating the success or failure of the deletion.
    """
    try:
        uuid_obj = uuid.UUID(role_id)
    except ValueError:
        return api_response(message='Invalid role ID format', status_code=400)

    async for session in get_db_session():
        result = await session.execute(select(Role).filter_by(id=uuid_obj))
        role = result.scalars().first()

        if not role:
            return api_response(message='Role not found', status_code=404)
        
        await session.delete(role)
        await session.commit()

        return api_response(message='Role has been deleted successfully')