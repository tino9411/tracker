from flask import jsonify, request
from .models import User, Role
from .database import db
from .schemas import UserSchema, RoleSchema
from .utils import hash_password, check_password, generate_reset_link, send_email, check_user_role
from flask_jwt_extended import create_access_token, create_refresh_token, set_refresh_cookies, unset_jwt_cookies, get_jwt_identity, set_access_cookies
from sqlalchemy.exc import IntegrityError
from marshmallow import ValidationError
import uuid
import secrets
from datetime import datetime, timezone, timedelta


def create_user():
    """
    Create a new user and assign the default "user" role.

    - Validates the input data using Marshmallow.
    - Hashes the user's password.
    - Assigns the "user" role to the new user.
    - Saves the user in the database.

    Returns:
        JSON response containing the created user or an error message.
    """
    data = request.get_json()

    # Validate and deserialize input
    try:
        user_data = UserSchema().load(data)
    except ValidationError as err:
        return jsonify(err.messages), 400

    # Has the password after validation

    user_data['password'] = hash_password(data['password'])
    # Create a new User instance
    new_user = User(**user_data)

    try:
        # Query the "user" role from the database
        user_role = Role.query.filter_by(name='user').first()

        if not user_role:
            return jsonify({'error': 'Default user role not found'}), 500
        
        # Assign the "user" role to the new user
        new_user.roles.append(user_role)

        # Add thr new "user" role to the new user
        db.session.add(new_user)
        db.session.commit()

        # Serialize the user object using UserSchema
        user_json = UserSchema().dump(new_user)
        return jsonify(user_json), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({
            'error': 'Username or email already exists'
        }), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


def get_user(user_id):
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
    try:
        # Validate the user_id format (ensure it's a UUID)
        uuid_obj = uuid.UUID(user_id)

        # Query the database for the user
        user = User.query.get(uuid_obj)

        # Check if user exists
        if user:
            # Serialize the user data using Marshmallow
            user_json = UserSchema().dump(user)

            return jsonify(user_json), 200
        else:
            # Return a 404 error if the user is not found
            return jsonify({'error': 'User not found'}), 404
    except ValidationError as err:
        return jsonify({
            'error': 'Invalid user ID format', 'message': str(err)
        }), 400
    except Exception as e:
        return jsonify({
            'error': 'An unexpected error occured', 'message': str(e)
        }), 500


def update_user(user_id):
    """
    Update a user's information.

    - Validates the user ID format.
    - Validates and deserializes input data for partial updates.
    - Updates the user's information in the database.

    Args:
        user_id (str): The UUID of the user.

    Returns:
        JSON response containing the updated user data or an error message.
    """
    try:
        # Validate the UUID format
        uuid_obj = uuid.UUID(user_id)

        # Query the databse for the user
        user = User.query.get(uuid_obj)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Parse the request data
        data = request.get_json()

        # Validate and deserialize the incoming data using partial=true to allow partial update
        try:
            user_data = UserSchema().load(data, partial=True)
        except ValidationError as err:
            return jsonify({
                'error': 'Invalid data', 'messages': err.messages
            }), 400

        # Update the user object with the provided data
        for key, value in user_data.items():
            setattr(user, key, value)

        # Save the updated user to the database
        db.session.commit()

        # Serialize and return the updated user
        updated_user = UserSchema().dump(user)
        return jsonify(updated_user), 200

    except ValueError:
        return jsonify({'error': 'Invalid user ID format'}), 400
    except Exception as e:
        return jsonify({
            'error': 'An unexpecred error occured', 'message': str(e)
        }), 500


def delete_user(user_id):
    """
    Delete a user from the system.

    - Validates the user ID format.
    - Allows users to delete their own accounts.
    - Allows admins to delete other users' accounts.

    Args:
        user_id (str): The UUID of the user.

    Returns:
        JSON response indicating the success or failure of the deletion.
    """
    try:
        # Validate the UUID format
        uuid_obj = uuid.UUID(user_id)

        # Get the ID of the current user from the JWT token
        current_user_id = get_jwt_identity()

        # Query the databse for the user
        user = User.query.get(uuid_obj)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if the user is trying to delete thier own account
        if str(current_user_id) == user_id:
            # Allow the user to delete their own account
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'Your account has been deleted'}), 200
        
        # Check if the current user as the 'admin' role
        if not check_user_role('admin'):
            return jsonify({'message': 'You do not have permission to delete other users'}), 403

        # Delete the user if they are an admin
        db.session.delete(user)
        db.session.commit()

        return jsonify({
            'message': str("User has been deleted")
        }), 200

    except ValueError:
        # Handle invalid UUID format
        db.session.rollback()
        return jsonify({'error': 'Invalid user ID format'  }), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


def update_password(user_id):
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
    try:
        # Validate the UUID format
        uuid_obj = uuid.UUID(user_id)

        # Query the database for the user
        user = User.query.get(uuid_obj)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        # Extract current and new passwords from the request
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not current_password or not new_password:
            return jsonify({'error': 'Current and new passwords are required'}), 400

        if not check_password(user.password, current_password):
            return jsonify({
                'error': 'Incorrect current password'
            }), 400

        # Hash the new password
        hashed_new_password = hash_password(new_password)

        # Update the user's password in the database
        user.password = hashed_new_password
        db.session.commit()

        # TODO: Invalidate active session

        return jsonify({'message': 'Password updated successfully'}), 200

    except ValueError:
        # Handle invalid UUID format
        return jsonify({'error': 'Invalid user ID format'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


def reset_password():
    """
    Initiate the password reset process.

    - Validates the user's email.
    - Generates a reset token and sends it via email.

    Returns:
        JSON response indicating the success or failure of the reset request.
    """
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        user = User.query.filter_by(email=email).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Generate a reset token
        reset_token = secrets.token_urlsafe(32)
        token_expiry = datetime.now(timezone.utc) + timedelta(hours=1)  # Token is valid for one hour

        # Store the token and expiry in the database
        user.reset_token = reset_token
        user.token_expiry = token_expiry
        db.session.commit()

        # Generate reset link to send to user's email
        reset_link = generate_reset_link(user)
        email_sent = send_email(
            subject="Password Reset Request",
            recipients=[user.email],
            body=f"To reset your password, click the following link: {reset_link}\n\n"
                 f"If you did not request this, please ignore this email."
        )

        if not email_sent:
            return jsonify({'error': 'Failed to send email'}), 500

        return jsonify({
                'message': 'Password reset email sent'
            }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'error': str(e)
        }), 500


def reset_password_with_token():
    """
    Reset a user's password using a reset token.

    - Validates the reset token and new password.
    - Updates the user's password if the token is valid and not expired.

    Returns:
        JSON response indicating the success or failure of the password reset.
    """
    try:
        data = request.get_json()
        reset_token = data.get('token')
        new_password = data.get('new_password')

        if not reset_token or not new_password:
            return jsonify({
                'error': 'Token and new password are required'
            }), 400

        # Find the user by reset token
        user = User.query.filter_by(reset_token=reset_token).first()

        if not user:
            return jsonify({
                'error': 'Invalid or expired token'}), 400
        # Convert the naive token_expiry to a timezone-aware datetime
        if user.token_expiry.tzinfo is None:
            user.token_expiry = user.token_expiry.replace(tzinfo=timezone.utc)

        # Check if the token as expired
        current_time = datetime.now(timezone.utc)
        if current_time > user.token_expiry:
            return jsonify({
                'error': 'Token has expired'}), 400

        # Hash the password
        hashed_new_password = hash_password(new_password)
        # Update the user's password and clear the reset token
        user.password = hashed_new_password
        user.reset_token = None
        user.tokens_expiry = None
        db.session.commit()

        return jsonify({
            'message': 'Password has been reset successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


def login():
    """
    Authenticate a user and return JWT tokens.

    - Validates the user's email and password.
    - Reactivates the user if they were deactivated.
    - Generates and returns JWT access and refresh tokens.

    Returns:
        JSON response containing the JWT tokens or an error message.
    """
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({
                'error': 'Email and password are required'
            }), 400
        
        # Query the database for the user
        user = User.query.filter_by(email=email).first()

        if not user or not check_password(user.password, password):
            return jsonify({
                'error': 'Invalid email or password'
            }), 401
        
        if not user.isActive:
            # Automatically reactivate the user during login
            user.isActive = True
            db.session.commit()
        
        # Create JWT tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        # Return tokens
        response =  jsonify({
            'access_token': access_token
        })
        set_access_cookies(response, access_token)
        set_refresh_cookies(response, refresh_token)

        return response, 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

def logout():
    """
    Log out the current user.

    - Clears the JWT cookies.

    Returns:
        JSON response indicating the success of the logout.
    """
    response = jsonify({"msg": "Successfully logged out"})
    unset_jwt_cookies(response)  # Clear the refresh token cookie
    return response, 200
    

def refresh():
    """
    Refresh the JWT access token.

    - Generates a new access token using the current refresh token.

    Returns:
        JSON response containing the new access token.
    """
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify({'access_token': new_access_token}), 200


def deactivate(user_id):
    """
    Deactivate a user's account.

    - Validates the user ID format.
    - Deactivates the user's account if it is not already deactivated.

    Args:
        user_id (str): The UUID of the user.

    Returns:
        JSON response containing the updated user data or an error message.
    """
    try:
        # Validate the UUID format
        uuid_obj = uuid.UUID(user_id)

        # Query the database for the user
        user = User.query.get(uuid_obj)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not user.isActive:
            return jsonify({'error': 'User is already deactivated'}), 400
        
        # Deactivate the user
        user.isActive = False
        db.session.commit()

        # Serialize and return the updated user
        updated_user = UserSchema().dump(user)
        return jsonify(updated_user), 200

    except ValueError:
        # Handle invalid UUID format
        return jsonify({'error': 'Invalid user ID format'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    

def reactivate(user_id):
    """
    Reactivate a user's account.

    - Validates the user ID format.
    - Reactivates the user's account if it is not already activated.

    Args:
        user_id (str): The UUID of the user.

    Returns:
        JSON response containing the updated user data or an error message.
    """
    try:
        # Validate the UUID format
        uuid_obj = uuid.UUID(user_id)
        # Query the database for the user
        user = User.query.get(uuid_obj)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.isActive:
            return jsonify({'error': 'User is already activated'}), 400
        
        # Reactivate the user
        user.isActive = True
        db.session.commit()

        # Serialize and return the updated user
        updated_user = UserSchema().dump(user)
        return jsonify(updated_user), 200

    except ValueError:
        # Handle invalid UUID format
        return jsonify({'error': 'Invalid user ID format'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


def assign_role_to_user(user_id, role_id):
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
        # Validate the UUID format for user and role
        uuid_user = uuid.UUID(user_id)
        uuid_role = uuid.UUID(role_id)

        # Query the database for user and the role
        user = User.query.get(uuid_user)
        role = Role.query.get(uuid_role)

        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not role:
            return jsonify({'error': 'Role not found'}, 404)
        
        # Check if the role is already assigned
        if role in user.roles:
            return jsonify({'error': 'Role already assigned to user'}), 400
        
        # Assign the role to the user
        user.roles.append(role)
        db.session.commit()

        return jsonify({'message': f'Role {role.name} assigned to user {user.username} successfully'}), 200
    
    except ValueError:
        return jsonify({'error': 'Invalid ID format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def create_role():
    """
    Create a new role.

    - Validates and deserializes input data.
    - Saves the new role in the database.

    Returns:
        JSON response containing the created role or an error message.
    """
    data = request.get_json()
    try:
        role_data = RoleSchema().load(data)
        new_role = Role(**role_data)
        db.session.add(new_role)
        db.session.commit()
        # Serialize the user object using UserSchema
        role_json = RoleSchema().dump(new_role)
        return jsonify(role_json), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


def get_roles():
    """
    Retrieve all roles.

    - Queries the database for all roles.

    Returns:
        JSON response containing the list of roles.
    """
    roles = Role.query.all()
    roles_json = RoleSchema(many=True).dump(roles)
    return jsonify(roles_json), 200


def update_role(role_id):
    """
    Update a role's name.

    - Validates the role ID format.
    - Updates the role's name in the database.

    Args:
        role_id (str): The UUID of the role.

    Returns:
        JSON response containing the updated role data or an error message.
    """
    data = request.get_json()
    try:
        # Validate the role_id format (ensure it's a UUID)
        uuid_obj = uuid.UUID(role_id)

        # Query the database for the role
        role = Role.query.get(uuid_obj)

        if not role:
            return jsonify({'error': 'Role not found'}), 404
        role.name = data.get('name', role.name)
        db.session.commit()
        return RoleSchema().jsonify(role), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


def delete_role(role_id):
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
       # Validate the role_id format (ensure it's a UUID)
        uuid_obj = uuid.UUID(role_id)

        # Query the database for the role
        role = Role.query.get(uuid_obj)

        if not role:
            return jsonify({'error': 'Role not found'}), 404 
        
        # Delete the user
        db.session.delete(role)
        db.session.commit()

        return jsonify({
            'message': str("Role has been deleted")
        }), 200

    except ValueError:
        # Handle invalid UUID format
        db.session.rollback()
        return jsonify({'error': 'Invalid role ID format'  }), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500