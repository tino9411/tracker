from flask import jsonify, request
from .models import User
from .database import db
from .schemas import UserSchema
from .utils import hash_password, check_password, generate_reset_link, send_email
from sqlalchemy.exc import IntegrityError
from marshmallow import ValidationError
import uuid
import secrets
from datetime import datetime, timezone, timedelta


def create_user():
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
    try:
        # Validate the UUID format
        uuid_obj = uuid.UUID(user_id)

        # Query the databse for the user
        user = User.query.get(uuid_obj)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Delete the user
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
