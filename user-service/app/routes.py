from flask import Blueprint, request, jsonify
from .models import User
from .database import db
from .schemas import UserSchema
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
from marshmallow import ValidationError
import uuid


user = Blueprint('user', __name__)


@user.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()

    # Validate and deserialize input
    try:
        user_data = UserSchema().load(data)
    except ValidationError as err:
        return jsonify(err.messages), 400

    # Has the password after validation

    user_data['password'] = generate_password_hash(data['password'], method='pbkdf2:sha256')
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


@user.route('/users/<user_id>', methods=['GET'])
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


@user.route('/users/<user_id>', methods=['PATCH'])
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


@user.route('/users/<user_id>', methods=['DELETE'])
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
        return jsonify(
            {
                'error': 'Invalid user ID format'  
            }), 400
        db.session.rollback()

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
