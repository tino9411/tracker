from flask import Blueprint, request, jsonify
from .models import User
from .database import db
from .schemas import UserSchema
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
from marshmallow import ValidationError


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

    user_data['password'] = generate_password_hash(data['password'], method='sha256')
    # Create a new User instance
    new_user = User(**user_data)

    try:
        db.session.add(new_user)
        db.session.commit()
        return UserSchema().jsonify(new_user), 201  # Serialize and return the newly created user
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Username or email already exists'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
