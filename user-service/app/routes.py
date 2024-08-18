from flask import Blueprint
from .controllers import create_user, get_user, update_user, delete_user, update_password, reset_password, reset_password_with_token

user = Blueprint('user', __name__)


@user.route('/users', methods=['POST'])
def create_user_route():
    return create_user()


@user.route('/users/<user_id>', methods=['GET'])
def get_user_route(user_id):
    return get_user(user_id)


@user.route('/users/<user_id>', methods=['PATCH'])
def update_user_route(user_id):
    return update_user(user_id)


@user.route('/users/<user_id>', methods=['DELETE'])
def delete_user_route(user_id):
    return delete_user(user_id)


@user.route('/users/<user_id>/password', methods=['PATCH'])
def update_password_route(user_id):
    return update_password(user_id)


@user.route('/reset-password', methods=['POST'])
def reset_password_route():
    return reset_password()


@user.route('/reset-password-with-token', methods=['PATCH'])
def reset_password_with_token_route():
    return reset_password_with_token()