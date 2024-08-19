from flask import Blueprint
from flask_jwt_extended import jwt_required
from .controllers import  create_user, get_user, update_user, delete_user, update_password, reset_password, logout, refresh, reset_password_with_token, login, deactivate, reactivate

user = Blueprint('user', __name__)


@user.route('/users', methods=['POST'])
def create_user_route():
    return create_user()


@user.route('/users/<user_id>', methods=['GET'])
@jwt_required()
def get_user_route(user_id):
    return get_user(user_id)


@user.route('/users/<user_id>', methods=['PATCH'])
@jwt_required()
def update_user_route(user_id):
    return update_user(user_id)


@user.route('/users/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_user_route(user_id):
    return delete_user(user_id)


@user.route('/users/<user_id>/password', methods=['PATCH'])
@jwt_required()
def update_password_route(user_id):
    return update_password(user_id)


@user.route('/reset-password', methods=['POST'])
def reset_password_route():
    return reset_password()


@user.route('/reset-password-with-token', methods=['PATCH'])
def reset_password_with_token_route():
    return reset_password_with_token()


@user.route('/login', methods=['POST'])
def login_route():
    return login()


@user.route('/logout', methods=['POST'])
@jwt_required()
def logout_route():
    return logout()


@user.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_route():
    return refresh()


@user.route('/users/<user_id>/deactivate', methods=['PATCH'])
@jwt_required()
def deactivate_route(user_id):
    return deactivate(user_id)


@user.route('/users/<user_id>/reactivate', methods=['PATCH'])
@jwt_required()
def reactivate_route(user_id):
    return reactivate(user_id)