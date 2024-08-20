from quart import Blueprint
from quart_jwt_extended import jwt_required, jwt_refresh_token_required
from .controllers import (
    create_user, get_user, update_user, delete_user, update_password,
    reset_password, logout, refresh, reset_password_with_token,
    login, deactivate, reactivate, create_role, get_roles,
    update_role, delete_role, assign_role_to_user
)

user = Blueprint('user', __name__)


@user.route('/users', methods=['POST'])
async def create_user_route():
    return await create_user()

@user.route('/users/<user_id>', methods=['GET'])
@jwt_required
async def get_user_route(user_id):
    return await get_user(user_id)

@user.route('/users/<user_id>', methods=['PATCH'])
@jwt_required
async def update_user_route(user_id):
    return await update_user(user_id)

@user.route('/users/<user_id>', methods=['DELETE'])
@jwt_required
async def delete_user_route(user_id):
    return await delete_user(user_id)

@user.route('/users/<user_id>/password', methods=['PATCH'])
@jwt_required
async def update_password_route(user_id):
    return await update_password(user_id)

@user.route('/reset-password', methods=['POST'])
async def reset_password_route():
    return await reset_password()

@user.route('/reset-password-with-token', methods=['PATCH'])
async def reset_password_with_token_route():
    return await reset_password_with_token()

@user.route('/login', methods=['POST'])
async def login_route():
    return await login()

@user.route('/logout', methods=['POST'])
@jwt_required
async def logout_route():
    return await logout()

@user.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
async def refresh_route():
    return await refresh()

@user.route('/users/<user_id>/deactivate', methods=['PATCH'])
@jwt_required
async def deactivate_route(user_id):
    return await deactivate(user_id)

@user.route('/users/<user_id>/reactivate', methods=['PATCH'])
@jwt_required
async def reactivate_route(user_id):
    return await reactivate(user_id)

@user.route('/users/<user_id>/roles/<role_id>', methods=['POST'])
@jwt_required
async def assign_role_to_user_route(user_id, role_id):
    return await assign_role_to_user(user_id, role_id)

# Role-related routes
@user.route('/roles', methods=['POST'])
@jwt_required
async def create_role_route():
    return await create_role()

@user.route('/roles', methods=['GET'])
@jwt_required
async def get_roles_route():
    return await get_roles()

@user.route('/roles/<role_id>', methods=['PATCH'])
@jwt_required
async def update_role_route(role_id):
    return await update_role(role_id)

@user.route('/roles/<role_id>', methods=['DELETE'])
@jwt_required
async def delete_role_route(role_id):
    return await delete_role(role_id)