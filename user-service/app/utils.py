from werkzeug.security import check_password_hash, generate_password_hash
from flask import request


def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256')


def check_password(hashed_password, current_password):
    """
    Checks if the current_password matches the hashed_password.

    :param hashed_password: The hashed password stored in the database.
    :param current_password: The plain text password provided by the user.
    :return: True if the password matches, otherwise False.
    """
    return check_password_hash(hashed_password, current_password)


def generate_reset_link(user):
    # Use request.host_url to dynamically get the base URL
    base_url = request.host_url.rstrip('/')
    return f"{base_url}/reset_password?token={user.reset_token}"
