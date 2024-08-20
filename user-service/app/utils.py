from werkzeug.security import check_password_hash, generate_password_hash
from flask import request
from flask_mail import Message
from .mail import mail_instance
from .models import User
from flask_jwt_extended import get_jwt_identity
import logging


def check_user_role(required_role):
    """
    Checks if the current user has the required role.

    :param required_role: The name of the role to check (e.g., 'admin').
    :return: True if the user has the role, False otherwise.
    """

    # Get the ID of the current user from the JWT token
    current_user_id = get_jwt_identity()

    # Query the database for the current user
    user = User.query.get(current_user_id)

    if not user:
        return False

    # Check if the user has the required role
    return user.has_role(required_role)


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


def generate_reset_link(user):
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


def send_email(subject, recipients, body):
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
        mail_instance.send(msg)
        logging.info(f"Email sent successfully to {recipients}")
        return True
    except Exception as e:
        # Log the exception or handle it as needed
        logging.error(f"Failed to send email: {e}")
        return False