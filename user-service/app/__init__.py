from dotenv import load_dotenv
import os
from flask import Flask
from flask_jwt_extended import JWTManager
from .mail import mail_instance
from .routes import user
from .database import db


load_dotenv()

jwt = JWTManager()


def create_app():
    app = Flask(__name__)

    # Load configuration from environment variables
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@postgres:5432/user_db'
    app.config['SQLALCHEMY_TRACK_NOTIFICATIONS'] = False

    # JWT Configuration
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 900))
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', 604800))
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']  # Ensures tokens are looked for in cookies
    app.config['JWT_COOKIE_CSRF_PROTECT'] = True  # Using CSRF protection with cookies

    # Flask-Mail configuration
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

    # Initialize extensions with the app instance
    db.init_app(app)
    mail_instance.init_app(app)
    jwt.init_app(app)


    with app.app_context():
        db.create_all()
    app.register_blueprint(user, url_prefix='/api')

    return app