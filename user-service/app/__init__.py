from dotenv import load_dotenv
import os
from flask import Flask
# from flask_mail import Mail
from .mail import mail_instance
from .routes import user
from .database import db

# Initialize extensions
# mail = Mail()
load_dotenv()

def create_app():
    app = Flask(__name__)

    # Load configuration from environment variables
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@postgres:5432/user_db'
    app.config['SQLALCHEMY_TRACK_NOTIFICATIONS'] = False


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


    with app.app_context():
        db.create_all()
    app.register_blueprint(user, url_prefix='/api')

    return app