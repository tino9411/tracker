from flask import Flask
from .database import db
from .routes import user


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@postgres:5432/user_db'
    app.config['SQLALCHEMY_TRACK_NOTIFICATIONS'] = False
    db.init_app(app)

    with app.app_context():
        db.create_all()
    app.register_blueprint(user)

    return app
