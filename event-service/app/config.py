import os
from dotenv import load_dotenv

load_dotenv()


class Config:

    def __init__(self, testing=False):
        self.SECRET_KEY = os.environ.get('SECRET_KEY')
        if testing or os.getenv('TESTING'):
            self.SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL',
                                                          'postgresql+asyncpg://postgres:password@postgres_test:5432/test_user_db')
        else:
            self.SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False

        # JWT Configuration
        self.JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
        self.JWT_ACCESS_TOKEN_EXPIRES = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 900))
        self.JWT_REFRESH_TOKEN_EXPIRES = int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', 604800))
        self.JWT_TOKEN_LOCATION = ['cookies']
        self.JWT_COOKIE_CSRF_PROTECT = True

        # Quart-Mail configuration
        self.MAIL_SERVER = os.environ.get('MAIL_SERVER')
        self.MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
        self.MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
        self.MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
        self.MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
        self.MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')

