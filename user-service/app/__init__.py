import os
import logging
from dotenv import load_dotenv
from quart import Quart
from quart_rate_limiter import RateLimiter
from quart_jwt_extended import JWTManager
from .mail import mail_instance
from .routes import user
from .database import async_session, Base, engine
from .default_roles import create_default_roles

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

jwt = JWTManager()

def create_app():
    app = Quart(__name__)
    RateLimiter(app)


    # Load configuration from environment variables
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_NOTIFICATIONS'] = False

    logger.info(f"Database URL: {app.config['SQLALCHEMY_DATABASE_URI']}")

    # JWT Configuration
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 900))
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', 604800))
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_CSRF_PROTECT'] = True

    # Quart-Mail configuration (compatible with Quart)
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

    # Initialize extensions with the app instance
    mail_instance.init_app(app)
    jwt.init_app(app)

    # Use an async context with Quart
    @app.before_serving
    async def startup():
        logger.info("Starting up the application")
        async with app.app_context():
            try:
                logger.info("Attempting to create database tables")
                async with engine.begin() as conn:
                    await conn.run_sync(Base.metadata.create_all)
                logger.info("Database tables created successfully")
                
                logger.info("Creating default roles")
                async with async_session() as session:
                    await create_default_roles(session)
                logger.info("Default roles created successfully")
            except Exception as e:
                logger.error(f"Error during startup: {str(e)}")
                raise

    # Register the startup task to run when the app starts
    app.before_serving(startup)
    
    app.register_blueprint(user, url_prefix='/api')

    return app