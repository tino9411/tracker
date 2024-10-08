import logging
from quart import Quart
from quart_rate_limiter import RateLimiter
from quart_jwt_extended import JWTManager
from .config import Config
from .mail import mail_instance
from .routes import user
from .database import async_session, Base, engine
from .default_roles import create_default_roles

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

jwt = JWTManager()

async def create_app(testing=False):
    app = Quart(__name__)
    RateLimiter(app)

    app.config.from_object(Config(testing=testing))

    # Initialize extensions with the app instance
    mail_instance.init_app(app)
    jwt.init_app(app)

    @app.route('/')
    async def root():
        return {"status": "OK"}, 200
    
    # Use an async context with Quart
    @app.before_serving
    async def startup():
        logger.info("Starting up the application")
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

    app.register_blueprint(user, url_prefix='/api')
    return app