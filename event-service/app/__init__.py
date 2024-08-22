import logging
from quart import Quart
from quart_rate_limiter import RateLimiter
from quart_jwt_extended import JWTManager
from .config import Config
from .database import async_session, Base, engine
from .routes import event
from .kafka import consume_events
import asyncio

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

jwt = JWTManager()

async def create_app(testing=False):
    app = Quart(__name__)
    RateLimiter(app)
    app.config.from_object(Config(testing=testing))
    # Initialize extensions with the app instance
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
        except Exception as e:
            logger.error(f"Error during startup: {str(e)}")
            raise
    
    app.register_blueprint(event, url_prefix='/api')

    # Start consuming events in the background
    loop = asyncio.get_event_loop()
    loop.create_task(consume_events())

    return app