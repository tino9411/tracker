# __init__.py

import logging
from quart import Quart
from quart_rate_limiter import RateLimiter
from quart_jwt_extended import JWTManager
from .config import Config
from .database import Base, engine
from .routes import event
from .kafka import consume_events, create_topics

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

jwt = JWTManager()


async def create_app(testing=False):
    app = Quart(__name__)
    RateLimiter(app)
    app.config.from_object(Config(testing=testing))
    jwt.init_app(app)

    @app.route("/")
    async def root():
        return {"status": "OK"}, 200

    @app.before_serving
    async def startup():
        logger.info("Starting up the application")
        try:
            logger.info("Attempting to create database tables")
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created successfully")
            create_topics()
            app.add_background_task(consume_events)
        except Exception as e:
            logger.error(f"Error during startup: {str(e)}")
            raise

    @app.after_serving
    async def shutdown():
        logger.info("Shutting down the application")
        from .kafka import stop_kafka_consumer, stop_kafka_producer

        await stop_kafka_consumer()
        await stop_kafka_producer()

    app.register_blueprint(event, url_prefix="/api")

    return app

