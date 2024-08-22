import os
import logging
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from contextlib import asynccontextmanager
from sqlalchemy.future import select

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get the DATABASE_URL from environment variables
if os.getenv('TESTING'):
    database_url = os.environ.get('TEST_DATABASE_URL', 'postgresql+asyncpg://postgres:password@postgres_test:5432/test_event_db')
else:
    database_url = os.environ.get('DATABASE_URL')

logger.info(f"Connecting to database: {database_url}")

# Create the async engine
try:
    engine = create_async_engine(
        database_url,
        echo=True,  # Set to True for SQL debugging; remove or set to False in production
    )
    logger.info("Database engine created successfully")
except Exception as e:
    logger.error(f"Error creating database engine: {str(e)}")
    raise

# Create an async session factory
async_session = sessionmaker(
    engine, expire_on_commit=False, class_=AsyncSession
)

# Base class for your models
Base = declarative_base()

# Dependency injection for db session
@asynccontextmanager
async def get_db_session():
    async with async_session() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Error in database session: {str(e)}")
            await session.rollback()
            raise
        finally:
            await session.close()


async def check_database_health() -> bool:
    """
    Check the health of the database connection.

    Returns:
        bool: True if the database connection is healthy, False otherwise.
    """
    try:
        async with get_db_session() as session:
            await session.execute('SELECT 1')  # Simple query to check connection
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False
    

