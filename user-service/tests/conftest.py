import pytest
import pytest_asyncio
from app import create_app
from app.database import Base, engine, async_session
from app.default_roles import create_default_roles
import asyncio

@pytest_asyncio.fixture(scope="function")
async def app():
    app = await create_app(testing=True)
    async with app.app_context():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
        
        async with async_session() as session:
            await create_default_roles(session)
            await session.commit()
        
        yield app

    # Cleanup after each test
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest_asyncio.fixture
async def client(app):
    return app.test_client()

@pytest_asyncio.fixture
async def session():
    async with async_session() as session:
        yield session
        await session.rollback()

# You can keep this for now, but we'll address the warning later
@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()