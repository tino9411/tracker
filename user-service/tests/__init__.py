# tests/test_user_service.py
import pytest
import asyncio
from quart import Quart
from app import create_app
from app.database import async_session, Base, engine
from sqlalchemy.ext.asyncio import AsyncSession

@pytest.fixture
async def app():
    app = create_app()
    async with app.app_context():
        # Create tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        yield app

        # Drop tables after test
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
async def client(app: Quart):
    return app.test_client()

@pytest.fixture
async def session():
    async with async_session() as session:
        yield session
        await session.rollback()

@pytest.mark.asyncio
async def test_create_user(client):
    user_data = {
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "strongpassword",
        "first_name": "Test",
        "last_name": "User"
    }

    response = await client.post('/api/users', json=user_data)
    assert response.status_code == 201

    data = await response.get_json()
    assert data['username'] == user_data['username']
    assert 'id' in data