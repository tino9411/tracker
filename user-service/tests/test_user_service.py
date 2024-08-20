import pytest
from quart import Quart
from quart.testing import QuartClient

# Assuming you have these imports in your actual application
from app import create_app
from app.database import async_session, Base, engine

@pytest.fixture
async def app():
    app = create_app()
    async with app.app_context():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield app
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
async def client(app):
    app = await anext(app)  # Resolve the app fixture
    return app.test_client()

@pytest.mark.asyncio
async def test_create_user(client):
    client = await client  # Await the client fixture
    user_data = {
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "StrongPassword1!",
        "first_name": "New",
        "last_name": "User"
    }
    response = await client.post('/api/users', json=user_data)
    assert response.status_code == 201
    data = await response.json()
    assert data['data']['username'] == user_data['username']
    assert 'id' in data['data']

@pytest.mark.asyncio
async def test_server_is_up(client):
    client = await client  # Await the client fixture
    response = await client.get('/')
    assert response.status_code != 404