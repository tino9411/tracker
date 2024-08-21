import pytest
import logging
from quart.testing import QuartClient
from sqlalchemy.ext.asyncio import AsyncSession

from _pytest.config import Config
from _pytest.terminal import TerminalReporter

class SummaryReporter:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = 0
        self.skipped = 0
        self.total = 0

    def pytest_runtest_logreport(self, report):
        if report.when == 'call':
            self.total += 1
            if report.passed:
                self.passed += 1
            elif report.failed:
                self.failed += 1
            elif report.skipped:
                self.skipped += 1

    def pytest_terminal_summary(self, terminalreporter, exitstatus, config):
        terminalreporter.section('Test Summary', sep='-')
        terminalreporter.line(f"Total Tests: {self.total}")
        terminalreporter.line(f"Passed: {self.passed}")
        terminalreporter.line(f"Failed: {self.failed}")
        terminalreporter.line(f"Errors: {self.errors}")
        terminalreporter.line(f"Skipped: {self.skipped}")

def pytest_configure(config):
    config.pluginmanager.register(SummaryReporter(), "summary_reporter")

logger = logging.getLogger(__name__)

# Consistent user data
TEST_USER_DATA = {
    "username": "testuser",
    "email": "testuser@example.com",
    "password": "TestPassword1!",
    "first_name": "Test",
    "last_name": "User"
}

async def login_user(client: QuartClient, email: str, password: str):
    login_data = {"email": email, "password": password}
    response = await client.post('/api/login', json=login_data)
    assert response.status_code == 200
    cookies = response.headers.getlist('Set-Cookie')
    csrf_token = None
    for cookie in cookies:
        if 'csrf_access_token' in cookie:
            csrf_token = cookie.split(';')[0].split('=')[1]
    assert csrf_token is not None
    return csrf_token

async def create_test_user(client: QuartClient):
    response = await client.post('/api/users', json=TEST_USER_DATA)
    assert response.status_code == 201
    response_data = await response.get_json()
    return response_data['data']['id']

@pytest.mark.asyncio
async def test_create_user(app: QuartClient, client: QuartClient, session: AsyncSession):
    logger.info(f"Sending POST request to /api/users with data: {TEST_USER_DATA}")
    
    response = await client.post('/api/users', json=TEST_USER_DATA)
    logger.info(f"Received response with status code: {response.status_code}")
    
    response_data = await response.get_json()
    logger.info(f"Response data: {response_data}")
    
    assert response.status_code == 201, f"Expected 201, got {response.status_code}. Response: {response_data}"
    
    assert 'data' in response_data, "Response does not contain 'data' key"
    user = response_data['data']
    
    assert user['username'] == TEST_USER_DATA['username'], f"Username mismatch. Expected {TEST_USER_DATA['username']}, got {user['username']}"
    assert 'id' in user, "User data does not contain 'id'"

@pytest.mark.asyncio
async def test_login(app: QuartClient, client: QuartClient, session: AsyncSession):
    await create_test_user(client)

    login_data = {
        "email": TEST_USER_DATA["email"],
        "password": TEST_USER_DATA["password"]
    }
    response = await client.post('/api/login', json=login_data)
    assert response.status_code == 200

    response_data = await response.get_json()
    assert 'access_token' in response_data['data']

    cookies = response.headers.getlist('Set-Cookie')
    csrf_token = None
    for cookie in cookies:
        if 'csrf_access_token' in cookie:
            csrf_token = cookie.split(';')[0].split('=')[1]
    assert csrf_token is not None

@pytest.mark.asyncio
async def test_get_user(app: QuartClient, client: QuartClient, session: AsyncSession):
    user_id = await create_test_user(client)
    csrf_token = await login_user(client, TEST_USER_DATA['email'], TEST_USER_DATA['password'])

    headers = {'X-CSRF-TOKEN': csrf_token}
    response = await client.get(f'/api/users/{user_id}', headers=headers)
    assert response.status_code == 200

    response_data = await response.get_json()
    assert 'data' in response_data
    user = response_data['data']
    assert user['username'] == TEST_USER_DATA['username']
    assert user['email'] == TEST_USER_DATA['email']

@pytest.mark.asyncio
async def test_update_user(app: QuartClient, client: QuartClient, session: AsyncSession):
    user_id = await create_test_user(client)
    csrf_token = await login_user(client, TEST_USER_DATA['email'], TEST_USER_DATA['password'])

    update_data = {
        "first_name": "Updated",
        "last_name": "Name"
    }
    headers = {'X-CSRF-TOKEN': csrf_token}
    response = await client.patch(f'/api/users/{user_id}', json=update_data, headers=headers)
    assert response.status_code == 200

    response_data = await response.get_json()
    assert 'data' in response_data
    user = response_data['data']
    assert user['first_name'] == update_data['first_name']
    assert user['last_name'] == update_data['last_name']

@pytest.mark.asyncio
async def test_delete_user(app: QuartClient, client: QuartClient, session: AsyncSession):
    user_id = await create_test_user(client)
    csrf_token = await login_user(client, TEST_USER_DATA['email'], TEST_USER_DATA['password'])

    headers = {'X-CSRF-TOKEN': csrf_token}
    response = await client.delete(f'/api/users/{user_id}', headers=headers)
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_server_is_up(app: QuartClient, client: QuartClient):
    logger.info("Sending GET request to /")
    response = await client.get('/')
    logger.info(f"Received response with status code: {response.status_code}")
    assert response.status_code == 200