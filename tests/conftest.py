import pytest
from app import app as flask_app
from server.database import Database

@pytest.fixture
def app():
    # Configure app for testing
    flask_app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
        "WTF_CSRF_ENABLED": False,
        "DEBUG": True  # Enabled to test admin routes
    })
    
    with flask_app.app_context():
        db = Database()
        db.clear_all_data()
        yield flask_app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth_user(client):
    # Register and logout a standard user for testing
    client.post('/register', json={"username": "testuser", "password": "Password123!"})
    client.get('/logout')
    return {"username": "testuser", "password": "Password123!"}