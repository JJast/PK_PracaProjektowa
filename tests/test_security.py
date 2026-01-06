def test_brute_force_identical_error(client):
    """Protection against user enumeration"""
    r1 = client.post('/login', json={"username": "no", "password": "p"})
    client.post('/register', json={"username": "yes", "password": "p"})
    r2 = client.post('/login', json={"username": "yes", "password": "wrong"})
    assert r1.get_json()['error'] == r2.get_json()['error']

def test_cookie_httponly(client):
    """Check HttpOnly flag on session cookie"""
    res = client.post('/register', json={"username": "a", "password": "b"})
    assert 'HttpOnly' in res.headers.get('Set-Cookie', '')

def test_dashboard_unauthorized(client):
    """Ensure dashboard is protected"""
    res = client.get('/credentials')
    assert res.status_code == 401

def test_dashboard_authorized(client, auth_user):
    """Test dashboard access with valid session"""
    client.post('/login', json=auth_user)
    with client.session_transaction() as sess:
        sess['authenticated'] = True # Bypass WebAuthn for this unit test
    res = client.get('/credentials')
    assert res.status_code == 200
    assert 'credentials' in res.get_json()

def test_session_fixation(client, auth_user):
    """Verify session ID changes after login to prevent fixation attacks"""
    # 1. Initial request to get a session cookie
    res1 = client.get('/')
    old_cookie = res1.headers.get('Set-Cookie', '')

    # 2. Login
    res2 = client.post('/login', json=auth_user)
    new_cookie = res2.headers.get('Set-Cookie', '')
    
    # Verify that a new session cookie was issued and it's different from the old one
    assert new_cookie != ""
    assert old_cookie != new_cookie

def test_cors_headers(client):
    """Verify CORS allow origins (from app.py config)"""
    res = client.options('/login', headers={'Origin': 'http://localhost:5173', 'Access-Control-Request-Method': 'POST'})
    assert res.headers.get('Access-Control-Allow-Origin') == 'http://localhost:5173'

def test_unauthenticated_credentials_access(client):
    """Check that /credentials returns 401 without 'authenticated' flag"""
    client.post('/register', json={"username": "u", "password": "p"})
    # Logged in but not 'authenticated' (2FA pending)
    res = client.get('/credentials')
    assert res.status_code == 401

def test_session_lifetime_config(app):
    """Security test: Verify that permanent session lifetime is set to 30 minutes"""
    with app.test_request_context():
        from datetime import timedelta
        assert app.permanent_session_lifetime == timedelta(minutes=30)