from unittest.mock import patch, MagicMock

# --- Registration Flow Tests ---

def test_webauthn_register_no_session(client):
    """Verify that registration options require an active session (403)"""
    res = client.get('/webauthn/register')
    assert res.status_code == 403

def test_webauthn_register_options_success(client):
    """Verify successful generation of WebAuthn registration options for logged-in user"""
    client.post('/register', json={"username": "user1", "password": "password123"})
    res = client.get('/webauthn/register')
    assert res.status_code == 200
    data = res.get_json()
    assert 'options' in data
    assert 'challenge' in data['options']
    assert data['options']['rp']['id'] == 'localhost'

@patch('server.webauthn.routes.verify_registration_response')
def test_verify_registration_success(mock_verify, client):
    """Test successful WebAuthn credential verification and recovery code generation"""
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['username'] = 'tester'
        sess['challenge'] = b'random_challenge'
    
    # Mock successful verification result from webauthn library
    mock_res = MagicMock()
    mock_res.credential_id = b'new_credential_id'
    mock_res.credential_public_key = b'new_public_key'
    mock_verify.return_value = mock_res

    res = client.post('/webauthn/register/verify', json={
        "label": "My Key", 
        "id": "id", 
        "rawId": "id", 
        "type": "public-key", 
        "response": {}
    })
    assert res.status_code == 200
    assert 'recovery_code' in res.get_json()

def test_verify_registration_no_challenge(client):
    """Verify that registration verification fails if challenge is missing from session"""
    res = client.post('/webauthn/register/verify', json={"label": "Key"})
    assert res.status_code == 400
    assert "Session expired" in res.get_json()['error']

@patch('server.webauthn.routes.verify_registration_response')
def test_verify_registration_exception(mock_verify, client):
    """Test how the system handles internal exceptions during registration verification"""
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['challenge'] = b'chall'
    
    # Force an exception during verification
    mock_verify.side_effect = Exception("Verification failed")
    
    res = client.post('/webauthn/register/verify', json={"label": "Key"})
    assert res.status_code == 400
    assert "Verification failed" in res.get_json()['error']

# --- Authentication Flow Tests ---

def test_auth_options_no_prelogin(client):
    """Verify that authentication options are denied if user hasn't passed password check"""
    res = client.get('/webauthn/authenticate')
    assert res.status_code == 403

def test_webauthn_authenticate_options_success(client):
    """Verify successful retrieval of authentication options during login flow"""
    # Simulate a user who has passed the first factor (password)
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['authenticating'] = True
    
    res = client.get('/webauthn/authenticate')
    assert res.status_code == 200
    assert 'options' in res.get_json()

def test_verify_auth_missing_id(client):
    """Test that authentication verification fails if credential ID is missing"""
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['challenge'] = b'chall'
    
    res = client.post('/webauthn/authenticate/verify', json={})
    assert res.status_code == 400
    assert "Missing credential ID" in res.get_json()['error']

def test_verify_auth_unknown_credential(client):
    """Test authentication attempt with a credential ID not present in database"""
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['challenge'] = b'chall'
    
    res = client.post('/webauthn/authenticate/verify', json={"id": "unknown_id"})
    assert res.status_code == 400
    assert "Unknown credential" in res.get_json()['error']

@patch('server.webauthn.routes.verify_authentication_response')
def test_verify_auth_exception(mock_verify, client):
    """Test system response when the webauthn signature verification fails"""
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['challenge'] = b'c'
    
    # Mock DB finding the credential but verification failing
    with patch('server.database.Database.get_credential', return_value=(1, 1, 'id', 'pk', 'label', 0, None, 'hash')):
        mock_verify.side_effect = Exception("Invalid signature")
        res = client.post('/webauthn/authenticate/verify', json={"id": "id"})
        assert res.status_code == 400
        assert "Invalid signature" in res.get_json()['error']

# --- Account Recovery Tests ---

def test_recovery_missing_code(client):
    """Verify that recovery request fails if no code is provided"""
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['challenge'] = 'test'
    res = client.post('/webauthn/authenticate/recover', json={"recovery_code": ""})
    assert res.status_code == 400

def test_recovery_wrong_code(client):
    """Verify that invalid recovery code results in 401 Unauthorized"""
    # Need to register user to ensure DB lookup logic doesn't crash
    client.post('/register', json={"username": "rec_tester", "password": "p"})
    
    with client.session_transaction() as sess:
        sess['authenticating'] = True
        sess['challenge'] = 'test'
    
    res = client.post('/webauthn/authenticate/recover', json={"recovery_code": "000000"})
    assert res.status_code == 401
    assert "incorrect" in res.get_json()['error']

def test_recovery_session_expired(client):
    """Ensure recovery fails if session challenge is missing"""
    res = client.post('/webauthn/authenticate/recover', json={"recovery_code": "123456"})
    assert res.status_code == 400
    assert "Session expired" in res.get_json()['error']