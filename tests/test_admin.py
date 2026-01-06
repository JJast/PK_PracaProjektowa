def test_db_status(client):
    """Check database status reporting"""
    res = client.get('/admin/db-status')
    assert res.status_code == 200
    data = res.get_json()
    assert 'users_count' in data
    # Check the value inside the 'data' dictionary
    assert data.get('database_file') == 'webauthn.db'

def test_clear_db_success(client):
    """Verify database clearing in debug mode"""
    client.post('/register', json={"username": "temp", "password": "p"})
    res = client.get('/admin/clear-db')
    assert res.status_code == 200
    assert res.get_json()['status'] == 'db_cleared'
    
    # Check if user count is 0 now
    status = client.get('/admin/db-status').get_json()
    assert status['users_count'] == 0

def test_clear_db_forbidden_no_debug(app, client):
    """Test that clear-db fails if debug mode is OFF"""
    app.config['DEBUG'] = False
    res = client.get('/admin/clear-db')
    assert res.status_code == 403

def test_admin_session_cleared(client):
    """Ensure clear-db also clears the user session"""
    client.post('/register', json={"username": "u", "password": "p"})
    client.get('/admin/clear-db')
    with client.session_transaction() as sess:
        assert len(sess) == 0