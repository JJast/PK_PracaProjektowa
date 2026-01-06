import pytest
from server.database import Database

@pytest.fixture
def db():
    # Use a clean instance for unit testing the DB logic
    d = Database()
    d.clear_all_data()
    return d

def test_db_add_and_get_user(db):
    """Unit test: Verify user creation and retrieval in SQLite"""
    user_id = db.add_user("unit_tester", "hash123")
    assert user_id is not None
    user = db.get_user("unit_tester")
    assert user[1] == "unit_tester"
    assert user[2] == "hash123"

def test_db_get_user_by_id(db):
    """Unit test: Verify retrieval by primary key"""
    uid = db.add_user("id_test", "h")
    user = db.get_user_by_id(uid)
    assert user[1] == "id_test"

def test_db_add_credential(db):
    """Unit test: Verify WebAuthn credential storage"""
    uid = db.add_user("web_user", "h")
    db.add_credential(uid, "cred_id_123", "pub_key_hex", "Mobile Phone", "recovery_hash")
    
    creds = db.get_credentials(uid)
    assert len(creds) == 1
    assert creds[0][2] == "cred_id_123"
    assert creds[0][4] == "Mobile Phone"

def test_db_update_sign_count(db):
    """Unit test: Verify that signature counter increments correctly"""
    uid = db.add_user("counter_user", "h")
    db.add_credential(uid, "cid", "pk", "label", "hash")
    
    # Update count to 5
    db.update_sign_count("cid", 5)
    cred = db.get_credential("cid")
    assert cred[5] == 5 # sign_count column index

def test_db_get_non_existent_user(db):
    """Unit test: Verify behavior when user is not found"""
    assert db.get_user("nobody") is None