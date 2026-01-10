from utils import base64_to_base64url, generate_recovery_code, webauthn_options_to_dict
from unittest.mock import MagicMock

def test_base64_conversion():
    """Verify base64url encoding (removing padding and changing chars)"""
    data = b'\xff\x00\xab' # Some bytes
    # Standard b64: /wC r
    # URL safe: /wC r -> _wCr (but with padding removed)
    result = base64_to_base64url(data)
    assert "=" not in result
    assert "+" not in result
    assert "/" not in result

def test_recovery_code_generation():
    """Verify that recovery codes are 6-digit strings"""
    code = generate_recovery_code()
    assert len(code) == 6
    assert code.isdigit()

def test_webauthn_options_mapping():
    """Verify that complex WebAuthn objects are correctly mapped to dicts"""
    mock_options = MagicMock()
    mock_options.challenge = b'test_challenge'
    mock_options.rp.name = "Test RP"
    mock_options.rp.id = "localhost"
    mock_options.user.id = b'user_id'
    mock_options.user.name = "user@test"
    mock_options.user.display_name = "User"
    
    # We only mock attributes used in the function
    result = webauthn_options_to_dict(mock_options)
    assert 'challenge' in result
    assert result['rp']['name'] == "Test RP"
    assert 'user' in result