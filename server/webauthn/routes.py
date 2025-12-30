from utils import base64_to_base64url, webauthn_options_to_dict
from flask import Blueprint, request, jsonify, session

from database import Database

# WebAuthn dependencies
from webauthn import (
    options_to_json,
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    base64url_to_bytes,
)

import base64

from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    ResidentKeyRequirement,
)

webauthn_bp = Blueprint("webauthn", __name__)
db = Database()

# RP Configuration
RP_ID = "localhost"
RP_NAME = "WebAuthn Demo App"
ORIGIN = "http://localhost:5000"

@webauthn_bp.route('/register')
def webauthn_register():
    # if 'user_id' not in session or not session.get('registering'):
    if 'user_id' not in session:
        return jsonify({'error': 'Not registering or session expired'}), 403

    user_id = session['user_id']
    username = session['username']

    # Get existing credentials to exclude them
    existing_credentials = db.get_credentials(user_id)
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred[2]))
        for cred in existing_credentials
    ]

    # Generate registration options
    registration_options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user_id).encode(),
        user_name=username,
        user_display_name=username,
        attestation=AttestationConveyancePreference.DIRECT,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=exclude_credentials,
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        timeout=60000,
    )

    # Store challenge in session as bytes
    session['challenge'] = registration_options.challenge
    session['user_handle'] = registration_options.user.id

    # Convert options to JSON-serializable dict
    options_dict = webauthn_options_to_dict(registration_options)

    return jsonify({'options': options_dict, 'action': 'register'})

@webauthn_bp.route('/register/verify', methods=['POST'])
def webauthn_register_verify():
    if 'user_id' not in session or 'challenge' not in session:
        return jsonify({'error': 'Session expired'}), 400
    
    print(f"Verifying registration response for user_id: {session['user_id']}")

    try:
        credential_data = request.json
        
        print(f"Verifying registration response with challenge: {session['challenge']}")

        verification = verify_registration_response(
            credential=credential_data,
            expected_challenge=session['challenge'],
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=False,
        )

        print(verification)
        
        # Store the credential using base64url encoding
        credential_id = base64.urlsafe_b64encode(verification.credential_id).decode('utf-8').rstrip('=')
        public_key = base64.urlsafe_b64encode(verification.credential_public_key).decode('utf-8').rstrip('=')
        
        db.add_credential(session['user_id'], credential_id, public_key)
        
        # Clean up session
        session.pop('challenge', None)
        session.pop('user_handle', None)
        session.pop('registering', None)
        session['authenticated'] = True
        
        return jsonify({'status': 'ok'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@webauthn_bp.route('/authenticate')
def webauthn_authenticate():
    if 'user_id' not in session or not session.get('authenticating'):
        return jsonify({'error': 'Not authenticating or session expired'}), 403

    user_id = session['user_id']
    credentials = db.get_credentials(user_id)

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred[2]))
        for cred in credentials
    ]

    authentication_options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
        timeout=60000,
    )

    session['challenge'] = authentication_options.challenge

    # Convert options to JSON-serializable dict
    options_dict = webauthn_options_to_dict(authentication_options)

    return jsonify({'options': options_dict, 'action': 'authenticate'})

@webauthn_bp.route('/authenticate/verify', methods=['POST'])
def webauthn_authenticate_verify():
    if 'user_id' not in session or 'challenge' not in session:
        return jsonify({'error': 'Session expired'}), 400
    
    try:
        credential_data = request.json
        credential_id = credential_data.get('rawId') or credential_data.get('id')
        
        if not credential_id:
            return jsonify({'error': 'Missing credential ID'}), 400
        
        stored_credential = db.get_credential(credential_id)
        if not stored_credential:
            return jsonify({'error': 'Unknown credential'}), 400
        
        verification = verify_authentication_response(
            credential=credential_data,
            expected_challenge=session['challenge'],
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64url_to_bytes(stored_credential[3]),
            credential_current_sign_count=stored_credential[4],
            require_user_verification=False,
        )
        
        # Update sign count
        db.update_sign_count(stored_credential[2], verification.new_sign_count)
        
        # Clean up session
        session.pop('challenge', None)
        session.pop('authenticating', None)
        session['authenticated'] = True
        
        return jsonify({'status': 'ok'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400
