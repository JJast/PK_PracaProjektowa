from flask import Flask, request, jsonify, session, redirect, url_for, send_from_directory
from flask_cors import CORS
import os
import secrets
import json
import base64
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

# WebAuthn dependencies
from webauthn import (
    options_to_json,
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    base64url_to_bytes,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    ResidentKeyRequirement,
)

app = Flask(__name__, static_folder=None)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-this-in-production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
# Enable CORS for common dev origins so React dev server can call the API with credentials
CORS(app, supports_credentials=True, origins=[
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:5000",
])

# Database setup
class Database:
    def __init__(self):
        self.conn = sqlite3.connect('webauthn.db', check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                credential_id TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                sign_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        self.conn.commit()
    
    def add_user(self, username, password_hash):
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (username, password_hash)
        )
        self.conn.commit()
        return cursor.lastrowid
    
    def get_user(self, username):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        return cursor.fetchone()
    
    def get_user_by_id(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        return cursor.fetchone()
    
    def add_credential(self, user_id, credential_id, public_key):
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT INTO credentials (user_id, credential_id, public_key) VALUES (?, ?, ?)',
            (user_id, credential_id, public_key)
        )
        self.conn.commit()
    
    def get_credentials(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM credentials WHERE user_id = ?', (user_id,))
        return cursor.fetchall()
    
    def get_credential(self, credential_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM credentials WHERE credential_id = ?', (credential_id,))
        return cursor.fetchone()
    
    def update_sign_count(self, credential_id, sign_count):
        cursor = self.conn.cursor()
        cursor.execute(
            'UPDATE credentials SET sign_count = ? WHERE credential_id = ?',
            (sign_count, credential_id)
        )
        self.conn.commit()
    
    def clear_all_data(self):
        """Clear all data from both tables"""
        self.conn.execute('DELETE FROM credentials')
        self.conn.execute('DELETE FROM users')
        self.conn.commit()

db = Database()

# RP Configuration
RP_ID = "localhost"
RP_NAME = "WebAuthn Demo App"
ORIGIN = "http://localhost:5000"

# Frontend build directory (Vite default = dist)
BASE_DIR = os.path.dirname(__file__)
FRONTEND_BUILD_DIR = os.path.join(BASE_DIR, 'front-react', 'dist')

def send_index():
    """Send the SPA index.html from the React build directory.
    If the build isn't present return a helpful JSON error for dev.
    """
    index_path = os.path.join(FRONTEND_BUILD_DIR, 'index.html')
    if os.path.exists(index_path):
        return send_from_directory(FRONTEND_BUILD_DIR, 'index.html')
    return jsonify({
        'error': 'Frontend build not found. Run `npm run build` in front-react and place output in front-react/dist'
    }), 500

def webauthn_options_to_dict(options):
    """Convert WebAuthn options to a JSON-serializable dictionary using base64url encoding"""
    options_dict = {}
    
    # Convert basic fields
    if hasattr(options, 'rp'):
        options_dict['rp'] = {
            'name': options.rp.name,
            'id': options.rp.id,
        }
    
    if hasattr(options, 'user'):
        options_dict['user'] = {
            'id': base64_to_base64url(options.user.id),
            'name': options.user.name,
            'displayName': options.user.display_name,
        }
    
    if hasattr(options, 'challenge'):
        options_dict['challenge'] = base64_to_base64url(options.challenge)
    
    if hasattr(options, 'pub_key_cred_params'):
        options_dict['pubKeyCredParams'] = [
            {
                'type': param.type,
                'alg': param.alg,
            }
            for param in options.pub_key_cred_params
        ]
    
    if hasattr(options, 'timeout'):
        options_dict['timeout'] = options.timeout
    
    if hasattr(options, 'exclude_credentials'):
        options_dict['excludeCredentials'] = [
            {
                'type': cred.type,
                'id': base64_to_base64url(cred.id),
                'transports': getattr(cred, 'transports', []),
            }
            for cred in options.exclude_credentials
        ]
    
    if hasattr(options, 'allow_credentials'):
        options_dict['allowCredentials'] = [
            {
                'type': cred.type,
                'id': base64_to_base64url(cred.id),
                'transports': getattr(cred, 'transports', []),
            }
            for cred in options.allow_credentials
        ]
    
    if hasattr(options, 'authenticator_selection'):
        auth_selection = {}
        if options.authenticator_selection.authenticator_attachment:
            auth_selection['authenticatorAttachment'] = options.authenticator_selection.authenticator_attachment.value
        if options.authenticator_selection.resident_key:
            auth_selection['residentKey'] = options.authenticator_selection.resident_key.value
        if options.authenticator_selection.user_verification:
            auth_selection['userVerification'] = options.authenticator_selection.user_verification.value
        if options.authenticator_selection.require_resident_key is not None:
            auth_selection['requireResidentKey'] = options.authenticator_selection.require_resident_key
        
        options_dict['authenticatorSelection'] = auth_selection
    
    if hasattr(options, 'attestation'):
        options_dict['attestation'] = options.attestation.value
    
    if hasattr(options, 'extensions'):
        options_dict['extensions'] = options.extensions
    
    return options_dict

def base64_to_base64url(data):
    """Convert bytes to base64url string without padding"""
    if isinstance(data, bytes):
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
    return data

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)

@app.route('/')
def index():
    # Serve the SPA. The React app is expected to handle routes like /login, /register, /dashboard
    return send_index()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() or request.form
        username = data.get('username')
        password = data.get('password')

        if db.get_user(username):
            return jsonify({'error': 'Username already exists'}), 400

        password_hash = generate_password_hash(password)
        user_id = db.add_user(username, password_hash)

        session['user_id'] = user_id
        session['username'] = username
        session['registering'] = True

        # Client should call the webauthn registration options endpoint next
        return jsonify({'status': 'ok', 'next': '/webauthn/register'})

    # GET -> serve SPA
    return send_index()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() or request.form
        username = data.get('username')
        password = data.get('password')

        user = db.get_user(username)
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['authenticating'] = True

            credentials = db.get_credentials(user[0])
            if credentials:
                return jsonify({'status': 'ok', 'webauthn': True, 'next': '/webauthn/authenticate'})
            else:
                session['authenticated'] = True
                return jsonify({'status': 'ok', 'webauthn': False, 'next': '/dashboard'})

        return jsonify({'error': 'Invalid credentials'}), 400

    # GET -> serve SPA
    return send_index()

@app.route('/webauthn/register')
def webauthn_register():
    if 'user_id' not in session or not session.get('registering'):
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

@app.route('/webauthn/register/verify', methods=['POST'])
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

@app.route('/webauthn/authenticate')
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

@app.route('/webauthn/authenticate/verify', methods=['POST'])
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

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or not session.get('authenticated'):
        return jsonify({'error': 'Not authenticated'}), 401

    user = db.get_user_by_id(session['user_id'])
    credentials = db.get_credentials(session['user_id'])

    return jsonify({
        'username': session.get('username'),
        'credentials_count': len(credentials)
    })

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({'status': 'ok'})

# Admin routes for development
@app.route('/admin/clear-db')
def clear_db():
    """Dangerous: Clears all data - only for development!"""
    if not app.debug:
        return "This route is only available in debug mode", 403
    
    db.clear_all_data()
    session.clear()
    return jsonify({'status': 'db_cleared'})

@app.route('/admin/db-status')
def db_status():
    """Show current database status"""
    users_count = db.conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    credentials_count = db.conn.execute('SELECT COUNT(*) FROM credentials').fetchone()[0]
    
    return jsonify({
        'users_count': users_count,
        'credentials_count': credentials_count,
        'database_file': 'webauthn.db'
    })


# Serve static files and fallback to index for SPA routes
@app.route('/<path:filename>')
def serve_static(filename):
    file_path = os.path.join(FRONTEND_BUILD_DIR, filename)
    if os.path.exists(file_path):
        return send_from_directory(FRONTEND_BUILD_DIR, filename)
    return send_index()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)