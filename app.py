from flask import Flask, request, jsonify, session, redirect, url_for, send_from_directory
from flask_cors import CORS
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

from server.webauthn.routes import webauthn_bp
from server.admin.routes import admin_bp

from database import Database

app = Flask(__name__, static_folder=None)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-this-in-production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
# Enable CORS for common dev origins so React dev server can call the API with credentials
CORS(app, supports_credentials=True, origins=[
    "http://localhost:5173",
    "http://localhost:5000",
])
db = Database()

app.register_blueprint(webauthn_bp, url_prefix="/webauthn/")
app.register_blueprint(admin_bp, url_prefix="/admin/")

# Frontend build directory (Vite default = dist)
BASE_DIR = os.path.dirname(__file__)
FRONTEND_BUILD_DIR = os.path.join(BASE_DIR, 'frontend', 'dist')

def send_index():
    """Send the SPA index.html from the React build directory.
    If the build isn't present return a helpful JSON error for dev.
    """
    index_path = os.path.join(FRONTEND_BUILD_DIR, 'index.html')
    if os.path.exists(index_path):
        return send_from_directory(FRONTEND_BUILD_DIR, 'index.html')
    return jsonify({
        'error': 'Frontend build not found. Run `npm run build` in frontend directory and place output in frontend/dist'
    }), 500


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

# Serve static files and fallback to index for SPA routes
@app.route('/<path:filename>')
def serve_static(filename):
    file_path = os.path.join(FRONTEND_BUILD_DIR, filename)
    if os.path.exists(file_path):
        return send_from_directory(FRONTEND_BUILD_DIR, filename)
    return send_index()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)