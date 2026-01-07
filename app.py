from flask import Flask, request, jsonify, session, redirect, url_for, send_from_directory
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect, generate_csrf
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import secrets
from flask_mail import Mail, Message

from server.webauthn.routes import webauthn_bp
from server.admin.routes import admin_bp
from server.database import Database

load_dotenv()
app = Flask(__name__, static_folder=None)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_DEFAULT_SENDER")

mail = Mail(app)

if (os.environ.get("SECRET_KEY") is None):
    raise ValueError("Missing environment variable: SECRET_KEY")

app.register_blueprint(webauthn_bp, url_prefix="/webauthn/")
app.register_blueprint(admin_bp, url_prefix="/admin/")

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
# Enable CORS for common dev origins so React dev server can call the API with credentials
CORS(app, supports_credentials=True, origins=[
    "http://localhost:5173",
    "http://localhost:5000",
])
csrf = CSRFProtect(app)
db = Database()

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

        if username is None or password is None:
            return jsonify({'error': 'Missing credentials'}), 400

        if db.get_user(username):
            return jsonify({'error': 'Username already exists'}), 400

        password_hash = generate_password_hash(password)
        user_id = db.add_user(username, password_hash)

        try:
            msg = Message(
                "Welcome to Fraktal - Your Account is Ready",
                recipients=[username]
            )
            msg.html = get_registration_email_body(username)
            
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Mail notification failed: {e}")
            pass

        session['user_id'] = user_id
        session['username'] = username
        session['registering'] = True

        # Client should call the webauthn registration options endpoint next
        # return jsonify({'status': 'ok', 'next': '/webauthn/register'})
        return jsonify({'status': 'ok'})

    # GET -> serve SPA
    return send_index()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() or request.form
        username = data.get('username')
        password = data.get('password')

        if username is None or password is None:
            return jsonify({'error': 'Missing credentials'}), 400

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

@app.route('/credentials')
def dashboard():
    if 'user_id' not in session or not session.get('authenticated'):
        return jsonify({'error': 'Not authenticated'}), 401

    user = db.get_user_by_id(session['user_id'])
    credentials = db.get_credentials(session['user_id'])

    credentials_view = [{
            "id": credential[2],
            "key_label": credential[4],
            "created_at": credential[6],
        } for credential in credentials
    ]

    return jsonify({
        'username': session.get('username'),
        'credentials': credentials_view
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

@app.route('/csrf-token')
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token})

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        username = data.get('username')
        user = db.get_user(username)
        
        if user:
            token = secrets.token_urlsafe(32)
            expiry = datetime.now() + timedelta(hours=1)
            db.set_reset_token(user[0], token, expiry)
            
            reset_link = f"http://localhost:5173/reset-password/{token}"
            
            msg = Message(
                "Fraktal - Password Reset Instructions",
                recipients=[username]
            )
            msg.html = get_reset_email_body(reset_link)
            
            mail.send(msg)
            
        return jsonify({'message': 'If an account exists with this email, you will receive a reset link shortly.'}), 200
        
    except Exception as e:
        print(f"SMTP Error: {str(e)}")
        return jsonify({'error': 'Server was unable to send the email. Please try again later.'}), 500

def get_reset_email_body(reset_link):
    return f"""
    <html>
    <body style="font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1e293b; margin: 0; padding: 0; background-color: #f1f5f9;">
        <div style="max-width: 600px; margin: 40px auto; padding: 0; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
            <div style="background-color: #2563eb; padding: 30px; text-align: center;">
                <h1 style="color: #ffffff; margin: 0; font-size: 32px; letter-spacing: -0.025em; font-weight: 800;">Fraktal</h1>
                <p style="color: #bfdbfe; margin: 5px 0 0 0; font-size: 14px;">Secure Access Management</p>
            </div>
            
            <div style="padding: 40px; text-align: center;">
                <h2 style="margin-top: 0; color: #0f172a; font-size: 24px;">Password Reset Request</h2>
                <p style="color: #475569; font-size: 16px;">We received a request to reset the password for your <strong>Fraktal</strong> account.</p>
                <p style="color: #475569; font-size: 16px;">Click the button below to choose a new password. If you didn't request this, you can safely ignore this email.</p>
                
                <div style="margin: 35px 0;">
                    <a href="{reset_link}" 
                       style="background-color: #2563eb; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block; font-size: 16px;">
                       Reset Password
                    </a>
                </div>
                
                <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 30px 0;" />
                
                <p style="font-size: 12px; color: #94a3b8; line-height: 1.4;">
                    This link will expire in 60 minutes for security reasons.<br>
                    If the button above doesn't work, copy and paste this URL into your browser:<br>
                    <span style="word-break: break-all; color: #2563eb;">{reset_link}</span>
                </p>
            </div>
            
            <div style="background-color: #f8fafc; padding: 20px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #e2e8f0;">
                &copy; 2026 Fraktal Authentication Services. All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """

def get_registration_email_body(username):
    return f"""
    <html>
    <body style="font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1e293b; margin: 0; padding: 0; background-color: #f1f5f9;">
        <div style="max-width: 600px; margin: 40px auto; padding: 0; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
            <div style="background-color: #2563eb; padding: 30px; text-align: center;">
                <h1 style="color: #ffffff; margin: 0; font-size: 32px; letter-spacing: -0.025em; font-weight: 800;">Fraktal</h1>
                <p style="color: #bfdbfe; margin: 5px 0 0 0; font-size: 14px;">Welcome to the Future of Security</p>
            </div>
            
            <div style="padding: 40px; text-align: center;">
                <h2 style="margin-top: 0; color: #0f172a; font-size: 24px;">Welcome, {username}!</h2>
                <p style="color: #475569; font-size: 16px;">Your account has been successfully created in the <strong>Fraktal</strong> ecosystem.</p>
                <p style="color: #475569; font-size: 16px;">To ensure the highest level of protection, we highly recommend enabling <strong>Two-Factor Authentication (2FA)</strong> using hardware keys or biometrics.</p>
                
                <div style="margin: 35px 0;">
                    <a href="http://localhost:5173/login" 
                       style="background-color: #2563eb; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block; font-size: 16px;">
                       Sign In to Your Account
                    </a>
                </div>
                
                <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 30px 0;" />
                
                <div style="text-align: left; background-color: #f8fafc; padding: 20px; border-radius: 8px;">
                    <h3 style="font-size: 14px; color: #1e293b; margin-top: 0;">Why use Fraktal?</h3>
                    <ul style="font-size: 13px; color: #64748b; padding-left: 20px; margin-bottom: 0;">
                        <li>FIDO2/WebAuthn standard support for phishing resistance.</li>
                        <li>Encrypted credential storage[cite: 194].</li>
                        <li>Seamless integration with YubiKey and Windows Hello[cite: 119].</li>
                    </ul>
                </div>
            </div>
            
            <div style="background-color: #f8fafc; padding: 20px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #e2e8f0;">
                &copy; 2026 Fraktal Authentication Services. All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    data = request.get_json()
    new_password = data.get('password')

    if not new_password:
        return jsonify({'error': 'Nowe hasło jest wymagane'}), 400

    user = db.get_user_by_reset_token(token)
    
    if not user:
        return jsonify({'error': 'Token jest nieprawidłowy lub wygasł'}), 400

    new_hash = generate_password_hash(new_password)
    db.update_password(user[0], new_hash)

    return jsonify({'status': 'ok', 'message': 'Hasło zostało pomyślnie zmienione'})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)