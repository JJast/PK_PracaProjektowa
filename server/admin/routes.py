from flask import jsonify, session, Blueprint, current_app
from server.database import Database

admin_bp = Blueprint("admin", __name__)
db = Database()

# Admin routes for development
@admin_bp.route('/clear-db')
def clear_db():
    """Dangerous: Clears all data - only for development!"""
    if not current_app.debug:
        return "This route is only available in debug mode", 403
    
    db.clear_all_data()
    session.clear()
    return jsonify({'status': 'db_cleared'})

@admin_bp.route('/db-status')
def db_status():
    """Show current database status"""
    users_count = db.conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    credentials_count = db.conn.execute('SELECT COUNT(*) FROM credentials').fetchone()[0]
    
    return jsonify({
        'users_count': users_count,
        'credentials_count': credentials_count,
        'database_file': 'webauthn.db'
    })