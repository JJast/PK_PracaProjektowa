import sqlite3

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
                key_label TEXT NOT NULL,
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
    
    def add_credential(self, user_id, credential_id, public_key, label: str):
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT INTO credentials (user_id, credential_id, public_key, key_label) VALUES (?, ?, ?, ?)',
            (user_id, credential_id, public_key, label)
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
