import sqlite3
import os
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get the absolute path to the database file
db_path = os.path.abspath('ssh_keys.db')
logger.info(f"Database will be created at: {db_path}")

def get_db():
    """Get a database connection."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with the required tables."""
    conn = get_db()
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS ssh_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_key TEXT UNIQUE NOT NULL,
                key_type TEXT NOT NULL,
                comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP
            )
        ''')
        conn.commit()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database tables: {str(e)}")
        raise
    finally:
        conn.close()

# Initialize the database
init_db()

class SSHKey:
    @staticmethod
    def create(public_key: str, key_type: str, comment: str) -> int:
        """Create a new SSH key record."""
        conn = get_db()
        try:
            cursor = conn.execute(
                'INSERT INTO ssh_keys (key_type, public_key, comment) VALUES (?, ?, ?)',
                (key_type, public_key, comment)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            raise ValueError("Public key already exists")
        finally:
            conn.close()

    @staticmethod
    def get_all():
        """Get all SSH keys."""
        conn = get_db()
        try:
            return conn.execute('SELECT * FROM ssh_keys').fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_by_public_key(public_key: str):
        """Get an SSH key by its public key."""
        conn = get_db()
        try:
            return conn.execute(
                'SELECT * FROM ssh_keys WHERE public_key = ?',
                (public_key,)
            ).fetchone()
        finally:
            conn.close() 