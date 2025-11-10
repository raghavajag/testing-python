# Session Repository
import sqlite3

class SessionRepository:
    def __init__(self):
        self.db_path = 'banking.db'
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)
    
    def get_session(self, token_hash):
        """Get session by token hash"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE token_hash = ?", (token_hash,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return {'user_id': result[1], 'token': result[0]}
        return None
