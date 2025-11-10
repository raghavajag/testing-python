# Permission Repository
import sqlite3
import json

class PermissionRepository:
    def __init__(self):
        self.db_path = 'banking.db'
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)
    
    def fetch_permissions(self, user_id):
        """Fetch user permissions"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT permissions FROM user_permissions WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return json.loads(result[0])
        return []
    
    def get_admin_config(self):
        """Get admin configuration"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT config_value FROM system_config WHERE config_key = 'admin_users'")
        result = cursor.fetchone()
        conn.close()
        if result:
            return json.loads(result[0])
        return {'admin_users': []}
