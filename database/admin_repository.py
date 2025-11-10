# Admin Repository
import sqlite3

class AdminRepository:
    def __init__(self):
        self.db_path = 'banking.db'
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)
    
    def get_panel_data(self):
        """Get admin panel data"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin_panels")
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_current_status(self):
        """Get current system status"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT status, uptime FROM system_status ORDER BY timestamp DESC LIMIT 1")
        result = cursor.fetchone()
        conn.close()
        if result:
            return {'status': result[0], 'uptime': result[1]}
        return {'status': 'unknown', 'uptime': 0}
    
    # VULN 8: FALSE_POSITIVE_MISCONFIGURATION - Predefined query sink
    def run_health_query(self, health_query):
        """Run health check query - SAFE (predefined query from config)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(health_query)  # Query from config file, not user input
        result = cursor.fetchone()
        conn.close()
        return {'healthy': result[0] if result else False}
