# Report Repository
import sqlite3

class ReportRepository:
    def __init__(self):
        self.db_path = 'banking.db'
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)
    
    def get_report_data(self):
        """Get report data"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 100")
        results = cursor.fetchall()
        conn.close()
        return results
