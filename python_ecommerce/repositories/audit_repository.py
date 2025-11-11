# Audit Repository stub
import sqlite3

class AuditRepository:
    def __init__(self):
        self.db = sqlite3.connect('ecommerce.db')
    
    def search_logs_raw(self, query):
        """VULN_4 Path 3 SINK"""
        cursor = self.db.cursor()
        sql = f"SELECT * FROM audit_logs WHERE {query}"
        cursor.execute(sql)  # VULN 4: SQL INJECTION (PROTECTED)
        return [dict(row) for row in cursor.fetchall()]
