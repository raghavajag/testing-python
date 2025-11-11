"""
Legacy Repository - Deprecated database operations (Dead Code)
Contains VULN-4 unreachable path sink
"""
import sqlite3

class LegacyRepository:
    def __init__(self):
        self.db_path = 'ecommerce.db'
    
    def old_query_method(self, order_id: str):
        """
        VULN-4 Dead Path SINK: SQL Injection in unreachable code
        This method is never called due to dead code in controller
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Vulnerable but unreachable
        query = f"SELECT * FROM orders_legacy WHERE id = '{order_id}'"
        cursor.execute(query)  # Dead code sink - never reached
        results = cursor.fetchall()
        conn.close()
        return results
