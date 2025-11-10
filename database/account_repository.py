# Account Repository - Database Layer
import sqlite3

class AccountRepository:
    def __init__(self):
        self.db_path = 'banking.db'
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)
    
    # VULN 1: TRUE_POSITIVE - SQL INJECTION SINK
    def execute_user_search_query(self, query):
        """Execute user search query - VULNERABLE SINK"""
        conn = self.get_connection()
        cursor = conn.cursor()
        # DIRECT SQL EXECUTION WITHOUT PARAMETERIZATION
        cursor.execute(query)  # VULN 1: SQL INJECTION SINK
        results = cursor.fetchall()
        conn.close()
        return results
    
    # VULN 3: FALSE_POSITIVE_SANITIZED - Parameterized query
    def execute_safe_account_query(self, query, account_id):
        """Execute account query with parameterization - SAFE"""
        conn = self.get_connection()
        cursor = conn.cursor()
        # PARAMETERIZED QUERY - SAFE despite being flagged
        cursor.execute(query, (account_id,))  # Safe: parameterized
        results = cursor.fetchone()
        conn.close()
        return results
    
    def get_user_by_token(self, token):
        """Get user by token"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE token = ?", (token,))
        result = cursor.fetchone()
        conn.close()
        return result
    
    # VULN 5: FALSE_POSITIVE_UNREACHABLE - Dead code sink
    def execute_legacy_search(self, query):
        """Legacy search - DEAD CODE"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query)  # Sink in dead code
        results = cursor.fetchall()
        conn.close()
        return results
