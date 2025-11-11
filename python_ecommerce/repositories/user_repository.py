"""
User Repository - User data access
Contains SINKS for VULN_4 (protected) and VULN_8 (good_to_fix)
"""

import sqlite3

class UserRepository:
    def __init__(self):
        self.db_connection = self._get_db_connection()
    
    def _get_db_connection(self):
        conn = sqlite3.connect('ecommerce.db')
        conn.row_factory = sqlite3.Row
        return conn
    
    # ===== VULN_4 SINKS (FALSE_POSITIVE_PROTECTED) =====
    
    def search_users_raw(self, criteria):
        """
        VULN_4 - Path 1 SINK (Function 6/6) - PROTECTED
        SQL injection but protected by @require_admin + @require_csrf_token + @rate_limit
        """
        cursor = self.db_connection.cursor()
        
        # VULNERABLE: String concatenation BUT protected by multiple security layers
        query = f"SELECT * FROM users WHERE username LIKE '%{criteria}%' OR email LIKE '%{criteria}%'"
        cursor.execute(query)  # VULN 4: SQL INJECTION (BUT PROTECTED)
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
    
    # ===== VULN_8 SINKS (GOOD_TO_FIX) =====
    
    def lookup_by_id_unsafe(self, customer_id, search_type):
        """
        VULN_8 - Path 1 SINK (Function 5/5) - GOOD_TO_FIX
        Has weak validation, can be bypassed
        """
        cursor = self.db_connection.cursor()
        
        # VULNERABLE: Weak validation allows SQL injection
        if search_type == 'exact':
            query = f"SELECT * FROM customers WHERE id = '{customer_id}'"
        else:
            query = f"SELECT * FROM customers WHERE id LIKE '%{customer_id}%'"
        
        cursor.execute(query)  # VULN 8: SQL INJECTION (Weak validation)
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
    
    def execute_report_query(self, query):
        """
        VULN_8 - Path 3 SINK (Function 6/6) - GOOD_TO_FIX
        Report query execution with weak validation
        """
        cursor = self.db_connection.cursor()
        
        # VULNERABLE: Query string not properly sanitized
        full_query = f"SELECT * FROM users WHERE {query}"
        cursor.execute(full_query)  # VULN 8: SQL INJECTION (Weak validation)
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
