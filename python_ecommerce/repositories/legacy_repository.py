"""
Legacy Repository - DEAD CODE repository
Contains SINKS for VULN_1 (dead_code) - all paths unreachable
"""

import sqlite3

class LegacyRepository:
    """
    This entire repository is DEAD CODE - never called
    """
    def __init__(self):
        self.db_connection = self._get_db_connection()
    
    def _get_db_connection(self):
        conn = sqlite3.connect('legacy.db')
        conn.row_factory = sqlite3.Row
        return conn
    
    def search_legacy_db(self, query):
        """
        VULN_1 - Path 1 SINK (Function 5/5) - DEAD CODE
        SQL injection but entire path is unreachable
        """
        cursor = self.db_connection.cursor()
        
        # VULNERABLE but DEAD CODE
        sql = f"SELECT * FROM legacy_products WHERE name LIKE '%{query}%'"
        cursor.execute(sql)  # VULN 1: SQL INJECTION (DEAD CODE)
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
    
    def execute_old_query(self, param):
        """
        VULN_1 - Path 2 SINK (Function 5/5) - DEAD CODE
        """
        cursor = self.db_connection.cursor()
        
        # VULNERABLE but DEAD CODE
        sql = f"SELECT * FROM old_data WHERE field = '{param}'"
        cursor.execute(sql)  # VULN 1: SQL INJECTION (DEAD CODE)
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
    
    def search_archive(self, search_key):
        """
        VULN_1 - Path 3 SINK (Function 5/5) - DEAD CODE
        """
        cursor = self.db_connection.cursor()
        
        # VULNERABLE but DEAD CODE
        sql = f"SELECT * FROM archive WHERE search_key = '{search_key}'"
        cursor.execute(sql)  # VULN 1: SQL INJECTION (DEAD CODE)
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
