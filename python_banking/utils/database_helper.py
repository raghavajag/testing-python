"""
Database Helper - Raw database operations (SINK LEVEL)
"""

import sqlite3

class DatabaseHelper:
    def __init__(self):
        self.connection = None
    
    def get_connection(self):
        if not self.connection:
            self.connection = sqlite3.connect('banking.db')
        return self.connection
    
    def execute_raw_query(self, query):
        """
        Execute raw SQL query - VULNERABLE SINK
        This is where SQL injection actually occurs
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query)  # VULNERABLE: Direct query execution
        results = cursor.fetchall()
        return results
    
    def execute_parameterized_query(self, query, params):
        """
        Execute parameterized query - SAFE
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        results = cursor.fetchall()
        return results
    
    def execute_transaction(self, queries):
        """
        Execute multiple queries in a transaction
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            conn.execute("BEGIN TRANSACTION")
            for query in queries:
                cursor.execute(query)
            conn.commit()
            return {"success": True}
        except Exception as e:
            conn.rollback()
            return {"success": False, "error": str(e)}
