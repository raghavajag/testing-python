"""
Product Repository - Database operations for products
Contains VULN-1, VULN-2, VULN-3 SINKS
"""
import sqlite3

class ProductRepository:
    def __init__(self):
        self.db_path = 'ecommerce.db'
    
    def execute_search_query(self, search_term: str, category: str):
        """
        VULN-1 SINK: SQL Injection vulnerability
        TRUE POSITIVE - Unsafe query construction
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # VULNERABLE: String concatenation in SQL query
        if category:
            query = f"SELECT * FROM products WHERE name LIKE '{search_term}' AND category = '{category}'"
        else:
            query = f"SELECT * FROM products WHERE name LIKE '{search_term}'"
        
        cursor.execute(query)  # VULN 1: SQL INJECTION SINK
        results = cursor.fetchall()
        conn.close()
        return results
    
    def execute_filter_query(self, filters: dict):
        """
        VULN-2 SINK: SQL Injection pattern but sanitized
        FALSE POSITIVE - Input is sanitized before reaching here
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Build query from sanitized filters
        conditions = []
        for key, value in filters.items():
            conditions.append(f"{key} = '{value}'")
        
        query = "SELECT * FROM products WHERE " + " AND ".join(conditions)
        cursor.execute(query)  # Pattern detected but input is sanitized - FP_SANITIZED
        results = cursor.fetchall()
        conn.close()
        return results
    
    def execute_legacy_query(self, search: str):
        """
        VULN-3 SINK: SQL Injection in dead code
        FALSE POSITIVE - Unreachable code path
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Vulnerable pattern but never reached
        query = f"SELECT * FROM products WHERE id = '{search}'"
        cursor.execute(query)  # Pattern detected but code is dead - FP_DEAD_CODE
        results = cursor.fetchall()
        conn.close()
        return results
