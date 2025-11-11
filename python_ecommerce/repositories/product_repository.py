"""
Product Repository - Database access layer
Contains VULNERABILITY SINKS for VULN_2 (sanitized) and VULN_6 (must_fix)
"""

import sqlite3
from typing import List, Dict, Any

class ProductRepository:
    def __init__(self):
        self.db_connection = self._get_db_connection()
    
    def _get_db_connection(self):
        conn = sqlite3.connect('ecommerce.db')
        conn.row_factory = sqlite3.Row
        return conn
    
    # ===== VULN_2 SINK (FALSE_POSITIVE_SANITIZED - ORM) =====
    
    def search_products_safe(self, query, category):
        """
        VULN_2 - Path 1 SINK (Function 5/5) - SANITIZED
        Uses parameterized queries (ORM-style) - SAFE
        """
        cursor = self.db_connection.cursor()
        
        # SAFE: Parameterized query prevents SQL injection
        sql = "SELECT * FROM products WHERE name LIKE ? AND category = ?"
        cursor.execute(sql, (f"%{query}%", category))  # SAFE - parameterized
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
    
    def search_with_filters(self, params):
        """
        VULN_2 - Path 2 SINK (Function 6/6) - SANITIZED
        ORM-style search with filters - SAFE
        """
        cursor = self.db_connection.cursor()
        
        # Build safe parameterized query
        query_parts = []
        query_params = []
        
        if 'name' in params:
            query_parts.append("name LIKE ?")
            query_params.append(f"%{params['name']}%")
        
        if 'category' in params:
            query_parts.append("category = ?")
            query_params.append(params['category'])
        
        where_clause = " AND ".join(query_parts) if query_parts else "1=1"
        sql = f"SELECT * FROM products WHERE {where_clause}"
        
        # SAFE: Parameterized execution
        cursor.execute(sql, tuple(query_params))
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
    
    # ===== VULN_6 SINKS (MUST_FIX - NO SANITIZATION) =====
    
    def quick_search_raw(self, search_term):
        """
        VULN_6 - Path 1 SINK (Function 5/5) - VULNERABLE
        Direct SQL concatenation - SQL INJECTION
        """
        cursor = self.db_connection.cursor()
        
        # VULNERABLE: String concatenation in SQL query
        query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
        cursor.execute(query)  # VULN 6: SQL INJECTION SINK
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
    
    def legacy_search_unsafe(self, term):
        """
        VULN_6 - Path 2 SINK (Function 5/5) - VULNERABLE
        Legacy search with string formatting - SQL INJECTION
        """
        cursor = self.db_connection.cursor()
        
        # VULNERABLE: String formatting in SQL
        query = "SELECT * FROM products WHERE description LIKE '%{}%' OR name LIKE '%{}%'".format(term, term)
        cursor.execute(query)  # VULN 6: SQL INJECTION SINK
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
    
    def execute_raw_search(self, term):
        """
        VULN_6 - Path 3 SINK (Function 6/6) - VULNERABLE
        Raw search execution - SQL INJECTION
        """
        cursor = self.db_connection.cursor()
        
        # VULNERABLE: Direct string concatenation
        query = f"SELECT * FROM products WHERE name = '{term}' OR sku = '{term}'"
        cursor.execute(query)  # VULN 6: SQL INJECTION SINK
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
    
    def search_in_category_raw(self, category, keyword):
        """
        VULN_6 - Path 4 SINK (Function 6/6) - VULNERABLE
        Category search with concatenation - SQL INJECTION
        """
        cursor = self.db_connection.cursor()
        
        # VULNERABLE: String concatenation
        query = f"SELECT * FROM products WHERE category = '{category}' AND (name LIKE '%{keyword}%' OR description LIKE '%{keyword}%')"
        cursor.execute(query)  # VULN 6: SQL INJECTION SINK
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
