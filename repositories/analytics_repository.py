"""
Analytics Repository - Database operations for analytics
Contains VULN-8 SINK
"""
import sqlite3

class AnalyticsRepository:
    def __init__(self):
        self.db_path = 'ecommerce.db'
    
    def execute_analytics(self, query_params: dict, metrics: list):
        """
        VULN-8 SINK: SQL Injection in analytics
        TRUE POSITIVE - Dynamic query building without sanitization
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # VULNERABLE: Build complex query from user input
        table = query_params.get('table', 'analytics')
        filters = query_params.get('filters', {})
        group_by = query_params.get('group_by', [])
        
        # Build WHERE clause
        where_clauses = []
        for key, value in filters.items():
            where_clauses.append(f"{key} = '{value}'")
        
        # Build GROUP BY clause
        group_by_str = ', '.join(group_by) if group_by else ''
        
        # Construct query
        query = f"SELECT {', '.join(metrics)} FROM {table}"
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        if group_by_str:
            query += f" GROUP BY {group_by_str}"
        
        cursor.execute(query)  # VULN 8: SQL INJECTION SINK
        results = cursor.fetchall()
        conn.close()
        return results
