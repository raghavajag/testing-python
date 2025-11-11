"""
Order Repository - Database operations for orders
Contains VULN-4 and VULN-5 SINKS
"""
import sqlite3

class OrderRepository:
    def __init__(self):
        self.db_path = 'ecommerce.db'
    
    def execute_order_query(self, order_id: str, customer: str):
        """
        VULN-4 SINK: SQL Injection vulnerability
        TRUE POSITIVE - Unsafe query with user input
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # VULNERABLE: Direct string interpolation
        if customer:
            query = f"SELECT * FROM orders WHERE order_id = '{order_id}' AND customer_name = '{customer}'"
        else:
            query = f"SELECT * FROM orders WHERE order_id = '{order_id}'"
        
        cursor.execute(query)  # VULN 4: SQL INJECTION SINK
        results = cursor.fetchall()
        conn.close()
        return results
    
    def execute_report_query(self, validated_params: dict):
        """
        VULN-5 SINK: SQL Injection pattern in safe context
        FALSE POSITIVE - Uses parameterized queries despite pattern detection
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Safe: Using parameterized queries despite being flagged
        query = f"SELECT * FROM orders WHERE report_type = ? AND date BETWEEN ? AND ?"
        cursor.execute(query, (
            validated_params['type'],
            validated_params['start_date'],
            validated_params['end_date']
        ))  # Pattern detected but safe context - FP_SAFE_CONTEXT
        results = cursor.fetchall()
        conn.close()
        return results
