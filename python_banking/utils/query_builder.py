"""
Query Builder - SQL query construction
"""

from utils.string_helper import StringHelper
from utils.database_helper import DatabaseHelper

class QueryBuilder:
    def __init__(self):
        self.string_helper = StringHelper()
        self.db_helper = DatabaseHelper()
    
    def execute_search_query(self, search_term, account_type):
        """
        Build and execute search query - orchestrates the whole flow
        """
        # Build the query
        query = self.build_search_query(search_term, account_type)
        
        # Format it
        formatted_query = self.format_query_for_execution(query)
        
        # Execute using database helper
        results = self.db_helper.execute_raw_query(formatted_query)
        return results
    
    def build_search_query(self, search_term, account_type):
        """
        Build search query - VULNERABLE: String concatenation
        """
        if account_type:
            query = f"SELECT * FROM accounts WHERE name LIKE '%{search_term}%' AND type = '{account_type}'"
        else:
            query = f"SELECT * FROM accounts WHERE name LIKE '%{search_term}%'"
        
        return query
    
    def format_query_for_execution(self, query):
        """
        Format query before execution - adds prefixes/suffixes
        Normalizes the query string first
        """
        # Normalize before formatting
        normalized = self.string_helper.normalize_string(query)
        
        formatted = normalized.strip()
        if not formatted.endswith(';'):
            formatted += ';'
        return formatted
    
    def build_date_range_query(self, account_number, start_date, end_date):
        """
        Build date range query - VULNERABLE
        """
        query = f"""
            SELECT * FROM transactions 
            WHERE account_number = '{account_number}' 
            AND transaction_date BETWEEN '{start_date}' AND '{end_date}'
            ORDER BY transaction_date DESC
        """
        return query
    
    def build_transfer_query(self, from_account, to_account, amount):
        """
        Build transfer query
        """
        queries = [
            f"UPDATE accounts SET balance = balance - {amount} WHERE account_number = '{from_account}'",
            f"UPDATE accounts SET balance = balance + {amount} WHERE account_number = '{to_account}'",
            f"INSERT INTO transactions (from_account, to_account, amount) VALUES ('{from_account}', '{to_account}', {amount})"
        ]
        return queries
