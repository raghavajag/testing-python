# Query Builder Utility
class QueryBuilder:
    def create_user_search_query(self, search_term):
        """Create user search query - VULNERABLE (no sanitization)"""
        # Direct string concatenation - vulnerable to SQL injection
        return f"SELECT * FROM users WHERE username LIKE '%{search_term}%' OR email LIKE '%{search_term}%'"
    
    def create_parameterized_query(self, table, record_id):
        """Create parameterized query - SAFE"""
        # Returns query with placeholder for parameterization
        return f"SELECT * FROM {table} WHERE id = ?"
    
    def create_unsafe_query(self, query_input):
        """Create unsafe query - for dead code path"""
        return f"SELECT * FROM accounts WHERE account_number = '{query_input}'"
