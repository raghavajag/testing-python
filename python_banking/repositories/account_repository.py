"""
Account Repository - Data access layer for accounts
"""

from utils.database_helper import DatabaseHelper
from utils.query_builder import QueryBuilder

class AccountRepository:
    def __init__(self):
        self.db_helper = DatabaseHelper()
        self.query_builder = QueryBuilder()
    
    def search_accounts_raw(self, search_term, account_type):
        """
        Search accounts using raw SQL - VULNERABLE
        This is the sink for VULN_1
        """
        # Delegate to query builder for execution
        results = self.query_builder.execute_search_query(search_term, account_type)
        return results
    
    def find_account_by_number(self, account_number):
        """
        Find account by number - uses parameterized query
        """
        query = "SELECT * FROM accounts WHERE account_number = ?"
        params = [account_number]
        
        result = self.db_helper.execute_parameterized_query(query, params)
        return result[0] if result else None
    
    def get_balance_raw(self, account_number):
        """
        Get account balance using raw SQL - VULNERABLE
        This is the sink for VULN_3
        """
        query = f"SELECT balance FROM accounts WHERE account_number = '{account_number}'"
        
        result = self.db_helper.execute_raw_query(query)
        return result[0]['balance'] if result else 0
    
    def get_transactions_in_range(self, account_number, start_date, end_date):
        """
        Get transactions in date range - VULNERABLE
        This is the sink for VULN_4
        """
        query = self.query_builder.build_date_range_query(
            account_number, start_date, end_date
        )
        
        results = self.db_helper.execute_raw_query(query)
        return results
    
    def execute_transfer(self, from_account, to_account, amount):
        """
        Execute fund transfer
        """
        query = self.query_builder.build_transfer_query(
            from_account, to_account, amount
        )
        
        result = self.db_helper.execute_transaction(query)
        return result
