"""
Account Service - Business logic for account operations
"""

from repositories.account_repository import AccountRepository
from services.validation_service import ValidationService
from utils.auth_helper import AuthHelper
from utils.logger_helper import LoggerHelper

class AccountService:
    def __init__(self):
        self.account_repository = AccountRepository()
        self.validation_service = ValidationService()
        self.auth_helper = AuthHelper()
        self.logger = LoggerHelper()
    
    def search_by_criteria(self, search_term, account_type):
        """
        Business logic for searching accounts
        Calls validation then repository
        """
        self.logger.log_search_request(search_term, account_type)
        
        # Pass validated input through to repository
        validated_input = self.validation_service.validate_and_sanitize(search_term, account_type)
        
        results = self.account_repository.search_accounts_raw(validated_input['term'], validated_input['type'])
        return results
    
    def process_transfer(self, from_account, to_account, amount):
        """
        Business logic for fund transfers
        """
        validated_accounts = self.validation_service.validate_account_ids(
            from_account, to_account
        )
        
        from_acc = self.account_repository.find_account_by_number(from_account)
        to_acc = self.account_repository.find_account_by_number(to_account)
        
        if from_acc and to_acc:
            result = self.account_repository.execute_transfer(
                from_account, to_account, amount
            )
            return result
        return {"error": "Account not found"}
    
    def get_account_balance(self, token):
        """
        Get account balance from token
        """
        account_number = self.auth_helper.extract_account_from_token(token)
        
        balance = self.account_repository.get_balance_raw(account_number)
        return balance
    
    def generate_statement(self, account_number, start_date, end_date):
        """
        Generate account statement for date range
        """
        date_range = self.validation_service.parse_date_range(start_date, end_date)
        
        transactions = self.account_repository.get_transactions_in_range(
            account_number, date_range['start'], date_range['end']
        )
        
        return {
            "account": account_number,
            "transactions": transactions,
            "period": date_range
        }
