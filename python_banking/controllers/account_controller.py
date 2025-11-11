"""
Account Controller - Entry points for account operations
"""

from flask import Blueprint, request, jsonify
from services.account_service import AccountService
from services.validation_service import ValidationService
from utils.auth_helper import AuthHelper

account_bp = Blueprint('account', __name__)
account_service = AccountService()
validation_service = ValidationService()
auth_helper = AuthHelper()

@account_bp.route('/search', methods=['GET'])
def search_accounts():
    """
    VULN_1: SQL Injection via account search
    Attack Path: search_accounts -> account_service.search_by_criteria -> 
                 validation_service.sanitize_search_input -> 
                 account_repository.search_accounts_raw -> 
                 database_helper.execute_raw_query
    """
    search_term = request.args.get('q', '')
    account_type = request.args.get('type', '')
    
    results = account_service.search_by_criteria(search_term, account_type)
    return jsonify(results)

@account_bp.route('/transfer', methods=['POST'])
def transfer_funds():
    """
    VULN_2: SQL Injection via funds transfer
    Attack Path: transfer_funds -> account_service.process_transfer ->
                 validation_service.validate_account_ids ->
                 account_repository.find_account_by_number ->
                 database_helper.execute_parameterized_query
    """
    data = request.get_json()
    from_account = data.get('from_account')
    to_account = data.get('to_account')
    amount = data.get('amount')
    
    result = account_service.process_transfer(from_account, to_account, amount)
    return jsonify(result)

@account_bp.route('/balance', methods=['GET'])
def get_balance():
    """
    VULN_3: SQL Injection via balance inquiry
    Attack Path: get_balance -> account_service.get_account_balance ->
                 auth_helper.extract_account_from_token ->
                 account_repository.get_balance_raw ->
                 database_helper.execute_raw_query
    """
    token = request.headers.get('Authorization', '')
    
    balance = account_service.get_account_balance(token)
    return jsonify({"balance": balance})

@account_bp.route('/statement', methods=['GET'])
def get_statement():
    """
    VULN_4: SQL Injection via statement generation
    Attack Path: get_statement -> account_service.generate_statement ->
                 validation_service.parse_date_range ->
                 account_repository.get_transactions_in_range ->
                 database_helper.execute_raw_query
    """
    account_number = request.args.get('account')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    statement = account_service.generate_statement(account_number, start_date, end_date)
    return jsonify(statement)
