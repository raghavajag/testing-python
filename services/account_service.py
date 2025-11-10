# Account Service Layer
from database.account_repository import AccountRepository
from utils.query_builder import QueryBuilder
from utils.template_renderer import TemplateRenderer

class AccountService:
    def __init__(self):
        self.account_repo = AccountRepository()
        self.query_builder = QueryBuilder()
        self.template_renderer = TemplateRenderer()
    
    # VULN 1: TRUE_POSITIVE - SQL Injection Path
    def search_user_by_name(self, search_term):
        """Search users by name - VULNERABLE"""
        # Chain continues: search_user_by_name → build_search_query → execute_user_search_query
        query = self.build_search_query(search_term)
        return self.account_repo.execute_user_search_query(query)
    
    def build_search_query(self, search_term):
        """Build search query - NO SANITIZATION"""
        # Direct string concatenation - vulnerable
        return self.query_builder.create_user_search_query(search_term)
    
    # VULN 3: FALSE_POSITIVE_SANITIZED - SQL with validation
    def get_account_details(self, account_id):
        """Get account details - SANITIZED"""
        # Chain: get_account_details → check_account_permissions → build_account_query → execute_safe_account_query
        if self.check_account_permissions(account_id):
            query = self.build_account_query(account_id)
            return self.account_repo.execute_safe_account_query(query, account_id)
        return None
    
    def check_account_permissions(self, account_id):
        """Check account access permissions"""
        # Validate account_id is numeric
        return account_id.isdigit()
    
    def build_account_query(self, account_id):
        """Build account query - will be parameterized"""
        return self.query_builder.create_parameterized_query('accounts', account_id)
    
    # VULN 4: FALSE_POSITIVE_SANITIZED - SSTI with escaping
    def load_user_profile(self, token):
        """Load user profile - SAFE RENDERING"""
        # Chain: load_user_profile → format_profile_data → build_profile_template → render_safe_profile
        profile_data = self.format_profile_data(token)
        template = self.build_profile_template(profile_data)
        return self.template_renderer.render_safe_profile(template, profile_data)
    
    def format_profile_data(self, token):
        """Format profile data"""
        # Get user data
        return self.account_repo.get_user_by_token(token)
    
    def build_profile_template(self, profile_data):
        """Build profile template"""
        # Return safe template with placeholders
        return "<div>Name: {{ name }}, Email: {{ email }}</div>"
    
    # VULN 5: FALSE_POSITIVE_UNREACHABLE - Dead code path
    def deprecated_search_accounts(self, query_input):
        """DEPRECATED: Old search function - never called"""
        # This creates a dead code path
        unsafe_query = self.query_builder.create_unsafe_query(query_input)
        return self.account_repo.execute_legacy_search(unsafe_query)
