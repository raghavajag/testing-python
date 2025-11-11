"""
Admin Service - Admin-only operations
Contains paths for VULN_4 (protected) and VULN_8 (good_to_fix)
"""

from repositories.user_repository import UserRepository
from repositories.audit_repository import AuditRepository
from services.query_builder import QueryBuilder

class AdminService:
    def __init__(self):
        self.user_repository = UserRepository()
        self.audit_repository = AuditRepository()
        self.query_builder = QueryBuilder()
    
    # ===== VULN_4 PATHS (FALSE_POSITIVE_PROTECTED) =====
    
    def search_users_advanced(self, search_query, filters):
        """
        VULN_4 - Path 1 Function 2/6
        PROTECTED by @require_admin + @require_csrf_token + @rate_limit
        """
        # Build search criteria
        criteria = self.query_builder.build_user_search_criteria(search_query, filters)
        
        # Execute search
        return self._execute_protected_user_search(criteria)
    
    def _execute_protected_user_search(self, criteria):
        """VULN_4 - Path 1 Function 3/6"""
        # Additional validation
        validated_criteria = self.query_builder.validate_search_criteria(criteria)
        
        # Search via repository (has SQL injection but protected by auth)
        return self.user_repository.search_users_raw(validated_criteria)
    
    def search_audit_logs(self, user_filter, action_filter):
        """
        VULN_4 - Path 3 Function 2/6
        PROTECTED by @require_admin + @require_csrf_token
        """
        # Build audit query
        query = self.query_builder.build_audit_query(user_filter, action_filter)
        
        # Execute audit search
        return self.audit_repository.search_logs_raw(query)
    
    # ===== VULN_8 PATHS (GOOD_TO_FIX - Weak validation) =====
    
    def lookup_customer_data(self, customer_id, search_type):
        """
        VULN_8 - Path 1 Function 2/5
        Has validation but can be bypassed
        """
        # Weak validation - only checks if not empty
        if not customer_id:
            return []
        
        # VULNERABLE: Validation is too weak
        return self.user_repository.lookup_by_id_unsafe(customer_id, search_type)
    
    def generate_custom_report(self, report_type, query_string):
        """
        VULN_8 - Path 3 Function 2/6
        Custom reporting with weak validation
        """
        # Check report type is allowed
        allowed_types = ['sales', 'users', 'products', 'orders']
        if report_type not in allowed_types:
            return {'error': 'Invalid report type'}
        
        # VULNERABLE: Query string not sanitized
        query = self.query_builder.build_report_query(report_type, query_string)
        return self.user_repository.execute_report_query(query)
