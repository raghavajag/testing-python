"""
Admin Controller - Handles admin operations
Contains VULN-6 and VULN-7 with template injection patterns
"""
from services.admin_service import AdminService

class AdminController:
    def __init__(self):
        self.admin_service = AdminService()
    
    def process_bulk_update(self, template: str, products: list):
        """
        VULN-6 Chain Step 1: Entry point for bulk product update
        Template is sanitized before use - FP_SANITIZED
        """
        return self.admin_service.validate_template(template, products)
    
    def generate_dashboard(self, user_id: str):
        """
        VULN-7 Chain Step 1: Entry point for dashboard generation
        Template from trusted sources only - FP_SAFE_CONTEXT
        """
        return self.admin_service.generate_dashboard(user_id)
