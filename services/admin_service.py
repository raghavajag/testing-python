"""
Admin Service - Business logic for admin operations
VULN-6 and VULN-7 chain continues here
"""
from middleware.template_processor import TemplateProcessor
from repositories.dashboard_repository import DashboardRepository

class AdminService:
    def __init__(self):
        self.template_processor = TemplateProcessor()
        self.dashboard_repo = DashboardRepository()
    
    def validate_template(self, template: str, products: list):
        """
        VULN-6 Chain Step 2: Validate template input
        Sanitization happens here - FP_SANITIZED
        """
        sanitized = self.template_processor.sanitize_template_input(template)
        return self.template_processor.render_update_template(sanitized, products)
    
    def generate_dashboard(self, user_id: str):
        """
        VULN-7 Chain Step 2: Generate dashboard
        Uses trusted templates only - FP_SAFE_CONTEXT
        """
        dashboard_data = self.dashboard_repo.build_dashboard_data(user_id)
        return self.dashboard_repo.create_dashboard_template(dashboard_data)
