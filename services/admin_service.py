# Admin Service Layer
from database.admin_repository import AdminRepository
from utils.template_renderer import TemplateRenderer
from utils.config_loader import ConfigLoader

class AdminService:
    def __init__(self):
        self.admin_repo = AdminRepository()
        self.template_renderer = TemplateRenderer()
        self.config_loader = ConfigLoader()
    
    # VULN 6: FALSE_POSITIVE_UNREACHABLE - No route to this
    def render_internal_panel(self, template):
        """Render internal admin panel - UNREACHABLE"""
        # This function is never called via any route
        panel_data = self.admin_repo.get_panel_data()
        return self.template_renderer.render_admin_template(template, panel_data)
    
    # VULN 7: FALSE_POSITIVE_MISCONFIGURATION - Constant template
    def get_system_status(self):
        """Get system status with safe template"""
        # Chain: get_system_status → format_status_message → build_status_report → render_status_template
        status_data = self.format_status_message()
        report = self.build_status_report(status_data)
        return report
    
    def format_status_message(self):
        """Format status message"""
        return self.admin_repo.get_current_status()
    
    def build_status_report(self, status_data):
        """Build status report"""
        # Use hardcoded safe template
        safe_template = "System Status: {status}, Uptime: {uptime}"
        return self.template_renderer.render_status_template(safe_template, status_data)
    
    # VULN 8: FALSE_POSITIVE_MISCONFIGURATION - Predefined query
    def check_db_connection(self):
        """Check database health - SAFE QUERY"""
        # Chain: check_db_connection → get_db_metrics → run_health_query
        metrics = self.get_db_metrics()
        return metrics
    
    def get_db_metrics(self):
        """Get database metrics"""
        # Load predefined health check query from config
        health_query = self.config_loader.get_health_check_query()
        return self.admin_repo.run_health_query(health_query)
