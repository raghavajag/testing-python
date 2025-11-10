# Report Service Layer  
from utils.template_renderer import TemplateRenderer
from database.report_repository import ReportRepository

class ReportService:
    def __init__(self):
        self.template_renderer = TemplateRenderer()
        self.report_repo = ReportRepository()
    
    # VULN 2: TRUE_POSITIVE - SSTI Path
    def process_report_request(self, template):
        """Process report generation request - VULNERABLE"""
        # Chain: process_report_request → render_report_template → generate_html_report
        report_data = self.render_report_template(template)
        return report_data
    
    def render_report_template(self, template):
        """Render report template - NO ESCAPING"""
        # Get report data
        data = self.report_repo.get_report_data()
        return self.template_renderer.generate_html_report(template, data)
