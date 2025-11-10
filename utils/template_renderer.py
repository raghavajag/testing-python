# Template Renderer Utility
from flask import render_template_string
from markupsafe import escape

class TemplateRenderer:
    # VULN 2: TRUE_POSITIVE - SSTI SINK
    def generate_html_report(self, template, data):
        """Generate HTML report - VULNERABLE SINK"""
        # Direct template rendering without escaping
        return render_template_string(template)  # VULN 2: SSTI SINK
    
    # VULN 4: FALSE_POSITIVE_SANITIZED - Safe rendering with escaping
    def render_safe_profile(self, template, data):
        """Render profile safely with escaping"""
        # Escape all data before rendering
        safe_data = {k: escape(str(v)) for k, v in data.items()}
        return render_template_string(template, **safe_data)
    
    # VULN 6: FALSE_POSITIVE_UNREACHABLE - Dead code sink
    def render_admin_template(self, template, data):
        """Render admin template - UNREACHABLE"""
        # This function is never called
        return render_template_string(template)  # Unreachable sink
    
    # VULN 7: FALSE_POSITIVE_MISCONFIGURATION - Constant template
    def render_status_template(self, template, data):
        """Render status with hardcoded template - SAFE"""
        # Template is a constant string from code, not user input
        # Even though it calls render_template_string, template is safe
        return render_template_string(template, **data)
