"""
Template Processor - Template handling middleware
VULN-6 sanitization happens here
"""
import re
from markupsafe import escape

class TemplateProcessor:
    def sanitize_template_input(self, template: str):
        """
        VULN-6 Chain Step 3: Sanitize template input
        Proper escaping and sanitization - FP_SANITIZED
        """
        # Escape HTML and potentially dangerous characters
        sanitized = escape(template)
        # Remove any remaining template injection patterns
        sanitized = re.sub(r'\{\{.*?\}\}', '', str(sanitized))
        sanitized = re.sub(r'\{%.*?%\}', '', sanitized)
        return sanitized
    
    def render_update_template(self, sanitized_template: str, products: list):
        """
        VULN-6 Chain Step 4: Render template (SINK)
        Template is already sanitized - FP_SANITIZED
        """
        from flask import render_template_string
        # Even though this is render_template_string, input is sanitized
        return render_template_string(sanitized_template)  # FP: Sanitized input
