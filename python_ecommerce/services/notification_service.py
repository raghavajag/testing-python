"""
Notification Service - Handles email/notification rendering
Contains VULNERABILITY SINKS for VULN_3 (sanitized) and VULN_7 (must_fix)
"""

from flask import render_template_string
from services.template_renderer import TemplateRenderer
from services.email_validator import EmailValidator

class NotificationService:
    def __init__(self):
        self.template_renderer = TemplateRenderer()
        self.email_validator = EmailValidator()
    
    # ===== VULN_3 SINKS (FALSE_POSITIVE_SANITIZED - ALLOWLIST VALIDATION) =====
    
    def send_validated_email(self, email_content):
        """
        VULN_3 - Path 1 Function 5/6
        Send email with pre-validated template
        """
        # Use validated template from allowlist
        rendered = self.template_renderer.render_from_validated_template(email_content)
        return {'status': 'sent', 'content': rendered}
    
    def send_custom_notification(self, order_id, notification_type, template_data):
        """
        VULN_3 - Path 2 Function 3/6
        Send custom notification with validation
        """
        # Validate notification type against allowed types
        if not self.email_validator.is_allowed_notification_type(notification_type):
            return {'status': 'error', 'message': 'Invalid notification type'}
        
        # Render with safe template
        return self.template_renderer.render_safe_notification(
            order_id, notification_type, template_data
        )
    
    def send_status_update(self, notification):
        """
        VULN_3 - Path 3 Function 5/6
        Send status update notification
        """
        # Render using validated template
        rendered = self.template_renderer.render_status_template(notification)
        return {'status': 'sent', 'content': rendered}
    
    # ===== VULN_7 SINKS (MUST_FIX - NO VALIDATION) =====
    
    def preview_email_template(self, template_string, order_data):
        """
        VULN_7 - Path 1 SINK (Function 5/5) - VULNERABLE
        Preview email template - DIRECT SSTI
        """
        # VULNERABLE: Direct template rendering with user input
        return render_template_string(template_string, **order_data)  # VULN 7: SSTI SINK
    
    def send_raw_template_email(self, email_meta, template):
        """
        VULN_7 - Path 2 Function 5/6
        Send email with raw template
        """
        # DANGEROUS: Renders user template directly
        rendered = self.template_renderer.render_unsafe_template(template, email_meta)
        return {'status': 'sent', 'content': rendered}
    
    def render_order_receipt(self, order_id, template):
        """
        VULN_7 - Path 3 SINK (Function 5/5) - VULNERABLE
        Render order receipt from template
        """
        order_data = {'order_id': order_id, 'date': 'today'}
        
        # VULNERABLE: Direct render_template_string with user input
        return render_template_string(template, **order_data)  # VULN 7: SSTI SINK
    
    def render_and_send_campaign(self, campaign_data, template_content):
        """
        VULN_7 - Path 4 Function 5/6
        Render and send marketing campaign
        """
        # DANGEROUS: Renders user template
        rendered = self.template_renderer.render_campaign_template(
            template_content, campaign_data
        )
        return {'status': 'sent', 'campaign': rendered}
