"""
Order Service - Business logic for orders
Contains paths for VULN_3 (sanitized) and VULN_7 (must_fix)
"""

from services.notification_service import NotificationService
from services.template_service import TemplateService
from services.email_formatter import EmailFormatter

class OrderService:
    def __init__(self):
        self.notification_service = NotificationService()
        self.template_service = TemplateService()
        self.email_formatter = EmailFormatter()
    
    # ===== VULN_3 PATHS (FALSE_POSITIVE_SANITIZED - VALIDATION) =====
    
    def send_confirmation_email(self, order_id, template_name, custom_message):
        """
        VULN_3 - Path 1 Function 2/6
        Send order confirmation with validated template
        """
        # Validate template name against allowlist
        validated_template = self.template_service.validate_template_name(template_name)
        
        # Build email content
        email_content = self.email_formatter.format_confirmation_email(
            order_id, validated_template, custom_message
        )
        
        # Send via notification service
        return self.notification_service.send_validated_email(email_content)
    
    def notify_status_change(self, order_id, new_status, message):
        """
        VULN_3 - Path 3 Function 2/6
        Notify customer of order status change
        """
        # Sanitize status and message
        safe_status = self.template_service.sanitize_status_value(new_status)
        safe_message = self.template_service.sanitize_message_content(message)
        
        # Format notification
        notification = self.email_formatter.format_status_notification(
            order_id, safe_status, safe_message
        )
        
        # Send notification
        return self.notification_service.send_status_update(notification)
    
    # ===== VULN_7 PATHS (MUST_FIX - NO VALIDATION) =====
    
    def send_custom_order_email(self, recipient, subject, template):
        """
        VULN_7 - Path 2 Function 2/6
        Send custom email - NO TEMPLATE VALIDATION
        """
        # Format email metadata
        email_meta = self.email_formatter.prepare_email_metadata(recipient, subject)
        
        # DANGEROUS: No validation on template
        return self.notification_service.send_raw_template_email(email_meta, template)
    
    def send_marketing_campaign(self, campaign_name, template_content, recipient_list):
        """
        VULN_7 - Path 4 Function 2/6
        Send marketing campaign - VULNERABLE
        """
        # Prepare campaign
        campaign_data = self.email_formatter.prepare_campaign_data(
            campaign_name, recipient_list
        )
        
        # DANGEROUS: Template goes directly to rendering
        return self.notification_service.render_and_send_campaign(
            campaign_data, template_content
        )
