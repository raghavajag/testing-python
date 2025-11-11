# Stub files for remaining dependencies

class CacheService:
    def get_search_cache(self, params):
        return None
    def set_search_cache(self, params, results):
        pass

class EmailValidator:
    def is_allowed_notification_type(self, notif_type):
        allowed = ['email', 'sms', 'push']
        return notif_type in allowed

class EmailFormatter:
    def format_confirmation_email(self, order_id, template, message):
        return {'template': template, 'order_id': order_id, 'message': message}
    
    def format_status_notification(self, order_id, status, message):
        return {'order_id': order_id, 'status': status, 'message': message}
    
    def prepare_email_metadata(self, recipient, subject):
        return {'recipient': recipient, 'subject': subject}
    
    def prepare_campaign_data(self, campaign, recipients):
        return {'campaign': campaign, 'recipients': recipients}

class TemplateService:
    def validate_template_name(self, name):
        allowed = ['default', 'premium', 'express']
        return name if name in allowed else 'default'
    
    def sanitize_status_value(self, status):
        allowed = ['pending', 'shipped', 'delivered']
        return status if status in allowed else 'pending'
    
    def sanitize_message_content(self, message):
        # Remove dangerous characters
        return message.replace('<', '').replace('>', '')

class ReportService:
    def __init__(self):
        from services.template_renderer import TemplateRenderer
        self.renderer = TemplateRenderer()
    
    def create_custom_report(self, report_type, template_name, parameters):
        """VULN_5 Path 1 Function 3/6"""
        from services.template_service import TemplateService
        ts = TemplateService()
        validated = ts.validate_template_name(template_name)
        return self.renderer.render_from_validated_template({'template': validated, **parameters})
    
    def preview_analytics_report(self, metric_type, template_content):
        """VULN_5 Path 3 Function 3/6"""
        # Has validation middleware, renders safely
        return self.renderer.render_from_validated_template({'template': 'analytics', 'metric': metric_type})
