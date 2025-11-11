"""
Template Renderer - Final rendering layer
Contains actual SSTI sinks for VULN_7
"""

from flask import render_template_string

class TemplateRenderer:
    def __init__(self):
        self.safe_templates = {
            'order_confirm': '<h1>Order Confirmed</h1><p>Order ID: {{ order_id }}</p>',
            'status_update': '<h1>Status Update</h1><p>Status: {{ status }}</p>',
            'notification': '<div>Notification: {{ message }}</div>'
        }
    
    # SAFE methods for VULN_3
    def render_from_validated_template(self, content):
        """Safe rendering with predefined templates"""
        template_name = content.get('template', 'default')
        if template_name in self.safe_templates:
            return render_template_string(self.safe_templates[template_name], **content)
        return "Invalid template"
    
    def render_safe_notification(self, order_id, notif_type, data):
        """Safe notification rendering"""
        safe_template = self.safe_templates.get('notification', '')
        return render_template_string(safe_template, order_id=order_id, **data)
    
    def render_status_template(self, notification):
        """Safe status rendering"""
        return render_template_string(
            self.safe_templates['status_update'],
            **notification
        )
    
    # VULNERABLE methods for VULN_7
    def render_unsafe_template(self, template, data):
        """
        VULN_7 SINK - Direct rendering of user template
        """
        return render_template_string(template, **data)  # VULN 7: SSTI SINK
    
    def render_campaign_template(self, template_content, campaign_data):
        """
        VULN_7 SINK - Marketing campaign rendering
        """
        return render_template_string(template_content, **campaign_data)  # VULN 7: SSTI SINK
