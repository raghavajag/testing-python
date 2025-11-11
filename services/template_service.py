"""
Template Service - VULNERABILITY 2
===================================
Contains SSTI (Server-Side Template Injection) in render_user_template()

VULN 2: render_template_string(template_str) with unsanitized input
"""

from flask import render_template_string
from typing import Optional
from demo_vuln.services.user_service import UserService


class TemplateService:
    """Template rendering service - Contains VULN 2: SSTI"""

    def __init__(self, user_service: UserService):
        self.user_service = user_service

    def render_user_template(self, template_str: str) -> str:
        """
        Render user template - VULNERABLE SINK #2
        
        VULN 2: SSTI (Server-Side Template Injection) SINK
        This function renders templates with unsanitized user input
        """
        # VULN 2: SSTI - render_template_string with unsanitized input
        return render_template_string(template_str)  # Dangerous!

    def render_safe_template(self, user_id: str) -> str:
        """
        Render template with sanitized input - PROTECTED
        Uses predefined template with proper escaping
        """
        # Sanitize by using predefined template
        template = "<h1>User Profile</h1><p>ID: {{ user_id }}</p>"
        return render_template_string(template, user_id=user_id)


class EmailService:
    """Email generation service - Intermediate layer"""

    def __init__(self, template_service: TemplateService):
        self.template_service = template_service

    def generate_email(self, template: str) -> str:
        """Generate email from template - passes through to TemplateService"""
        return self.template_service.render_user_template(template)

    def generate_welcome_email(self, username: str) -> str:
        """
        Generate welcome email - SANITIZED
        Uses safe template with proper escaping
        """
        # Uses safe template with escaping
        safe_template = "<h1>Welcome!</h1><p>Hello {{ username }}</p>"
        return render_template_string(safe_template, username=username)


class NotificationService:
    """Notification service - Middle layer"""

    def __init__(self, email_service: EmailService):
        self.email_service = email_service

    def send_notification(self, template: str) -> str:
        """Send notification - passes through to EmailService"""
        return self.email_service.generate_email(template)

    def send_custom_notification(self, message: str) -> str:
        """Send custom notification"""
        template = f"<div>{message}</div>"
        return self.send_notification(template)


class MarketingService:
    """Marketing campaign service - Top layer"""

    def __init__(self, notification_service: NotificationService):
        self.notification_service = notification_service

    def send_campaign(self, campaign_template: str) -> str:
        """Send marketing campaign - passes through to NotificationService"""
        return self.notification_service.send_notification(campaign_template)

    def send_personalized_campaign(self, user_id: str, template: str) -> str:
        """Send personalized campaign"""
        return self.send_campaign(template)
