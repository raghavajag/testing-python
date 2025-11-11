"""
Legacy Services - DEAD CODE
============================
These services are never instantiated or called

These paths demonstrate FALSE POSITIVE - DEAD CODE classification
"""

from typing import Optional, Dict, Any, List
from demo_vuln.services.user_service import UserService
from demo_vuln.services.template_service import TemplateService
from demo_vuln.services.analytics_service import AnalyticsService


class UnusedLegacyService:
    """
    Legacy user service that is NEVER instantiated or called - DEAD CODE
    
    This creates DEAD CODE attack paths that should be classified as
    FALSE POSITIVE because the code is unreachable
    """

    def __init__(self, user_service: UserService):
        self.user_service = user_service

    def legacy_user_lookup(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Legacy method - NEVER CALLED
        
        Attack path: user_id → legacy_user_lookup → user_service.find_user_by_id →
                     ... → SQL INJECTION SINK
        
        Classification: FALSE POSITIVE - DEAD CODE
        Reason: This entire class is never instantiated in app.py
        """
        return self.user_service.find_user_by_id(user_id)
    
    def deprecated_user_report(self, user_id: str) -> str:
        """
        Deprecated method - NEVER CALLED
        
        Classification: FALSE POSITIVE - DEAD CODE
        """
        user = self.user_service.find_user_by_id(user_id)
        return f"[DEPRECATED] User: {user}" if user else "Not found"


class DeadTemplateService:
    """
    Template service that is NEVER used - DEAD CODE
    
    This creates DEAD CODE attack paths for SSTI
    """

    def __init__(self, template_service: TemplateService):
        self.template_service = template_service

    def render_legacy_template(self, template: str) -> str:
        """
        Legacy template rendering - NEVER CALLED
        
        Attack path: template → render_legacy_template →
                     template_service.render_user_template → ... → SSTI SINK
        
        Classification: FALSE POSITIVE - DEAD CODE
        Reason: This entire class is never instantiated in app.py
        """
        return self.template_service.render_user_template(template)
    
    def deprecated_email_template(self, template: str) -> str:
        """
        Deprecated email template - NEVER CALLED
        
        Classification: FALSE POSITIVE - DEAD CODE
        """
        return self.template_service.render_user_template(f"<email>{template}</email>")


class UnusedAnalyticsService:
    """
    Analytics service that is NEVER used - DEAD CODE
    
    This creates DEAD CODE attack paths for analytics SQL injection
    """

    def __init__(self, analytics_service: AnalyticsService):
        self.analytics_service = analytics_service

    def get_legacy_stats(self, filter_str: str) -> List[Dict[str, Any]]:
        """
        Legacy stats - NEVER CALLED
        
        Attack path: filter_str → get_legacy_stats →
                     analytics_service.get_user_stats → ... → SQL INJECTION SINK
        
        Classification: FALSE POSITIVE - DEAD CODE
        Reason: This entire class is never instantiated in app.py
        """
        return self.analytics_service.get_user_stats(filter_str)
    
    def deprecated_dashboard_stats(self, filter_str: str) -> List[Dict[str, Any]]:
        """
        Deprecated dashboard stats - NEVER CALLED
        
        Classification: FALSE POSITIVE - DEAD CODE
        """
        return self.analytics_service.get_user_stats(f"legacy_{filter_str}")
