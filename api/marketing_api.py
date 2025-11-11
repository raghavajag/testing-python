"""
Marketing API
==============
Marketing endpoints with admin protection

These paths demonstrate FALSE POSITIVE - PROTECTED classification for SSTI
"""

from demo_vuln.services.template_service import MarketingService
from demo_vuln.auth import AuthService


class ProtectedMarketingAPI:
    """
    Protected marketing API - requires admin privileges
    
    This creates PROTECTED attack paths for SSTI that should be classified as
    FALSE POSITIVE due to admin authorization requirements
    """

    def __init__(self, marketing_service: MarketingService, auth_service: AuthService):
        self.marketing_service = marketing_service
        self.auth_service = auth_service

    def send_admin_campaign(self, template: str) -> str:
        """
        Send admin campaign - PROTECTED by admin authorization
        
        Attack path: template → send_admin_campaign → [ADMIN CHECK] →
                     marketing_service.send_campaign → ... → SSTI SINK
        
        Classification: FALSE POSITIVE - PROTECTED
        Reason: Requires admin privileges, limiting SSTI exploitation to admins
        """
        if not self.auth_service.is_admin():
            raise PermissionError("Admin privileges required")
        return self.marketing_service.send_campaign(template)
    
    def send_authenticated_notification(self, template: str) -> str:
        """
        Send authenticated notification - PROTECTED by authentication
        
        Attack path: template → send_authenticated_notification → [AUTH CHECK] →
                     marketing_service.send_campaign → ... → SSTI SINK
        
        Classification: FALSE POSITIVE - PROTECTED
        Reason: Requires authentication, limiting exploitation scope
        """
        if not self.auth_service.is_authenticated():
            raise PermissionError("Authentication required")
        return self.marketing_service.send_campaign(template)
