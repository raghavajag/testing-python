"""
Admin API
==========
Admin endpoints with authorization protection

These paths demonstrate FALSE POSITIVE - PROTECTED classification
"""

from typing import List, Dict, Any
from demo_vuln.services.analytics_service import DashboardService
from demo_vuln.auth import AuthService


class AdminAPI:
    """
    Admin API - requires admin privileges
    
    This creates PROTECTED attack paths that should be classified as
    FALSE POSITIVE due to admin authorization requirements
    """

    def __init__(self, dashboard_service: DashboardService, auth_service: AuthService):
        self.dashboard_service = dashboard_service
        self.auth_service = auth_service

    def get_admin_dashboard(self, filter_str: str) -> List[Dict[str, Any]]:
        """
        Get admin dashboard - PROTECTED by admin authorization
        
        Attack path: filter_str → get_admin_dashboard → [ADMIN CHECK] →
                     dashboard_service.get_dashboard_data → ... → SQL INJECTION SINK
        
        Classification: FALSE POSITIVE - PROTECTED
        Reason: Requires admin privileges, limiting exploitation to admins
        """
        if not self.auth_service.is_admin():
            raise PermissionError("Admin privileges required")
        return self.dashboard_service.get_dashboard_data(filter_str)
    
    def get_admin_safe_dashboard(self, filter_str: str) -> List[Dict[str, Any]]:
        """
        Get admin safe dashboard - PROTECTED by admin + SANITIZED by validation
        
        Attack path: filter_str → get_admin_safe_dashboard → [ADMIN CHECK] →
                     dashboard_service.get_filtered_dashboard → [VALIDATION] →
                     ... → SQL INJECTION SINK
        
        Classification: FALSE POSITIVE - PROTECTED + SANITIZED
        Reason: Both admin authorization AND input validation protect this path
        """
        if not self.auth_service.is_admin():
            raise PermissionError("Admin privileges required")
        return self.dashboard_service.get_filtered_dashboard(filter_str)
