"""
Protected User API
===================
User endpoints with authentication protection

These paths demonstrate FALSE POSITIVE - PROTECTED classification
"""

from typing import Optional, Dict, Any
from demo_vuln.services.user_service import UserReportService
from demo_vuln.auth import AuthService


class ProtectedUserAPI:
    """
    Protected user API - requires authentication
    
    This creates PROTECTED attack paths that should be classified as
    FALSE POSITIVE due to authentication requirements
    """

    def __init__(self, report_service: UserReportService, auth_service: AuthService):
        self.report_service = report_service
        self.auth_service = auth_service

    def get_user_report(self, user_id: str) -> str:
        """
        Get user report - PROTECTED by authentication
        
        Attack path: user_id → get_user_report → [AUTH CHECK] → 
                     report_service.generate_report → ... → SQL INJECTION SINK
        
        Classification: FALSE POSITIVE - PROTECTED
        Reason: Requires authentication, limiting exploitation
        """
        if not self.auth_service.is_authenticated():
            raise PermissionError("Authentication required")
        return self.report_service.generate_report(user_id)
    
    def get_user_report_by_email(self, email: str) -> str:
        """
        Get user report by email - PROTECTED by auth + SANITIZED by validation
        
        Attack path: email → get_user_report_by_email → [AUTH CHECK] →
                     report_service.generate_email_report → [EMAIL VALIDATION] →
                     ... → SQL INJECTION SINK
        
        Classification: FALSE POSITIVE - PROTECTED + SANITIZED
        Reason: Both authentication AND email validation protect this path
        """
        if not self.auth_service.is_authenticated():
            raise PermissionError("Authentication required")
        return self.report_service.generate_email_report(email)
