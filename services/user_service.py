"""
User Service - VULNERABILITY 1
===============================
Contains SQL Injection in find_user_by_id()

VULN 1: cursor.execute(query) with unsanitized user_id
"""

import re
from typing import Optional, Dict, Any
from demo_vuln.database import DatabaseManager


class UserService:
    """User management service - Contains VULN 1: SQL INJECTION"""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def find_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Find user by ID - VULNERABLE SINK #1
        
        VULN 1: SQL INJECTION SINK
        This function performs SQL injection via string concatenation
        """
        cursor = self.db_manager.get_cursor()
        query = f"SELECT * FROM users WHERE id = '{user_id}'"  # SQL Injection!
        cursor.execute(query)  # VULN 1: SQL INJECTION SINK
        result = cursor.fetchone()
        return dict(zip(['id', 'name', 'email'], result)) if result else None

    def find_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Find user by email - SANITIZED (validates email format)
        
        This path is PROTECTED by email validation before reaching the sink
        """
        # Email validation prevents SQL injection
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return None
        # Even though this calls find_user_by_id, the email validation sanitizes input
        return self.find_user_by_id(email)


class UserProfileService:
    """User profile operations - Intermediate layer"""

    def __init__(self, user_service: UserService):
        self.user_service = user_service

    def get_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user profile - passes through to UserService"""
        return self.user_service.find_user_by_id(user_id)

    def get_profile_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get profile by email - calls sanitized path"""
        return self.user_service.find_user_by_email(email)


class UserReportService:
    """User report generation - Top layer"""

    def __init__(self, profile_service: UserProfileService):
        self.profile_service = profile_service

    def generate_report(self, user_id: str) -> str:
        """Generate user report"""
        user = self.profile_service.get_profile(user_id)
        if user:
            return f"Report for {user['name']}"
        return "User not found"
    
    def generate_email_report(self, email: str) -> str:
        """Generate report by email - uses sanitized path"""
        user = self.profile_service.get_profile_by_email(email)
        if user:
            return f"Email Report for {user['name']}"
        return "User not found"
