"""
Authentication Service
======================
Handles authentication and authorization
"""

from typing import Optional


class AuthService:
    """Authentication and authorization service"""

    def __init__(self):
        self.current_user: Optional[str] = None
        self.admin_users = ['admin', 'superuser']

    def login(self, username: str, password: str) -> bool:
        """Simple login - for demo purposes"""
        if username in ['alice', 'bob', 'admin'] and password == 'password':
            self.current_user = username
            return True
        return False

    def logout(self):
        """Logout current user"""
        self.current_user = None

    def is_admin(self) -> bool:
        """Check if current user is admin"""
        return self.current_user in self.admin_users

    def is_authenticated(self) -> bool:
        """Check if user is authenticated"""
        return self.current_user is not None
