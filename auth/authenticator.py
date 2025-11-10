# Authentication Layer
from auth.session_manager import SessionManager
from auth.role_validator import RoleValidator
from database.user_repository import UserRepository

class Authenticator:
    def __init__(self):
        self.session_manager = SessionManager()
        self.role_validator = RoleValidator()
        self.user_repo = UserRepository()
    
    def authenticate_request(self, token, context):
        """Authenticate user request with context"""
        # Chain: authenticate_request → validate_user_role → get_user_permissions
        session = self.session_manager.validate_session(token)
        if session:
            return self.role_validator.validate_user_role(session['user_id'], context)
        return False
    
    def authenticate_admin(self, token):
        """Authenticate admin user"""
        # Chain: authenticate_admin → check_admin_privileges → load_admin_config
        session = self.session_manager.validate_session(token)
        if session:
            return self.role_validator.check_admin_privileges(session['user_id'])
        return False
