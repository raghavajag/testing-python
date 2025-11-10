# Session Management
import hashlib
from database.session_repository import SessionRepository

class SessionManager:
    def __init__(self):
        self.session_repo = SessionRepository()
    
    def validate_session(self, token):
        """Validate session token and return session data"""
        if not token:
            return None
        
        # Hash token for lookup
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return self.session_repo.get_session(token_hash)
