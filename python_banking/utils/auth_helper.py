"""
Auth Helper - Authentication utilities
"""

import base64
import json

class AuthHelper:
    def extract_account_from_token(self, token):
        """
        Extract account number from JWT-like token
        """
        if not token:
            return ""
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        try:
            decoded = base64.b64decode(token).decode('utf-8')
            data = json.loads(decoded)
            return data.get('account_number', '')
        except:
            return ""
