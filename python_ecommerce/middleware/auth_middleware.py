"""
Auth Middleware - Authentication and authorization
Provides protection for VULN_4 and VULN_5
"""

from functools import wraps
from flask import request, jsonify, session

def require_auth(f):
    """Require user authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Require admin role - STRONG protection"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Check if user is admin
        if not session.get('is_admin', False):
            return jsonify({'error': 'Admin privileges required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def require_csrf_token(f):
    """Require CSRF token - Additional protection layer"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        csrf_token = request.headers.get('X-CSRF-Token')
        session_token = session.get('csrf_token')
        
        if not csrf_token or csrf_token != session_token:
            return jsonify({'error': 'Invalid CSRF token'}), 403
        
        return f(*args, **kwargs)
    return decorated_function
