"""
Rate Limiter - Rate limiting middleware
Provides additional protection layer for VULN_4 and VULN_5
"""

from functools import wraps
from flask import request, jsonify
import time
from collections import defaultdict

# Simple in-memory rate limiting
rate_limit_store = defaultdict(list)

def rate_limit(max_requests=100, window_seconds=3600):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client identifier
            client_id = request.remote_addr
            
            # Current time
            now = time.time()
            
            # Clean old requests
            rate_limit_store[client_id] = [
                req_time for req_time in rate_limit_store[client_id]
                if now - req_time < window_seconds
            ]
            
            # Check rate limit
            if len(rate_limit_store[client_id]) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            # Add current request
            rate_limit_store[client_id].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
