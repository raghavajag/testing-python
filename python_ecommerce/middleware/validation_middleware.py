"""
Validation Middleware - Input validation
Provides sanitization for VULN_3 and VULN_5
"""

from functools import wraps
from flask import request, jsonify
import re

def validate_order_input(f):
    """Validate order input data"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        data = request.get_json()
        
        # Validate order_id
        order_id = data.get('order_id')
        if not order_id or not isinstance(order_id, (int, str)):
            return jsonify({'error': 'Invalid order_id'}), 400
        
        # Validate template name against allowlist
        template = data.get('template', 'default')
        allowed_templates = ['default', 'premium', 'express', 'standard']
        if template not in allowed_templates:
            return jsonify({'error': 'Invalid template'}), 400
        
        return f(*args, **kwargs)
    return decorated_function

def validate_product_search(f):
    """Validate product search input"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        query = request.args.get('q', '')
        
        # Length validation
        if len(query) > 200:
            return jsonify({'error': 'Query too long'}), 400
        
        return f(*args, **kwargs)
    return decorated_function

def validate_template_input(f):
    """Validate template input against allowlist"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        data = request.get_json()
        
        # Validate template against allowed patterns
        template = data.get('template', '')
        
        # Allowlist validation: only alphanumeric and safe characters
        if not re.match(r'^[a-zA-Z0-9_\-\s\.]+$', template):
            return jsonify({'error': 'Invalid template format'}), 400
        
        # Check template is in allowlist
        allowed = ['dashboard', 'report', 'analytics', 'widget', 'chart']
        if template not in allowed:
            return jsonify({'error': 'Template not in allowlist'}), 400
        
        return f(*args, **kwargs)
    return decorated_function
