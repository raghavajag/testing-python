"""
Validation Middleware - Input validation and sanitization
VULN-2 sanitization happens here
"""
import re

class ValidationMiddleware:
    def sanitize_input(self, filters: dict):
        """
        VULN-2 Chain Step 3: Sanitize filter input
        Proper sanitization applied - makes this FP_SANITIZED
        """
        sanitized = {}
        for key, value in filters.items():
            # Remove SQL injection characters
            if isinstance(value, str):
                # Whitelist alphanumeric and safe characters only
                sanitized_value = re.sub(r'[^\w\s-]', '', value)
                sanitized[key] = sanitized_value
            else:
                sanitized[key] = value
        return sanitized
