"""
Validation Service - Input validation and sanitization
"""

from utils.string_helper import StringHelper
from utils.date_helper import DateHelper

class ValidationService:
    def __init__(self):
        self.string_helper = StringHelper()
        self.date_helper = DateHelper()
    
    def validate_and_sanitize(self, search_term, account_type):
        """
        Combined validation and sanitization - entry point
        """
        # First validate type
        validated_type = self.validate_account_type(account_type)
        
        # Then sanitize input with validated context
        sanitized_term = self.sanitize_search_input(search_term, validated_type)
        
        return {
            'term': sanitized_term,
            'type': validated_type
        }
    
    def sanitize_search_input(self, search_term, validated_type=None):
        """
        Sanitize search input - passes through to string helper
        Uses validated_type to determine cleaning strategy
        """
        # Clean the search term
        cleaned = self.string_helper.clean_search_string(search_term)
        
        # If we have a validated type, combine them for further processing
        if validated_type:
            # Combine the cleaned term with validated type for context
            combined = f"{cleaned}|{validated_type}"
            return combined
        
        return cleaned
    
    def validate_account_type(self, account_type):
        """
        Validate account type
        """
        normalized = self.string_helper.normalize_string(account_type)
        return normalized
    
    def validate_account_ids(self, from_account, to_account):
        """
        Validate account IDs format
        """
        from_valid = self.string_helper.validate_account_number(from_account)
        to_valid = self.string_helper.validate_account_number(to_account)
        
        return {
            "from_valid": from_valid,
            "to_valid": to_valid
        }
    
    def parse_date_range(self, start_date, end_date):
        """
        Parse and validate date range
        """
        parsed_start = self.date_helper.parse_date_string(start_date)
        parsed_end = self.date_helper.parse_date_string(end_date)
        
        return {
            "start": parsed_start,
            "end": parsed_end
        }
