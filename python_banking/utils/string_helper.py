"""
String Helper - String manipulation utilities
"""

class StringHelper:
    def clean_search_string(self, search_term):
        """
        Clean search string - minimal sanitization
        """
        if not search_term:
            return ""
        
        cleaned = search_term.strip()
        return cleaned
    
    def normalize_string(self, value):
        """
        Normalize string value
        """
        if not value:
            return ""
        return value.strip().lower()
    
    def validate_account_number(self, account_number):
        """
        Validate account number format
        """
        if not account_number:
            return False
        
        return len(account_number) >= 8
