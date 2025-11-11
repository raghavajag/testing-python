"""
Date Helper - Date parsing and manipulation
"""

from datetime import datetime

class DateHelper:
    def parse_date_string(self, date_string):
        """
        Parse date string - passes through as-is for SQL
        """
        if not date_string:
            return ""
        
        return date_string
