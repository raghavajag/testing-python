"""
Logger Helper - Logging utilities
"""

class LoggerHelper:
    def log_search_request(self, search_term, account_type):
        """
        Log search request
        """
        print(f"Search request: term={search_term}, type={account_type}")
