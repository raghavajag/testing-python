# Analytics Service stub
from repositories.user_repository import UserRepository

class AnalyticsService:
    def __init__(self):
        self.user_repository = UserRepository()
    
    def generate_user_report(self, params):
        """VULN_4 Path 2 Function 3/6"""
        query = params.get('query', '')
        return self._build_and_execute_report(query)
    
    def _build_and_execute_report(self, query):
        """VULN_4 Path 2 Function 4/6"""
        return self._execute_user_query(query)
    
    def _execute_user_query(self, query):
        """VULN_4 Path 2 Function 5/6"""
        return self.user_repository.search_users_raw(query)
    
    def search_transactions(self, filter_str, date_range):
        """VULN_8 Path 2 Function 3/6"""
        query = self._build_transaction_query(filter_str, date_range)
        return self.user_repository.execute_report_query(query)
    
    def _build_transaction_query(self, filter_str, date_range):
        """VULN_8 Path 2 Function 4/6"""
        return f"transaction_id LIKE '%{filter_str}%'"
    
    def export_filtered_data(self, export_type, filter_criteria):
        """VULN_8 Path 4 Function 3/6"""
        query = self._prepare_export_query(filter_criteria)
        return self.user_repository.execute_report_query(query)
    
    def _prepare_export_query(self, criteria):
        """VULN_8 Path 4 Function 4/6"""
        return f"user_id LIKE '%{criteria}%'"
