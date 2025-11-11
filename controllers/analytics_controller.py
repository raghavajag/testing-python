"""
Analytics Controller - Handles analytics and reporting
Contains VULN-8 with complex query transformation chain
"""
from services.analytics_service import AnalyticsService

class AnalyticsController:
    def __init__(self):
        self.analytics_service = AnalyticsService()
    
    def process_analytics_request(self, query_params: dict, metrics: list):
        """
        VULN-8 Chain Step 1: Entry point for analytics queries
        TRUE POSITIVE - No sanitization in analytics pipeline
        """
        return self.analytics_service.transform_query(query_params, metrics)
