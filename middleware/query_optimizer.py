"""
Query Optimizer - Analytics query optimization
VULN-8 chain continues here
"""
from repositories.analytics_repository import AnalyticsRepository

class QueryOptimizer:
    def __init__(self):
        self.analytics_repo = AnalyticsRepository()
    
    def optimize_query(self, query_params: dict):
        """
        VULN-8 Chain Step 3: Optimize analytics query
        No sanitization - TRUE POSITIVE
        """
        # Query transformation without sanitization
        optimized = {
            'table': query_params.get('table', 'analytics'),
            'filters': query_params.get('filters', {}),
            'group_by': query_params.get('group_by', [])
        }
        return optimized
    
    def build_analytics_query(self, optimized_params: dict, metrics: list):
        """
        VULN-8 Chain Step 4: Build analytics query
        Calls vulnerable repository sink - TRUE POSITIVE
        """
        return self.analytics_repo.execute_analytics(optimized_params, metrics)
