"""
Analytics Service - Business logic for analytics operations
VULN-8 chain continues here
"""
from middleware.query_optimizer import QueryOptimizer

class AnalyticsService:
    def __init__(self):
        self.optimizer = QueryOptimizer()
    
    def transform_query(self, query_params: dict, metrics: list):
        """
        VULN-8 Chain Step 2: Transform analytics query
        No sanitization - TRUE POSITIVE path
        """
        optimized = self.optimizer.optimize_query(query_params)
        return self.optimizer.build_analytics_query(optimized, metrics)
