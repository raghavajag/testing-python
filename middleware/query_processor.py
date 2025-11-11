"""
Query Processor - Middleware for query building
VULN-1, VULN-2, VULN-3 chain continues here
"""
from repositories.product_repository import ProductRepository

class QueryProcessor:
    def __init__(self):
        self.product_repo = ProductRepository()
    
    def enrich_query(self, search_term: str):
        """
        VULN-1 Chain Step 3: Enrich search query
        No sanitization - passes tainted data forward
        """
        # Add wildcards and processing
        enriched = f"%{search_term}%"
        return enriched
    
    def build_query(self, enriched_term: str, category: str):
        """
        VULN-1 Chain Step 4: Build final query
        Calls repository sink - TRUE POSITIVE
        """
        return self.product_repo.execute_search_query(enriched_term, category)
    
    def prepare_query(self, sanitized_filters: dict):
        """
        VULN-2 Chain Step 4: Prepare sanitized query
        Data is already sanitized - FP_SANITIZED
        """
        return self.product_repo.execute_filter_query(sanitized_filters)
    
    def legacy_query_builder(self, search: str):
        """
        VULN-3 Chain Step 3: Legacy query builder (dead code)
        Part of unreachable chain
        """
        return self.product_repo.execute_legacy_query(search)
