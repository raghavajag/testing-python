"""
Product Service - Business logic for product operations
VULN-1, VULN-2, VULN-3 chain continues here
"""
from middleware.query_processor import QueryProcessor
from middleware.validation_middleware import ValidationMiddleware

class ProductService:
    def __init__(self):
        self.query_processor = QueryProcessor()
        self.validator = ValidationMiddleware()
    
    def process_search_query(self, search_term: str, category: str):
        """
        VULN-1 Chain Step 2: Process search query
        Passes to query enrichment layer
        """
        enriched_term = self.query_processor.enrich_query(search_term)
        return self.query_processor.build_query(enriched_term, category)
    
    def validate_and_filter(self, filters: dict):
        """
        VULN-2 Chain Step 2: Validate and filter products
        Includes sanitization step - FP_SANITIZED
        """
        sanitized_filters = self.validator.sanitize_input(filters)
        return self.query_processor.prepare_query(sanitized_filters)
    
    def legacy_search_handler(self, search: str):
        """
        VULN-3 Chain Step 2: Legacy search handler (dead code)
        Part of unreachable code path
        """
        # This function is part of dead code chain
        return self.query_processor.legacy_query_builder(search)
