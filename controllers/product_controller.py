"""
Product Controller - Handles product-related requests
Contains VULN-1, VULN-2, VULN-3 with different classification scenarios
"""
from services.product_service import ProductService

class ProductController:
    def __init__(self):
        self.product_service = ProductService()
    
    def handle_search(self, search_term: str, category: str):
        """
        VULN-1 Chain Step 1: Entry point for product search
        Passes untrusted input to service layer
        """
        # No validation - direct pass-through
        return self.product_service.process_search_query(search_term, category)
    
    def handle_filter(self, filters: dict):
        """
        VULN-2 Chain Step 1: Entry point for product filtering
        This path includes sanitization - should be FP_SANITIZED
        """
        # Pass filters to service for processing
        return self.product_service.validate_and_filter(filters)
    
    def handle_legacy_search(self, search: str):
        """
        VULN-3 Chain Step 1: Dead code path - never reached
        This is deprecated and unreachable code
        """
        # This function exists but is never called due to dead code in app.py
        return self.product_service.legacy_search_handler(search)
