"""
Search Service - Handles various search operations
Contains paths for VULN_2 (sanitized) and VULN_6 (must_fix)
"""

from repositories.product_repository import ProductRepository
from services.search_helper import SearchHelper
from services.cache_service import CacheService

class SearchService:
    def __init__(self):
        self.product_repository = ProductRepository()
        self.search_helper = SearchHelper()
        self.cache_service = CacheService()
    
    # ===== VULN_2 PATHS (FALSE_POSITIVE_SANITIZED) =====
    
    def perform_advanced_search(self, query, filters):
        """
        VULN_2 - Path 2 Function 2/6
        Advanced search with multiple filters
        """
        # Build search parameters
        search_params = self.search_helper.build_search_parameters(query, filters)
        
        # Apply filters and search
        return self._execute_filtered_search(search_params)
    
    def _execute_filtered_search(self, params):
        """
        VULN_2 - Path 2 Function 3/6
        Execute search with validated parameters
        """
        # Check cache first
        cached_result = self.cache_service.get_search_cache(params)
        if cached_result:
            return cached_result
        
        # Execute search via ORM (SAFE)
        results = self.product_repository.search_with_filters(params)
        
        # Cache results
        self.cache_service.set_search_cache(params, results)
        return results
    
    # ===== VULN_6 PATHS (MUST_FIX) =====
    
    def quick_search_products(self, search_term):
        """
        VULN_6 - Path 1 Function 2/5
        Quick search - VULNERABLE, no sanitization
        """
        # Format search term
        formatted = self.search_helper.quick_format_search(search_term)
        
        # DANGEROUS: Direct to unsafe repository method
        return self.product_repository.quick_search_raw(formatted)
    
    def process_bulk_search(self, search_terms):
        """
        VULN_6 - Path 3 Function 2/6
        Process multiple search terms - VULNERABLE
        """
        results = []
        for term in search_terms:
            # Process each term
            processed_term = self.search_helper.preprocess_bulk_term(term)
            
            # DANGEROUS: Each term goes through vulnerable path
            term_results = self._execute_single_bulk_search(processed_term)
            results.extend(term_results)
        
        return results
    
    def _execute_single_bulk_search(self, term):
        """
        VULN_6 - Path 3 Function 3/6
        Execute single search in bulk operation
        """
        # Additional processing
        enhanced_term = self.search_helper.enhance_search_term(term)
        
        # DANGEROUS: Calls vulnerable search
        return self.product_repository.execute_raw_search(enhanced_term)
