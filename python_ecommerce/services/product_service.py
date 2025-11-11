"""
Product Service - Business logic for product operations
Contains attack paths for VULN_2 (sanitized) and VULN_6 (must_fix)
"""

from repositories.product_repository import ProductRepository
from services.search_helper import SearchHelper
from services.filter_service import FilterService

class ProductService:
    def __init__(self):
        self.product_repository = ProductRepository()
        self.search_helper = SearchHelper()
        self.filter_service = FilterService()
    
    # ===== VULN_2 PATHS (FALSE_POSITIVE_SANITIZED) =====
    
    def search_products(self, query, category):
        """
        VULN_2 - Path 1 Function 2/5
        Search products with preprocessing
        """
        # Enrich query with search hints
        enriched_query = self.search_helper.enrich_search_query(query)
        
        # Call repository with ORM-based safe search
        return self.product_repository.search_products_safe(enriched_query, category)
    
    def filter_products_by_price_and_name(self, name_filter, min_price, max_price):
        """
        VULN_2 - Path 3 Function 2/6
        Filter products by price and name
        """
        # Validate price range
        validated_prices = self.filter_service.validate_price_range(min_price, max_price)
        
        # Apply filtering logic
        return self.filter_service.apply_name_and_price_filter(
            name_filter, validated_prices['min'], validated_prices['max']
        )
    
    # ===== VULN_6 PATHS (MUST_FIX) =====
    
    def legacy_product_search(self, term):
        """
        VULN_6 - Path 2 Function 2/5
        Legacy search - NO SANITIZATION
        """
        # Format term for legacy system
        formatted_term = self.search_helper.format_legacy_term(term)
        
        # DANGEROUS: Calls unsafe legacy search
        return self.product_repository.legacy_search_unsafe(formatted_term)
    
    def search_in_category(self, category, keyword):
        """
        VULN_6 - Path 4 Function 2/6
        Search within specific category - VULNERABLE
        """
        # Validate category exists
        category_validated = self.filter_service.check_category_exists(category)
        
        if category_validated:
            # Calls unsafe search method
            return self.search_helper.search_category_products(category, keyword)
        
        return []
