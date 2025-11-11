"""
Filter Service - Product filtering logic
Part of VULN_2 attack paths
"""

from repositories.product_repository import ProductRepository

class FilterService:
    def __init__(self):
        self.product_repository = ProductRepository()
    
    def validate_price_range(self, min_price, max_price):
        """VULN_2 Path 3 Function 3/6"""
        # Validate and sanitize prices
        min_val = max(0, int(min_price) if min_price else 0)
        max_val = min(999999, int(max_price) if max_price else 999999)
        return {'min': min_val, 'max': max_val}
    
    def apply_name_and_price_filter(self, name_filter, min_price, max_price):
        """VULN_2 Path 3 Function 4/6"""
        # Build filter parameters
        params = {
            'name': name_filter,
            'min_price': min_price,
            'max_price': max_price
        }
        # Call repository with parameters (uses safe ORM query)
        return self._execute_price_filter(params)
    
    def _execute_price_filter(self, params):
        """VULN_2 Path 3 Function 5/6"""
        # Execute filter via safe repository method
        return self.product_repository.search_with_filters(params)
    
    def check_category_exists(self, category):
        """VULN_6 Path 4 Function 3/6"""
        # Simple existence check
        valid_categories = ['electronics', 'clothing', 'books', 'toys']
        return category in valid_categories
