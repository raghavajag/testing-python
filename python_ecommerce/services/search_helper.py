"""
Search Helper - Utility methods for search operations
Part of attack path chains for VULN_2 and VULN_6
"""

class SearchHelper:
    def __init__(self):
        self.stop_words = ['the', 'a', 'an', 'and', 'or']
    
    # Methods for VULN_2 paths (sanitized)
    def enrich_search_query(self, query):
        """VULN_2 Path 1 Function 3/5"""
        # Remove stop words and trim
        words = query.split()
        filtered = [w for w in words if w.lower() not in self.stop_words]
        return ' '.join(filtered)
    
    def build_search_parameters(self, query, filters):
        """VULN_2 Path 2 Function 3/6"""
        params = {'name': query}
        if 'category' in filters:
            params['category'] = filters['category']
        if 'min_price' in filters:
            params['min_price'] = filters['min_price']
        return params
    
    # Methods for VULN_6 paths (vulnerable)
    def quick_format_search(self, term):
        """VULN_6 Path 1 Function 3/5"""
        # Simple trim, no sanitization
        return term.strip()
    
    def format_legacy_term(self, term):
        """VULN_6 Path 2 Function 3/5"""
        # Legacy formatting, no escaping
        return term.replace('  ', ' ')
    
    def preprocess_bulk_term(self, term):
        """VULN_6 Path 3 Function 4/6"""
        # Basic preprocessing, no sanitization
        return term.lower().strip()
    
    def enhance_search_term(self, term):
        """VULN_6 Path 3 Function 5/6"""
        # Add wildcards but no escaping
        return f"%{term}%"
    
    def search_category_products(self, category, keyword):
        """VULN_6 Path 4 Function 5/6"""
        from repositories.product_repository import ProductRepository
        repo = ProductRepository()
        return repo.search_in_category_raw(category, keyword)
