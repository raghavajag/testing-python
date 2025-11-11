"""
Product Controller - Entry points for product-related operations
Contains entry points for VULN_2 (sanitized) and VULN_6 (must_fix)
"""

from flask import Blueprint, request, jsonify, render_template_string
from services.product_service import ProductService
from services.search_service import SearchService
from middleware.auth_middleware import require_auth
from middleware.validation_middleware import validate_product_search

product_bp = Blueprint('product', __name__)
product_service = ProductService()
search_service = SearchService()

@product_bp.route('/search', methods=['GET'])
def search_products():
    """
    ENTRY POINT for VULN_2 (FALSE_POSITIVE_SANITIZED)
    Public product search with ORM-based sanitization
    Attack paths: 3 paths, each 5-6 functions deep
    """
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    
    # Path 1: Direct search
    results = product_service.search_products(query, category)
    return jsonify(results)

@product_bp.route('/advanced-search', methods=['POST'])
def advanced_product_search():
    """
    ENTRY POINT for VULN_2 (FALSE_POSITIVE_SANITIZED) - Path 2
    Advanced search with filters
    """
    data = request.get_json()
    query = data.get('query', '')
    filters = data.get('filters', {})
    
    # Path 2: Through search service
    results = search_service.perform_advanced_search(query, filters)
    return jsonify(results)

@product_bp.route('/filter', methods=['GET'])
def filter_products():
    """
    ENTRY POINT for VULN_2 (FALSE_POSITIVE_SANITIZED) - Path 3
    Filter products with multiple criteria
    """
    min_price = request.args.get('min_price', 0)
    max_price = request.args.get('max_price', 99999)
    name_filter = request.args.get('name', '')
    
    # Path 3: Through product filtering
    results = product_service.filter_products_by_price_and_name(
        name_filter, min_price, max_price
    )
    return jsonify(results)

@product_bp.route('/quick-search', methods=['GET'])
def quick_search():
    """
    ENTRY POINT for VULN_6 (MUST_FIX)
    Quick search WITHOUT sanitization - direct SQL injection
    Attack paths: 4 paths, showing unprotected vulnerability
    """
    search_term = request.args.get('term', '')
    
    # Path 1: Direct quick search
    results = search_service.quick_search_products(search_term)
    return jsonify(results)

@product_bp.route('/legacy-search', methods=['GET'])
def legacy_search():
    """
    ENTRY POINT for VULN_6 (MUST_FIX) - Path 2
    Legacy search endpoint, also vulnerable
    """
    term = request.args.get('q', '')
    
    # Path 2: Through legacy service
    results = product_service.legacy_product_search(term)
    return jsonify(results)

@product_bp.route('/bulk-search', methods=['POST'])
def bulk_search():
    """
    ENTRY POINT for VULN_6 (MUST_FIX) - Path 3
    Bulk search for multiple terms
    """
    data = request.get_json()
    search_terms = data.get('terms', [])
    
    # Path 3: Bulk search processing
    results = search_service.process_bulk_search(search_terms)
    return jsonify(results)

@product_bp.route('/category-search', methods=['GET'])
def category_search():
    """
    ENTRY POINT for VULN_6 (MUST_FIX) - Path 4
    Search within category
    """
    category = request.args.get('category', '')
    keyword = request.args.get('keyword', '')
    
    # Path 4: Category-specific search
    results = product_service.search_in_category(category, keyword)
    return jsonify(results)
