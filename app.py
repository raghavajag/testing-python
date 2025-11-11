"""
E-Commerce Platform - Main Application Entry Point
Contains 8 vulnerability sinks with complex attack paths for testing
"""
from flask import Flask, request, jsonify
from controllers.product_controller import ProductController
from controllers.order_controller import OrderController
from controllers.admin_controller import AdminController
from controllers.analytics_controller import AnalyticsController

app = Flask(__name__)

# Initialize controllers
product_controller = ProductController()
order_controller = OrderController()
admin_controller = AdminController()
analytics_controller = AnalyticsController()

# ==================== PRODUCT ROUTES ====================

@app.route('/api/products/search', methods=['GET'])
def search_products():
    """
    VULN-1: TRUE POSITIVE - SQL Injection via product search
    Attack Path: search_products -> handle_search -> process_search_query -> 
                 enrich_query -> build_query -> execute_search_query [SINK]
    """
    search_term = request.args.get('q', '')
    category = request.args.get('category', '')
    return jsonify(product_controller.handle_search(search_term, category))

@app.route('/api/products/filter', methods=['POST'])
def filter_products():
    """
    VULN-2: FALSE POSITIVE (FP_SANITIZED) - SQL Injection with proper sanitization
    Attack Path: filter_products -> handle_filter -> validate_and_filter -> 
                 sanitize_input -> prepare_query -> execute_filter_query [SINK]
    """
    data = request.get_json()
    filters = data.get('filters', {})
    return jsonify(product_controller.handle_filter(filters))

@app.route('/api/products/legacy-search', methods=['GET'])
def legacy_product_search():
    """
    VULN-3: FALSE POSITIVE (FP_DEAD_CODE) - Unreachable SQL injection
    This endpoint is never called - deprecated and dead code
    """
    if False:  # Dead code branch - never executed
        search = request.args.get('search', '')
        return jsonify(product_controller.handle_legacy_search(search))
    return jsonify({"error": "Endpoint deprecated"}), 404

# ==================== ORDER ROUTES ====================

@app.route('/api/orders/search', methods=['GET'])
def search_orders():
    """
    VULN-4: TRUE POSITIVE - SQL Injection with multiple paths
    Has both reachable and unreachable attack paths
    Attack Path 1 (REACHABLE): search_orders -> process_order_search -> 
                                query_orders -> execute_order_query [SINK]
    Attack Path 2 (UNREACHABLE): search_orders -> legacy_order_lookup -> ... [DEAD]
    """
    order_id = request.args.get('order_id', '')
    customer = request.args.get('customer', '')
    return jsonify(order_controller.process_order_search(order_id, customer))

@app.route('/api/orders/report', methods=['POST'])
def generate_order_report():
    """
    VULN-5: FALSE POSITIVE (FP_SAFE_CONTEXT) - SQL injection pattern in safe context
    Attack Path: generate_order_report -> create_report -> build_report_query -> 
                 validate_report_params -> format_report_data -> execute_report_query [SINK]
    Uses parameterized queries internally despite pattern match
    """
    data = request.get_json()
    report_type = data.get('type', 'summary')
    date_range = data.get('date_range', {})
    return jsonify(order_controller.create_report(report_type, date_range))

# ==================== ADMIN ROUTES ====================

@app.route('/api/admin/products/bulk-update', methods=['POST'])
def admin_bulk_update():
    """
    VULN-6: FALSE POSITIVE (FP_SANITIZED) - Template injection with sanitization
    Attack Path: admin_bulk_update -> process_bulk_update -> validate_template -> 
                 sanitize_template_input -> render_update_template [SINK]
    """
    data = request.get_json()
    template = data.get('template', '')
    products = data.get('products', [])
    return jsonify(admin_controller.process_bulk_update(template, products))

@app.route('/api/admin/dashboard', methods=['GET'])
def admin_dashboard():
    """
    VULN-7: FALSE POSITIVE (FP_SAFE_CONTEXT) - Template rendering in safe context
    Attack Path: admin_dashboard -> generate_dashboard -> build_dashboard_data -> 
                 create_dashboard_template -> render_dashboard [SINK]
    Template content is from trusted sources only
    """
    user_id = request.args.get('user_id', '')
    return admin_controller.generate_dashboard(user_id)

# ==================== ANALYTICS ROUTES ====================

@app.route('/api/analytics/query', methods=['POST'])
def analytics_query():
    """
    VULN-8: TRUE POSITIVE - SQL Injection via analytics
    Attack Path: analytics_query -> process_analytics_request -> 
                 transform_query -> optimize_query -> build_analytics_query -> 
                 execute_analytics [SINK]
    """
    data = request.get_json()
    query_params = data.get('query', {})
    metrics = data.get('metrics', [])
    return jsonify(analytics_controller.process_analytics_request(query_params, metrics))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
