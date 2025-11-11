"""
Admin Controller - Entry points for admin-only operations
Contains entry points for VULN_4 (protected) and VULN_8 (good_to_fix)
"""

from flask import Blueprint, request, jsonify
from services.admin_service import AdminService
from services.analytics_service import AnalyticsService
from middleware.auth_middleware import require_admin, require_csrf_token
from middleware.rate_limiter import rate_limit

admin_bp = Blueprint('admin', __name__)
admin_service = AdminService()
analytics_service = AnalyticsService()

@admin_bp.route('/user-search', methods=['POST'])
@require_admin
@require_csrf_token
@rate_limit(max_requests=100, window_seconds=3600)
def admin_search_users():
    """
    ENTRY POINT for VULN_4 (FALSE_POSITIVE_PROTECTED)
    Admin user search with multiple security layers
    Attack paths: 3 paths, each protected by admin auth + CSRF + rate limiting
    """
    data = request.get_json()
    search_query = data.get('query', '')
    filters = data.get('filters', {})
    
    # Path 1: Direct admin search
    results = admin_service.search_users_advanced(search_query, filters)
    return jsonify(results)

@admin_bp.route('/bulk-user-query', methods=['POST'])
@require_admin
@require_csrf_token
def bulk_user_query():
    """
    ENTRY POINT for VULN_4 (FALSE_POSITIVE_PROTECTED) - Path 2
    Bulk user query for admin dashboard
    """
    data = request.get_json()
    query_params = data.get('params', {})
    
    # Path 2: Through analytics service
    results = analytics_service.generate_user_report(query_params)
    return jsonify(results)

@admin_bp.route('/audit-log', methods=['GET'])
@require_admin
@require_csrf_token
def get_audit_logs():
    """
    ENTRY POINT for VULN_4 (FALSE_POSITIVE_PROTECTED) - Path 3
    Fetch audit logs with search
    """
    user_filter = request.args.get('user', '')
    action_filter = request.args.get('action', '')
    
    # Path 3: Audit log search
    results = admin_service.search_audit_logs(user_filter, action_filter)
    return jsonify(results)

@admin_bp.route('/customer-lookup', methods=['GET'])
def customer_lookup():
    """
    ENTRY POINT for VULN_8 (GOOD_TO_FIX)
    Customer lookup with weak validation
    Attack paths: 4 paths, has validation but can be bypassed
    """
    customer_id = request.args.get('id', '')
    search_type = request.args.get('type', 'exact')
    
    # Path 1: Basic lookup
    results = admin_service.lookup_customer_data(customer_id, search_type)
    return jsonify(results)

@admin_bp.route('/transaction-search', methods=['POST'])
def search_transactions():
    """
    ENTRY POINT for VULN_8 (GOOD_TO_FIX) - Path 2
    Transaction search with partial validation
    """
    data = request.get_json()
    transaction_filter = data.get('filter', '')
    date_range = data.get('date_range', {})
    
    # Path 2: Through transaction service
    results = analytics_service.search_transactions(transaction_filter, date_range)
    return jsonify(results)

@admin_bp.route('/report-query', methods=['POST'])
def custom_report_query():
    """
    ENTRY POINT for VULN_8 (GOOD_TO_FIX) - Path 3
    Custom report with query building
    """
    data = request.get_json()
    report_type = data.get('type', '')
    query_string = data.get('query', '')
    
    # Path 3: Custom report generation
    results = admin_service.generate_custom_report(report_type, query_string)
    return jsonify(results)

@admin_bp.route('/data-export', methods=['POST'])
def export_data():
    """
    ENTRY POINT for VULN_8 (GOOD_TO_FIX) - Path 4
    Data export with filter
    """
    data = request.get_json()
    export_type = data.get('type', '')
    filter_criteria = data.get('filter', '')
    
    # Path 4: Data export service
    results = analytics_service.export_filtered_data(export_type, filter_criteria)
    return jsonify(results)
