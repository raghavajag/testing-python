# Main Flask Application - Entry Points
from flask import Flask, request, jsonify
from auth.authenticator import Authenticator
from services.account_service import AccountService
from services.report_service import ReportService
from services.admin_service import AdminService

app = Flask(__name__)
authenticator = Authenticator()
account_service = AccountService()
report_service = ReportService()
admin_service = AdminService()

# VULN 1: TRUE_POSITIVE - SQL Injection via user search
# Path: api_search_user → authenticate_request → validate_user_role → get_user_permissions → search_user_by_name → build_search_query → execute_user_search_query (SINK)
@app.route('/api/search-user', methods=['POST'])
def api_search_user():
    """Public API endpoint for user search"""
    token = request.headers.get('Authorization')
    search_term = request.json.get('username', '')
    
    # Authenticate and search
    if authenticator.authenticate_request(token, search_term):
        results = account_service.search_user_by_name(search_term)
        return jsonify(results)
    return jsonify({'error': 'Unauthorized'}), 401


# VULN 2: TRUE_POSITIVE - SSTI via custom report generation
# Path: api_generate_report → authenticate_admin → check_admin_privileges → load_admin_config → process_report_request → render_report_template → generate_html_report (SINK)
@app.route('/api/generate-report', methods=['POST'])
def api_generate_report():
    """Admin endpoint for custom report generation"""
    token = request.headers.get('Authorization')
    template = request.json.get('report_template', '')
    
    if authenticator.authenticate_admin(token):
        report_html = report_service.process_report_request(template)
        return jsonify({'report': report_html})
    return jsonify({'error': 'Forbidden'}), 403


# VULN 3: FALSE_POSITIVE_SANITIZED - SQL Injection with validation
# Path: api_get_account → authenticate_request → validate_session → check_account_permissions → get_account_details → build_account_query → execute_safe_account_query (SINK with sanitization)
@app.route('/api/account/<account_id>', methods=['GET'])
def api_get_account(account_id):
    """Endpoint to get account details - SANITIZED"""
    token = request.headers.get('Authorization')
    
    if authenticator.authenticate_request(token, account_id):
        account = account_service.get_account_details(account_id)
        return jsonify(account)
    return jsonify({'error': 'Unauthorized'}), 401


# VULN 4: FALSE_POSITIVE_SANITIZED - SSTI with escaping
# Path: api_user_profile → authenticate_request → load_user_profile → format_profile_data → build_profile_template → render_safe_profile (SINK with escaping)
@app.route('/api/profile', methods=['GET'])
def api_user_profile():
    """User profile with safe template rendering"""
    token = request.headers.get('Authorization')
    
    if authenticator.authenticate_request(token, None):
        profile_html = account_service.load_user_profile(token)
        return jsonify({'profile': profile_html})
    return jsonify({'error': 'Unauthorized'}), 401


# VULN 5: FALSE_POSITIVE_UNREACHABLE - Dead code SQL injection
# Path: UNREACHABLE - deprecated_search_accounts is never called
@app.route('/api/legacy/search', methods=['POST'])
def api_legacy_search():
    """DEPRECATED: This endpoint is no longer used"""
    # This function is marked as deprecated and never called in production
    return jsonify({'error': 'Endpoint deprecated'}), 410


# VULN 6: FALSE_POSITIVE_UNREACHABLE - Internal admin function never exposed
# This function exists but has no route decorator - unreachable via HTTP
def internal_admin_panel():
    """Internal function without route - unreachable"""
    template = request.args.get('panel_template', '')
    return admin_service.render_internal_panel(template)


# VULN 7: FALSE_POSITIVE_MISCONFIGURATION - Safe constant template
# Path: api_status_report → get_system_status → format_status_message → build_status_report → render_status_template (SINK with constant)
@app.route('/api/status', methods=['GET'])
def api_status_report():
    """System status with hardcoded safe template"""
    status = admin_service.get_system_status()
    return jsonify({'status': status})


# VULN 8: FALSE_POSITIVE_MISCONFIGURATION - Query from config file
# Path: api_database_health → check_db_connection → get_db_metrics → run_health_query (SINK with predefined query)
@app.route('/api/db-health', methods=['GET'])
def api_database_health():
    """Database health check with predefined queries"""
    token = request.headers.get('Authorization')
    
    if authenticator.authenticate_admin(token):
        health = admin_service.check_db_connection()
        return jsonify({'health': health})
    return jsonify({'error': 'Forbidden'}), 403


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
