"""
Report Controller - Entry points for reporting operations  
Contains entry points for VULN_5 (protected)
"""

from flask import Blueprint, request, jsonify, render_template_string
from services.report_service import ReportService
from services.template_service import TemplateService
from middleware.auth_middleware import require_auth, require_admin
from middleware.validation_middleware import validate_template_input
from middleware.rate_limiter import rate_limit

report_bp = Blueprint('report', __name__)
report_service = ReportService()
template_service = TemplateService()

@report_bp.route('/custom-report', methods=['POST'])
@require_admin
@require_auth
@rate_limit(max_requests=50, window_seconds=3600)
@validate_template_input
def generate_custom_report():
    """
    ENTRY POINT for VULN_5 (FALSE_POSITIVE_PROTECTED)
    Generate custom report with template - PROTECTED by multiple layers
    Attack paths: 3 paths, each with admin auth + CSRF + rate limiting + validation
    """
    data = request.get_json()
    report_type = data.get('type', '')
    template_name = data.get('template', '')
    parameters = data.get('parameters', {})
    
    # Path 1: Direct custom report
    result = report_service.create_custom_report(report_type, template_name, parameters)
    return result

@report_bp.route('/dashboard-widget', methods=['POST'])
@require_admin
@rate_limit(max_requests=100, window_seconds=3600)
def create_dashboard_widget():
    """
    ENTRY POINT for VULN_5 (FALSE_POSITIVE_PROTECTED) - Path 2
    Create dashboard widget with custom template
    """
    data = request.get_json()
    widget_type = data.get('type', '')
    widget_template = data.get('template', '')
    widget_data = data.get('data', {})
    
    # Path 2: Through template service
    result = template_service.render_dashboard_widget(widget_type, widget_template, widget_data)
    return result

@report_bp.route('/analytics-preview', methods=['POST'])
@require_admin
@validate_template_input
def preview_analytics():
    """
    ENTRY POINT for VULN_5 (FALSE_POSITIVE_PROTECTED) - Path 3
    Preview analytics report
    """
    data = request.get_json()
    metric_type = data.get('metric', '')
    template_content = data.get('template', '')
    
    # Path 3: Analytics preview
    result = report_service.preview_analytics_report(metric_type, template_content)
    return result
