"""
Order Controller - Entry points for order-related operations
Contains entry points for VULN_3 (sanitized) and VULN_7 (must_fix)
"""

from flask import Blueprint, request, jsonify, render_template_string
from services.order_service import OrderService
from services.notification_service import NotificationService
from middleware.auth_middleware import require_auth
from middleware.validation_middleware import validate_order_input

order_bp = Blueprint('order', __name__)
order_service = OrderService()
notification_service = NotificationService()

@order_bp.route('/confirmation', methods=['POST'])
@validate_order_input
def send_order_confirmation():
    """
    ENTRY POINT for VULN_3 (FALSE_POSITIVE_SANITIZED)
    Send order confirmation with validated template
    Attack paths: 3 paths, each 5-6 functions deep
    """
    data = request.get_json()
    order_id = data.get('order_id')
    template_name = data.get('template', 'default')
    custom_message = data.get('message', '')
    
    # Path 1: Standard confirmation
    result = order_service.send_confirmation_email(order_id, template_name, custom_message)
    return jsonify(result)

@order_bp.route('/notification', methods=['POST'])
def send_order_notification():
    """
    ENTRY POINT for VULN_3 (FALSE_POSITIVE_SANITIZED) - Path 2
    Send custom order notification
    """
    data = request.get_json()
    order_id = data.get('order_id')
    notification_type = data.get('type', 'email')
    template_data = data.get('template_data', {})
    
    # Path 2: Through notification service
    result = notification_service.send_custom_notification(order_id, notification_type, template_data)
    return jsonify(result)

@order_bp.route('/status-update', methods=['POST'])
@require_auth
def send_status_update():
    """
    ENTRY POINT for VULN_3 (FALSE_POSITIVE_SANITIZED) - Path 3
    Send order status update
    """
    data = request.get_json()
    order_id = data.get('order_id')
    new_status = data.get('status')
    message = data.get('message', '')
    
    # Path 3: Status update notification
    result = order_service.notify_status_change(order_id, new_status, message)
    return jsonify(result)

@order_bp.route('/preview', methods=['POST'])
def preview_order_email():
    """
    ENTRY POINT for VULN_7 (MUST_FIX)
    Preview order email with user-provided template - NO VALIDATION
    Attack paths: 4 paths showing unprotected SSTI
    """
    data = request.get_json()
    template_string = data.get('template', '')
    order_data = data.get('order_data', {})
    
    # Path 1: Direct preview
    result = notification_service.preview_email_template(template_string, order_data)
    return result

@order_bp.route('/custom-email', methods=['POST'])
def send_custom_email():
    """
    ENTRY POINT for VULN_7 (MUST_FIX) - Path 2
    Send custom email with raw template
    """
    data = request.get_json()
    recipient = data.get('email')
    subject = data.get('subject')
    template = data.get('body_template', '')
    
    # Path 2: Custom email sending
    result = order_service.send_custom_order_email(recipient, subject, template)
    return jsonify(result)

@order_bp.route('/render-receipt', methods=['POST'])
def render_receipt():
    """
    ENTRY POINT for VULN_7 (MUST_FIX) - Path 3
    Render order receipt from template
    """
    data = request.get_json()
    order_id = data.get('order_id')
    template = data.get('receipt_template', '')
    
    # Path 3: Receipt rendering
    result = notification_service.render_order_receipt(order_id, template)
    return result

@order_bp.route('/marketing', methods=['POST'])
def send_marketing_email():
    """
    ENTRY POINT for VULN_7 (MUST_FIX) - Path 4
    Send marketing email with custom template
    """
    data = request.get_json()
    campaign_name = data.get('campaign')
    template_content = data.get('template', '')
    recipient_list = data.get('recipients', [])
    
    # Path 4: Marketing email campaign
    result = order_service.send_marketing_campaign(campaign_name, template_content, recipient_list)
    return jsonify(result)
