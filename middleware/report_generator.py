"""
Report Generator - Report building middleware
VULN-5 chain continues here
"""

class ReportGenerator:
    def validate_report_params(self, report_type: str, date_range: dict):
        """
        VULN-5 Chain Step 3: Validate report parameters
        Whitelist validation - FP_SAFE_CONTEXT
        """
        # Strict whitelist for report types
        allowed_types = ['summary', 'detailed', 'analytics', 'export']
        if report_type not in allowed_types:
            report_type = 'summary'  # Default to safe value
        
        # Validate date range
        validated = {
            'type': report_type,
            'start_date': date_range.get('start', '2024-01-01'),
            'end_date': date_range.get('end', '2024-12-31')
        }
        return validated
    
    def format_report_data(self, validated_params: dict):
        """
        VULN-5 Chain Step 4: Format report data
        Uses parameterized queries - FP_SAFE_CONTEXT
        """
        from repositories.order_repository import OrderRepository
        order_repo = OrderRepository()
        return order_repo.execute_report_query(validated_params)
