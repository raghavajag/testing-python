"""
Order Service - Business logic for order operations
VULN-4 and VULN-5 chain continues here
"""
from repositories.order_repository import OrderRepository
from middleware.report_generator import ReportGenerator

class OrderService:
    def __init__(self):
        self.order_repo = OrderRepository()
        self.report_gen = ReportGenerator()
    
    def query_orders(self, order_id: str, customer: str):
        """
        VULN-4 Chain Step 2: Query orders from repository
        TRUE POSITIVE - Direct pass to vulnerable repository method
        """
        return self.order_repo.execute_order_query(order_id, customer)
    
    def build_report_query(self, report_type: str, date_range: dict):
        """
        VULN-5 Chain Step 2: Build report query
        Validates parameters before execution - FP_SAFE_CONTEXT
        """
        validated_params = self.report_gen.validate_report_params(report_type, date_range)
        return self.report_gen.format_report_data(validated_params)
