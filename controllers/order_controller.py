"""
Order Controller - Handles order-related requests
Contains VULN-4 and VULN-5 with complex attack paths
"""
from services.order_service import OrderService
from services.legacy_service import LegacyOrderService

class OrderController:
    def __init__(self):
        self.order_service = OrderService()
        self.legacy_service = LegacyOrderService()
    
    def process_order_search(self, order_id: str, customer: str):
        """
        VULN-4 Chain Step 1: Entry point for order search
        Has both reachable and unreachable paths
        """
        # Main path - REACHABLE
        results = self.order_service.query_orders(order_id, customer)
        
        # Legacy path - UNREACHABLE (dead code)
        if False:  # Never executed
            legacy_results = self.legacy_service.legacy_order_lookup(order_id)
            return legacy_results
        
        return results
    
    def create_report(self, report_type: str, date_range: dict):
        """
        VULN-5 Chain Step 1: Entry point for report generation
        Uses safe context with parameterized queries - FP_SAFE_CONTEXT
        """
        return self.order_service.build_report_query(report_type, date_range)
