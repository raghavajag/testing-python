"""
Legacy Service - Deprecated order service (Dead Code)
VULN-4 unreachable path continues here
"""
from repositories.legacy_repository import LegacyRepository

class LegacyOrderService:
    def __init__(self):
        self.legacy_repo = LegacyRepository()
    
    def legacy_order_lookup(self, order_id: str):
        """
        VULN-4 Chain (Dead Path): Legacy order lookup
        This is never reached due to dead code in controller
        """
        return self.legacy_repo.old_query_method(order_id)
