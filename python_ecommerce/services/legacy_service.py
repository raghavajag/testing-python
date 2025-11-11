"""
Legacy Service - DEAD CODE service
Contains paths for VULN_1 (dead_code)
"""

from repositories.legacy_repository import LegacyRepository

class LegacyService:
    """
    This entire service is DEAD CODE - never called in production
    """
    def __init__(self):
        self.legacy_repository = LegacyRepository()
    
    def search_old_database(self, query):
        """
        VULN_1 - Path 1 Function 2/5 - DEAD CODE
        """
        # Process query for old system
        processed = self._process_legacy_query(query)
        return self.legacy_repository.search_legacy_db(processed)
    
    def _process_legacy_query(self, query):
        """VULN_1 - Path 1 Function 3/5 - DEAD CODE"""
        # Legacy query processing
        return query.replace('-', ' ')
    
    def execute_legacy_query(self, search_param):
        """
        VULN_1 - Path 2 Function 2/5 - DEAD CODE
        """
        # Format for legacy system
        formatted = self._format_for_legacy(search_param)
        return self.legacy_repository.execute_old_query(formatted)
    
    def _format_for_legacy(self, param):
        """VULN_1 - Path 2 Function 3/5 - DEAD CODE"""
        return param.upper()
    
    def search_archived_data(self, archive_id, keyword):
        """
        VULN_1 - Path 3 Function 2/5 - DEAD CODE
        """
        # Search in archives
        search_key = self._build_archive_key(archive_id, keyword)
        return self.legacy_repository.search_archive(search_key)
    
    def _build_archive_key(self, archive_id, keyword):
        """VULN_1 - Path 3 Function 3/5 - DEAD CODE"""
        return f"{archive_id}:{keyword}"
