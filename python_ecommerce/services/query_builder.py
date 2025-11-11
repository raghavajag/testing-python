# Query Builder - Helper for building queries
class QueryBuilder:
    def build_user_search_criteria(self, query, filters):
        """VULN_4 Path 1 Function 4/6"""
        return query
    
    def validate_search_criteria(self, criteria):
        """VULN_4 Path 1 Function 5/6"""
        return criteria
    
    def build_audit_query(self, user_filter, action_filter):
        """VULN_4 Path 3 Function 3/6"""
        return f"user_name LIKE '%{user_filter}%' AND action LIKE '%{action_filter}%'"
    
    def build_report_query(self, report_type, query_string):
        """VULN_8 Path 3 Function 3/6"""
        return f"report_type = '{report_type}' AND {query_string}"
