"""
Analytics Service - VULNERABILITY 3
====================================
Contains SQL Injection in get_user_stats()

VULN 3: cursor.execute(query) with unsanitized filter
"""

import re
from typing import List, Dict, Any
from demo_vuln.database import DatabaseManager


class AnalyticsService:
    """Analytics service - Contains VULN 3: SQL INJECTION"""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def get_user_stats(self, user_filter: str) -> List[Dict[str, Any]]:
        """
        Get user statistics - VULNERABLE SINK #3
        
        VULN 3: SQL INJECTION SINK
        This function performs SQL injection via string concatenation
        """
        cursor = self.db_manager.get_cursor()
        query = f"SELECT user_id, COUNT(*) as count FROM events WHERE user_id LIKE '%{user_filter}%' GROUP BY user_id"
        cursor.execute(query)  # VULN 3: SQL INJECTION SINK
        results = cursor.fetchall()
        return [dict(zip(['user_id', 'count'], row)) for row in results]

    def get_user_stats_safe(self, user_filter: str) -> List[Dict[str, Any]]:
        """
        Get user statistics with sanitization - PROTECTED
        
        This path is PROTECTED by input validation before reaching the sink
        """
        # Sanitize input - only alphanumeric
        if not re.match(r'^[a-zA-Z0-9_-]+$', user_filter):
            return []
        return self.get_user_stats(user_filter)


class ReportingService:
    """Reporting service - Intermediate layer"""

    def __init__(self, analytics_service: AnalyticsService):
        self.analytics_service = analytics_service

    def generate_stats_report(self, filter_criteria: str) -> List[Dict[str, Any]]:
        """Generate statistics report - passes through to AnalyticsService"""
        return self.analytics_service.get_user_stats(filter_criteria)

    def generate_safe_stats_report(self, filter_criteria: str) -> List[Dict[str, Any]]:
        """Generate safe statistics report - uses sanitized path"""
        return self.analytics_service.get_user_stats_safe(filter_criteria)


class DashboardService:
    """Dashboard service - Top layer"""

    def __init__(self, reporting_service: ReportingService):
        self.reporting_service = reporting_service

    def get_dashboard_data(self, filter_str: str) -> List[Dict[str, Any]]:
        """Get dashboard data - passes through to ReportingService"""
        return self.reporting_service.generate_stats_report(filter_str)

    def get_filtered_dashboard(self, filter_str: str) -> List[Dict[str, Any]]:
        """Get filtered dashboard with sanitization - uses safe path"""
        return self.reporting_service.generate_safe_stats_report(filter_str)
