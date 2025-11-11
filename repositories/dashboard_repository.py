"""
Dashboard Repository - Database operations for dashboard
Contains VULN-7 SINK
"""
import sqlite3

class DashboardRepository:
    def __init__(self):
        self.db_path = 'ecommerce.db'
        # Predefined trusted templates
        self.trusted_templates = {
            'admin_dashboard': '<h1>Admin Dashboard</h1><div>{{stats}}</div>',
            'user_dashboard': '<h1>User Dashboard</h1><div>{{data}}</div>',
            'analytics_dashboard': '<h1>Analytics</h1><div>{{charts}}</div>'
        }
    
    def build_dashboard_data(self, user_id: str):
        """
        VULN-7 Chain Step 3: Build dashboard data
        Query uses safe practices - FP_SAFE_CONTEXT
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Safe parameterized query
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        
        return {
            'user': user_data,
            'stats': self._get_user_stats(user_id)
        }
    
    def _get_user_stats(self, user_id: str):
        """Helper to get user statistics"""
        return {'orders': 10, 'revenue': 1000}
    
    def create_dashboard_template(self, dashboard_data: dict):
        """
        VULN-7 Chain Step 4 & SINK: Create and render dashboard template
        FALSE POSITIVE - Uses only trusted templates from internal source
        """
        from flask import render_template_string
        
        # Template comes from trusted internal dictionary, NOT user input
        template = self.trusted_templates.get('admin_dashboard', self.trusted_templates['user_dashboard'])
        
        # Even though render_template_string is used, template is from trusted source
        return render_template_string(template, **dashboard_data)  # FP_SAFE_CONTEXT: Trusted template
