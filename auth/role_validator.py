# Role Validation Layer
from database.permission_repository import PermissionRepository

class RoleValidator:
    def __init__(self):
        self.permission_repo = PermissionRepository()
    
    def validate_user_role(self, user_id, context):
        """Validate user role and permissions"""
        # Get user permissions for context
        permissions = self.get_user_permissions(user_id)
        return 'search_users' in permissions
    
    def get_user_permissions(self, user_id):
        """Get user permissions from database"""
        return self.permission_repo.fetch_permissions(user_id)
    
    def check_admin_privileges(self, user_id):
        """Check if user has admin privileges"""
        # Load admin config and verify
        admin_config = self.load_admin_config()
        return user_id in admin_config.get('admin_users', [])
    
    def load_admin_config(self):
        """Load admin configuration"""
        return self.permission_repo.get_admin_config()
