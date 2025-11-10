# Configuration Loader Utility
import json

class ConfigLoader:
    def __init__(self):
        self.config_file = 'config/app_config.json'
    
    def get_health_check_query(self):
        """Get predefined health check query from config"""
        # Load from configuration file, not user input
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                return config.get('health_check_query', 'SELECT 1')
        except:
            # Fallback to safe default
            return 'SELECT 1'
