"""
Python Banking Application - Comprehensive Security Testing
============================================================

A realistic banking application with multiple attack vectors.
Designed to test cross-file, cross-class attack path detection.

Architecture:
- controllers/ - HTTP endpoints (Flask routes)
- services/ - Business logic layer
- repositories/ - Data access layer
- utils/ - Utility functions
- models/ - Data models
"""

from flask import Flask, request, jsonify
from controllers.account_controller import account_bp
from controllers.transaction_controller import transaction_bp
from controllers.loan_controller import loan_bp
from controllers.admin_controller import admin_bp

app = Flask(__name__)

# Register blueprints
app.register_blueprint(account_bp, url_prefix='/api/accounts')
app.register_blueprint(transaction_bp, url_prefix='/api/transactions')
app.register_blueprint(loan_bp, url_prefix='/api/loans')
app.register_blueprint(admin_bp, url_prefix='/api/admin')

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
