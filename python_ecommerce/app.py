"""
Python Flask E-Commerce Testing Application
============================================

This testing codebase contains 8 carefully crafted vulnerabilities to test
the AI-SAST scanner's classification logic:

VULNERABILITY DISTRIBUTION:
1. VULN_1 (SQL Injection) - FALSE_POSITIVE_DEAD_CODE: Legacy unused code
2. VULN_2 (SQL Injection) - FALSE_POSITIVE_SANITIZED: ORM with parameterized queries
3. VULN_3 (SSTI) - FALSE_POSITIVE_SANITIZED: Input validation with allowlist
4. VULN_4 (SQL Injection) - FALSE_POSITIVE_PROTECTED: Admin-only with CSRF + auth
5. VULN_5 (SSTI) - FALSE_POSITIVE_PROTECTED: Multiple security layers
6. VULN_6 (SQL Injection) - MUST_FIX: Direct SQL injection, no protections
7. VULN_7 (SSTI) - MUST_FIX: Template injection, user input unescaped
8. VULN_8 (SQL Injection) - GOOD_TO_FIX: Has validation but can be bypassed

Each vulnerability has 3-5 attack paths with 5-6+ function chains.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3

app = Flask(__name__)
CORS(app)

# Database connection
def get_db_connection():
    conn = sqlite3.connect('ecommerce.db')
    conn.row_factory = sqlite3.Row
    return conn

# Entry points for all vulnerabilities defined in controllers
from controllers.product_controller import product_bp
from controllers.order_controller import order_bp  
from controllers.admin_controller import admin_bp
from controllers.report_controller import report_bp
from controllers.legacy_controller import legacy_bp

app.register_blueprint(product_bp, url_prefix='/api/products')
app.register_blueprint(order_bp, url_prefix='/api/orders')
app.register_blueprint(admin_bp, url_prefix='/api/admin')
app.register_blueprint(report_bp, url_prefix='/api/reports')
app.register_blueprint(legacy_bp, url_prefix='/api/legacy')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
