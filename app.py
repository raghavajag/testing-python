"""
MINIMAL FALSE POSITIVE TEST CODEBASE
=====================================

10 Total Sinks:
- 3 True Positives (must_fix)
- 7 False Positives:
  - 3 Sanitized (parameterized queries, shlex.quote, html.escape)
  - 2 Protected (behind @admin_required)
  - 2 Dead Code (feature flags, unreachable)
"""

import os
import re
import html
import subprocess
import sqlite3
import shlex
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, session, Response

app = Flask(__name__)
app.secret_key = 'test-secret-key'

# Feature flag - ALWAYS FALSE (for dead code)
ENABLE_DEBUG_MODE = False

# =============================================================================
# DATABASE
# =============================================================================

class Database:
    def __init__(self):
        self.conn = sqlite3.connect(':memory:', check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        
    def execute_raw(self, query: str):
        """VULNERABLE: Raw SQL execution"""
        cursor = self.conn.cursor()
        cursor.execute(query)  # SINK: SQL Injection
        return cursor
    
    def execute_safe(self, query: str, params: tuple):
        """SAFE: Parameterized query"""
        cursor = self.conn.cursor()
        cursor.execute(query, params)  # SINK but SAFE: Parameterized
        return cursor

db = Database()

# =============================================================================
# AUTH DECORATORS
# =============================================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """STRONG PROTECTION: Admin + IP whitelist + MFA"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Login required'}), 401
        if not session.get('is_admin'):
            return jsonify({'error': 'Admin required'}), 403
        # IP whitelist check
        if request.remote_addr not in ['127.0.0.1', '10.0.0.1']:
            return jsonify({'error': 'IP not allowed'}), 403
        # MFA check
        if not session.get('mfa_verified'):
            return jsonify({'error': 'MFA required'}), 403
        return f(*args, **kwargs)
    return decorated


# =============================================================================
# TRUE POSITIVES (3 vulnerabilities - must be flagged as must_fix)
# =============================================================================

@app.route('/api/tp/sql', methods=['GET'])
@login_required
def tp_sql_injection():
    """TP-001: SQL Injection - No sanitization"""
    user_input = request.args.get('search', '')
    # VULNERABLE: Direct string concatenation into SQL
    query = f"SELECT * FROM users WHERE name LIKE '%{user_input}%'"
    cursor = db.execute_raw(query)  # SINK: SQL Injection [TP-001]
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/api/tp/cmd', methods=['POST'])
@login_required
def tp_command_injection():
    """TP-002: Command Injection - No sanitization"""
    host = request.json.get('host', '')
    # VULNERABLE: User input directly in shell command
    command = f"ping -c 1 {host}"
    result = subprocess.check_output(command, shell=True)  # SINK: Command Injection [TP-002]
    return jsonify({'output': result.decode()})


@app.route('/api/tp/xss', methods=['GET'])
@login_required
def tp_xss():
    """TP-003: XSS - No escaping"""
    name = request.args.get('name', '')
    # VULNERABLE: User input directly in HTML
    html_output = f"<h1>Hello, {name}!</h1>"
    return Response(html_output, mimetype='text/html')  # SINK: XSS [TP-003]


# =============================================================================
# FALSE POSITIVES - SANITIZED (3 cases)
# =============================================================================

@app.route('/api/fp/sani/sql', methods=['GET'])
@login_required
def fp_sanitized_sql():
    """FP-SANI-001: SQL with parameterized query - FALSE POSITIVE"""
    user_input = request.args.get('id', '')
    # SANITIZED: Using parameterized query with ?
    cursor = db.execute_safe(
        "SELECT * FROM users WHERE id = ?",
        (user_input,)  # Parameter binding prevents injection
    )  # SINK but SAFE: Parameterized [FP-SANI-001]
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/api/fp/sani/cmd', methods=['POST'])
@login_required
def fp_sanitized_cmd():
    """FP-SANI-002: Command with shlex.quote - FALSE POSITIVE"""
    host = request.json.get('host', '')
    # SANITIZED: Using shlex.quote to escape shell metacharacters
    safe_host = shlex.quote(host)
    command = f"ping -c 1 {safe_host}"
    result = subprocess.check_output(command, shell=True)  # SINK but SAFE: shlex.quote [FP-SANI-002]
    return jsonify({'output': result.decode()})


@app.route('/api/fp/sani/xss', methods=['GET'])
@login_required
def fp_sanitized_xss():
    """FP-SANI-003: XSS with html.escape - FALSE POSITIVE"""
    name = request.args.get('name', '')
    # SANITIZED: Using html.escape to prevent XSS
    safe_name = html.escape(name)
    html_output = f"<h1>Hello, {safe_name}!</h1>"
    return Response(html_output, mimetype='text/html')  # SINK but SAFE: html.escape [FP-SANI-003]


# =============================================================================
# FALSE POSITIVES - PROTECTED (2 cases behind @admin_required)
# =============================================================================

@app.route('/admin/fp/prot/sql', methods=['GET'])
@admin_required  # PROTECTED: Requires admin + IP whitelist + MFA
def fp_protected_sql():
    """FP-PROT-001: SQL behind admin_required - FALSE POSITIVE"""
    query = request.args.get('q', '')
    # Protected by @admin_required decorator (admin + IP + MFA)
    cursor = db.execute_raw(f"SELECT * FROM audit WHERE action = '{query}'")  # SINK but PROTECTED [FP-PROT-001]
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/admin/fp/prot/cmd', methods=['POST'])
@admin_required  # PROTECTED: Requires admin + IP whitelist + MFA
def fp_protected_cmd():
    """FP-PROT-002: Command behind admin_required - FALSE POSITIVE"""
    cmd = request.json.get('cmd', '')
    # Protected by @admin_required decorator (admin + IP + MFA)
    result = subprocess.check_output(cmd, shell=True)  # SINK but PROTECTED [FP-PROT-002]
    return jsonify({'output': result.decode()})


# =============================================================================
# FALSE POSITIVES - DEAD CODE (2 cases)
# =============================================================================

@app.route('/api/fp/dead/sql', methods=['GET'])
def fp_dead_code_sql():
    """FP-DEAD-001: SQL behind always-false flag - FALSE POSITIVE"""
    if ENABLE_DEBUG_MODE:  # Always False - code never executes
        query = request.args.get('q', '')
        cursor = db.execute_raw(f"SELECT * FROM debug WHERE q = '{query}'")  # SINK but DEAD [FP-DEAD-001]
        return jsonify([dict(row) for row in cursor.fetchall()])
    return jsonify({'error': 'Debug mode disabled'}), 404


@app.route('/api/fp/dead/cmd', methods=['GET'])
def fp_dead_code_cmd():
    """FP-DEAD-002: Command after unconditional return - FALSE POSITIVE"""
    return jsonify({'status': 'ok'})  # Always returns here
    # Code below NEVER executes
    cmd = request.args.get('cmd', '')
    os.system(cmd)  # SINK but DEAD [FP-DEAD-002]
    return jsonify({'executed': True})


# =============================================================================
# DATABASE INIT
# =============================================================================

def init_db():
    cursor = db.conn.cursor()
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT,
            email TEXT
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY,
            action TEXT,
            timestamp TEXT
        );
        CREATE TABLE IF NOT EXISTS debug (
            id INTEGER PRIMARY KEY,
            q TEXT
        );
        INSERT OR IGNORE INTO users (id, name, email) VALUES (1, 'admin', 'admin@test.com');
        INSERT OR IGNORE INTO users (id, name, email) VALUES (2, 'user', 'user@test.com');
    ''')
    db.conn.commit()


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5001)
