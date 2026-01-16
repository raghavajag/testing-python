"""
FALSE POSITIVE STRESS TEST CODEBASE
====================================

Designed to stress-test AI-SAST False Positive detection capabilities.

INVENTORY:
==========
TRUE POSITIVES (10 total - must be flagged as must_fix):
- TP-SQL-001: Raw SQL injection, no sanitization
- TP-SQL-002: SQL injection via string formatting
- TP-CMD-001: Command injection via subprocess shell=True
- TP-CMD-002: Command injection via os.system
- TP-SSTI-001: Direct render_template_string with user input
- TP-SSTI-002: Template injection via custom engine
- TP-XSS-001: Reflected XSS in response
- TP-XSS-002: Stored XSS in database
- TP-PATH-001: Path traversal in file read
- TP-SSRF-001: SSRF via user-controlled URL

FALSE POSITIVES - SANITIZED (25 total):
- FP-SANI-SQL-001 to 010: SQL with parameterized queries
- FP-SANI-CMD-001 to 005: Commands with proper escaping/allowlists
- FP-SANI-SSTI-001 to 005: Templates with escaping/sandboxing
- FP-SANI-XSS-001 to 005: XSS with html.escape or markupsafe

FALSE POSITIVES - PROTECTED (25 total):
- FP-PROT-SQL-001 to 010: SQL behind @admin_required, @role_required
- FP-PROT-CMD-001 to 005: Commands behind @superuser_only
- FP-PROT-SSTI-001 to 005: Templates behind @internal_only
- FP-PROT-XSS-001 to 005: XSS behind @auth_required with IP check

FALSE POSITIVES - DEAD CODE (25 total):
- FP-DEAD-SQL-001 to 010: SQL in never-called functions
- FP-DEAD-CMD-001 to 005: Commands behind always-false flags
- FP-DEAD-SSTI-001 to 005: Templates in deprecated modules
- FP-DEAD-XSS-001 to 005: XSS in unreachable code branches

TOTAL: 10 True Positives + 75 False Positives = 85 findings
"""

import os
import re
import html
import subprocess
import sqlite3
import hashlib
import urllib.request
import shlex
from functools import wraps
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple, Callable

from flask import Flask, request, jsonify, render_template_string, g, session, abort, Response
from werkzeug.security import generate_password_hash, check_password_hash

# Try importing markupsafe for proper escaping
try:
    from markupsafe import escape as safe_escape, Markup
except ImportError:
    from html import escape as safe_escape
    Markup = str

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-prod')

# =============================================================================
# FEATURE FLAGS (For dead code simulation)
# =============================================================================

ENABLE_LEGACY_FEATURES = False  # Always False - dead code
ENABLE_DEBUG_MODE = False       # Always False - dead code
ENABLE_ADMIN_BACKDOOR = False   # Always False - dead code
EXPERIMENTAL_SQL = False        # Always False - dead code
DEPRECATED_TEMPLATES = False    # Always False - dead code

# =============================================================================
# DATABASE LAYER
# =============================================================================

class Database:
    """Database connection manager with multiple execution methods."""
    
    def __init__(self, db_path: str = ':memory:'):
        self.db_path = db_path
        self._connection = None
    
    def get_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            self._connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self._connection.row_factory = sqlite3.Row
        return self._connection
    
    # === VULNERABLE SINKS ===
    
    def execute_raw(self, query: str) -> sqlite3.Cursor:
        """SINK: Raw SQL execution - VULNERABLE"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query)  # SINK: SQL Injection
        return cursor
    
    # === SAFE EXECUTION METHODS ===
    
    def execute_parameterized(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """SAFE: Parameterized query execution"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)  # SAFE: Parameterized
        return cursor
    
    def execute_with_named_params(self, query: str, params: dict) -> sqlite3.Cursor:
        """SAFE: Named parameter query execution"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)  # SAFE: Named params
        return cursor


db = Database()


# =============================================================================
# AUTHENTICATION DECORATORS
# =============================================================================

def login_required(f: Callable) -> Callable:
    """Basic authentication check."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f: Callable) -> Callable:
    """Admin role authentication check - STRONG PROTECTION."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        if not session.get('is_admin'):
            return jsonify({'error': 'Admin privileges required'}), 403
        # Additional IP whitelist check
        allowed_ips = ['127.0.0.1', '10.0.0.0/8', '192.168.0.0/16']
        client_ip = request.remote_addr
        if not any(client_ip.startswith(ip.split('/')[0][:8]) for ip in allowed_ips):
            return jsonify({'error': 'IP not whitelisted for admin access'}), 403
        return f(*args, **kwargs)
    return decorated


def superuser_only(f: Callable) -> Callable:
    """Superuser-only access - STRONGEST PROTECTION."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        if session.get('role') != 'superuser':
            return jsonify({'error': 'Superuser privileges required'}), 403
        # MFA verification required
        if not session.get('mfa_verified'):
            return jsonify({'error': 'MFA verification required'}), 403
        return f(*args, **kwargs)
    return decorated


def internal_only(f: Callable) -> Callable:
    """Internal network only access."""
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr
        if not client_ip.startswith('10.') and not client_ip.startswith('192.168.'):
            return jsonify({'error': 'Internal network access only'}), 403
        return f(*args, **kwargs)
    return decorated


def role_required(role: str) -> Callable:
    """Role-based access control decorator."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            if session.get('role') != role:
                return jsonify({'error': f'{role} role required'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# =============================================================================
# INPUT VALIDATION / SANITIZATION UTILITIES
# =============================================================================

class InputSanitizer:
    """Comprehensive input sanitization utilities."""
    
    # SQL-safe patterns
    SQL_SAFE_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.@]+$')
    NUMERIC_PATTERN = re.compile(r'^\d+$')
    UUID_PATTERN = re.compile(r'^[a-f0-9\-]{36}$')
    
    # Command injection prevention
    COMMAND_ALLOWLIST = ['ping', 'traceroute', 'nslookup', 'dig', 'host']
    HOST_PATTERN = re.compile(r'^[a-zA-Z0-9\.\-]+$')
    
    @classmethod
    def sanitize_sql_identifier(cls, value: str) -> str:
        """Sanitize value for use in SQL identifier context."""
        if not cls.SQL_SAFE_PATTERN.match(value):
            raise ValueError(f"Invalid SQL identifier: {value}")
        return value
    
    @classmethod
    def sanitize_numeric(cls, value: str) -> int:
        """Ensure value is numeric only."""
        if not cls.NUMERIC_PATTERN.match(str(value)):
            raise ValueError(f"Non-numeric value: {value}")
        return int(value)
    
    @classmethod
    def sanitize_hostname(cls, hostname: str) -> str:
        """Sanitize hostname for safe command usage."""
        if not cls.HOST_PATTERN.match(hostname):
            raise ValueError(f"Invalid hostname: {hostname}")
        if len(hostname) > 253:
            raise ValueError("Hostname too long")
        return hostname
    
    @classmethod
    def sanitize_command(cls, cmd: str) -> str:
        """Validate command against allowlist."""
        base_cmd = cmd.split()[0] if cmd else ''
        if base_cmd not in cls.COMMAND_ALLOWLIST:
            raise ValueError(f"Command not allowed: {base_cmd}")
        return cmd
    
    @classmethod
    def escape_html(cls, value: str) -> str:
        """Escape HTML entities."""
        return html.escape(str(value))
    
    @classmethod
    def escape_template(cls, template: str) -> str:
        """Escape Jinja2 template expressions."""
        # Remove dangerous template constructs
        dangerous_patterns = ['{{', '}}', '{%', '%}', '{#', '#}']
        result = template
        for pattern in dangerous_patterns:
            result = result.replace(pattern, '')
        return result


sanitizer = InputSanitizer()


# =============================================================================
# TRUE POSITIVES (10 vulnerabilities that MUST be detected)
# =============================================================================

# --- TP-SQL-001: Raw SQL injection ---
@app.route('/api/v1/tp/sql/search', methods=['GET'])
@login_required
def tp_sql_001_raw_injection():
    """TP-SQL-001: Direct SQL injection - no sanitization."""
    search_term = request.args.get('q', '')
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    cursor = db.execute_raw(query)  # SINK: SQL Injection
    return jsonify([dict(row) for row in cursor.fetchall()])


# --- TP-SQL-002: SQL injection via format string ---
@app.route('/api/v1/tp/sql/user/<user_id>', methods=['GET'])
@login_required
def tp_sql_002_format_injection(user_id: str):
    """TP-SQL-002: SQL injection via format string."""
    # VULNERABLE: String formatting with user input
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    cursor = db.execute_raw(query)  # SINK: SQL Injection
    return jsonify(dict(cursor.fetchone()) if cursor.fetchone() else {})


# --- TP-CMD-001: Command injection via subprocess ---
@app.route('/api/v1/tp/cmd/ping', methods=['POST'])
@login_required
def tp_cmd_001_subprocess_injection():
    """TP-CMD-001: Command injection via subprocess shell=True."""
    host = request.json.get('host', '')
    # VULNERABLE: User input in shell command
    command = f"ping -c 1 {host}"
    result = subprocess.check_output(command, shell=True)  # SINK: Command Injection
    return jsonify({'output': result.decode()})


# --- TP-CMD-002: Command injection via os.system ---
@app.route('/api/v1/tp/cmd/trace', methods=['POST'])
@login_required
def tp_cmd_002_os_system():
    """TP-CMD-002: Command injection via os.system."""
    target = request.json.get('target', '')
    # VULNERABLE: Direct os.system call
    os.system(f"traceroute {target}")  # SINK: Command Injection
    return jsonify({'status': 'trace initiated'})


# --- TP-SSTI-001: Direct SSTI ---
@app.route('/api/v1/tp/ssti/render', methods=['POST'])
@login_required
def tp_ssti_001_direct():
    """TP-SSTI-001: Direct template injection."""
    template = request.json.get('template', '')
    data = request.json.get('data', {})
    # VULNERABLE: User-controlled template
    return render_template_string(template, **data)  # SINK: SSTI


# --- TP-SSTI-002: SSTI via custom engine ---
class UnsafeTemplateEngine:
    """Unsafe template engine that passes through user input."""
    
    def render(self, template: str, context: dict) -> str:
        """VULNERABLE: No escaping or sandboxing."""
        return render_template_string(template, **context)  # SINK: SSTI


@app.route('/api/v1/tp/ssti/custom', methods=['POST'])
@login_required
def tp_ssti_002_custom_engine():
    """TP-SSTI-002: Template injection via custom engine."""
    engine = UnsafeTemplateEngine()
    template = request.json.get('template', '')
    context = request.json.get('context', {})
    result = engine.render(template, context)
    return Response(result, mimetype='text/html')


# --- TP-XSS-001: Reflected XSS ---
@app.route('/api/v1/tp/xss/reflect', methods=['GET'])
@login_required
def tp_xss_001_reflected():
    """TP-XSS-001: Reflected XSS in response."""
    name = request.args.get('name', 'Guest')
    # VULNERABLE: No HTML escaping
    html_response = f"<html><body><h1>Hello, {name}!</h1></body></html>"
    return Response(html_response, mimetype='text/html')  # SINK: XSS


# --- TP-XSS-002: Stored XSS ---
@app.route('/api/v1/tp/xss/store', methods=['POST'])
@login_required
def tp_xss_002_stored():
    """TP-XSS-002: Stored XSS via database."""
    comment = request.json.get('comment', '')
    # VULNERABLE: Storing unescaped user input
    query = f"INSERT INTO comments (text) VALUES ('{comment}')"
    db.execute_raw(query)  # Also SQL injection
    return jsonify({'status': 'stored'})


# --- TP-PATH-001: Path traversal ---
@app.route('/api/v1/tp/path/read', methods=['GET'])
@login_required
def tp_path_001_traversal():
    """TP-PATH-001: Path traversal in file read."""
    filename = request.args.get('file', '')
    # VULNERABLE: No path sanitization
    filepath = f"/var/data/{filename}"
    with open(filepath, 'r') as f:  # SINK: Path Traversal
        content = f.read()
    return jsonify({'content': content})


# --- TP-SSRF-001: SSRF ---
@app.route('/api/v1/tp/ssrf/fetch', methods=['POST'])
@login_required
def tp_ssrf_001_fetch():
    """TP-SSRF-001: SSRF via user-controlled URL."""
    url = request.json.get('url', '')
    # VULNERABLE: No URL validation
    response = urllib.request.urlopen(url)  # SINK: SSRF
    return jsonify({'content': response.read().decode()})


# =============================================================================
# FALSE POSITIVES - SANITIZED (25 false positives)
# =============================================================================

# --- FP-SANI-SQL-001 to 010: Parameterized SQL queries ---

@app.route('/api/v1/fp/sani/sql/001', methods=['GET'])
@login_required
def fp_sani_sql_001():
    """FP-SANI-SQL-001: Parameterized query with ?."""
    user_id = request.args.get('id', '')
    # SANITIZED: Using parameterized query
    cursor = db.execute_parameterized(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)  # SAFE: Parameter binding
    )
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # SINK but SAFE
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/api/v1/fp/sani/sql/002', methods=['GET'])
@login_required
def fp_sani_sql_002():
    """FP-SANI-SQL-002: Named parameter query."""
    email = request.args.get('email', '')
    # SANITIZED: Named parameters
    cursor = db.execute_with_named_params(
        "SELECT * FROM users WHERE email = :email",
        {'email': email}  # SAFE: Named binding
    )
    cursor.execute("SELECT * FROM users WHERE email = :email", {'email': email})  # SINK but SAFE
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/api/v1/fp/sani/sql/003', methods=['GET'])
@login_required
def fp_sani_sql_003():
    """FP-SANI-SQL-003: Multiple parameter binding."""
    name = request.args.get('name', '')
    status = request.args.get('status', '')
    # SANITIZED: Multiple parameters
    cursor = db.get_connection().cursor()
    cursor.execute(
        "SELECT * FROM users WHERE name = ? AND status = ?",
        (name, status)  # SAFE: Tuple binding
    )  # SINK but SAFE
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/api/v1/fp/sani/sql/004', methods=['POST'])
@login_required
def fp_sani_sql_004():
    """FP-SANI-SQL-004: executemany with parameters."""
    items = request.json.get('items', [])
    conn = db.get_connection()
    cursor = conn.cursor()
    # SANITIZED: executemany with parameter list
    cursor.executemany(
        "INSERT INTO items (name, value) VALUES (?, ?)",
        [(item['name'], item['value']) for item in items]  # SAFE
    )  # SINK but SAFE
    conn.commit()
    return jsonify({'status': 'inserted'})


@app.route('/api/v1/fp/sani/sql/005', methods=['GET'])
@login_required
def fp_sani_sql_005():
    """FP-SANI-SQL-005: Validated identifier + parameterized value."""
    table = request.args.get('table', 'users')
    search = request.args.get('q', '')
    # SANITIZED: Identifier validation + param binding
    safe_table = sanitizer.sanitize_sql_identifier(table)
    cursor = db.get_connection().cursor()
    cursor.execute(
        f"SELECT * FROM {safe_table} WHERE name LIKE ?",
        (f'%{search}%',)  # SAFE: Param for value
    )  # SINK but SAFE (identifier validated, value parameterized)
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/api/v1/fp/sani/sql/006', methods=['GET'])
@login_required
def fp_sani_sql_006():
    """FP-SANI-SQL-006: Numeric validation before query."""
    user_id = request.args.get('id', '')
    # SANITIZED: Numeric validation
    safe_id = sanitizer.sanitize_numeric(user_id)  # Raises if not numeric
    cursor = db.get_connection().cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {safe_id}")  # SINK but SAFE (validated numeric)
    return jsonify(dict(cursor.fetchone()) if cursor.fetchone() else {})


@app.route('/api/v1/fp/sani/sql/007', methods=['GET'])
@login_required
def fp_sani_sql_007():
    """FP-SANI-SQL-007: UUID validation."""
    record_id = request.args.get('id', '')
    # SANITIZED: UUID format validation
    if not sanitizer.UUID_PATTERN.match(record_id):
        return jsonify({'error': 'Invalid UUID'}), 400
    cursor = db.get_connection().cursor()
    cursor.execute(f"SELECT * FROM records WHERE id = '{record_id}'")  # SINK but SAFE (UUID validated)
    return jsonify(dict(cursor.fetchone()) if cursor.fetchone() else {})


@app.route('/api/v1/fp/sani/sql/008', methods=['GET'])
@login_required
def fp_sani_sql_008():
    """FP-SANI-SQL-008: Allowlist column selection."""
    column = request.args.get('sort', 'id')
    ALLOWED_COLUMNS = ['id', 'name', 'email', 'created_at']
    # SANITIZED: Column allowlist
    if column not in ALLOWED_COLUMNS:
        column = 'id'  # Default to safe value
    cursor = db.get_connection().cursor()
    cursor.execute(f"SELECT * FROM users ORDER BY {column}")  # SINK but SAFE (allowlist)
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/api/v1/fp/sani/sql/009', methods=['POST'])
@login_required
def fp_sani_sql_009():
    """FP-SANI-SQL-009: ORM-style query builder."""
    filters = request.json.get('filters', {})
    query_parts = ["SELECT * FROM users WHERE 1=1"]
    params = []
    # SANITIZED: Building parameterized query
    if 'name' in filters:
        query_parts.append("AND name = ?")
        params.append(filters['name'])
    if 'email' in filters:
        query_parts.append("AND email = ?")
        params.append(filters['email'])
    cursor = db.get_connection().cursor()
    cursor.execute(" ".join(query_parts), tuple(params))  # SINK but SAFE
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/api/v1/fp/sani/sql/010', methods=['GET'])
@login_required
def fp_sani_sql_010():
    """FP-SANI-SQL-010: Escaped LIKE pattern."""
    search = request.args.get('q', '')
    # SANITIZED: Escape LIKE special characters and parameterize
    escaped = search.replace('%', '\\%').replace('_', '\\_')
    cursor = db.get_connection().cursor()
    cursor.execute(
        "SELECT * FROM users WHERE name LIKE ? ESCAPE '\\'",
        (f'%{escaped}%',)  # SAFE: Escaped + parameterized
    )  # SINK but SAFE
    return jsonify([dict(row) for row in cursor.fetchall()])


# --- FP-SANI-CMD-001 to 005: Safe command execution ---

@app.route('/api/v1/fp/sani/cmd/001', methods=['POST'])
@login_required
def fp_sani_cmd_001():
    """FP-SANI-CMD-001: Command with shlex.quote."""
    host = request.json.get('host', '')
    # SANITIZED: Using shlex.quote for shell escaping
    safe_host = shlex.quote(host)
    result = subprocess.check_output(
        f"ping -c 1 {safe_host}",
        shell=True  # SINK but SAFE (shlex.quote)
    )
    return jsonify({'output': result.decode()})


@app.route('/api/v1/fp/sani/cmd/002', methods=['POST'])
@login_required
def fp_sani_cmd_002():
    """FP-SANI-CMD-002: Command list without shell=True."""
    host = request.json.get('host', '')
    # SANITIZED: Using list arguments, no shell
    result = subprocess.check_output(
        ['ping', '-c', '1', host],
        shell=False  # SAFE: No shell interpretation
    )  # SINK but SAFE
    return jsonify({'output': result.decode()})


@app.route('/api/v1/fp/sani/cmd/003', methods=['POST'])
@login_required
def fp_sani_cmd_003():
    """FP-SANI-CMD-003: Hostname validation before command."""
    host = request.json.get('host', '')
    # SANITIZED: Strict hostname validation
    safe_host = sanitizer.sanitize_hostname(host)  # Raises if invalid
    result = subprocess.check_output(
        f"ping -c 1 {safe_host}",
        shell=True  # SINK but SAFE (hostname validated)
    )
    return jsonify({'output': result.decode()})


@app.route('/api/v1/fp/sani/cmd/004', methods=['POST'])
@login_required
def fp_sani_cmd_004():
    """FP-SANI-CMD-004: Command allowlist."""
    cmd = request.json.get('cmd', '')
    # SANITIZED: Command allowlist validation
    sanitizer.sanitize_command(cmd)  # Raises if not in allowlist
    result = subprocess.check_output(
        cmd,
        shell=True  # SINK but SAFE (allowlist)
    )
    return jsonify({'output': result.decode()})


@app.route('/api/v1/fp/sani/cmd/005', methods=['POST'])
@login_required
def fp_sani_cmd_005():
    """FP-SANI-CMD-005: subprocess.run with explicit args."""
    target = request.json.get('target', '')
    # SANITIZED: Hostname validated + explicit argument list
    safe_target = sanitizer.sanitize_hostname(target)
    result = subprocess.run(
        ['traceroute', '-m', '5', safe_target],
        capture_output=True,
        text=True,
        timeout=30
    )  # SAFE: List args, no shell
    return jsonify({'output': result.stdout})


# --- FP-SANI-SSTI-001 to 005: Safe template rendering ---

@app.route('/api/v1/fp/sani/ssti/001', methods=['POST'])
@login_required
def fp_sani_ssti_001():
    """FP-SANI-SSTI-001: Escaped template data."""
    name = request.json.get('name', '')
    # SANITIZED: Data escaped before template
    safe_name = safe_escape(name)
    template = "<h1>Hello, {{ name }}!</h1>"
    return render_template_string(template, name=safe_name)  # SINK but SAFE


@app.route('/api/v1/fp/sani/ssti/002', methods=['POST'])
@login_required
def fp_sani_ssti_002():
    """FP-SANI-SSTI-002: Static template, dynamic data only."""
    user = request.json.get('user', {})
    # SANITIZED: Template is static (not user-controlled)
    STATIC_TEMPLATE = """
    <html>
    <body>
        <h1>User Profile</h1>
        <p>Name: {{ user.name | e }}</p>
        <p>Email: {{ user.email | e }}</p>
    </body>
    </html>
    """
    return render_template_string(STATIC_TEMPLATE, user=user)  # SINK but SAFE


@app.route('/api/v1/fp/sani/ssti/003', methods=['POST'])
@login_required
def fp_sani_ssti_003():
    """FP-SANI-SSTI-003: Template expression stripping."""
    template = request.json.get('template', '')
    data = request.json.get('data', {})
    # SANITIZED: Remove dangerous template expressions
    safe_template = sanitizer.escape_template(template)
    return render_template_string(safe_template, **data)  # SINK but SAFE


@app.route('/api/v1/fp/sani/ssti/004', methods=['POST'])
@login_required  
def fp_sani_ssti_004():
    """FP-SANI-SSTI-004: Jinja2 sandbox environment."""
    template = request.json.get('template', '')
    data = request.json.get('data', {})
    # SANITIZED: Using sandboxed environment
    from jinja2.sandbox import SandboxedEnvironment
    env = SandboxedEnvironment()
    tmpl = env.from_string(template)
    return Response(tmpl.render(**data), mimetype='text/html')  # SAFE: Sandboxed


@app.route('/api/v1/fp/sani/ssti/005', methods=['POST'])
@login_required
def fp_sani_ssti_005():
    """FP-SANI-SSTI-005: Template allowlist."""
    template_name = request.json.get('template', '')
    data = request.json.get('data', {})
    ALLOWED_TEMPLATES = {
        'greeting': "<h1>Hello, {{ name | e }}!</h1>",
        'profile': "<p>User: {{ username | e }}</p>",
        'status': "<span>Status: {{ status | e }}</span>",
    }
    # SANITIZED: Template selected from allowlist
    if template_name not in ALLOWED_TEMPLATES:
        return jsonify({'error': 'Invalid template'}), 400
    template = ALLOWED_TEMPLATES[template_name]
    return render_template_string(template, **data)  # SINK but SAFE (allowlist)


# --- FP-SANI-XSS-001 to 005: XSS with proper escaping ---

@app.route('/api/v1/fp/sani/xss/001', methods=['GET'])
@login_required
def fp_sani_xss_001():
    """FP-SANI-XSS-001: HTML escaped output."""
    name = request.args.get('name', 'Guest')
    # SANITIZED: HTML escaping
    safe_name = html.escape(name)
    html_response = f"<html><body><h1>Hello, {safe_name}!</h1></body></html>"
    return Response(html_response, mimetype='text/html')  # SAFE


@app.route('/api/v1/fp/sani/xss/002', methods=['GET'])
@login_required
def fp_sani_xss_002():
    """FP-SANI-XSS-002: Markupsafe escaped output."""
    message = request.args.get('msg', '')
    # SANITIZED: Markupsafe escaping
    safe_msg = safe_escape(message)
    return Response(f"<p>{safe_msg}</p>", mimetype='text/html')  # SAFE


@app.route('/api/v1/fp/sani/xss/003', methods=['GET'])
@login_required
def fp_sani_xss_003():
    """FP-SANI-XSS-003: JSON response (no HTML interpretation)."""
    data = request.args.get('data', '')
    # SANITIZED: JSON response - no HTML rendering
    return jsonify({'data': data})  # SAFE: JSON content-type


@app.route('/api/v1/fp/sani/xss/004', methods=['GET'])
@login_required
def fp_sani_xss_004():
    """FP-SANI-XSS-004: Content-Type text/plain."""
    content = request.args.get('content', '')
    # SANITIZED: Plain text response
    return Response(content, mimetype='text/plain')  # SAFE


@app.route('/api/v1/fp/sani/xss/005', methods=['POST'])
@login_required
def fp_sani_xss_005():
    """FP-SANI-XSS-005: Stored with escaping before retrieval."""
    comment = request.json.get('comment', '')
    # SANITIZED: Escape before storage
    safe_comment = html.escape(comment)
    cursor = db.get_connection().cursor()
    cursor.execute(
        "INSERT INTO comments (text) VALUES (?)",
        (safe_comment,)  # SAFE: Escaped + parameterized
    )
    return jsonify({'status': 'stored safely'})


# =============================================================================
# FALSE POSITIVES - PROTECTED (25 false positives behind auth decorators)
# =============================================================================

# --- FP-PROT-SQL-001 to 010: SQL behind strong auth ---

@app.route('/admin/fp/prot/sql/001', methods=['GET'])
@admin_required  # PROTECTED: Admin only
def fp_prot_sql_001():
    """FP-PROT-SQL-001: SQL behind admin_required."""
    query = request.args.get('q', '')
    # Protected by @admin_required - admin audit query
    cursor = db.execute_raw(f"SELECT * FROM audit_logs WHERE action LIKE '%{query}%'")  # SINK but PROTECTED
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/admin/fp/prot/sql/002', methods=['GET'])
@admin_required
def fp_prot_sql_002():
    """FP-PROT-SQL-002: SQL behind admin with IP whitelist."""
    table = request.args.get('table', '')
    # Protected by @admin_required (includes IP whitelist)
    cursor = db.execute_raw(f"SELECT COUNT(*) FROM {table}")  # SINK but PROTECTED
    return jsonify({'count': cursor.fetchone()[0]})


@app.route('/admin/fp/prot/sql/003', methods=['POST'])
@superuser_only  # PROTECTED: Superuser + MFA
def fp_prot_sql_003():
    """FP-PROT-SQL-003: SQL behind superuser_only."""
    query = request.json.get('query', '')
    # Protected by @superuser_only (requires MFA)
    cursor = db.execute_raw(query)  # SINK but PROTECTED
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/admin/fp/prot/sql/004', methods=['GET'])
@role_required('dba')  # PROTECTED: DBA role
def fp_prot_sql_004():
    """FP-PROT-SQL-004: SQL behind DBA role."""
    schema = request.args.get('schema', '')
    # Protected by @role_required('dba')
    cursor = db.execute_raw(f"SELECT * FROM {schema}.tables")  # SINK but PROTECTED
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/internal/fp/prot/sql/005', methods=['GET'])
@internal_only  # PROTECTED: Internal network
def fp_prot_sql_005():
    """FP-PROT-SQL-005: SQL behind internal_only."""
    metric = request.args.get('metric', '')
    # Protected by @internal_only (IP check)
    cursor = db.execute_raw(f"SELECT * FROM metrics WHERE name = '{metric}'")  # SINK but PROTECTED
    return jsonify([dict(row) for row in cursor.fetchall()])


@app.route('/admin/fp/prot/sql/006', methods=['GET'])
@admin_required
@internal_only  # DOUBLE PROTECTION
def fp_prot_sql_006():
    """FP-PROT-SQL-006: SQL behind double protection."""
    user = request.args.get('user', '')
    # Protected by @admin_required AND @internal_only
    cursor = db.execute_raw(f"SELECT * FROM users WHERE username = '{user}'")  # SINK but PROTECTED
    return jsonify(dict(cursor.fetchone()) if cursor.fetchone() else {})


@app.route('/admin/fp/prot/sql/007', methods=['POST'])
@superuser_only
def fp_prot_sql_007():
    """FP-PROT-SQL-007: Batch SQL behind superuser."""
    queries = request.json.get('queries', [])
    results = []
    # Protected by @superuser_only
    for q in queries:
        cursor = db.execute_raw(q)  # SINK but PROTECTED
        results.append([dict(row) for row in cursor.fetchall()])
    return jsonify(results)


@app.route('/admin/fp/prot/sql/008', methods=['GET'])
@admin_required
def fp_prot_sql_008():
    """FP-PROT-SQL-008: SQL export behind admin."""
    format_str = request.args.get('format', '')
    # Protected by @admin_required
    cursor = db.execute_raw(f"SELECT * FROM users")  # SINK but PROTECTED
    return jsonify({'data': [dict(row) for row in cursor.fetchall()], 'format': format_str})


@app.route('/admin/fp/prot/sql/009', methods=['DELETE'])
@superuser_only
def fp_prot_sql_009():
    """FP-PROT-SQL-009: SQL delete behind superuser."""
    table = request.args.get('table', '')
    condition = request.args.get('where', '')
    # Protected by @superuser_only
    db.execute_raw(f"DELETE FROM {table} WHERE {condition}")  # SINK but PROTECTED
    return jsonify({'status': 'deleted'})


@app.route('/admin/fp/prot/sql/010', methods=['PUT'])
@admin_required
def fp_prot_sql_010():
    """FP-PROT-SQL-010: SQL update behind admin."""
    data = request.json
    table = data.get('table', '')
    set_clause = data.get('set', '')
    where = data.get('where', '')
    # Protected by @admin_required
    db.execute_raw(f"UPDATE {table} SET {set_clause} WHERE {where}")  # SINK but PROTECTED
    return jsonify({'status': 'updated'})


# --- FP-PROT-CMD-001 to 005: Commands behind strong auth ---

@app.route('/admin/fp/prot/cmd/001', methods=['POST'])
@superuser_only  # PROTECTED
def fp_prot_cmd_001():
    """FP-PROT-CMD-001: Command behind superuser_only."""
    cmd = request.json.get('cmd', '')
    # Protected by @superuser_only
    result = subprocess.check_output(cmd, shell=True)  # SINK but PROTECTED
    return jsonify({'output': result.decode()})


@app.route('/admin/fp/prot/cmd/002', methods=['POST'])
@admin_required
@internal_only  # DOUBLE PROTECTION
def fp_prot_cmd_002():
    """FP-PROT-CMD-002: Command behind admin + internal."""
    script = request.json.get('script', '')
    # Protected by @admin_required AND @internal_only
    os.system(f"bash -c '{script}'")  # SINK but PROTECTED
    return jsonify({'status': 'executed'})


@app.route('/admin/fp/prot/cmd/003', methods=['POST'])
@role_required('operator')  # PROTECTED
def fp_prot_cmd_003():
    """FP-PROT-CMD-003: Command behind operator role."""
    host = request.json.get('host', '')
    # Protected by @role_required('operator')
    result = subprocess.check_output(f"ping -c 3 {host}", shell=True)  # SINK but PROTECTED
    return jsonify({'output': result.decode()})


@app.route('/internal/fp/prot/cmd/004', methods=['POST'])
@internal_only  # PROTECTED
def fp_prot_cmd_004():
    """FP-PROT-CMD-004: Command behind internal_only."""
    diagnostic = request.json.get('cmd', '')
    # Protected by @internal_only
    result = subprocess.run(diagnostic, shell=True, capture_output=True)  # SINK but PROTECTED
    return jsonify({'output': result.stdout.decode()})


@app.route('/admin/fp/prot/cmd/005', methods=['POST'])
@superuser_only
@internal_only  # TRIPLE CHECK
def fp_prot_cmd_005():
    """FP-PROT-CMD-005: Command behind superuser + internal."""
    command = request.json.get('command', '')
    # Protected by @superuser_only AND @internal_only
    output = os.popen(command).read()  # SINK but PROTECTED
    return jsonify({'output': output})


# --- FP-PROT-SSTI-001 to 005: Templates behind strong auth ---

@app.route('/admin/fp/prot/ssti/001', methods=['POST'])
@admin_required  # PROTECTED
def fp_prot_ssti_001():
    """FP-PROT-SSTI-001: Template behind admin_required."""
    template = request.json.get('template', '')
    data = request.json.get('data', {})
    # Protected by @admin_required
    return render_template_string(template, **data)  # SINK but PROTECTED


@app.route('/admin/fp/prot/ssti/002', methods=['POST'])
@superuser_only  # PROTECTED
def fp_prot_ssti_002():
    """FP-PROT-SSTI-002: Template behind superuser_only."""
    template = request.json.get('template', '')
    # Protected by @superuser_only
    return render_template_string(template)  # SINK but PROTECTED


@app.route('/internal/fp/prot/ssti/003', methods=['POST'])
@internal_only  # PROTECTED
def fp_prot_ssti_003():
    """FP-PROT-SSTI-003: Template behind internal_only."""
    template = request.json.get('template', '')
    context = request.json.get('context', {})
    # Protected by @internal_only
    return render_template_string(template, **context)  # SINK but PROTECTED


@app.route('/admin/fp/prot/ssti/004', methods=['POST'])
@role_required('template_admin')  # PROTECTED
def fp_prot_ssti_004():
    """FP-PROT-SSTI-004: Template behind template_admin role."""
    template = request.json.get('template', '')
    # Protected by @role_required('template_admin')
    engine = UnsafeTemplateEngine()
    return Response(engine.render(template, {}), mimetype='text/html')  # SINK but PROTECTED


@app.route('/admin/fp/prot/ssti/005', methods=['POST'])
@admin_required
@superuser_only  # MULTIPLE PROTECTION
def fp_prot_ssti_005():
    """FP-PROT-SSTI-005: Template behind admin + superuser."""
    template = request.json.get('template', '')
    data = request.json.get('data', {})
    # Protected by @admin_required AND @superuser_only
    return render_template_string(template, **data)  # SINK but PROTECTED


# --- FP-PROT-XSS-001 to 005: XSS behind strong auth ---

@app.route('/admin/fp/prot/xss/001', methods=['GET'])
@admin_required  # PROTECTED
def fp_prot_xss_001():
    """FP-PROT-XSS-001: XSS behind admin_required."""
    content = request.args.get('content', '')
    # Protected by @admin_required
    return Response(f"<div>{content}</div>", mimetype='text/html')  # SINK but PROTECTED


@app.route('/admin/fp/prot/xss/002', methods=['GET'])
@superuser_only  # PROTECTED
def fp_prot_xss_002():
    """FP-PROT-XSS-002: XSS behind superuser_only."""
    html_content = request.args.get('html', '')
    # Protected by @superuser_only
    return Response(html_content, mimetype='text/html')  # SINK but PROTECTED


@app.route('/internal/fp/prot/xss/003', methods=['GET'])
@internal_only  # PROTECTED
def fp_prot_xss_003():
    """FP-PROT-XSS-003: XSS behind internal_only."""
    message = request.args.get('msg', '')
    # Protected by @internal_only
    return Response(f"<h1>{message}</h1>", mimetype='text/html')  # SINK but PROTECTED


@app.route('/admin/fp/prot/xss/004', methods=['POST'])
@admin_required
def fp_prot_xss_004():
    """FP-PROT-XSS-004: Stored XSS behind admin."""
    content = request.json.get('content', '')
    # Protected by @admin_required
    db.execute_raw(f"INSERT INTO admin_content (html) VALUES ('{content}')")  # SINK but PROTECTED
    return jsonify({'status': 'stored'})


@app.route('/admin/fp/prot/xss/005', methods=['GET'])
@role_required('content_manager')  # PROTECTED
def fp_prot_xss_005():
    """FP-PROT-XSS-005: XSS behind content_manager role."""
    page = request.args.get('page', '')
    # Protected by @role_required('content_manager')
    return Response(f"<html><body>{page}</body></html>", mimetype='text/html')  # SINK but PROTECTED


# =============================================================================
# FALSE POSITIVES - DEAD CODE (25 false positives in unreachable code)
# =============================================================================

# --- FP-DEAD-SQL-001 to 010: SQL in dead code ---

class LegacyDatabaseModule:
    """DEAD CODE: Never instantiated or called."""
    
    def __init__(self, db: Database):
        self.db = db
    
    def legacy_query(self, user_input: str) -> list:
        """FP-DEAD-SQL-001: SQL in never-called class."""
        query = f"SELECT * FROM legacy WHERE field = '{user_input}'"
        cursor = self.db.execute_raw(query)  # SINK but DEAD CODE
        return cursor.fetchall()
    
    def legacy_search(self, term: str) -> list:
        """FP-DEAD-SQL-002: Another method in dead class."""
        cursor = self.db.execute_raw(f"SELECT * FROM search WHERE term = '{term}'")  # SINK but DEAD CODE
        return cursor.fetchall()


def deprecated_sql_function(query: str):
    """FP-DEAD-SQL-003: Deprecated function, no callers."""
    cursor = db.execute_raw(query)  # SINK but DEAD CODE
    return cursor.fetchall()


def unused_data_export(table: str):
    """FP-DEAD-SQL-004: Unused export function."""
    cursor = db.execute_raw(f"SELECT * FROM {table}")  # SINK but DEAD CODE
    return cursor.fetchall()


def _internal_audit_query(audit_type: str):
    """FP-DEAD-SQL-005: Internal function never called."""
    cursor = db.execute_raw(f"SELECT * FROM audit WHERE type = '{audit_type}'")  # SINK but DEAD CODE
    return cursor.fetchall()


@app.route('/api/v1/dead/sql/006', methods=['GET'])
def fp_dead_sql_006():
    """FP-DEAD-SQL-006: Behind always-false flag."""
    if ENABLE_LEGACY_FEATURES:  # Always False
        query = request.args.get('q', '')
        cursor = db.execute_raw(f"SELECT * FROM legacy WHERE q = '{query}'")  # SINK but DEAD CODE
        return jsonify([dict(row) for row in cursor.fetchall()])
    return jsonify({'error': 'Feature disabled'}), 404


@app.route('/api/v1/dead/sql/007', methods=['GET'])
def fp_dead_sql_007():
    """FP-DEAD-SQL-007: Behind always-false debug flag."""
    if ENABLE_DEBUG_MODE:  # Always False
        sql = request.args.get('sql', '')
        cursor = db.execute_raw(sql)  # SINK but DEAD CODE
        return jsonify([dict(row) for row in cursor.fetchall()])
    return jsonify({'error': 'Debug mode disabled'}), 404


@app.route('/api/v1/dead/sql/008', methods=['POST'])
def fp_dead_sql_008():
    """FP-DEAD-SQL-008: Behind impossible condition."""
    data = request.json
    if data.get('impossible_key') == 'impossible_value_12345':  # Never true
        query = data.get('query', '')
        cursor = db.execute_raw(query)  # SINK but DEAD CODE
        return jsonify([dict(row) for row in cursor.fetchall()])
    return jsonify({'error': 'Invalid request'}), 400


@app.route('/api/v1/dead/sql/009', methods=['GET'])
def fp_dead_sql_009():
    """FP-DEAD-SQL-009: After unconditional return."""
    return jsonify({'status': 'ok'})
    # Code below never executes
    query = request.args.get('q', '')
    cursor = db.execute_raw(f"SELECT * FROM dead WHERE q = '{query}'")  # SINK but DEAD CODE
    return jsonify([dict(row) for row in cursor.fetchall()])


def fp_dead_sql_010_helper(user_input: str):
    """FP-DEAD-SQL-010: Helper function with no route caller."""
    cursor = db.execute_raw(f"SELECT * FROM helper WHERE input = '{user_input}'")  # SINK but DEAD CODE
    return cursor.fetchall()


# --- FP-DEAD-CMD-001 to 005: Commands in dead code ---

def deprecated_command_executor(cmd: str):
    """FP-DEAD-CMD-001: Deprecated command function."""
    result = subprocess.check_output(cmd, shell=True)  # SINK but DEAD CODE
    return result.decode()


class LegacySystemTools:
    """DEAD CODE: Never used class."""
    
    def run_command(self, command: str) -> str:
        """FP-DEAD-CMD-002: Command in dead class."""
        return subprocess.check_output(command, shell=True).decode()  # SINK but DEAD CODE
    
    def system_exec(self, cmd: str):
        """FP-DEAD-CMD-003: Another dead command method."""
        os.system(cmd)  # SINK but DEAD CODE


@app.route('/api/v1/dead/cmd/004', methods=['POST'])
def fp_dead_cmd_004():
    """FP-DEAD-CMD-004: Behind admin backdoor flag."""
    if ENABLE_ADMIN_BACKDOOR:  # Always False
        cmd = request.json.get('cmd', '')
        result = subprocess.check_output(cmd, shell=True)  # SINK but DEAD CODE
        return jsonify({'output': result.decode()})
    return jsonify({'error': 'Not available'}), 404


@app.route('/api/v1/dead/cmd/005', methods=['POST'])
def fp_dead_cmd_005():
    """FP-DEAD-CMD-005: In unreachable else branch."""
    mode = request.json.get('mode', 'safe')
    if mode == 'safe':
        return jsonify({'status': 'safe mode active'})
    elif mode == 'safe':  # Duplicate condition - unreachable
        cmd = request.json.get('cmd', '')
        os.system(cmd)  # SINK but DEAD CODE
        return jsonify({'status': 'executed'})
    return jsonify({'status': 'unknown mode'})


# --- FP-DEAD-SSTI-001 to 005: Templates in dead code ---

class DeprecatedTemplateRenderer:
    """DEAD CODE: Deprecated template class."""
    
    def render(self, template: str, data: dict) -> str:
        """FP-DEAD-SSTI-001: Template in dead class."""
        return render_template_string(template, **data)  # SINK but DEAD CODE


def unused_template_function(template: str, context: dict):
    """FP-DEAD-SSTI-002: Unused template function."""
    return render_template_string(template, **context)  # SINK but DEAD CODE


@app.route('/api/v1/dead/ssti/003', methods=['POST'])
def fp_dead_ssti_003():
    """FP-DEAD-SSTI-003: Behind deprecated flag."""
    if DEPRECATED_TEMPLATES:  # Always False
        template = request.json.get('template', '')
        return render_template_string(template)  # SINK but DEAD CODE
    return jsonify({'error': 'Templates disabled'}), 404


@app.route('/api/v1/dead/ssti/004', methods=['POST'])
def fp_dead_ssti_004():
    """FP-DEAD-SSTI-004: After return statement."""
    return jsonify({'status': 'endpoint deprecated'})
    template = request.json.get('template', '')
    return render_template_string(template)  # SINK but DEAD CODE


def _private_template_render(tmpl: str):
    """FP-DEAD-SSTI-005: Private function never called."""
    return render_template_string(tmpl)  # SINK but DEAD CODE


# --- FP-DEAD-XSS-001 to 005: XSS in dead code ---

def deprecated_html_builder(content: str) -> str:
    """FP-DEAD-XSS-001: Deprecated HTML function."""
    return f"<div>{content}</div>"  # SINK but DEAD CODE


class LegacyResponseBuilder:
    """DEAD CODE: Legacy response builder."""
    
    def build_html(self, user_content: str) -> str:
        """FP-DEAD-XSS-002: XSS in dead class."""
        return f"<html><body>{user_content}</body></html>"  # SINK but DEAD CODE


@app.route('/api/v1/dead/xss/003', methods=['GET'])
def fp_dead_xss_003():
    """FP-DEAD-XSS-003: Behind debug flag."""
    if ENABLE_DEBUG_MODE:  # Always False
        content = request.args.get('content', '')
        return Response(f"<debug>{content}</debug>", mimetype='text/html')  # SINK but DEAD CODE
    return jsonify({'error': 'Debug disabled'}), 404


@app.route('/api/v1/dead/xss/004', methods=['GET'])
def fp_dead_xss_004():
    """FP-DEAD-XSS-004: Unreachable code path."""
    return jsonify({'status': 'ok'})
    html = request.args.get('html', '')
    return Response(html, mimetype='text/html')  # SINK but DEAD CODE


def _internal_html_renderer(markup: str):
    """FP-DEAD-XSS-005: Internal function no callers."""
    return Response(markup, mimetype='text/html')  # SINK but DEAD CODE


# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

def init_database():
    """Initialize database with required tables."""
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            username TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            is_admin INTEGER DEFAULT 0,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            action TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            value TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS records (
            id TEXT PRIMARY KEY,
            data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            value REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS admin_content (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            html TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    
    # Insert sample users
    cursor.execute(
        "INSERT OR IGNORE INTO users (email, name, username, password_hash, is_admin, role) VALUES (?, ?, ?, ?, ?, ?)",
        ('admin@test.com', 'Admin User', 'admin', generate_password_hash('admin123'), 1, 'superuser')
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (email, name, username, password_hash, is_admin, role) VALUES (?, ?, ?, ?, ?, ?)",
        ('user@test.com', 'Regular User', 'user', generate_password_hash('user123'), 0, 'user')
    )
    
    conn.commit()


# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    init_database()
    app.run(debug=True, host='0.0.0.0', port=5001)
