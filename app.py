"""
QA Multilang Testbed - Python Flask Application
================================================

FINAL BOSS TEST CODEBASE for AI-SAST Pipeline Stress Testing

This application simulates a production-grade banking/fintech API with:
- Multi-hop call chains (6+ functions deep)
- Dead code paths
- Sanitized paths (true false positives)
- Protected paths (auth decorators)
- Various vulnerability types (SQLi, XSS, Command Injection, SSTI)
- Mixed reachability scenarios

VULNERABILITY INVENTORY:
========================
1. VULN-PY-001: SQL Injection via audit log search (6-hop chain, LIVE)
2. VULN-PY-002: SQL Injection with parameterized query (FALSE POSITIVE - SANITIZED)
3. VULN-PY-003: Command Injection via network diagnostics (4-hop chain, LIVE)
4. VULN-PY-004: SSTI via template rendering (5-hop chain, LIVE)
5. VULN-PY-005: SQL Injection in dead code path (FALSE POSITIVE - DEAD CODE)
6. VULN-PY-006: XSS via response builder (3-hop chain, PROTECTED by admin decorator)
7. VULN-PY-007: SQL Injection with partial sanitization (LIVE - sanitization bypassed)
8. VULN-PY-008: Command Injection behind feature flag (DEAD CODE - always false)
"""

import os
import re
import html
import subprocess
import sqlite3
import hashlib
from functools import wraps
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple

from flask import Flask, request, jsonify, render_template_string, g, session, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-prod')

# =============================================================================
# DATABASE LAYER
# =============================================================================

class DatabaseConnection:
    """Production-style database connection manager."""
    
    def __init__(self, db_path: str = ':memory:'):
        self.db_path = db_path
        self._connection = None
    
    def get_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            self._connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self._connection.row_factory = sqlite3.Row
        return self._connection
    
    def execute_raw(self, query: str) -> sqlite3.Cursor:
        """
        SINK: SQL Injection
        Executes raw SQL without parameterization.
        Used by multiple vulnerability paths.
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query)  # VULN: SQL INJECTION SINK
        return cursor
    
    def execute_safe(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """
        SAFE: Parameterized query execution.
        This is the correct way to execute SQL.
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)  # SAFE: Parameterized
        return cursor
    
    def execute_with_validation(self, query: str, user_input: str) -> sqlite3.Cursor:
        """
        PARTIAL SANITIZATION: Validates but doesn't fully sanitize.
        Can be bypassed with certain payloads.
        """
        # Weak validation - only checks for simple quotes
        if "'" in user_input:
            user_input = user_input.replace("'", "")
        # Still vulnerable to other injection techniques
        final_query = query.format(user_input=user_input)
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(final_query)  # VULN: SQL INJECTION (partial sanitization bypass)
        return cursor


db = DatabaseConnection()


# =============================================================================
# AUTHENTICATION & AUTHORIZATION DECORATORS
# =============================================================================

def login_required(f):
    """Decorator that requires user authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            abort(401)
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    PROTECTION DECORATOR: Requires admin privileges.
    Vulnerabilities behind this are false_positive_protected.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            abort(401)
        if not session.get('is_admin', False):
            abort(403)
        # Additional security: verify admin status from database
        user = db.execute_safe(
            "SELECT is_admin FROM users WHERE id = ?",
            (session['user_id'],)
        ).fetchone()
        if not user or not user['is_admin']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def rate_limited(max_requests: int = 100, window_seconds: int = 60):
    """Rate limiting decorator."""
    def decorator(f):
        request_counts: Dict[str, List[datetime]] = {}
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            now = datetime.now()
            
            if client_ip not in request_counts:
                request_counts[client_ip] = []
            
            # Clean old requests
            request_counts[client_ip] = [
                t for t in request_counts[client_ip]
                if now - t < timedelta(seconds=window_seconds)
            ]
            
            if len(request_counts[client_ip]) >= max_requests:
                abort(429)
            
            request_counts[client_ip].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# =============================================================================
# SERVICE LAYER - Audit Service (Multi-hop vulnerability chain)
# =============================================================================

class AuditService:
    """
    Service handling audit log operations.
    Contains VULN-PY-001: 6-hop SQL Injection chain.
    """
    
    def __init__(self, db_connection: DatabaseConnection):
        self.db = db_connection
        self.log_formatter = AuditLogFormatter()
        self.query_builder = AuditQueryBuilder()
    
    def search_audit_logs(self, search_params: Dict[str, Any]) -> List[Dict]:
        """
        HOP 1: Entry point for audit log search.
        Receives user input from controller.
        """
        # Extract search criteria
        user_filter = search_params.get('user_filter', '')
        action_filter = search_params.get('action_filter', '')
        date_range = search_params.get('date_range', {})
        
        # Build and execute query
        results = self._execute_filtered_search(user_filter, action_filter, date_range)
        
        # Format results
        return self.log_formatter.format_audit_results(results)
    
    def _execute_filtered_search(
        self, 
        user_filter: str, 
        action_filter: str, 
        date_range: Dict[str, str]
    ) -> List[sqlite3.Row]:
        """
        HOP 2: Delegates to query builder for SQL construction.
        """
        query = self.query_builder.build_search_query(
            user_filter=user_filter,
            action_filter=action_filter,
            start_date=date_range.get('start'),
            end_date=date_range.get('end')
        )
        return self._run_audit_query(query)
    
    def _run_audit_query(self, query: str) -> List[sqlite3.Row]:
        """
        HOP 3: Executes the constructed query.
        Delegates to repository layer.
        """
        repo = AuditRepository(self.db)
        return repo.execute_search(query)


class AuditQueryBuilder:
    """Builds SQL queries for audit log searches."""
    
    def build_search_query(
        self,
        user_filter: str,
        action_filter: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
    ) -> str:
        """
        HOP 4: Constructs SQL query with user input.
        VULNERABILITY: Concatenates user input directly into query.
        """
        base_query = "SELECT * FROM audit_logs WHERE 1=1"
        
        if user_filter:
            # VULNERABLE: Direct string concatenation
            base_query += f" AND user_id = '{user_filter}'"
        
        if action_filter:
            # VULNERABLE: Direct string concatenation
            base_query += f" AND action LIKE '%{action_filter}%'"
        
        if start_date:
            base_query += f" AND created_at >= '{start_date}'"
        
        if end_date:
            base_query += f" AND created_at <= '{end_date}'"
        
        return base_query


class AuditRepository:
    """Data access layer for audit logs."""
    
    def __init__(self, db_connection: DatabaseConnection):
        self.db = db_connection
    
    def execute_search(self, query: str) -> List[sqlite3.Row]:
        """
        HOP 5: Passes query to database layer.
        """
        return self._execute_and_fetch(query)
    
    def _execute_and_fetch(self, query: str) -> List[sqlite3.Row]:
        """
        HOP 6: Final execution - SINK.
        """
        cursor = self.db.execute_raw(query)  # SINK: SQL Injection
        return cursor.fetchall()


class AuditLogFormatter:
    """Formats audit log results for API response."""
    
    def format_audit_results(self, results: List[sqlite3.Row]) -> List[Dict]:
        """Transforms database rows to API response format."""
        formatted = []
        for row in results:
            formatted.append({
                'id': row['id'] if 'id' in row.keys() else None,
                'user_id': row['user_id'] if 'user_id' in row.keys() else None,
                'action': row['action'] if 'action' in row.keys() else None,
                'timestamp': row['created_at'] if 'created_at' in row.keys() else None,
                'details': row['details'] if 'details' in row.keys() else None
            })
        return formatted


# =============================================================================
# SERVICE LAYER - User Service (Sanitized paths - False Positives)
# =============================================================================

class UserService:
    """
    Service handling user operations.
    Contains VULN-PY-002: SQL Injection with parameterized queries (FALSE POSITIVE).
    """
    
    def __init__(self, db_connection: DatabaseConnection):
        self.db = db_connection
        self.validator = InputValidator()
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """
        HOP 1: Entry point for user lookup.
        Uses SAFE parameterized queries.
        """
        # Validate email format
        if not self.validator.validate_email(email):
            return None
        
        # Safe query execution
        return self._fetch_user_record(email)
    
    def _fetch_user_record(self, email: str) -> Optional[Dict]:
        """
        HOP 2: Executes parameterized query.
        FALSE POSITIVE - This is SAFE.
        """
        cursor = self.db.execute_safe(
            "SELECT id, email, name, created_at FROM users WHERE email = ?",
            (email,)  # SAFE: Parameterized
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    
    def search_users(self, search_term: str) -> List[Dict]:
        """
        Another safe path using ORM-style query building.
        FALSE POSITIVE - This is SAFE.
        """
        # Sanitize search term
        safe_term = self.validator.sanitize_search_term(search_term)
        
        cursor = self.db.execute_safe(
            "SELECT id, email, name FROM users WHERE name LIKE ? OR email LIKE ?",
            (f'%{safe_term}%', f'%{safe_term}%')  # SAFE: Parameterized
        )
        return [dict(row) for row in cursor.fetchall()]


class InputValidator:
    """Input validation utilities."""
    
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    def validate_email(self, email: str) -> bool:
        """Validates email format using regex."""
        if not email or len(email) > 254:
            return False
        return bool(self.EMAIL_PATTERN.match(email))
    
    def sanitize_search_term(self, term: str) -> str:
        """Sanitizes search term for safe database queries."""
        # Remove SQL metacharacters
        sanitized = re.sub(r'[\'";\\%_]', '', term)
        # Limit length
        return sanitized[:100]


# =============================================================================
# SERVICE LAYER - Network Service (Command Injection)
# =============================================================================

class NetworkDiagnosticService:
    """
    Service for network diagnostics.
    Contains VULN-PY-003: Command Injection (4-hop chain).
    """
    
    def __init__(self):
        self.command_builder = DiagnosticCommandBuilder()
        self.executor = CommandExecutor()
    
    def run_connectivity_check(self, target_host: str) -> Dict[str, Any]:
        """
        HOP 1: Entry point for network diagnostics.
        """
        # Basic format validation (insufficient!)
        if not target_host or len(target_host) > 255:
            return {'error': 'Invalid host'}
        
        return self._perform_ping_check(target_host)
    
    def _perform_ping_check(self, host: str) -> Dict[str, Any]:
        """
        HOP 2: Delegates to command builder.
        """
        command = self.command_builder.build_ping_command(host)
        return self.executor.run_command(command)


class DiagnosticCommandBuilder:
    """Builds system commands for diagnostics."""
    
    def build_ping_command(self, host: str) -> str:
        """
        HOP 3: Constructs command string.
        VULNERABLE: Direct string interpolation.
        """
        return f"ping -c 1 -W 2 {host}"  # VULN: Command Injection


class CommandExecutor:
    """Executes system commands."""
    
    def run_command(self, command: str) -> Dict[str, Any]:
        """
        HOP 4: Executes command - SINK.
        """
        try:
            result = subprocess.check_output(
                command,
                shell=True,  # SINK: Command Injection
                stderr=subprocess.STDOUT,
                timeout=10
            )
            return {
                'success': True,
                'output': result.decode('utf-8', errors='replace')
            }
        except subprocess.CalledProcessError as e:
            return {
                'success': False,
                'error': e.output.decode('utf-8', errors='replace')
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Command timed out'
            }


# =============================================================================
# SERVICE LAYER - Report Service (SSTI Vulnerability)
# =============================================================================

class ReportGenerationService:
    """
    Service for generating reports.
    Contains VULN-PY-004: Server-Side Template Injection (5-hop chain).
    """
    
    def __init__(self, db_connection: DatabaseConnection):
        self.db = db_connection
        self.template_engine = CustomTemplateEngine()
        self.data_fetcher = ReportDataFetcher(db_connection)
    
    def generate_custom_report(self, report_config: Dict[str, Any]) -> str:
        """
        HOP 1: Entry point for report generation.
        """
        template = report_config.get('template', '')
        data_source = report_config.get('data_source', 'default')
        
        # Fetch data for report
        report_data = self.data_fetcher.fetch_report_data(data_source)
        
        # Render template with data
        return self._render_report(template, report_data)
    
    def _render_report(self, template: str, data: Dict) -> str:
        """
        HOP 2: Delegates to template engine.
        """
        return self.template_engine.render_custom_template(template, data)


class ReportDataFetcher:
    """Fetches data for reports."""
    
    def __init__(self, db_connection: DatabaseConnection):
        self.db = db_connection
    
    def fetch_report_data(self, source: str) -> Dict[str, Any]:
        """Retrieves data based on source configuration."""
        if source == 'users':
            cursor = self.db.execute_safe("SELECT COUNT(*) as total FROM users", ())
            return {'total_users': cursor.fetchone()['total']}
        elif source == 'transactions':
            cursor = self.db.execute_safe("SELECT SUM(amount) as total FROM transactions", ())
            row = cursor.fetchone()
            return {'total_amount': row['total'] if row else 0}
        return {'source': source}


class CustomTemplateEngine:
    """Custom template rendering engine."""
    
    def render_custom_template(self, template: str, data: Dict) -> str:
        """
        HOP 3: Passes to internal renderer.
        """
        return self._process_template(template, data)
    
    def _process_template(self, template: str, data: Dict) -> str:
        """
        HOP 4: Prepares template for rendering.
        """
        # Inject data into template context
        context = {**data, 'generated_at': datetime.now().isoformat()}
        return self._execute_render(template, context)
    
    def _execute_render(self, template: str, context: Dict) -> str:
        """
        HOP 5: Executes template rendering - SINK.
        """
        # VULNERABLE: User-controlled template
        return render_template_string(template, **context)  # SINK: SSTI


# =============================================================================
# DEAD CODE PATHS
# =============================================================================

class LegacyReportingModule:
    """
    DEAD CODE: This module is never imported or called.
    Contains VULN-PY-005: SQL Injection (FALSE POSITIVE - DEAD CODE).
    """
    
    def __init__(self, db_connection: DatabaseConnection):
        self.db = db_connection
    
    def generate_legacy_report(self, report_type: str, user_id: str) -> str:
        """
        DEAD CODE: Never called from any entry point.
        Contains vulnerable SQL but unreachable.
        """
        query = f"SELECT * FROM legacy_reports WHERE type = '{report_type}' AND user_id = '{user_id}'"
        cursor = self.db.execute_raw(query)  # VULN but DEAD CODE
        results = cursor.fetchall()
        return self._format_legacy_results(results)
    
    def _format_legacy_results(self, results: List) -> str:
        """Formats legacy report results."""
        return '\n'.join(str(r) for r in results)


def deprecated_data_export(query: str) -> List:
    """
    DEAD CODE: Deprecated function, no callers.
    Contains SQL Injection but never executed.
    """
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)  # VULN but DEAD CODE
    return cursor.fetchall()


# Feature flag that is always False
ENABLE_EXPERIMENTAL_FEATURES = False


class ExperimentalFeatures:
    """
    DEAD CODE: Behind always-false feature flag.
    Contains VULN-PY-008: Command Injection (FALSE POSITIVE - DEAD CODE).
    """
    
    def execute_custom_script(self, script_path: str) -> str:
        """
        DEAD CODE: Never executed due to feature flag.
        """
        if ENABLE_EXPERIMENTAL_FEATURES:  # Always False
            result = subprocess.check_output(
                f"bash {script_path}",  # VULN but in dead code block
                shell=True
            )
            return result.decode()
        return "Feature disabled"


# =============================================================================
# PROTECTED PATHS (Admin-only endpoints)
# =============================================================================

class AdminPanelService:
    """
    Service for admin panel operations.
    Contains VULN-PY-006: XSS (FALSE POSITIVE - PROTECTED by admin_required).
    """
    
    def __init__(self):
        self.response_builder = AdminResponseBuilder()
    
    def render_admin_dashboard(self, custom_message: str) -> str:
        """
        HOP 1: Entry point for admin dashboard.
        Protected by @admin_required decorator at controller level.
        """
        stats = self._fetch_admin_stats()
        return self.response_builder.build_dashboard_html(custom_message, stats)
    
    def _fetch_admin_stats(self) -> Dict[str, int]:
        """Fetches statistics for admin dashboard."""
        return {
            'total_users': 1500,
            'active_sessions': 234,
            'pending_requests': 45
        }


class AdminResponseBuilder:
    """Builds HTML responses for admin panel."""
    
    def build_dashboard_html(self, message: str, stats: Dict[str, int]) -> str:
        """
        HOP 2: Builds HTML response.
        """
        return self._construct_html_page(message, stats)
    
    def _construct_html_page(self, message: str, stats: Dict[str, int]) -> str:
        """
        HOP 3: Constructs HTML - SINK.
        XSS vulnerability but protected by admin_required.
        Only admins can trigger this, so it's acceptable.
        """
        # VULNERABLE to XSS but protected by admin_required decorator
        html_content = f"""
        <html>
        <head><title>Admin Dashboard</title></head>
        <body>
            <h1>Admin Dashboard</h1>
            <div class="message">{message}</div>
            <div class="stats">
                <p>Total Users: {stats['total_users']}</p>
                <p>Active Sessions: {stats['active_sessions']}</p>
                <p>Pending Requests: {stats['pending_requests']}</p>
            </div>
        </body>
        </html>
        """
        return html_content  # SINK: XSS (but admin-only)


# =============================================================================
# PARTIAL SANITIZATION (Bypassable)
# =============================================================================

class TransactionService:
    """
    Service for transaction operations.
    Contains VULN-PY-007: SQL Injection with partial sanitization.
    """
    
    def __init__(self, db_connection: DatabaseConnection):
        self.db = db_connection
    
    def search_transactions(self, account_id: str, filters: Dict[str, str]) -> List[Dict]:
        """
        HOP 1: Entry point for transaction search.
        """
        # Weak sanitization - only removes single quotes
        sanitized_account = self._weak_sanitize(account_id)
        return self._execute_transaction_search(sanitized_account, filters)
    
    def _weak_sanitize(self, value: str) -> str:
        """
        PARTIAL SANITIZATION: Removes single quotes but not other injection vectors.
        Can be bypassed with: 1 OR 1=1-- or UNION attacks without quotes.
        """
        return value.replace("'", "").replace('"', '')
    
    def _execute_transaction_search(
        self, 
        account_id: str, 
        filters: Dict[str, str]
    ) -> List[Dict]:
        """
        HOP 2: Builds and executes query.
        """
        query = f"SELECT * FROM transactions WHERE account_id = {account_id}"
        
        if filters.get('status'):
            query += f" AND status = '{self._weak_sanitize(filters['status'])}'"
        
        cursor = self.db.execute_raw(query)  # SINK: SQL Injection (bypassed sanitization)
        return [dict(row) for row in cursor.fetchall()]


# =============================================================================
# API CONTROLLERS
# =============================================================================

@app.route('/api/v1/audit/search', methods=['POST'])
@login_required
@rate_limited(max_requests=50)
def search_audit_logs():
    """
    VULN-PY-001: SQL Injection Entry Point
    6-hop chain: controller -> AuditService -> AuditQueryBuilder -> AuditRepository -> db.execute_raw
    """
    search_params = request.get_json() or {}
    
    audit_service = AuditService(db)
    results = audit_service.search_audit_logs(search_params)
    
    return jsonify({
        'success': True,
        'count': len(results),
        'results': results
    })


@app.route('/api/v1/users/search', methods=['GET'])
@login_required
def search_users():
    """
    VULN-PY-002: SQL Injection FALSE POSITIVE (Parameterized)
    Uses safe parameterized queries throughout.
    """
    search_term = request.args.get('q', '')
    
    user_service = UserService(db)
    results = user_service.search_users(search_term)
    
    return jsonify({
        'success': True,
        'count': len(results),
        'results': results
    })


@app.route('/api/v1/users/<email>', methods=['GET'])
@login_required
def get_user_by_email(email: str):
    """
    Another safe path - uses parameterized queries.
    FALSE POSITIVE - SANITIZED.
    """
    user_service = UserService(db)
    user = user_service.get_user_by_email(email)
    
    if user:
        return jsonify({'success': True, 'user': user})
    return jsonify({'success': False, 'error': 'User not found'}), 404


@app.route('/api/v1/network/ping', methods=['POST'])
@login_required
@admin_required
def network_ping():
    """
    VULN-PY-003: Command Injection Entry Point
    4-hop chain: controller -> NetworkDiagnosticService -> DiagnosticCommandBuilder -> CommandExecutor
    """
    data = request.get_json() or {}
    target_host = data.get('host', '')
    
    service = NetworkDiagnosticService()
    result = service.run_connectivity_check(target_host)
    
    return jsonify(result)


@app.route('/api/v1/reports/generate', methods=['POST'])
@login_required
def generate_report():
    """
    VULN-PY-004: SSTI Entry Point
    5-hop chain: controller -> ReportGenerationService -> CustomTemplateEngine -> render_template_string
    """
    report_config = request.get_json() or {}
    
    service = ReportGenerationService(db)
    try:
        report_html = service.generate_custom_report(report_config)
        return report_html, 200, {'Content-Type': 'text/html'}
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/dashboard', methods=['GET'])
@login_required
@admin_required
def admin_dashboard():
    """
    VULN-PY-006: XSS FALSE POSITIVE (PROTECTED)
    Protected by @admin_required - only admins can access.
    """
    custom_message = request.args.get('message', 'Welcome, Admin!')
    
    service = AdminPanelService()
    dashboard_html = service.render_admin_dashboard(custom_message)
    
    return dashboard_html, 200, {'Content-Type': 'text/html'}


@app.route('/api/v1/transactions/search', methods=['GET'])
@login_required
def search_transactions():
    """
    VULN-PY-007: SQL Injection with partial sanitization
    Sanitization can be bypassed - still vulnerable.
    """
    account_id = request.args.get('account_id', '')
    filters = {
        'status': request.args.get('status', ''),
        'type': request.args.get('type', '')
    }
    
    service = TransactionService(db)
    results = service.search_transactions(account_id, filters)
    
    return jsonify({
        'success': True,
        'count': len(results),
        'results': results
    })


# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """Login endpoint - safe implementation."""
    data = request.get_json() or {}
    email = data.get('email', '')
    password = data.get('password', '')
    
    # Safe parameterized query
    cursor = db.execute_safe(
        "SELECT id, email, password_hash, is_admin FROM users WHERE email = ?",
        (email,)
    )
    user = cursor.fetchone()
    
    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['is_admin'] = bool(user['is_admin'])
        return jsonify({'success': True, 'message': 'Login successful'})
    
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401


@app.route('/api/v1/auth/logout', methods=['POST'])
@login_required
def logout():
    """Logout endpoint."""
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out'})


# =============================================================================
# APPLICATION INITIALIZATION
# =============================================================================

def init_database():
    """Initialize database with tables and sample data."""
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS legacy_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            user_id TEXT NOT NULL,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    
    # Insert sample data
    cursor.execute(
        "INSERT OR IGNORE INTO users (email, name, password_hash, is_admin) VALUES (?, ?, ?, ?)",
        ('admin@example.com', 'Admin User', generate_password_hash('admin123'), 1)
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (email, name, password_hash, is_admin) VALUES (?, ?, ?, ?)",
        ('user@example.com', 'Regular User', generate_password_hash('user123'), 0)
    )
    
    conn.commit()


if __name__ == '__main__':
    init_database()
    app.run(debug=True, host='0.0.0.0', port=5000)
