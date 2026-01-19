# tests/testcode/python_flask/app.py
"""
Multi-hop attack path test project for Python Flask.

This file contains various vulnerability scenarios to test:
1. Multi-hop LIVE paths (route -> controller -> service -> sink)
2. Dead code paths (unused functions)
3. Sanitized paths (validation before sink)
4. Protected paths (auth decorators)
5. Mixed paths (some safe, some unsafe)
"""
from flask import Flask, request, jsonify
import os
import subprocess

app = Flask(__name__)

# ==============================================================================
# SCENARIO A: Multi-hop LIVE path (4 hops: route -> controller -> service -> sink)
# Expected: LIVE, classification=must_fix
# ==============================================================================

def execute_command(cmd):
    """SINK: Command injection - final hop"""
    return subprocess.check_output(cmd, shell=True)  # VULNERABLE SINK

def process_command_in_service(user_cmd):
    """SERVICE LAYER: Passes command to executor - hop 3"""
    formatted_cmd = f"echo {user_cmd}"
    return execute_command(formatted_cmd)

def handle_command_request(data):
    """CONTROLLER: Extracts command from request - hop 2"""
    cmd = data.get('command')
    return process_command_in_service(cmd)

@app.route('/api/execute', methods=['POST'])
def execute_endpoint():
    """ENTRYPOINT: HTTP route handler - hop 1"""
    data = request.get_json()
    result = handle_command_request(data)
    return jsonify({'output': result.decode()})


# ==============================================================================
# SCENARIO B: Dead code path (function with no callers)
# Expected: DEAD, classification=false_positive_deadcode
# ==============================================================================

def unused_dangerous_function(user_input):
    """DEAD CODE: No callers in entire codebase"""
    return os.system(user_input)  # DEAD SINK - should be false positive

def another_unused_helper():
    """DEAD CODE: Also no callers"""
    password = input("Enter password: ")  # DEAD SINK
    return password


# ==============================================================================
# SCENARIO C: Sanitized path (validation before sink)
# Expected: LIVE but PROTECTED/SANITIZED, classification=false_positive_sanitized
# ==============================================================================

def sanitize_input(user_input):
    """SANITIZER: Removes dangerous characters"""
    import re
    return re.sub(r'[;&|`$]', '', user_input)

def execute_safe_command(cmd):
    """SINK: But receives sanitized input"""
    return subprocess.check_output(cmd, shell=True)

def handle_safe_request(data):
    """CONTROLLER: Applies sanitization before sink"""
    raw_cmd = data.get('command')
    safe_cmd = sanitize_input(raw_cmd)  # SANITIZER EDGE
    return execute_safe_command(safe_cmd)

@app.route('/api/safe-execute', methods=['POST'])
def safe_execute_endpoint():
    """ENTRYPOINT: Route with sanitized path"""
    data = request.get_json()
    result = handle_safe_request(data)
    return jsonify({'output': result.decode()})


# ==============================================================================
# SCENARIO D: Protected path (auth decorator blocks unauthorized access)
# Expected: LIVE but PROTECTED, classification=false_positive_protected
# ==============================================================================

def require_admin(f):
    """AUTH DECORATOR: Blocks unauthorized access"""
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not verify_admin_token(token):
            return jsonify({'error': 'Unauthorized'}), 403
        return f(*args, **kwargs)
    return wrapper

def verify_admin_token(token):
    """Verifies admin token"""
    return token == 'admin-secret-token'

def run_admin_command(cmd):
    """SINK: Command injection - but protected by auth"""
    return os.popen(cmd).read()

@app.route('/api/admin/run', methods=['POST'])
@require_admin  # PROTECTION: Auth decorator
def admin_run_endpoint():
    """PROTECTED ENTRYPOINT: Requires admin auth"""
    data = request.get_json()
    cmd = data.get('command')
    result = run_admin_command(cmd)
    return jsonify({'output': result})


# ==============================================================================
# SCENARIO E: Mixed paths (multiple paths, some safe, some unsafe)
# Expected: LIVE for unsafe path, PROTECTED for safe path
# ==============================================================================

def dangerous_sink(query):
    """SINK: SQL injection"""
    import sqlite3
    conn = sqlite3.connect(':memory:')
    return conn.execute(query)  # VULNERABLE

def safe_sink(query, params):
    """SAFE SINK: Parameterized query"""
    import sqlite3
    conn = sqlite3.connect(':memory:')
    return conn.execute(query, params)  # SAFE - parameterized

def query_service(user_input, use_safe_mode=False):
    """SERVICE: Two paths - one safe, one unsafe"""
    if use_safe_mode:
        # SAFE PATH
        return safe_sink("SELECT * FROM users WHERE name = ?", [user_input])
    else:
        # UNSAFE PATH
        return dangerous_sink(f"SELECT * FROM users WHERE name = '{user_input}'")

@app.route('/api/query', methods=['GET'])
def query_endpoint():
    """ENTRYPOINT: Has both safe and unsafe paths"""
    user_input = request.args.get('q')
    safe_mode = request.args.get('safe', 'false') == 'true'
    result = query_service(user_input, use_safe_mode=safe_mode)
    return jsonify({'result': str(result)})


# ==============================================================================
# SCENARIO F: Deep call chain (6+ hops)
# Expected: LIVE, tests deep traversal
# ==============================================================================

def final_sink(data):
    """SINK: XSS via innerHTML equivalent"""
    return f"<div>{data}</div>"  # VULNERABLE to XSS

def layer_5(data):
    return final_sink(data)

def layer_4(data):
    return layer_5(data)

def layer_3(data):
    return layer_4(data)

def layer_2(data):
    return layer_3(data)

def layer_1(data):
    return layer_2(data)

@app.route('/api/deep', methods=['GET'])
def deep_endpoint():
    """ENTRYPOINT: 6 hops to sink"""
    user_data = request.args.get('data')
    html = layer_1(user_data)
    return html


# ==============================================================================
# SCENARIO G: Branching paths with different outcomes
# Expected: One path LIVE, one path DEAD
# ==============================================================================

def sink_in_dead_branch(data):
    """SINK in dead branch - never executed"""
    return eval(data)

def sink_in_live_branch(data):
    """SINK in live branch - always executed"""
    return eval(data)

def branching_service(data, feature_flag):
    """SERVICE: Branches based on feature flag"""
    if feature_flag:
        # This branch is always taken (feature_flag=True hardcoded below)
        return sink_in_live_branch(data)
    else:
        # This branch is never taken - DEAD
        return sink_in_dead_branch(data)

@app.route('/api/branch', methods=['POST'])
def branch_endpoint():
    """ENTRYPOINT: Has branching paths"""
    data = request.get_json().get('data')
    # Feature flag is always True - dead branch never reached
    result = branching_service(data, feature_flag=True)
    return jsonify({'result': result})


if __name__ == '__main__':
    app.run(debug=True)
