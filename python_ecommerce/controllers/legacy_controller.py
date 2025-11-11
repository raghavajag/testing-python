"""
Legacy Controller - DEAD CODE - Never called in production
Contains entry points for VULN_1 (dead_code)
"""

from flask import Blueprint, request, jsonify
from services.legacy_service import LegacyService

legacy_bp = Blueprint('legacy', __name__)
legacy_service = LegacyService()

# NOTE: This entire controller is DEAD CODE
# It's registered in app.py but never actually called by any production code
# The routes exist but are not exposed in production routing

@legacy_bp.route('/old-search', methods=['GET'])
def old_legacy_search():
    """
    ENTRY POINT for VULN_1 (FALSE_POSITIVE_DEAD_CODE)
    Old legacy search endpoint - NEVER USED IN PRODUCTION
    Attack paths: 3 paths, ALL paths are dead code
    """
    query = request.args.get('q', '')
    
    # Path 1: Direct legacy search (dead)
    results = legacy_service.search_old_database(query)
    return jsonify(results)

@legacy_bp.route('/deprecated-query', methods=['POST'])
def deprecated_query():
    """
    ENTRY POINT for VULN_1 (FALSE_POSITIVE_DEAD_CODE) - Path 2
    Deprecated query endpoint - NEVER CALLED
    """
    data = request.get_json()
    search_param = data.get('search', '')
    
    # Path 2: Through deprecated service (dead)
    results = legacy_service.execute_legacy_query(search_param)
    return jsonify(results)

@legacy_bp.route('/archive-search', methods=['GET'])
def archive_search():
    """
    ENTRY POINT for VULN_1 (FALSE_POSITIVE_DEAD_CODE) - Path 3
    Archive search - UNREACHABLE
    """
    archive_id = request.args.get('id', '')
    keyword = request.args.get('keyword', '')
    
    # Path 3: Archive search (dead)
    results = legacy_service.search_archived_data(archive_id, keyword)
    return jsonify(results)
