from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.db import connection
from .models import User, Transaction
import html

"""
Django views for TEST CASES 1 & 5
"""

# ============================================================================
# TEST CASE 1: Django ORM Sanitization (True False Positive)
# ============================================================================

@require_http_methods(["GET"])
def get_user_by_email(request):
    """
    TEST CASE 1A - SAFE: Django ORM parameterized query
    
    ATTACK PATH (5 hops):
    Hop 1: HTTP Request → get_user_by_email(email)
    Hop 2: View extracts email from request.GET
    Hop 3: User.objects.filter(email=email) [Django ORM]
    Hop 4: Django generates parameterized SQL: SELECT * FROM users WHERE email = %s
    Hop 5: Database executes with parameter binding
    
    Expected Classification: false_positive_sanitized (Subcategory 2C - Architectural)
    Expected Rationale: "Django ORM's filter() method automatically uses parameterized queries
                         with parameter binding. The query is translated to SQL with placeholders
                         (e.g., WHERE email = %s) and values are passed separately, making SQL
                         injection impossible. This is Subcategory 2C (ORM Architectural Protection)."
    Expected Keywords: "Django ORM", "filter", "parameterized query", "Subcategory 2C"
    """
    email = request.GET.get('email', '')
    
    # Django ORM automatically parameterizes this query
    users = User.objects.filter(email=email)
    
    if users.exists():
        user = users.first()
        return JsonResponse({
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'role': user.role
        })
    else:
        return JsonResponse({'error': 'User not found'}, status=404)


@require_http_methods(["GET"])
def search_users(request):
    """
    TEST CASE 1B - SAFE: Django ORM with __icontains (parameterized LIKE)
    
    ATTACK PATH (5 hops):
    Hop 1: HTTP Request → search_users(search_term)
    Hop 2: View extracts search_term
    Hop 3: User.objects.filter(email__icontains=search_term) [Django ORM]
    Hop 4: Django generates: SELECT * FROM users WHERE email LIKE %s (with % wrapping)
    Hop 5: Parameterized query → Database
    
    Expected Classification: false_positive_sanitized (Subcategory 2C)
    """
    search_term = request.GET.get('search', '')
    
    # Django ORM parameterizes LIKE queries automatically
    users = User.objects.filter(email__icontains=search_term)
    
    results = [
        {'id': u.id, 'email': u.email, 'username': u.username}
        for u in users
    ]
    
    return JsonResponse({'users': results})


# ============================================================================
# TEST CASE 5: Ineffective Sanitization (False Negative - MUST CATCH)
# ============================================================================

@require_http_methods(["POST"])
def record_transaction_unsafe(request):
    """
    TEST CASE 5 - VULNERABLE: HTML escaping used for SQL injection prevention
    
    ATTACK PATH (5 hops):
    Hop 1: HTTP Request → record_transaction_unsafe(description)
    Hop 2: View extracts description from request.POST
    Hop 3: HTML escaping applied: html.escape(description)
    Hop 4: Raw SQL with string concatenation using HTML-escaped value
    Hop 5: cursor.execute() with concatenated SQL → Database (VULNERABLE!)
    
    Expected Classification: must_fix
    Expected Rationale: "CRITICAL: Ineffective sanitization detected. The code applies HTML
                         escaping (html.escape) to prevent SQL injection, which is the wrong
                         type of sanitization. HTML escaping converts < to &lt; but does NOT
                         protect against SQL injection. An attacker can bypass with payloads
                         like '; DROP TABLE users--. The vulnerability remains fully exploitable."
    Expected Keywords: "ineffective sanitization", "HTML escape", "SQL injection", "raw SQL"
    
    BUG EXPLANATION:
    - html.escape() converts: < to &lt;, > to &gt;, & to &amp;, etc.
    - SQL injection uses: ', ", ;, --, /*, UNION, etc.
    - html.escape() does NOT block these SQL metacharacters
    - Attacker payload: '; DELETE FROM transactions--
    - After HTML escape: '; DELETE FROM transactions-- (UNCHANGED!)
    """
    description = request.POST.get('description', '')
    account_id = request.POST.get('account_id', '')
    amount = request.POST.get('amount', '0')
    
    # BUG: HTML escaping for SQL injection - WRONG TYPE OF SANITIZATION!
    sanitized_description = html.escape(description)
    
    # VULNERABLE: Raw SQL with string concatenation
    with connection.cursor() as cursor:
        # This is vulnerable even with HTML escaping
        query = f"INSERT INTO transactions (account_id, description, amount, transaction_type) VALUES ({account_id}, '{sanitized_description}', {amount}, 'DEPOSIT')"
        cursor.execute(query)
    
    return JsonResponse({'status': 'recorded', 'description': sanitized_description})


@require_http_methods(["POST"])
def record_transaction_safe(request):
    """
    SAFE VERSION: Using Django ORM for comparison
    """
    description = request.POST.get('description', '')
    account_id = request.POST.get('account_id', '')
    amount = request.POST.get('amount', '0')
    
    # Safe: Django ORM with parameterized query
    transaction = Transaction.objects.create(
        account_id=account_id,
        description=description,  # No manual sanitization needed
        amount=amount,
        transaction_type='DEPOSIT'
    )
    
    return JsonResponse({'status': 'recorded', 'id': transaction.id})
