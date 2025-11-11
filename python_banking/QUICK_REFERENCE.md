# Python Banking - Quick Reference

## 8 Vulnerabilities Overview

| # | Type | Classification | File | Sink Function | Confidence |
|---|------|----------------|------|---------------|------------|
| 1 | SQL Injection | **must_fix** | database_service.py | search_transactions_vulnerable() | 0.95 |
| 2 | SQL Injection | false_positive_sanitized | database_service.py | get_user_by_id_with_validation() | 0.90 |
| 3 | SQL Injection | false_positive_sanitized | database_service.py | generate_report_parameterized() | 0.95 |
| 4 | Template Injection | **good_to_fix** | template_service.py | render_user_template() | 0.75 |
| 5 | Template Injection | false_positive_protected | template_service.py | render_preference_template() | 0.85 |
| 6 | SQL Injection | false_positive_protected | database_service.py | get_audit_logs_by_date() | 0.85 |
| 7 | Template Injection | false_positive_protected | template_service.py | render_admin_preview() | 0.90 |
| 8 | SQL Injection | false_positive_dead_code | database_service.py | execute_legacy_query() | 0.95 |

## True Positives (25%)
- **VULN 1**: Direct SQL injection, no protection → `must_fix`
- **VULN 4**: Template injection, weak validation → `good_to_fix`

## False Positives (75%)
- **VULN 2**: Validation-based protection (strict regex)
- **VULN 3**: Parameterized queries (ORM-style)
- **VULN 5**: Authentication protection (@login_required)
- **VULN 6**: Admin authorization (@admin_required)
- **VULN 7**: Defense-in-depth (6 layers)
- **VULN 8**: Dead code branch (unreachable)

## Entry Points (Flask Routes)
```python
/api/search                 → VULN 1 (must_fix)
/api/user/profile          → VULN 2 (FP - sanitized)
/api/report/generate       → VULN 3 (FP - sanitized)
/api/render/custom         → VULN 4 (good_to_fix)
/api/user/preferences      → VULN 5 (FP - protected) [@login_required]
/api/admin/audit           → VULN 6 (FP - protected) [@admin_required]
/api/admin/template/preview → VULN 7 (FP - protected) [@admin_required]
/api/legacy/import         → VULN 8 (FP - dead_code)
```

## Key Testing Points

### Must Detect Correctly
1. ✅ **VULN 1** has NO protections → `must_fix`
2. ✅ **VULN 2** uses `re.fullmatch(r'^[0-9]+$')` → `false_positive_sanitized`
3. ✅ **VULN 3** uses `cursor.execute(query, params)` → `false_positive_sanitized`
4. ✅ **VULN 4** has weak validation → `good_to_fix` (NOT false_positive)
5. ✅ **VULN 8** is in unreachable branch → `false_positive_dead_code`

### Must NOT Confuse
- ❌ Don't classify VULN 4 as `must_fix` (it has partial protection)
- ❌ Don't classify VULN 5/6/7 as `must_fix` (they have strong protection)
- ❌ Don't classify VULN 8 as `must_fix` (it's dead code)

## Attack Path Complexity
All vulnerabilities have **2-5 function hops** to test path analysis:
```
Entry Point → Service Layer → Validation/Processing → Database/Template → Sink
```

## Sink Patterns (As Required)
Only these two patterns are used:
1. `cursor.execute(query)` - SQL Injection
2. `return render_template_string(template_str)` - Template Injection
