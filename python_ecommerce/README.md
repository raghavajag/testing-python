# Python Flask E-Commerce - Testing Codebase Quick Reference

## Vulnerability Summary

| ID | Type | Classification | Line | File | Protection |
|----|------|----------------|------|------|------------|
| **VULN_1** | SQL | `false_positive_dead_code` | 22 | `repositories/legacy_repository.py` | Dead code (never called) |
| **VULN_2** | SQL | `false_positive_sanitized` | 24 | `repositories/product_repository.py` | Parameterized queries (ORM) |
| **VULN_3** | SSTI | `false_positive_sanitized` | varies | `services/notification_service.py` | Template allowlist validation |
| **VULN_4** | SQL | `false_positive_protected` | 24 | `repositories/user_repository.py` | Admin + CSRF + rate limit |
| **VULN_5** | SSTI | `false_positive_protected` | varies | `services/template_renderer.py` | Admin + validation + rate limit |
| **VULN_6** | SQL | `must_fix` | 69 | `repositories/product_repository.py` | None (public, no sanitization) |
| **VULN_7** | SSTI | `must_fix` | 42 | `services/notification_service.py` | None (direct render_template_string) |
| **VULN_8** | SQL | `good_to_fix` | 69 | `repositories/user_repository.py` | Weak validation (bypassable) |

## Entry Points by Vulnerability

### VULN_1 (Dead Code) - 3 paths
- `GET /api/legacy/old-search` → legacy_controller.py::old_legacy_search (line 15)
- `POST /api/legacy/deprecated-query` → legacy_controller.py::deprecated_query (line 26)
- `GET /api/legacy/archive-search` → legacy_controller.py::archive_search (line 37)

### VULN_2 (Sanitized - ORM) - 3 paths
- `GET /api/products/search` → product_controller.py::search_products (line 13)
- `POST /api/products/advanced-search` → product_controller.py::advanced_product_search (line 24)
- `GET /api/products/filter` → product_controller.py::filter_products (line 34)

### VULN_3 (Sanitized - Validation) - 3 paths
- `POST /api/orders/confirmation` → order_controller.py::send_order_confirmation (line 15)
- `POST /api/orders/notification` → order_controller.py::send_order_notification (line 25)
- `POST /api/orders/status-update` → order_controller.py::send_status_update (line 34)

### VULN_4 (Protected - Admin Auth) - 3 paths
- `POST /api/admin/user-search` → admin_controller.py::admin_search_users (line 16)
- `POST /api/admin/bulk-user-query` → admin_controller.py::bulk_user_query (line 27)
- `GET /api/admin/audit-log` → admin_controller.py::get_audit_logs (line 35)

### VULN_5 (Protected - Multi-layer) - 3 paths
- `POST /api/reports/custom-report` → report_controller.py::generate_custom_report (line 18)
- `POST /api/reports/dashboard-widget` → report_controller.py::create_dashboard_widget (line 28)
- `POST /api/reports/analytics-preview` → report_controller.py::preview_analytics (line 38)

### VULN_6 (Must Fix - No Protection) - 4 paths
- `GET /api/products/quick-search` → product_controller.py::quick_search (line 54)
- `GET /api/products/legacy-search` → product_controller.py::legacy_search (line 64)
- `POST /api/products/bulk-search` → product_controller.py::bulk_search (line 73)
- `GET /api/products/category-search` → product_controller.py::category_search (line 82)

### VULN_7 (Must Fix - SSTI) - 4 paths
- `POST /api/orders/preview` → order_controller.py::preview_order_email (line 53)
- `POST /api/orders/custom-email` → order_controller.py::send_custom_email (line 63)
- `POST /api/orders/render-receipt` → order_controller.py::render_receipt (line 73)
- `POST /api/orders/marketing` → order_controller.py::send_marketing_email (line 83)

### VULN_8 (Good to Fix - Weak Validation) - 4 paths
- `GET /api/admin/customer-lookup` → admin_controller.py::customer_lookup (line 47)
- `POST /api/admin/transaction-search` → admin_controller.py::search_transactions (line 56)
- `POST /api/admin/report-query` → admin_controller.py::custom_report_query (line 66)
- `POST /api/admin/data-export` → admin_controller.py::export_data (line 76)

## Sink Functions (Vulnerability Locations)

### SQL Injection Sinks

**SAFE (Parameterized)**:
```python
# VULN_2: repositories/product_repository.py
def search_products_safe(self, query, category):
    cursor.execute(sql, (f"%{query}%", category))  # ✅ SAFE
```

**VULNERABLE (String Concatenation)**:
```python
# VULN_6: repositories/product_repository.py
def quick_search_raw(self, search_term):
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)  # ❌ VULNERABLE

# VULN_4: repositories/user_repository.py (PROTECTED by auth)
def search_users_raw(self, criteria):
    query = f"SELECT * FROM users WHERE username LIKE '%{criteria}%'"
    cursor.execute(query)  # ❌ VULNERABLE (but protected)

# VULN_8: repositories/user_repository.py (WEAK validation)
def lookup_by_id_unsafe(self, customer_id, search_type):
    query = f"SELECT * FROM customers WHERE id = '{customer_id}'"
    cursor.execute(query)  # ❌ VULNERABLE (weak validation)
```

### SSTI Sinks

**SAFE (Validated Templates)**:
```python
# VULN_3: services/template_renderer.py
def render_from_validated_template(self, content):
    template_name = content.get('template', 'default')
    if template_name in self.safe_templates:
        return render_template_string(self.safe_templates[template_name], **content)  # ✅ SAFE
```

**VULNERABLE (Direct User Input)**:
```python
# VULN_7: services/notification_service.py
def preview_email_template(self, template_string, order_data):
    return render_template_string(template_string, **order_data)  # ❌ VULNERABLE
```

## Security Controls

### Authentication & Authorization
- **@require_auth**: Basic authentication (checks session)
- **@require_admin**: Admin role required (checks is_admin flag)
- **@require_csrf_token**: CSRF token validation

### Input Validation
- **@validate_order_input**: Validates order data and template allowlist
- **@validate_product_search**: Length validation for search queries
- **@validate_template_input**: Strict allowlist + regex validation

### Rate Limiting
- **@rate_limit(max_requests, window_seconds)**: Request rate limiting

## Testing Instructions

1. **Run scanner**:
   ```bash
   python app/main.py --target testing_codebases_v2/python_ecommerce/
   ```

2. **Expected output**: 8 vulnerabilities detected
3. **Expected classifications**:
   - 1 dead_code (VULN_1)
   - 2 sanitized (VULN_2, VULN_3)
   - 2 protected (VULN_4, VULN_5)
   - 2 must_fix (VULN_6, VULN_7)
   - 1 good_to_fix (VULN_8)

4. **Validation checks**:
   - All 27 attack paths enumerated
   - Correct function IDs (file::Class::method format)
   - Accurate line numbers
   - Proper classification reasoning

## File Structure

```
python_ecommerce/
├── controllers/        # 5 files, entry points
├── services/           # 10+ files, business logic
├── repositories/       # 4 files, database access (sinks)
├── middleware/         # 3 files, security controls
└── ground_truth.json   # Expected scanner output
```

## Key Patterns to Test

1. **ORM Detection**: Scanner must recognize `cursor.execute(sql, params)` as safe
2. **Allowlist Validation**: Must detect template name validation against allowlist
3. **Multi-layer Auth**: Must detect @require_admin + @require_csrf_token + @rate_limit stack
4. **Dead Code**: Must detect zero callers to legacy_controller routes
5. **Weak Validation**: Must recognize validation exists but can be bypassed (VULN_8)

---

**Total Functions**: ~60
**Total Lines**: ~2000
**Attack Paths**: 27 (avg 5.4 functions per path)
**Complexity**: Production-grade, multi-layer architecture
