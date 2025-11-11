# Python E-Commerce Test Codebase

## Overview
Comprehensive test codebase for AI-SAST scanner testing with 8 vulnerabilities designed to test classification logic.

## Statistics
- **Total Vulnerabilities**: 8
- **True Positives**: 3 (37.5%)
- **False Positives**: 5 (62.5%)
  - FP_DEAD_CODE: 1
  - FP_SANITIZED: 2
  - FP_SAFE_CONTEXT: 2

## Architecture
```
app.py (Entry points)
├── controllers/ (Request handling)
│   ├── product_controller.py
│   ├── order_controller.py
│   ├── admin_controller.py
│   └── analytics_controller.py
├── services/ (Business logic)
│   ├── product_service.py
│   ├── order_service.py
│   ├── admin_service.py
│   ├── analytics_service.py
│   └── legacy_service.py
├── middleware/ (Processing layers)
│   ├── query_processor.py
│   ├── validation_middleware.py
│   ├── report_generator.py
│   ├── template_processor.py
│   └── query_optimizer.py
└── repositories/ (Data access - SINKS)
    ├── product_repository.py
    ├── order_repository.py
    ├── analytics_repository.py
    ├── dashboard_repository.py
    └── legacy_repository.py
```

## Vulnerability Details

### TRUE POSITIVES (3)

#### VULN-1: Product Search SQL Injection
- **Path Length**: 5 functions
- **Entry**: `app.py::search_products` (line 18)
- **Sink**: `repositories/product_repository.py::execute_search_query` (line 24)
- **Issue**: No sanitization throughout entire chain

#### VULN-4: Order Search SQL Injection  
- **Path Length**: 4 functions (primary path)
- **Entry**: `app.py::search_orders` (line 43)
- **Sink**: `repositories/order_repository.py::execute_order_query` (line 23)
- **Issue**: Direct SQL concatenation
- **Note**: Has both reachable and unreachable paths

#### VULN-8: Analytics SQL Injection
- **Path Length**: 5 functions
- **Entry**: `app.py::analytics_query` (line 86)
- **Sink**: `repositories/analytics_repository.py::execute_analytics` (line 40)
- **Issue**: Dynamic query building with user-controlled clauses
- **Severity**: CRITICAL - allows arbitrary table access

### FALSE POSITIVES (5)

#### VULN-2: Product Filter (FP_SANITIZED)
- **Sanitization**: `middleware/validation_middleware.py::sanitize_input` (line 18)
- **Method**: Regex whitelist `r'[^\w\s-]'` removes SQL metacharacters
- **Sink**: `repositories/product_repository.py::execute_filter_query` (line 43)

#### VULN-3: Legacy Search (FP_DEAD_CODE)
- **Dead Code**: `app.py::legacy_product_search` (line 35) - `if False` branch
- **Sink**: `repositories/product_repository.py::execute_legacy_query` (line 57)
- **Reason**: Entire path is unreachable

#### VULN-5: Order Report (FP_SAFE_CONTEXT)
- **Safe Practice**: Parameterized query with ? placeholders and tuple binding
- **Validation**: Whitelist validation in `ReportGenerator.validate_report_params`
- **Sink**: `repositories/order_repository.py::execute_report_query` (line 41)

#### VULN-6: Bulk Update Template (FP_SANITIZED)
- **Sanitization**: `middleware/template_processor.py::sanitize_template_input` (line 11)
- **Methods**: 
  - markupsafe.escape() for HTML encoding
  - Regex removal of `{{ }}` patterns
  - Regex removal of `{% %}` patterns
- **Sink**: `render_template_string()` (line 27)

#### VULN-7: Dashboard Template (FP_SAFE_CONTEXT)
- **Safe Practice**: Template from trusted internal dictionary, not user input
- **Evidence**: `self.trusted_templates` defined in `__init__` (line 13-16)
- **Sink**: `repositories/dashboard_repository.py::create_dashboard_template` (line 51)

## Attack Path Complexity
- **Average path length**: 5 functions
- **Paths span**: Controllers → Services → Middleware → Repositories
- **Files involved**: 19 files
- **Total functions**: 35

## Testing Notes
1. All sinks use either `cursor.execute(query)` or `render_template_string()` as specified
2. Each path has 5-6+ function calls across multiple files
3. False positives test different classification scenarios
4. VULN-4 demonstrates mixed reachability (some paths dead, some live)
5. Ground truth JSON provides exact line numbers and classifications

## Running Tests
```bash
# Analyze with scanner
python app/main.py --codebase test_codebase_python_ecommerce

# Compare against ground truth
python verify_scanner_results.py --codebase test_codebase_python_ecommerce
```
