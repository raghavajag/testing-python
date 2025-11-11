# Demo Multi-Vulnerability Testing Package

## Overview

This is a **modular refactoring** of the original `vuln.py` file, maintaining the same 3 vulnerability sinks while spreading attack paths across multiple files for realistic testing.

## Structure

```
demo_vuln/
├── __init__.py                 # Package initialization
├── database.py                 # DatabaseManager
├── auth.py                     # AuthService (authentication/authorization)
├── app.py                      # Entry points for all attack paths
│
├── services/                   # Service layer with vulnerabilities
│   ├── __init__.py
│   ├── user_service.py         # VULN 1: SQL Injection
│   ├── template_service.py     # VULN 2: SSTI
│   └── analytics_service.py    # VULN 3: SQL Injection
│
├── api/                        # Protected API endpoints
│   ├── __init__.py
│   ├── user_api.py             # Protected user endpoints
│   ├── admin_api.py            # Admin-protected endpoints
│   └── marketing_api.py        # Marketing endpoints with auth
│
└── legacy/                     # Dead code (never called)
    ├── __init__.py
    └── legacy_services.py      # Unused legacy services
```

## Vulnerability Summary

### Same 3 Vulnerability Sinks as Original vuln.py:

1. **VULN 1**: SQL Injection in `UserService.find_user_by_id()`
   - Sink: `cursor.execute(query)` at line 28
   - Location: `services/user_service.py`

2. **VULN 2**: SSTI in `TemplateService.render_user_template()`
   - Sink: `render_template_string(template_str)` at line 26
   - Location: `services/template_service.py`

3. **VULN 3**: SQL Injection in `AnalyticsService.get_user_stats()`
   - Sink: `cursor.execute(query)` at line 30
   - Location: `services/analytics_service.py`

## Attack Paths Distribution

### Total: 15 Paths (80% False Positives)

- **TRUE POSITIVES: 3 (20%)**
  - VULN 1 Path 1: Direct SQL injection
  - VULN 2 Path 1: Direct SSTI
  - VULN 2 Path 2: SSTI via marketing

- **FALSE POSITIVES: 12 (80%)**
  - **PROTECTED (5 paths)**: Authentication/authorization required
    - VULN 1 Path 2: Protected by auth
    - VULN 1 Path 4: Protected by auth + sanitized
    - VULN 2 Path 3: Protected by admin
    - VULN 2 Path 4: Protected by auth
    - VULN 3 Path 1: Protected by admin
    - VULN 3 Path 3: Protected by admin + sanitized
  
  - **SANITIZED (4 paths)**: Input validation prevents exploitation
    - VULN 1 Path 3: Email validation
    - VULN 1 Path 5: Email validation in report
    - VULN 2 Path 5: Safe template with escaping
    - VULN 3 Path 2: Alphanumeric validation
    - VULN 3 Path 4: Direct validation
  
  - **DEAD CODE (3 paths)**: Never instantiated/called
    - VULN 1: `UnusedLegacyService` in `legacy/legacy_services.py`
    - VULN 2: `DeadTemplateService` in `legacy/legacy_services.py`
    - VULN 3: `UnusedAnalyticsService` in `legacy/legacy_services.py`

## Detailed Attack Path Analysis

### VULNERABILITY 1: SQL Injection in UserService

| Path | Classification | Hops | Protection |
|------|---------------|------|------------|
| Path 1 | TRUE POSITIVE | 4 | None |
| Path 2 | FALSE POSITIVE - PROTECTED | 6 | Authentication |
| Path 3 | FALSE POSITIVE - SANITIZED | 4 | Email validation |
| Path 4 | FALSE POSITIVE - PROTECTED + SANITIZED | 6 | Auth + validation |
| Path 5 | FALSE POSITIVE - SANITIZED | 4 | Email validation |

**Entry Points**: See `app.py` functions:
- `vuln1_path1_vulnerable()`
- `vuln1_path2_protected_auth()`
- `vuln1_path3_sanitized_email()`
- `vuln1_path4_protected_auth_sanitized()`
- `vuln1_path5_sanitized_email_report()`

### VULNERABILITY 2: SSTI in TemplateService

| Path | Classification | Hops | Protection |
|------|---------------|------|------------|
| Path 1 | TRUE POSITIVE | 5 | None |
| Path 2 | TRUE POSITIVE | 7 | None |
| Path 3 | FALSE POSITIVE - PROTECTED | 8 | Admin authorization |
| Path 4 | FALSE POSITIVE - PROTECTED | 8 | Authentication |
| Path 5 | FALSE POSITIVE - SANITIZED | 1 | Safe template |
| Path 6 | FALSE POSITIVE - DEAD CODE | N/A | Never called |

**Entry Points**: See `app.py` functions:
- `vuln2_path1_vulnerable()`
- `vuln2_path2_vulnerable_marketing()`
- `vuln2_path3_protected_admin()`
- `vuln2_path4_protected_auth()`
- `vuln2_path5_sanitized()`
- Dead code in `legacy/legacy_services.py::DeadTemplateService`

### VULNERABILITY 3: SQL Injection in AnalyticsService

| Path | Classification | Hops | Protection |
|------|---------------|------|------------|
| Path 1 | FALSE POSITIVE - PROTECTED | 6 | Admin authorization |
| Path 2 | FALSE POSITIVE - SANITIZED | 5 | Alphanumeric validation |
| Path 3 | FALSE POSITIVE - PROTECTED + SANITIZED | 6 | Admin + validation |
| Path 4 | FALSE POSITIVE - SANITIZED | 3 | Alphanumeric validation |
| Path 5 | FALSE POSITIVE - DEAD CODE | N/A | Never called |

**Entry Points**: See `app.py` functions:
- `vuln3_path1_protected_admin()`
- `vuln3_path2_sanitized()`
- `vuln3_path3_protected_admin_sanitized()`
- `vuln3_path4_sanitized_direct()`
- Dead code in `legacy/legacy_services.py::UnusedAnalyticsService`

## Key Differences from Original vuln.py

### ✅ Maintains:
- Same 3 vulnerability sinks
- Same sink patterns (`cursor.execute()` and `render_template_string()`)
- Similar attack path complexity (4-8 hops)
- Same false positive categories (PROTECTED, SANITIZED, DEAD CODE)

### ✨ Improvements:
- **Modular structure**: Code split across 11 files instead of 1 monolithic file
- **Realistic architecture**: Services, API layer, legacy code separation
- **80% false positives**: 12 FP out of 15 paths (was ~75% in original)
- **Better organization**: Clear separation of concerns
- **More testable**: Each service can be tested independently
- **Cross-file attack paths**: Paths now span multiple files and directories

## Running Tests

```python
# Run the main application to see path summary
python -m demo_vuln.app

# Run individual attack paths for testing
from demo_vuln.app import vuln1_path1_vulnerable, vuln2_path3_protected_admin

# Test a vulnerable path
vuln1_path1_vulnerable("' OR 1=1--")

# Test a protected path
vuln2_path3_protected_admin("{{ 7*7 }}")
```

## Expected Analyzer Behavior

The AI-SAST analyzer should:

1. **Detect all 3 vulnerability sinks** across multiple files
2. **Trace all 15 attack paths** across the modular structure
3. **Correctly classify**:
   - 3 TRUE POSITIVES (20%)
   - 12 FALSE POSITIVES (80%)
     - 5 PROTECTED
     - 4 SANITIZED
     - 3 DEAD CODE
4. **Follow import chains** across files:
   - `app.py` → `api/*.py` → `services/*.py` → sinks
5. **Identify dead code** in `legacy/legacy_services.py` (never imported in `app.py`)

## Success Metrics

✅ **100% accuracy** (15/15 correct classifications)
✅ **Cross-file path tracing** works correctly
✅ **Dead code detection** identifies unused legacy services
✅ **Protection recognition** identifies auth/authz controls
✅ **Sanitization detection** identifies input validation

## Testing Commands

```bash
# Navigate to the qina-clarity root directory
cd c:\Users\raghava\Desktop\work\attack-paths\qina-clarity

# Run the AI-SAST analyzer on demo_vuln package
python -m app.main --target demo_vuln

# Expected: 3 vulnerabilities detected with 15 attack paths
# Expected: 12 false positives, 3 true positives
```
