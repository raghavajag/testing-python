# Testing Guide - Python Banking Vulnerabilities

## Quick Start
```bash
cd testing_codebases_comprehensive/python_banking
python -m pytest  # or run your AI-SAST analyzer
```

## What Makes This Codebase Special?

### 1. Comprehensive Attack Paths (4-6 Functions)
- Every vulnerability has **multi-hop attack paths** spanning 3-5 functions
- Tests cross-file, cross-class method resolution
- Validates that static analyzer can trace data flow through multiple layers

### 2. Only Scanner-Detectable Sinks
Per requirements, we use ONLY these sinks:
- `cursor.execute(query)` - SQL Injection (6 instances)
- `render_template_string(template)` - SSTI (2 instances)

### 3. Real-World Patterns
- Parameterized queries (VULN 2)
- Allowlist validation (VULN 3)
- Defense-in-depth (VULN 4)
- Mixed live+dead paths (VULN 5 - CRITICAL TEST)
- Dead code detection (VULN 6)
- HTML escaping (VULN 7)

## Expected Results

### Must Fix (3):
1. **VULN 1**: Direct SQL injection (5-function path)
2. **VULN 5**: Mixed paths with live vulnerable path (4-function path)
3. **VULN 8**: Direct SSTI (3-function path)

### False Positives (5):
1. **VULN 2**: Parameterized query (5-function path) - Sanitized 2A
2. **VULN 3**: Allowlist validation (5-function path) - Sanitized 2B
3. **VULN 4**: Admin + CSRF + Rate Limit (4-function path) - Protected 3B
4. **VULN 6**: Unreachable function (4-function path) - Dead Code
5. **VULN 7**: HTML escaping (4-function path) - Sanitized 2A

## Critical Test Cases

### Test 1: Multi-Hop Resolution
**VULN 1** requires tracing through:
- Controller → Service → InputProcessor → Repository → DatabaseHelper
- **5 function calls** across **5 different files**
- Tests: Can analyzer resolve method calls across multiple layers?

### Test 2: Parameterized Query Recognition  
**VULN 2** tests if LLM recognizes:
- `cursor.execute(query, params)` vs `cursor.execute(query)`
- Difference between safe and unsafe SQL execution
- **Expected**: false_positive_sanitized (Subcategory 2A)

### Test 3: Validation Effectiveness
**VULN 3** tests if LLM understands:
- Allowlist validation restricts input space
- Only 4 hardcoded values allowed
- Validated variable is used (not original user input)
- **Expected**: false_positive_sanitized (Subcategory 2B)

### Test 4: Defense-in-Depth
**VULN 4** tests if LLM recognizes:
- Multiple independent security layers
- Admin role + CSRF + Rate limiting
- Combined effect makes exploitation impractical
- **Expected**: false_positive_protected (Subcategory 3B)

### Test 5: Mixed Paths (MOST CRITICAL)
**VULN 5** tests if LLM correctly handles:
- **Path A**: Live and vulnerable (type='detailed')
- **Path B**: Dead code (type='legacy')
- **Expected**: must_fix (because at least one path is live)
- **Path Assessment**: Path A = VULNERABLE, Path B = DEAD_CODE

**Failure Mode**: Incorrectly classifying as false_positive_dead_code
**Success Mode**: Correctly classifying as must_fix with mixed path assessment

### Test 6: Dead Code Detection
**VULN 6** tests if static analysis identifies:
- Function not registered as Flask route
- No calls to this function anywhere in codebase
- **Expected**: false_positive_dead_code

### Test 7: HTML Escaping
**VULN 7** tests if LLM recognizes:
- `html.escape()` called BEFORE `render_template_string()`
- Sanitization happens at correct point in data flow
- **Expected**: false_positive_sanitized (Subcategory 2A)

### Test 8: Direct SSTI
**VULN 8** tests baseline vulnerability detection:
- No sanitization, no protection
- **Expected**: must_fix with high confidence

## Success Criteria

✅ All 8 vulnerabilities detected by scanner
✅ 3/8 classified as must_fix (37.5%)
✅ 5/8 classified as false_positive (62.5%)
✅ Correct subcategories (2A, 2B, 3B)
✅ VULN 5 classified as must_fix (NOT dead code)
✅ High confidence scores (0.85+)
✅ All rationales cite specific code evidence
✅ No internal identifiers in customer-facing text
✅ Professional, developer-focused language

## Common Failure Modes to Watch For

❌ **VULN 5 misclassification**: Marking as dead code when live path exists
❌ **Parameterized query missed**: Not recognizing `cursor.execute(query, params)` as safe
❌ **Validation bypass**: Not understanding allowlist restricts input space
❌ **Defense-in-depth undervalued**: Not recognizing multiple layers combine effectively
❌ **Dead code false negative**: Not identifying truly unreachable code
❌ **HTML escape missed**: Not recognizing escaping prevents template injection

## Architecture Benefits

### Separation of Concerns
- **Controllers**: HTTP endpoints (entry points)
- **Services**: Business logic (orchestration)
- **Repositories**: Data access (SQL construction)
- **Utils**: Infrastructure (actual sinks)

### Why This Structure?
1. **Realistic**: Mirrors real-world application architecture
2. **Testable**: Each layer has clear responsibilities
3. **Traceable**: Clear data flow from entry to sink
4. **Comprehensive**: Requires full cross-file analysis

## File Overview

```
10 Python files, 8 vulnerabilities, 3-5 function paths each

Entry Points (Controllers):
- account_controller.py: 6 Flask routes (VULN 1-6)
- report_controller.py: 2 Flask routes (VULN 7-8)

Business Logic (Services):
- account_service.py: Account operations
- validation_service.py: Input validation
- report_service.py: Report generation

Data Access (Repositories):
- account_repository.py: SQL query construction

Infrastructure (Utils):
- database_helper.py: ACTUAL SINKS (cursor.execute)
- input_processor.py: Input processing
- auth_decorators.py: Security controls
```

## Next Steps

1. Run AI-SAST analyzer on this codebase
2. Compare results against expected classifications
3. Analyze any misclassifications
4. Review rationales for evidence-based reasoning
5. Validate path-level assessments for VULN 5

Good luck! ���
