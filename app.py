"""
Demo Multi-Vulnerability Application
=====================================

Entry points for all attack paths across modular structure.

VULNERABILITY SUMMARY:
- 3 Vulnerability Sinks (same as original vuln.py)
- 15 Attack Paths Total
- 80% False Positives (12 FP, 3 TP)

FALSE POSITIVE BREAKDOWN:
- 5 PROTECTED paths (authentication/authorization)
- 4 SANITIZED paths (input validation)
- 3 DEAD CODE paths (never instantiated/called)

TRUE POSITIVE BREAKDOWN:
- 3 VULNERABLE paths (no protection)
"""

from demo_vuln.database import DatabaseManager
from demo_vuln.auth import AuthService
from demo_vuln.services.user_service import UserService, UserProfileService, UserReportService
from demo_vuln.services.template_service import TemplateService, EmailService, NotificationService, MarketingService
from demo_vuln.services.analytics_service import AnalyticsService, ReportingService, DashboardService
from demo_vuln.api.user_api import ProtectedUserAPI
from demo_vuln.api.admin_api import AdminAPI
from demo_vuln.api.marketing_api import ProtectedMarketingAPI


# ============================================================================
# VULNERABILITY 1: SQL INJECTION - UserService.find_user_by_id()
# Total: 5 paths (1 VULNERABLE, 2 PROTECTED, 2 SANITIZED)
# ============================================================================

def vuln1_path1_vulnerable(user_input: str):
    """
    VULN 1 - Path 1: Direct SQL injection (4 hops) - TRUE POSITIVE
    
    Classification: VULNERABLE (TRUE POSITIVE)
    Attack path: user_input → generate_report → get_profile → find_user_by_id → cursor.execute
    Protection: NONE
    """
    db = DatabaseManager()
    user_service = UserService(db)
    profile_service = UserProfileService(user_service)
    report_service = UserReportService(profile_service)
    # 4 hops: report_service → profile_service → user_service → cursor.execute
    report_service.generate_report(user_input)


def vuln1_path2_protected_auth(user_input: str):
    """
    VULN 1 - Path 2: Protected by authentication (6 hops) - FALSE POSITIVE
    
    Classification: FALSE POSITIVE - PROTECTED
    Attack path: user_input → get_user_report → [AUTH CHECK] → generate_report → ... → cursor.execute
    Protection: Authentication required (ProtectedUserAPI)
    """
    db = DatabaseManager()
    auth = AuthService()
    user_service = UserService(db)
    profile_service = UserProfileService(user_service)
    report_service = UserReportService(profile_service)
    protected_api = ProtectedUserAPI(report_service, auth)
    # 6 hops but PROTECTED by authentication check
    protected_api.get_user_report(user_input)


def vuln1_path3_sanitized_email(email_input: str):
    """
    VULN 1 - Path 3: Sanitized by email validation (4 hops) - FALSE POSITIVE
    
    Classification: FALSE POSITIVE - SANITIZED
    Attack path: email_input → get_profile_by_email → find_user_by_email → [VALIDATION] → ... → cursor.execute
    Protection: Email regex validation prevents SQL injection
    """
    db = DatabaseManager()
    user_service = UserService(db)
    profile_service = UserProfileService(user_service)
    # 4 hops but SANITIZED by email validation
    profile_service.get_profile_by_email(email_input)


def vuln1_path4_protected_auth_sanitized(email_input: str):
    """
    VULN 1 - Path 4: Protected by auth + sanitized (6 hops) - FALSE POSITIVE
    
    Classification: FALSE POSITIVE - PROTECTED + SANITIZED
    Attack path: email_input → get_user_report_by_email → [AUTH CHECK] → [VALIDATION] → ... → cursor.execute
    Protection: Both authentication AND email validation
    """
    db = DatabaseManager()
    auth = AuthService()
    user_service = UserService(db)
    profile_service = UserProfileService(user_service)
    report_service = UserReportService(profile_service)
    protected_api = ProtectedUserAPI(report_service, auth)
    # 6 hops with BOTH authentication and validation protection
    protected_api.get_user_report_by_email(email_input)


def vuln1_path5_sanitized_email_report(email_input: str):
    """
    VULN 1 - Path 5: Sanitized email report (4 hops) - FALSE POSITIVE
    
    Classification: FALSE POSITIVE - SANITIZED
    Attack path: email_input → generate_email_report → get_profile_by_email → [VALIDATION] → cursor.execute
    Protection: Email validation
    """
    db = DatabaseManager()
    user_service = UserService(db)
    profile_service = UserProfileService(user_service)
    report_service = UserReportService(profile_service)
    # 4 hops but SANITIZED by email validation
    report_service.generate_email_report(email_input)


# ============================================================================
# VULNERABILITY 2: SSTI - TemplateService.render_user_template()
# Total: 6 paths (2 VULNERABLE, 2 PROTECTED, 1 SANITIZED, 1 DEAD CODE)
# ============================================================================

def vuln2_path1_vulnerable(template_input: str):
    """
    VULN 2 - Path 1: Direct SSTI (5 hops) - TRUE POSITIVE
    
    Classification: VULNERABLE (TRUE POSITIVE)
    Attack path: template → send_notification → generate_email → render_user_template → render_template_string
    Protection: NONE
    """
    db = DatabaseManager()
    user_service = UserService(db)
    template_service = TemplateService(user_service)
    email_service = EmailService(template_service)
    notification_service = NotificationService(email_service)
    # 5 hops: notification → email → template → render_template_string
    notification_service.send_notification(template_input)


def vuln2_path2_vulnerable_marketing(template_input: str):
    """
    VULN 2 - Path 2: SSTI via marketing (7 hops) - TRUE POSITIVE
    
    Classification: VULNERABLE (TRUE POSITIVE)
    Attack path: template → send_campaign → send_notification → ... → render_template_string
    Protection: NONE
    """
    db = DatabaseManager()
    user_service = UserService(db)
    template_service = TemplateService(user_service)
    email_service = EmailService(template_service)
    notification_service = NotificationService(email_service)
    marketing_service = MarketingService(notification_service)
    # 7 hops: marketing → notification → email → template → render_template_string
    marketing_service.send_campaign(template_input)


def vuln2_path3_protected_admin(template_input: str):
    """
    VULN 2 - Path 3: Protected by admin privileges (8 hops) - FALSE POSITIVE
    
    Classification: FALSE POSITIVE - PROTECTED
    Attack path: template → send_admin_campaign → [ADMIN CHECK] → send_campaign → ... → render_template_string
    Protection: Admin authorization required
    """
    db = DatabaseManager()
    auth = AuthService()
    user_service = UserService(db)
    template_service = TemplateService(user_service)
    email_service = EmailService(template_service)
    notification_service = NotificationService(email_service)
    marketing_service = MarketingService(notification_service)
    protected_marketing = ProtectedMarketingAPI(marketing_service, auth)
    # 8 hops but PROTECTED by admin authorization check
    protected_marketing.send_admin_campaign(template_input)


def vuln2_path4_protected_auth(template_input: str):
    """
    VULN 2 - Path 4: Protected by authentication (8 hops) - FALSE POSITIVE
    
    Classification: FALSE POSITIVE - PROTECTED
    Attack path: template → send_authenticated_notification → [AUTH CHECK] → ... → render_template_string
    Protection: Authentication required
    """
    db = DatabaseManager()
    auth = AuthService()
    user_service = UserService(db)
    template_service = TemplateService(user_service)
    email_service = EmailService(template_service)
    notification_service = NotificationService(email_service)
    marketing_service = MarketingService(notification_service)
    protected_marketing = ProtectedMarketingAPI(marketing_service, auth)
    # 8 hops but PROTECTED by authentication check
    protected_marketing.send_authenticated_notification(template_input)


def vuln2_path5_sanitized(username: str):
    """
    VULN 2 - Path 5: Sanitized welcome email (1 hop) - FALSE POSITIVE
    
    Classification: FALSE POSITIVE - SANITIZED
    Attack path: username → generate_welcome_email → render_template_string (with safe template)
    Protection: Uses predefined safe template with proper escaping
    """
    db = DatabaseManager()
    user_service = UserService(db)
    template_service = TemplateService(user_service)
    email_service = EmailService(template_service)
    # 1 hop but SANITIZED by using safe template
    email_service.generate_welcome_email(username)


# NOTE: vuln2_path6_dead_code is in legacy/legacy_services.py but NEVER called
# The DeadTemplateService class is never instantiated in this app


# ============================================================================
# VULNERABILITY 3: SQL INJECTION - AnalyticsService.get_user_stats()
# Total: 4 paths (0 VULNERABLE, 2 PROTECTED, 2 SANITIZED)
# ============================================================================

def vuln3_path1_protected_admin(filter_input: str):
    """
    VULN 3 - Path 1: Protected by admin privileges (6 hops) - FALSE POSITIVE
    
    Classification: FALSE POSITIVE - PROTECTED
    Attack path: filter → get_admin_dashboard → [ADMIN CHECK] → get_dashboard_data → ... → cursor.execute
    Protection: Admin authorization required
    """
    db = DatabaseManager()
    auth = AuthService()
    analytics_service = AnalyticsService(db)
    reporting_service = ReportingService(analytics_service)
    dashboard_service = DashboardService(reporting_service)
    admin_api = AdminAPI(dashboard_service, auth)
    # 6 hops but PROTECTED by admin authorization check
    admin_api.get_admin_dashboard(filter_input)


def vuln3_path2_sanitized(filter_input: str):
    """
    VULN 3 - Path 2: Sanitized by alphanumeric validation (5 hops) - FALSE POSITIVE
    
    Classification: FALSE POSITIVE - SANITIZED
    Attack path: filter → get_filtered_dashboard → generate_safe_stats_report → [VALIDATION] → cursor.execute
    Protection: Alphanumeric regex validation prevents SQL injection
    """
    db = DatabaseManager()
    analytics_service = AnalyticsService(db)
    reporting_service = ReportingService(analytics_service)
    dashboard_service = DashboardService(reporting_service)
    # 5 hops but SANITIZED by alphanumeric validation
    dashboard_service.get_filtered_dashboard(filter_input)


def vuln3_path3_protected_admin_sanitized(filter_input: str):
    """
    VULN 3 - Path 3: Protected by admin + sanitized (6 hops) - FALSE POSITIVE
    
    Classification: FALSE POSITIVE - PROTECTED + SANITIZED
    Attack path: filter → get_admin_safe_dashboard → [ADMIN CHECK] → [VALIDATION] → cursor.execute
    Protection: Both admin authorization AND input validation
    """
    db = DatabaseManager()
    auth = AuthService()
    analytics_service = AnalyticsService(db)
    reporting_service = ReportingService(analytics_service)
    dashboard_service = DashboardService(reporting_service)
    admin_api = AdminAPI(dashboard_service, auth)
    # 6 hops with BOTH admin authorization and validation protection
    admin_api.get_admin_safe_dashboard(filter_input)


def vuln3_path4_sanitized_direct(filter_input: str):
    """
    VULN 3 - Path 4: Sanitized direct stats (3 hops) - FALSE POSITIVE
    
    Classification: FALSE POSITIVE - SANITIZED
    Attack path: filter → get_user_stats_safe → [VALIDATION] → get_user_stats → cursor.execute
    Protection: Alphanumeric validation at analytics service level
    """
    db = DatabaseManager()
    analytics_service = AnalyticsService(db)
    # 3 hops but SANITIZED by alphanumeric validation
    analytics_service.get_user_stats_safe(filter_input)


# NOTE: vuln3_path5_dead_code is in legacy/legacy_services.py but NEVER called
# The UnusedAnalyticsService class is never instantiated in this app


# ============================================================================
# DEAD CODE PATHS (Never called in execution)
# ============================================================================

# These functions exist in legacy/legacy_services.py but are NEVER:
# 1. Imported in this file
# 2. Instantiated
# 3. Called from any execution path
#
# They represent DEAD CODE that should be classified as FALSE POSITIVE:
# - UnusedLegacyService.legacy_user_lookup() - VULN 1 DEAD CODE
# - DeadTemplateService.render_legacy_template() - VULN 2 DEAD CODE
# - UnusedAnalyticsService.get_legacy_stats() - VULN 3 DEAD CODE


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Initialize application and demonstrate paths"""
    db = DatabaseManager()
    db.initialize_schema()
    
    print("=" * 70)
    print("Demo Multi-Vulnerability Application (Modular Structure)")
    print("=" * 70)
    print()
    print("3 Vulnerabilities with 15 Attack Paths:")
    print()
    print("VULN 1 (SQL Injection - UserService):")
    print("  ├─ Path 1: VULNERABLE (TRUE POSITIVE)")
    print("  ├─ Path 2: PROTECTED by auth (FALSE POSITIVE)")
    print("  ├─ Path 3: SANITIZED by validation (FALSE POSITIVE)")
    print("  ├─ Path 4: PROTECTED + SANITIZED (FALSE POSITIVE)")
    print("  └─ Path 5: SANITIZED email report (FALSE POSITIVE)")
    print()
    print("VULN 2 (SSTI - TemplateService):")
    print("  ├─ Path 1: VULNERABLE (TRUE POSITIVE)")
    print("  ├─ Path 2: VULNERABLE via marketing (TRUE POSITIVE)")
    print("  ├─ Path 3: PROTECTED by admin (FALSE POSITIVE)")
    print("  ├─ Path 4: PROTECTED by auth (FALSE POSITIVE)")
    print("  ├─ Path 5: SANITIZED safe template (FALSE POSITIVE)")
    print("  └─ Path 6: DEAD CODE (FALSE POSITIVE - never instantiated)")
    print()
    print("VULN 3 (SQL Injection - AnalyticsService):")
    print("  ├─ Path 1: PROTECTED by admin (FALSE POSITIVE)")
    print("  ├─ Path 2: SANITIZED by validation (FALSE POSITIVE)")
    print("  ├─ Path 3: PROTECTED + SANITIZED (FALSE POSITIVE)")
    print("  ├─ Path 4: SANITIZED direct (FALSE POSITIVE)")
    print("  └─ Path 5: DEAD CODE (FALSE POSITIVE - never instantiated)")
    print()
    print("=" * 70)
    print("SUMMARY:")
    print("  Total Paths: 15")
    print("  TRUE POSITIVES: 3 (20%)")
    print("  FALSE POSITIVES: 12 (80%)")
    print("    └─ PROTECTED: 5 paths")
    print("    └─ SANITIZED: 4 paths")
    print("    └─ DEAD CODE: 3 paths")
    print("=" * 70)


if __name__ == "__main__":
    main()
