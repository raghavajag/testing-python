from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
from functools import wraps
from typing import Callable
import re

"""
TEST CASE 4: Defense-in-Depth with Multiple Security Layers (Python)
Demonstrates wrong variable bug (False Negative - MUST CATCH)
"""

Base = declarative_base()

# ============================================================================
# Models
# ============================================================================

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    username = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    role = Column(String(50), default='USER')
    created_at = Column(DateTime, default=datetime.utcnow)


class LoginAttempt(Base):
    __tablename__ = 'login_attempts'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), nullable=False)
    action = Column(String(100), nullable=False)
    ip_address = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)


# ============================================================================
# Security Decorators (Defense-in-Depth Layers)
# ============================================================================

def require_authentication(func: Callable) -> Callable:
    """
    Security Layer 1: Authentication check
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Simulated: Check if user is authenticated
        session = kwargs.get('session')
        if not session or 'user_id' not in session:
            raise PermissionError("Authentication required")
        return func(*args, **kwargs)
    return wrapper


def require_role(role: str) -> Callable:
    """
    Security Layer 2: Role-based access control
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            session = kwargs.get('session')
            user_role = session.get('role', 'USER')
            if user_role != role:
                raise PermissionError(f"Role {role} required")
            return func(*args, **kwargs)
        return wrapper
    return decorator


def csrf_protect(func: Callable) -> Callable:
    """
    Security Layer 3: CSRF token validation
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        request = kwargs.get('request')
        csrf_token = request.get('csrf_token')
        session = kwargs.get('session')
        expected_token = session.get('csrf_token')
        
        if csrf_token != expected_token:
            raise PermissionError("Invalid CSRF token")
        return func(*args, **kwargs)
    return wrapper


def rate_limit(max_requests: int = 100) -> Callable:
    """
    Security Layer 4: Rate limiting
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Simulated rate limiting check
            session = kwargs.get('session')
            request_count = session.get('request_count', 0)
            if request_count >= max_requests:
                raise PermissionError("Rate limit exceeded")
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ============================================================================
# Validation Helper
# ============================================================================

def validate_email(email: str) -> str:
    """
    Validates email format and returns sanitized version
    
    CRITICAL: This function creates a NEW sanitized variable
    The caller MUST use the returned value, not the original parameter
    """
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(email_pattern, email):
        raise ValueError(f"Invalid email format: {email}")
    
    # Create sanitized version
    sanitized = email.strip().lower()
    
    return sanitized  # Caller MUST use this return value!


# ============================================================================
# TEST CASE 4: Wrong Variable Bug (False Negative - MUST CATCH)
# ============================================================================

@csrf_protect
@require_authentication
@require_role('ADMIN')
@rate_limit(max_requests=50)
def record_login_attempt_vulnerable(email: str, action: str, db_session: Session, **kwargs):
    """
    TEST CASE 4 - VULNERABLE: Validation result not used (wrong variable bug)
    
    ATTACK PATH (7+ hops):
    Hop 1: HTTP Request → Framework
    Hop 2: @rate_limit decorator validates request count (Layer 1)
    Hop 3: @require_role decorator checks ADMIN role (Layer 2)
    Hop 4: @require_authentication decorator validates user (Layer 3)
    Hop 5: @csrf_protect decorator validates CSRF token (Layer 4)
    Hop 6: Function body executes → validate_email(email)
    Hop 7: Validation creates NEW variable: validated_email
    Hop 8: BUG: Code uses ORIGINAL email parameter → record_attempt(email, ...)
    Hop 9: SQLAlchemy INSERT with UNVALIDATED email → Database (VULNERABLE!)
    
    Expected Classification: must_fix
    Expected Rationale: "CRITICAL: Validation bypass detected (wrong variable bug). The function
                         calls validate_email() which creates a new sanitized variable, but the
                         code uses the original 'email' parameter when creating LoginAttempt.
                         The validation is performed but its result is unused. Despite 4 security
                         layers (rate limiting, role check, authentication, CSRF), the unsanitized
                         input flows directly to the database INSERT. This is a true vulnerability
                         that must be fixed."
    Expected Keywords: "wrong variable", "validation bypass", "unused validation result"
    
    COMPARISON WITH JAVA TEST CASE 4:
    - Java: String validatedEmail = validator.validateEmail(email); service.record(email);
    - Python: validated_email = validate_email(email); LoginAttempt(email=email)
    - Both perform validation but use the original unvalidated variable
    - Both should be classified as must_fix (validation bypass)
    
    CRITICAL INSIGHT FOR LLM:
    This test case demonstrates that defense-in-depth (4 security layers) does NOT
    mitigate a wrong variable bug. The LLM must:
    1. Track data flow from validation function to sink
    2. Detect that validated_email is created but not used
    3. Detect that original email parameter flows to database
    4. Classify as must_fix despite presence of security layers
    """
    
    # Step 1: Validation creates NEW variable (correct)
    validated_email = validate_email(email)
    
    # Step 2: BUG - Uses ORIGINAL email instead of validated_email
    login_attempt = LoginAttempt(
        email=email,  # WRONG! Should be: validated_email
        action=action,
        ip_address=kwargs.get('request', {}).get('ip_address', 'unknown')
    )
    
    db_session.add(login_attempt)
    db_session.commit()
    
    return {"status": "recorded", "email": email}


def record_login_attempt_safe(email: str, action: str, db_session: Session, **kwargs):
    """
    SAFE VERSION: Uses validated email (for comparison)
    """
    
    # Step 1: Validation creates NEW variable
    validated_email = validate_email(email)
    
    # Step 2: CORRECT - Uses validated_email
    login_attempt = LoginAttempt(
        email=validated_email,  # CORRECT!
        action=action,
        ip_address=kwargs.get('request', {}).get('ip_address', 'unknown')
    )
    
    db_session.add(login_attempt)
    db_session.commit()
    
    return {"status": "recorded", "email": validated_email}


# ============================================================================
# Additional Test: Variable Shadowing Bug
# ============================================================================

def process_user_input_shadowing_bug(username: str, db_session: Session):
    """
    Another variant of wrong variable bug: variable shadowing
    
    The validation creates a variable with a different name in a nested scope,
    but the outer scope still uses the original unsanitized variable.
    """
    
    # Outer scope: unsanitized username
    if len(username) > 0:
        # Inner scope: creates validated version
        validated_username = username.strip().lower()
        
        # Some logic that uses validated version
        if len(validated_username) < 3:
            raise ValueError("Username too short")
    
    # BUG: Uses outer scope 'username' instead of 'validated_username'
    # 'validated_username' is not in scope here!
    user = User(username=username)  # WRONG!
    
    db_session.add(user)
    db_session.commit()
    
    return user


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    # Setup database
    engine = create_engine('sqlite:///banking.db')
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    
    # Simulated session and request
    session = {
        'user_id': 1,
        'role': 'ADMIN',
        'csrf_token': 'abc123',
        'request_count': 10
    }
    
    request = {
        'csrf_token': 'abc123',
        'ip_address': '192.168.1.1'
    }
    
    # VULNERABLE: Wrong variable bug
    try:
        result = record_login_attempt_vulnerable(
            email="malicious' OR '1'='1",
            action="login",
            db_session=db,
            session=session,
            request=request
        )
        print("Vulnerable function executed:", result)
    except Exception as e:
        print("Error:", e)
    
    # SAFE: Uses validated variable
    try:
        result = record_login_attempt_safe(
            email="user@example.com",
            action="login",
            db_session=db,
            session=session,
            request=request
        )
        print("Safe function executed:", result)
    except Exception as e:
        print("Error:", e)
