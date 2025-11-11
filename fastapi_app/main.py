from fastapi import FastAPI, HTTPException, Depends, Query
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
import re

"""
FastAPI application for TEST CASE 2: Strict Validation with Pydantic
"""

app = FastAPI(title="Banking API - FP Test")

# ============================================================================
# Pydantic Models (Strict Validation)
# ============================================================================

class UserQueryByUsername(BaseModel):
    """
    TEST CASE 2 - SAFE: Pydantic strict validation
    
    Pydantic enforces strict field validation at the model level:
    - username: 3-20 characters, alphanumeric + underscore only
    - This validation happens BEFORE the handler even executes
    - SQL injection is impossible due to character restrictions
    """
    username: str = Field(
        ...,
        min_length=3,
        max_length=20,
        regex=r'^[a-zA-Z0-9_]+$',
        description="Username (alphanumeric and underscore only)"
    )
    
    @validator('username')
    def validate_username_strict(cls, v):
        """Additional validation layer"""
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', v):
            raise ValueError('Username must be 3-20 alphanumeric characters or underscore')
        return v


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    username: str
    role: str


# ============================================================================
# TEST CASE 2: Strict Validation with Pydantic (True False Positive)
# ============================================================================

@app.get("/api/users/by-username")
async def get_user_by_username(
    username: str = Query(
        ...,
        min_length=3,
        max_length=20,
        regex=r'^[a-zA-Z0-9_]+$',
        description="Username to search for"
    )
):
    """
    TEST CASE 2 - SAFE: Pydantic query parameter validation
    
    ATTACK PATH (5 hops):
    Hop 1: HTTP Request → FastAPI endpoint
    Hop 2: FastAPI/Pydantic validates query parameter against regex ^[a-zA-Z0-9_]{3,20}$
    Hop 3: If validation fails, returns 422 (Unprocessable Entity) - request never reaches handler
    Hop 4: If validation passes, get_user_by_username(validated_username)
    Hop 5: Database query with guaranteed-safe input
    
    Expected Classification: false_positive_sanitized (Subcategory 2B - Validation-Based)
    Expected Rationale: "The username parameter is validated by FastAPI/Pydantic with strict
                         constraints: regex='^[a-zA-Z0-9_]+$' ensures only alphanumeric characters
                         and underscores, min_length=3, max_length=20. This validation is enforced
                         at the framework level BEFORE the handler executes. All SQL metacharacters
                         (quotes, semicolons, comments) are blocked. The regex is anchored (^ and $)
                         preventing bypass. This is Subcategory 2B (Validation-Based Sanitization)."
    Expected Keywords: "Pydantic", "Query validation", "regex constraint", "alphanumeric only", "Subcategory 2B"
    
    COMPARISON WITH JAVA TEST CASE 2:
    - Java: Pattern.matches("^[a-zA-Z0-9_]{3,20}$", username)
    - Python: Query(..., regex=r'^[a-zA-Z0-9_]+$', min_length=3, max_length=20)
    - Both use strict regex validation with anchors
    - Both block all SQL metacharacters
    - Both should be classified as false_positive_sanitized (Subcategory 2B)
    """
    # Simulated database query (username is guaranteed safe by Pydantic)
    # In real app, this would call SQLAlchemy or Django ORM
    fake_user = {
        "id": 1,
        "email": f"{username}@example.com",
        "username": username,
        "role": "USER"
    }
    
    return fake_user


@app.post("/api/users/search")
async def search_users(query: UserQueryByUsername):
    """
    TEST CASE 2 - SAFE: Pydantic model-based validation
    
    ATTACK PATH (6 hops):
    Hop 1: HTTP POST Request → FastAPI endpoint
    Hop 2: FastAPI deserializes JSON body
    Hop 3: Pydantic validates against UserQueryByUsername schema
    Hop 4: Field-level validation (regex, length) runs
    Hop 5: Custom @validator runs additional checks
    Hop 6: If all pass, search_users(validated_query)
    Hop 7: Database query with guaranteed-safe input
    
    Multiple validation layers:
    - Field constraint: regex=r'^[a-zA-Z0-9_]+$'
    - Length constraints: min_length=3, max_length=20
    - Custom validator: validate_username_strict
    """
    # Simulated search (query.username is validated by Pydantic)
    results = [
        {
            "id": 1,
            "email": f"{query.username}@example.com",
            "username": query.username,
            "role": "USER"
        }
    ]
    
    return {"users": results}


# ============================================================================
# Email Validation Example (Additional Pydantic Features)
# ============================================================================

class EmailQuery(BaseModel):
    """Pydantic's EmailStr provides built-in email validation"""
    email: EmailStr = Field(..., description="Valid email address")


@app.get("/api/users/by-email")
async def get_user_by_email(email: EmailStr = Query(...)):
    """
    SAFE: EmailStr validation ensures valid email format
    
    Pydantic's EmailStr type:
    - Validates email format according to RFC 5322
    - Blocks many SQL injection payloads (no spaces, proper structure)
    - Combined with ORM, provides defense-in-depth
    """
    # Simulated query
    return {
        "id": 1,
        "email": email,
        "username": email.split('@')[0],
        "role": "USER"
    }


# ============================================================================
# Additional Pydantic Patterns
# ============================================================================

class AccountQuery(BaseModel):
    """Demonstrates multiple Pydantic validation features"""
    
    account_number: str = Field(
        ...,
        regex=r'^\d{10,12}$',
        description="Account number (10-12 digits)"
    )
    
    amount: float = Field(
        ...,
        gt=0,
        le=1000000,
        description="Transaction amount (positive, max 1M)"
    )
    
    @validator('account_number')
    def validate_account_number(cls, v):
        """Custom validation logic"""
        if not v.isdigit():
            raise ValueError('Account number must be numeric')
        return v


@app.post("/api/transactions/create")
async def create_transaction(tx: AccountQuery):
    """
    SAFE: Multiple Pydantic validations
    - account_number: regex + custom validator
    - amount: range validation (gt=0, le=1000000)
    """
    return {
        "status": "created",
        "account": tx.account_number,
        "amount": tx.amount
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
