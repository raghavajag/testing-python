from django.db import models

"""
Django models for TEST CASES 1 & 5
"""

class User(models.Model):
    """User model with Django ORM"""
    email = models.EmailField(unique=True, max_length=255)
    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=255)  # Hashed
    role = models.CharField(max_length=50, default='USER')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'users'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['username']),
        ]


class Account(models.Model):
    """Account model with foreign key to User"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='accounts')
    account_number = models.CharField(max_length=20, unique=True)
    balance = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    frozen = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'accounts'


class Transaction(models.Model):
    """Transaction model for TEST CASE 5"""
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='transactions')
    transaction_type = models.CharField(max_length=50)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'transactions'
