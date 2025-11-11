"""
Database Manager
================
Handles database connections and operations
"""

import sqlite3
from typing import Optional


class DatabaseManager:
    """Database connection and basic operations"""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.connection = None

    def connect(self) -> sqlite3.Connection:
        """Establish database connection"""
        if not self.connection:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
        return self.connection

    def get_cursor(self) -> sqlite3.Cursor:
        """Get database cursor"""
        if not self.connection:
            self.connect()
        return self.connection.cursor()
    
    def initialize_schema(self):
        """Initialize database schema"""
        cursor = self.get_cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT,
                email TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                user_id TEXT,
                event_type TEXT,
                timestamp INTEGER
            )
        """)
        cursor.execute("INSERT OR REPLACE INTO users VALUES ('1', 'Alice', 'alice@example.com')")
        cursor.execute("INSERT OR REPLACE INTO users VALUES ('2', 'Bob', 'bob@example.com')")
        cursor.execute("INSERT INTO events VALUES ('1', 'login', 1234567890)")
        cursor.execute("INSERT INTO events VALUES ('2', 'click', 1234567891)")
        self.connection.commit()
