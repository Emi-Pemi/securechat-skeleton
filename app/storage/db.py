#"""MySQL users table + salted hashing (no chat storage).""" 
#raise NotImplementedError("students: implement DB layer")

"""MySQL user storage with salted SHA-256 password hashing."""

import mysql.connector
from mysql.connector import Error
import os
import secrets
import hashlib
from dotenv import load_dotenv

load_dotenv()


class UserDatabase:
    """Handle MySQL database operations for user authentication."""
    
    def __init__(self):
        """Initialize database connection."""
        self.connection = None
        self.connect()
    
    def connect(self):
        """Establish MySQL connection."""
        try:
            self.connection = mysql.connector.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                user=os.getenv('DB_USER', 'scuser'),
                password=os.getenv('DB_PASSWORD', 'scpass'),
                database=os.getenv('DB_NAME', 'securechat')
            )
            if self.connection.is_connected():
                print("[+] Connected to MySQL database")
        except Error as e:
            print(f"[!] Error connecting to MySQL: {e}")
            raise
    
    def init_schema(self):
        """Create users table if it doesn't exist."""
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.connection.commit()
            print("[+] Database schema initialized")
        except Error as e:
            print(f"[!] Error creating schema: {e}")
            raise
    
    def register_user(self, email: str, username: str, salt: bytes, pwd_hash: str) -> tuple[bool, str]:
        """
        Register a new user.
        
        Args:
            email: User email
            username: Username
            salt: 16-byte random salt
            pwd_hash: Hex string of SHA-256(salt || password)
        
        Returns:
            tuple: (success, message)
        """
        try:
            cursor = self.connection.cursor()
            
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE email = %s OR username = %s", (email, username))
            if cursor.fetchone():
                return False, "User already exists"
            
            # Insert new user
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
            self.connection.commit()
            
            print(f"[+] User registered: {username} ({email})")
            return True, "Registration successful"
            
        except Error as e:
            print(f"[!] Registration error: {e}")
            return False, f"Registration failed: {str(e)}"
    
    def authenticate_user(self, email: str, pwd_hash: str) -> tuple[bool, str]:
        """
        Authenticate user by email and password hash.
        
        Args:
            email: User email
            pwd_hash: Hex string of SHA-256(salt || password)
        
        Returns:
            tuple: (success, username or error message)
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT username, pwd_hash FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            
            if not result:
                return False, "User not found"
            
            username, stored_hash = result
            
            # Constant-time comparison (important for security)
            if secrets.compare_digest(pwd_hash, stored_hash):
                print(f"[+] User authenticated: {username}")
                return True, username
            else:
                return False, "Invalid password"
                
        except Error as e:
            print(f"[!] Authentication error: {e}")
            return False, "Authentication failed"
    
    def get_user_salt(self, email: str) -> bytes | None:
        """
        Get user's salt for password hashing.
        
        Args:
            email: User email
        
        Returns:
            Salt as bytes, or None if user not found
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT salt FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            
            if result:
                return result[0]
            return None
            
        except Error as e:
            print(f"[!] Error fetching salt: {e}")
            return None
    
    def close(self):
        """Close database connection."""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("[+] Database connection closed")


def hash_password(password: str, salt: bytes) -> str:
    """
    Hash password with salt using SHA-256.
    
    Args:
        password: Plain password string
        salt: Random salt bytes
    
    Returns:
        Hex string of SHA-256(salt || password)
    """
    pwd_bytes = password.encode('utf-8')
    return hashlib.sha256(salt + pwd_bytes).hexdigest()


def generate_salt(length: int = 16) -> bytes:
    """Generate random salt."""
    return secrets.token_bytes(length)


# CLI for database initialization
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--init":
        db = UserDatabase()
        db.init_schema()
        db.close()
        print("[✓] Database initialized successfully")
    else:
        print("Usage: python -m app.storage.db --init")
