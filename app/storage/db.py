"""
MySQL users table + salted hashing (no chat storage).

Implements:
- Secure DB connect using .env
- Salted SHA-256 password hashing
- Insert (register) user
- Fetch user for login
- Constant-time comparison
- --init command to create table
"""

import os
import hashlib
import hmac
import pymysql
from dotenv import load_dotenv

load_dotenv()  # load .env variables

# Read DB config from .env file
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_USER", "scuser")
DB_PASS = os.getenv("DB_PASS", "scpass")
DB_NAME = os.getenv("DB_NAME", "securechat")


# ----------------------- DB CONNECTION -----------------------

def get_conn():
    """Return a MySQL connection using pymysql."""
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        autocommit=True
    )


# ----------------------- INITIALIZE TABLE -----------------------

def init_db():
    """Create users table (salted passwords)."""
    sql = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255),
        username VARCHAR(255) UNIQUE,
        salt VARBINARY(16),
        pwd_hash CHAR(64)
    );
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
        print("[OK] users table created / already exists.")
    finally:
        conn.close()


# ----------------------- PASSWORD HASHING -----------------------

def hash_password(password: str, salt: bytes) -> str:
    """
    Salted SHA-256 hash: hex(SHA256(salt || password)).
    - salt: bytes (16 bytes)
    - password: string
    """
    h = hashlib.sha256()
    h.update(salt + password.encode())
    return h.hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    """Prevent timing attacks."""
    return hmac.compare_digest(a, b)


# ----------------------- USER OPERATIONS -----------------------

def create_user(email: str, username: str, password: str) -> bool:
    """Register a new user with random salt + hashed password."""
    saline = os.urandom(16)
    pwd_hash = hash_password(password, saline)

    sql = """
    INSERT INTO users(email, username, salt, pwd_hash)
    VALUES (%s, %s, %s, %s)
    """

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (email, username, saline, pwd_hash))
        return True
    except pymysql.err.IntegrityError:
        # Username already exists
        return False
    finally:
        conn.close()


def fetch_user(username: str):
    """Fetch user salt + hash for login verification."""
    sql = """
    SELECT email, username, salt, pwd_hash
    FROM users
    WHERE username = %s
    LIMIT 1
    """

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (username,))
            row = cur.fetchone()
            return row  # tuple: (email, username, salt, pwd_hash)
    finally:
        conn.close()


def verify_user(username: str, password: str) -> bool:
    """Login: compute salted hash and compare with stored hash."""
    row = fetch_user(username)
    if not row:
        return False  # user does not exist

    email, usr, salt, stored_hash = row
    attempted_hash = hash_password(password, salt)

    return constant_time_compare(attempted_hash, stored_hash)


# ----------------------- CLI SUPPORT -----------------------

if __name__ == "__main__":
    import sys

    if "--init" in sys.argv:
        init_db()
    else:
        print("Usage:")
        print("python -m app.storage.db --init")
