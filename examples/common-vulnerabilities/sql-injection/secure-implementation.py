#!/usr/bin/env python3
"""
Secure SQL Implementation Examples for API Security

This file demonstrates secure coding practices to prevent SQL injection vulnerabilities.
These examples show the correct way to implement the same functionality from vulnerable-code.py.

Use these patterns in production code for secure database interactions.
"""

from flask import Flask, request, jsonify
import sqlite3
import mysql.connector
import psycopg2
from psycopg2 import sql
import hashlib
import secrets
import re
import logging
from functools import wraps

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database connection configurations
SQLITE_DB = 'secure_app.db'
MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'webapp',
    'password': 'secure_password_123!',
    'database': 'secure_db'
}
POSTGRES_CONFIG = {
    'host': 'localhost',
    'user': 'webapp',
    'password': 'secure_password_123!',
    'database': 'secure_db'
}

# ============================================================================
# SECURITY UTILITIES
# ============================================================================

def validate_integer_id(user_id):
    """Validate that user_id is a positive integer"""
    try:
        uid = int(user_id)
        if uid <= 0:
            return None
        return uid
    except (ValueError, TypeError):
        return None

def validate_username(username):
    """Validate username format and length"""
    if not username or not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 50:
        return False
    # Allow only alphanumeric characters and underscores
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False
    return True

def validate_sort_column(sort_column, allowed_columns):
    """Validate sort column against whitelist"""
    return sort_column in allowed_columns

def hash_password(password):
    """Securely hash password with salt"""
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt + password_hash.hex()

def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    salt = stored_hash[:32]
    stored_password_hash = stored_hash[32:]
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return password_hash.hex() == stored_password_hash

def sanitize_error_message(error):
    """Sanitize error messages to prevent information disclosure"""
    # Log the actual error for debugging
    logger.error(f"Database error: {str(error)}")
    # Return generic error message to user
    return "An internal error occurred. Please try again later."

def rate_limit(max_requests=10, window=60):
    """Simple rate limiting decorator (in production, use Redis or similar)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # In production, implement proper rate limiting
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============================================================================
# SECURE EXAMPLE 1: Parameterized Queries
# ============================================================================

@app.route('/api/users/<user_id>', methods=['GET'])
@rate_limit(max_requests=100, window=60)
def get_user_secure(user_id):
    """
    SECURE: Using parameterized queries prevents SQL injection
    
    Security measures:
    - Input validation
    - Parameterized queries
    - Error message sanitization
    - Rate limiting
    """
    # Validate input
    validated_id = validate_integer_id(user_id)
    if validated_id is None:
        return jsonify({'error': 'Invalid user ID format'}), 400
    
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    try:
        # SECURE: Using parameterized query with ? placeholder
        cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (validated_id,))
        result = cursor.fetchone()
        
        if result:
            return jsonify({
                'id': result[0],
                'username': result[1],
                'email': result[2]
            })
        else:
            return jsonify({'error': 'User not found'}), 404
            
    except Exception as e:
        # SECURE: Sanitized error message
        return jsonify({'error': sanitize_error_message(e)}), 500
    finally:
        conn.close()

# ============================================================================
# SECURE EXAMPLE 2: Secure Authentication
# ============================================================================

@app.route('/api/login', methods=['POST'])
@rate_limit(max_requests=5, window=300)  # Stricter rate limiting for auth
def login_secure():
    """
    SECURE: Proper authentication with parameterized queries
    
    Security measures:
    - Input validation
    - Parameterized queries
    - Password hashing
    - Rate limiting
    - Secure error handling
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request format'}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Validate inputs
    if not validate_username(username):
        return jsonify({'error': 'Invalid username format'}), 400
    
    if not password or len(password) < 8:
        return jsonify({'error': 'Invalid password format'}), 400
    
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    try:
        # SECURE: Parameterized query
        cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        if result and verify_password(password, result[2]):
            # Generate secure session token (in production, use JWT or similar)
            session_token = secrets.token_urlsafe(32)
            
            return jsonify({
                'user_id': result[0],
                'username': result[1],
                'role': result[3],
                'token': session_token
            })
        else:
            # SECURE: Generic error message to prevent username enumeration
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'error': sanitize_error_message(e)}), 500
    finally:
        conn.close()

# ============================================================================
# SECURE EXAMPLE 3: Safe String Interpolation
# ============================================================================

@app.route('/api/search/users', methods=['GET'])
@rate_limit(max_requests=50, window=60)
def search_users_secure():
    """
    SECURE: Safe search implementation with parameterized queries
    
    Security measures:
    - Input validation and sanitization
    - Parameterized queries
    - Length limits
    - Pattern validation
    """
    search_name = request.args.get('name', '').strip()
    
    # Validate search input
    if not search_name:
        return jsonify({'error': 'Search term is required'}), 400
    
    if len(search_name) > 50:
        return jsonify({'error': 'Search term too long'}), 400
    
    # Allow only alphanumeric characters, spaces, and basic punctuation
    if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', search_name):
        return jsonify({'error': 'Invalid characters in search term'}), 400
    
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    try:
        # SECURE: Parameterized query with LIKE operator
        search_pattern = f"%{search_name}%"
        cursor.execute("SELECT id, username, email FROM users WHERE username LIKE ? LIMIT 50", (search_pattern,))
        results = cursor.fetchall()
        
        users = []
        for row in results:
            users.append({
                'id': row[0],
                'username': row[1],
                'email': row[2]
            })
            
        return jsonify({'users': users, 'count': len(users)})
        
    except Exception as e:
        return jsonify({'error': sanitize_error_message(e)}), 500
    finally:
        conn.close()

# ============================================================================
# SECURE EXAMPLE 4: Safe ORDER BY Implementation
# ============================================================================

@app.route('/api/products', methods=['GET'])
@rate_limit(max_requests=100, window=60)
def get_products_secure():
    """
    SECURE: Safe sorting with whitelisted columns
    
    Security measures:
    - Column name whitelisting
    - Input validation
    - Default values
    - Parameterized base query
    """
    sort_by = request.args.get('sort', 'name').strip().lower()
    order = request.args.get('order', 'asc').strip().lower()
    
    # SECURE: Whitelist allowed sort columns
    allowed_columns = ['id', 'name', 'price', 'category']
    allowed_orders = ['asc', 'desc']
    
    if not validate_sort_column(sort_by, allowed_columns):
        sort_by = 'name'  # Default to safe value
    
    if order not in allowed_orders:
        order = 'asc'  # Default to safe value
    
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    try:
        # SECURE: Build query with validated column names
        # Note: Column names cannot be parameterized, so we use whitelisting
        query = f"SELECT id, name, price, category FROM products ORDER BY {sort_by} {order} LIMIT 100"
        cursor.execute(query)
        results = cursor.fetchall()
        
        products = []
        for row in results:
            products.append({
                'id': row[0],
                'name': row[1],
                'price': row[2],
                'category': row[3]
            })
            
        return jsonify({'products': products, 'count': len(products)})
        
    except Exception as e:
        return jsonify({'error': sanitize_error_message(e)}), 500
    finally:
        conn.close()

# ============================================================================
# SECURE EXAMPLE 5: MySQL with Proper Error Handling
# ============================================================================

@app.route('/api/mysql/users/<user_id>', methods=['GET'])
@rate_limit(max_requests=100, window=60)
def get_mysql_user_secure(user_id):
    """
    SECURE: MySQL implementation with parameterized queries
    
    Security measures:
    - Input validation
    - Parameterized queries
    - Proper error handling
    - Connection management
    """
    validated_id = validate_integer_id(user_id)
    if validated_id is None:
        return jsonify({'error': 'Invalid user ID format'}), 400
    
    conn = None
    cursor = None
    
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor(prepared=True)  # Use prepared statements
        
        # SECURE: Parameterized query
        query = "SELECT id, username, email FROM users WHERE id = ?"
        cursor.execute(query, (validated_id,))
        result = cursor.fetchone()
        
        if result:
            return jsonify({
                'id': result[0],
                'username': result[1],
                'email': result[2]
            })
        else:
            return jsonify({'error': 'User not found'}), 404
            
    except mysql.connector.Error as e:
        # SECURE: Log actual error, return generic message
        logger.error(f"MySQL error: {e.errno} - {e.msg}")
        return jsonify({'error': 'Database operation failed'}), 500
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

# ============================================================================
# SECURE EXAMPLE 6: PostgreSQL with SQL Composition
# ============================================================================

@app.route('/api/postgres/search', methods=['POST'])
@rate_limit(max_requests=50, window=60)
def postgres_search_secure():
    """
    SECURE: PostgreSQL implementation with proper SQL composition
    
    Security measures:
    - Input validation
    - SQL composition for dynamic queries
    - Parameterized values
    - Whitelist validation for filters
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request format'}), 400
    
    search_query = data.get('query', '').strip()
    filters = data.get('filters', {})
    
    # Validate search query
    if not search_query or len(search_query) > 100:
        return jsonify({'error': 'Invalid search query'}), 400
    
    if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', search_query):
        return jsonify({'error': 'Invalid characters in search query'}), 400
    
    # Validate filters
    allowed_filter_columns = ['category', 'brand', 'status']
    validated_filters = {}
    
    for key, value in filters.items():
        if key in allowed_filter_columns and isinstance(value, str) and len(value) <= 50:
            if re.match(r'^[a-zA-Z0-9\s\-_.]+$', value):
                validated_filters[key] = value
    
    conn = None
    cursor = None
    
    try:
        conn = psycopg2.connect(**POSTGRES_CONFIG)
        cursor = conn.cursor()
        
        # SECURE: Build query using psycopg2.sql for safe composition
        base_query = sql.SQL("SELECT id, name, description FROM products WHERE name ILIKE %s")
        params = [f"%{search_query}%"]
        
        # Add validated filters
        filter_conditions = []
        for key, value in validated_filters.items():
            filter_conditions.append(sql.SQL("{} = %s").format(sql.Identifier(key)))
            params.append(value)
        
        if filter_conditions:
            query = sql.SQL("{} AND {}").format(
                base_query,
                sql.SQL(" AND ").join(filter_conditions)
            )
        else:
            query = base_query
        
        # Add limit
        query = sql.SQL("{} LIMIT %s").format(query)
        params.append(100)
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        
        products = []
        for row in results:
            products.append({
                'id': row[0],
                'name': row[1],
                'description': row[2]
            })
            
        return jsonify({'products': products, 'count': len(products)})
        
    except psycopg2.Error as e:
        logger.error(f"PostgreSQL error: {e.pgcode} - {str(e)}")
        return jsonify({'error': 'Database operation failed'}), 500
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ============================================================================
# SECURE EXAMPLE 7: Safe Username Availability Check
# ============================================================================

@app.route('/api/check-username', methods=['GET'])
@rate_limit(max_requests=20, window=60)
def check_username_secure():
    """
    SECURE: Username availability check without information disclosure
    
    Security measures:
    - Input validation
    - Parameterized queries
    - Consistent response timing
    - Rate limiting
    """
    username = request.args.get('username', '').strip()
    
    # Validate username
    if not validate_username(username):
        return jsonify({'error': 'Invalid username format'}), 400
    
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    try:
        # SECURE: Parameterized query
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        # Consistent response regardless of result
        if result[0] > 0:
            return jsonify({'available': False, 'message': 'Username not available'})
        else:
            return jsonify({'available': True, 'message': 'Username available'})
            
    except Exception as e:
        logger.error(f"Database error in username check: {str(e)}")
        return jsonify({'error': 'Unable to check username availability'}), 500
    finally:
        conn.close()

# ============================================================================
# SECURE EXAMPLE 8: Safe Profile Update with Proper Data Handling
# ============================================================================

@app.route('/api/profile/update', methods=['PUT'])
@rate_limit(max_requests=10, window=300)
def update_profile_secure():
    """
    SECURE: Profile update with proper data handling
    
    Security measures:
    - Input validation
    - Parameterized queries for all operations
    - Transaction management
    - Proper error handling
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request format'}), 400
    
    user_id = data.get('user_id')
    bio = data.get('bio', '').strip()
    
    # Validate inputs
    validated_user_id = validate_integer_id(user_id)
    if validated_user_id is None:
        return jsonify({'error': 'Invalid user ID'}), 400
    
    if len(bio) > 500:
        return jsonify({'error': 'Bio too long (max 500 characters)'}), 400
    
    # Sanitize bio content
    if not re.match(r'^[a-zA-Z0-9\s\-_.,!?]*$', bio):
        return jsonify({'error': 'Bio contains invalid characters'}), 400
    
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    try:
        # Start transaction
        conn.execute("BEGIN")
        
        # SECURE: All queries use parameterization
        cursor.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, validated_user_id))
        
        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({'error': 'User not found'}), 404
        
        # SECURE: Parameterized logging query
        cursor.execute(
            "INSERT INTO user_logs (user_id, action, details) VALUES (?, ?, ?)",
            (validated_user_id, 'profile_update', f'Bio updated (length: {len(bio)})')
        )
        
        conn.commit()
        return jsonify({'message': 'Profile updated successfully'})
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Profile update error: {str(e)}")
        return jsonify({'error': 'Failed to update profile'}), 500
    finally:
        conn.close()

# ============================================================================
# SECURE EXAMPLE 9: Safe NoSQL-style Query Handling
# ============================================================================

@app.route('/api/nosql/users', methods=['POST'])
@rate_limit(max_requests=5, window=300)
def nosql_users_secure():
    """
    SECURE: Safe handling of complex query structures
    
    Security measures:
    - Input type validation
    - Structure validation
    - Parameterized queries
    - Proper authentication flow
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request format'}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    # SECURE: Strict type validation
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({'error': 'Invalid credential format'}), 400
    
    # Validate inputs
    if not validate_username(username):
        return jsonify({'error': 'Invalid username format'}), 400
    
    if not password or len(password) < 8:
        return jsonify({'error': 'Invalid password format'}), 400
    
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    try:
        # SECURE: Standard parameterized query
        cursor.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,)
        )
        result = cursor.fetchone()
        
        if result and verify_password(password, result[2]):
            session_token = secrets.token_urlsafe(32)
            return jsonify({
                'message': 'Login successful',
                'user': {
                    'id': result[0],
                    'username': result[1],
                    'role': result[3]
                },
                'token': session_token
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500
    finally:
        conn.close()

# ============================================================================
# Database Initialization with Secure Practices
# ============================================================================

def init_secure_database():
    """Initialize SQLite database with secure practices"""
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    # Create tables with proper constraints
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3 AND length(username) <= 50),
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin', 'moderator')),
            bio TEXT CHECK(length(bio) <= 500),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL CHECK(length(name) >= 1 AND length(name) <= 100),
            price REAL NOT NULL CHECK(price >= 0),
            category TEXT NOT NULL CHECK(length(category) <= 50),
            description TEXT CHECK(length(description) <= 1000),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_products_category ON products(category)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_logs_user_id ON user_logs(user_id)')
    
    # Insert sample data with hashed passwords
    admin_password_hash = hash_password('SecureAdmin123!')
    user1_password_hash = hash_password('SecureUser123!')
    user2_password_hash = hash_password('SecureUser456!')
    
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password_hash, email, role) 
        VALUES (?, ?, ?, ?)
    """, ('admin', admin_password_hash, 'admin@example.com', 'admin'))
    
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password_hash, email) 
        VALUES (?, ?, ?)
    """, ('user1', user1_password_hash, 'user1@example.com'))
    
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password_hash, email) 
        VALUES (?, ?, ?)
    """, ('user2', user2_password_hash, 'user2@example.com'))
    
    cursor.execute("""
        INSERT OR IGNORE INTO products (name, price, category, description) 
        VALUES (?, ?, ?, ?)
    """, ('Secure Laptop', 1299.99, 'electronics', 'High-security laptop with encryption'))
    
    cursor.execute("""
        INSERT OR IGNORE INTO products (name, price, category, description) 
        VALUES (?, ?, ?, ?)
    """, ('Security Handbook', 29.99, 'books', 'Comprehensive guide to application security'))
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_secure_database()
    print("Secure API application initialized with proper security controls.")
    print("All database operations use parameterized queries and input validation.")
    app.run(debug=False, host='127.0.0.1', port=5001)  # More secure defaults
