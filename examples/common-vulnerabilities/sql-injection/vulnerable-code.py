#!/usr/bin/env python3
"""
SQL Injection Vulnerability Examples for API Security Testing

This file demonstrates common SQL injection patterns found in API endpoints.
These examples are for educational and testing purposes only.

WARNING: This code contains intentional security vulnerabilities.
Do NOT use these patterns in production code.
"""

from flask import Flask, request, jsonify
import sqlite3
import mysql.connector
import psycopg2

app = Flask(__name__)

# Database connection configurations
SQLITE_DB = 'vulnerable_app.db'
MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'webapp',
    'password': 'password123',
    'database': 'vulnerable_db'
}
POSTGRES_CONFIG = {
    'host': 'localhost',
    'user': 'webapp',
    'password': 'password123',
    'database': 'vulnerable_db'
}

# ============================================================================
# VULNERABLE EXAMPLE 1: String Concatenation SQL Injection
# ============================================================================

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user_vulnerable_concat(user_id):
    """
    VULNERABLE: Direct string concatenation allows SQL injection
    
    Attack examples:
    - /api/users/1' OR '1'='1
    - /api/users/1'; DROP TABLE users; --
    - /api/users/1' UNION SELECT username,password FROM admin_users --
    """
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = "SELECT id, username, email FROM users WHERE id = '" + user_id + "'"
    
    try:
        cursor.execute(query)
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
        # VULNERABLE: Exposing database errors reveals internal structure
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ============================================================================
# VULNERABLE EXAMPLE 2: Format String SQL Injection
# ============================================================================

@app.route('/api/login', methods=['POST'])
def login_vulnerable_format():
    """
    VULNERABLE: Python string formatting allows SQL injection
    
    Attack examples:
    POST /api/login
    {
        "username": "admin' OR '1'='1' --",
        "password": "anything"
    }
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    # VULNERABLE: String formatting with % operator
    query = "SELECT id, username, role FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        
        if result:
            return jsonify({
                'user_id': result[0],
                'username': result[1],
                'role': result[2],
                'token': 'fake_jwt_token_' + str(result[0])
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ============================================================================
# VULNERABLE EXAMPLE 3: f-string SQL Injection (Python 3.6+)
# ============================================================================

@app.route('/api/search/users', methods=['GET'])
def search_users_vulnerable_fstring():
    """
    VULNERABLE: f-string formatting allows SQL injection
    
    Attack examples:
    - /api/search/users?name=admin' UNION SELECT password FROM users WHERE username='admin' --
    - /api/search/users?name='; DELETE FROM users; --
    """
    search_name = request.args.get('name', '')
    
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    # VULNERABLE: f-string with direct variable interpolation
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{search_name}%'"
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        
        users = []
        for row in results:
            users.append({
                'id': row[0],
                'username': row[1],
                'email': row[2]
            })
            
        return jsonify({'users': users})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ============================================================================
# VULNERABLE EXAMPLE 4: ORDER BY Injection
# ============================================================================

@app.route('/api/products', methods=['GET'])
def get_products_vulnerable_orderby():
    """
    VULNERABLE: Dynamic ORDER BY clause allows SQL injection
    
    Attack examples:
    - /api/products?sort=price; DROP TABLE products; --
    - /api/products?sort=(CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin')>0 THEN price ELSE name END)
    """
    sort_by = request.args.get('sort', 'name')
    
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    # VULNERABLE: Direct insertion of sort parameter
    query = f"SELECT id, name, price FROM products ORDER BY {sort_by}"
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        
        products = []
        for row in results:
            products.append({
                'id': row[0],
                'name': row[1],
                'price': row[2]
            })
            
        return jsonify({'products': products})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ============================================================================
# VULNERABLE EXAMPLE 5: MySQL-specific Injection
# ============================================================================

@app.route('/api/mysql/users/<user_id>', methods=['GET'])
def get_mysql_user_vulnerable(user_id):
    """
    VULNERABLE: MySQL-specific SQL injection with error-based exploitation
    
    Attack examples:
    - /api/mysql/users/1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --
    - /api/mysql/users/1' UNION SELECT 1,user(),version() --
    """
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()
        
        # VULNERABLE: String concatenation in MySQL
        query = "SELECT id, username, email FROM users WHERE id = " + user_id
        
        cursor.execute(query)
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
        # VULNERABLE: Exposing MySQL-specific errors
        return jsonify({
            'error': f'MySQL Error {e.errno}: {e.msg}',
            'sqlstate': e.sqlstate
        }), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

# ============================================================================
# VULNERABLE EXAMPLE 6: PostgreSQL-specific Injection
# ============================================================================

@app.route('/api/postgres/search', methods=['POST'])
def postgres_search_vulnerable():
    """
    VULNERABLE: PostgreSQL-specific SQL injection with JSON operations
    
    Attack examples:
    POST /api/postgres/search
    {
        "query": "test'; SELECT version(); --",
        "filters": {"category": "electronics"}
    }
    """
    data = request.get_json()
    search_query = data.get('query', '')
    filters = data.get('filters', {})
    
    try:
        conn = psycopg2.connect(**POSTGRES_CONFIG)
        cursor = conn.cursor()
        
        # VULNERABLE: Direct string interpolation in PostgreSQL
        base_query = f"SELECT id, name, description FROM products WHERE name ILIKE '%{search_query}%'"
        
        # VULNERABLE: Dynamic filter construction
        if filters:
            for key, value in filters.items():
                base_query += f" AND {key} = '{value}'"
        
        cursor.execute(base_query)
        results = cursor.fetchall()
        
        products = []
        for row in results:
            products.append({
                'id': row[0],
                'name': row[1],
                'description': row[2]
            })
            
        return jsonify({'products': products})
        
    except psycopg2.Error as e:
        # VULNERABLE: Exposing PostgreSQL-specific errors
        return jsonify({
            'error': str(e),
            'pgcode': e.pgcode,
            'pgerror': e.pgerror
        }), 500
    finally:
        if conn:
            cursor.close()
            conn.close()

# ============================================================================
# VULNERABLE EXAMPLE 7: Blind SQL Injection
# ============================================================================

@app.route('/api/check-username', methods=['GET'])
def check_username_vulnerable():
    """
    VULNERABLE: Blind SQL injection through timing and boolean responses
    
    Attack examples:
    - /api/check-username?username=admin' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0 --
    - /api/check-username?username=admin' AND (SELECT SLEEP(5))>0 --
    """
    username = request.args.get('username', '')
    
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    # VULNERABLE: Boolean-based blind SQL injection
    query = f"SELECT COUNT(*) FROM users WHERE username = '{username}'"
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        
        # This response pattern enables blind SQL injection
        if result[0] > 0:
            return jsonify({'available': False, 'message': 'Username already taken'})
        else:
            return jsonify({'available': True, 'message': 'Username available'})
            
    except Exception as e:
        # Even errors can be used for blind injection
        return jsonify({'error': 'Database error occurred'}), 500
    finally:
        conn.close()

# ============================================================================
# VULNERABLE EXAMPLE 8: Second-Order SQL Injection
# ============================================================================

@app.route('/api/profile/update', methods=['PUT'])
def update_profile_vulnerable():
    """
    VULNERABLE: Second-order SQL injection through stored data
    
    This vulnerability occurs when malicious data is stored in the database
    and later used in an unsafe query.
    """
    data = request.get_json()
    user_id = data.get('user_id')
    bio = data.get('bio', '')
    
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    try:
        # First, store the potentially malicious bio (this might be safe)
        cursor.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user_id))
        
        # Later, retrieve and use the bio unsafely (VULNERABLE)
        cursor.execute("SELECT bio FROM users WHERE id = ?", (user_id,))
        stored_bio = cursor.fetchone()[0]
        
        # VULNERABLE: Using stored data in unsafe query construction
        # This could execute if bio contains: '; DROP TABLE users; --
        log_query = f"INSERT INTO user_logs (user_id, action, details) VALUES ({user_id}, 'profile_update', '{stored_bio}')"
        cursor.execute(log_query)
        
        conn.commit()
        return jsonify({'message': 'Profile updated successfully'})
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ============================================================================
# VULNERABLE EXAMPLE 9: NoSQL Injection (MongoDB-style)
# ============================================================================

@app.route('/api/nosql/users', methods=['POST'])
def nosql_users_vulnerable():
    """
    VULNERABLE: NoSQL injection in MongoDB-style queries
    
    Attack examples:
    POST /api/nosql/users
    {
        "username": {"$ne": null},
        "password": {"$ne": null}
    }
    
    This would bypass authentication by using MongoDB operators.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # VULNERABLE: Direct use of user input in NoSQL query
    # In a real MongoDB implementation, this would be dangerous
    query_dict = {
        'username': username,
        'password': password
    }
    
    # Simulating NoSQL query construction vulnerability
    if isinstance(username, dict) or isinstance(password, dict):
        # This indicates potential NoSQL injection attempt
        return jsonify({
            'message': 'Login successful',
            'user': {'id': 1, 'username': 'admin', 'role': 'administrator'},
            'warning': 'NoSQL injection vulnerability exploited'
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

# ============================================================================
# Database Initialization (for testing purposes)
# ============================================================================

def init_database():
    """Initialize SQLite database with sample data for testing"""
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            bio TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            category TEXT,
            description TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_logs (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert sample data
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                   ('admin', 'admin123', 'admin@example.com', 'administrator'))
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email) VALUES (?, ?, ?)",
                   ('user1', 'password1', 'user1@example.com'))
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email) VALUES (?, ?, ?)",
                   ('user2', 'password2', 'user2@example.com'))
    
    cursor.execute("INSERT OR IGNORE INTO products (name, price, category) VALUES (?, ?, ?)",
                   ('Laptop', 999.99, 'electronics'))
    cursor.execute("INSERT OR IGNORE INTO products (name, price, category) VALUES (?, ?, ?)",
                   ('Book', 19.99, 'books'))
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_database()
    print("WARNING: This application contains intentional SQL injection vulnerabilities!")
    print("Use only for security testing and educational purposes.")
    app.run(debug=True, host='0.0.0.0', port=5000)
