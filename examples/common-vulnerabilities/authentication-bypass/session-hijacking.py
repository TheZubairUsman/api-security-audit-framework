#!/usr/bin/env python3
"""
Session Hijacking and Management Vulnerabilities

This file demonstrates common session management vulnerabilities and secure implementations.
Use vulnerable examples for security testing and secure examples in production.
"""

import os
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, make_response
from functools import wraps
import redis
import jwt

app = Flask(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

# Vulnerable configuration
app.secret_key = 'weak_secret_key'  # VULNERABLE: Weak secret key

# Secure configuration (commented out for demo)
# app.secret_key = secrets.token_hex(32)  # SECURE: Strong random secret

# Redis for secure session storage (optional)
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_available = True
except:
    redis_available = False

# In-memory storage for demo (use database in production)
sessions = {}
users = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user': {'password': 'user123', 'role': 'user'},
    'guest': {'password': 'guest123', 'role': 'guest'}
}

# ============================================================================
# VULNERABLE EXAMPLE 1: Predictable Session IDs
# ============================================================================

session_counter = 1000

@app.route('/api/vulnerable/login-predictable', methods=['POST'])
def vulnerable_login_predictable():
    """
    VULNERABLE: Uses predictable session IDs
    
    Attack: Increment session ID to access other users' sessions
    """
    global session_counter
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username in users and users[username]['password'] == password:
        # VULNERABLE: Predictable session ID
        session_counter += 1
        session_id = str(session_counter)
        
        sessions[session_id] = {
            'username': username,
            'role': users[username]['role'],
            'created_at': time.time()
        }
        
        response = make_response(jsonify({
            'message': 'Login successful',
            'session_id': session_id
        }))
        
        # VULNERABLE: Session ID in response body
        return response
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/vulnerable/profile-predictable')
def vulnerable_profile_predictable():
    """
    VULNERABLE: Uses predictable session validation
    """
    session_id = request.headers.get('X-Session-ID')
    
    if not session_id:
        return jsonify({'error': 'No session ID provided'}), 401
    
    if session_id in sessions:
        user_session = sessions[session_id]
        return jsonify({
            'username': user_session['username'],
            'role': user_session['role'],
            'session_id': session_id  # VULNERABLE: Exposes session ID
        })
    
    return jsonify({'error': 'Invalid session'}), 401

# ============================================================================
# VULNERABLE EXAMPLE 2: Session Fixation
# ============================================================================

@app.route('/api/vulnerable/login-fixation', methods=['POST'])
def vulnerable_login_fixation():
    """
    VULNERABLE: Session fixation vulnerability
    
    Attack: Provide session ID before authentication, then use it after
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # VULNERABLE: Uses existing session ID if provided
    session_id = request.headers.get('X-Session-ID')
    
    if username in users and users[username]['password'] == password:
        if not session_id:
            session_id = hashlib.md5(f"{username}{time.time()}".encode()).hexdigest()
        
        # VULNERABLE: Doesn't regenerate session ID after authentication
        sessions[session_id] = {
            'username': username,
            'role': users[username]['role'],
            'created_at': time.time()
        }
        
        return jsonify({
            'message': 'Login successful',
            'session_id': session_id
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

# ============================================================================
# VULNERABLE EXAMPLE 3: No Session Expiration
# ============================================================================

@app.route('/api/vulnerable/login-no-expiry', methods=['POST'])
def vulnerable_login_no_expiry():
    """
    VULNERABLE: Sessions never expire
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username in users and users[username]['password'] == password:
        session_id = secrets.token_urlsafe(32)
        
        # VULNERABLE: No expiration time set
        sessions[session_id] = {
            'username': username,
            'role': users[username]['role'],
            'created_at': time.time()
            # Missing: 'expires_at'
        }
        
        response = make_response(jsonify({'message': 'Login successful'}))
        # VULNERABLE: Cookie without expiration
        response.set_cookie('session_id', session_id, httponly=True)
        
        return response
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/vulnerable/profile-no-expiry')
def vulnerable_profile_no_expiry():
    """
    VULNERABLE: No session expiration check
    """
    session_id = request.cookies.get('session_id')
    
    if not session_id:
        return jsonify({'error': 'No session cookie'}), 401
    
    if session_id in sessions:
        user_session = sessions[session_id]
        # VULNERABLE: No expiration check
        return jsonify({
            'username': user_session['username'],
            'role': user_session['role'],
            'login_time': user_session['created_at']
        })
    
    return jsonify({'error': 'Invalid session'}), 401

# ============================================================================
# VULNERABLE EXAMPLE 4: Insecure Cookie Settings
# ============================================================================

@app.route('/api/vulnerable/login-insecure-cookie', methods=['POST'])
def vulnerable_login_insecure_cookie():
    """
    VULNERABLE: Insecure cookie settings
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username in users and users[username]['password'] == password:
        session_id = secrets.token_urlsafe(32)
        
        sessions[session_id] = {
            'username': username,
            'role': users[username]['role'],
            'created_at': time.time()
        }
        
        response = make_response(jsonify({'message': 'Login successful'}))
        
        # VULNERABLE: Insecure cookie settings
        response.set_cookie(
            'session_id', 
            session_id,
            # Missing: httponly=True, secure=True, samesite='Strict'
        )
        
        return response
    
    return jsonify({'error': 'Invalid credentials'}), 401

# ============================================================================
# VULNERABLE EXAMPLE 5: Session Data in JWT
# ============================================================================

@app.route('/api/vulnerable/login-jwt-session', methods=['POST'])
def vulnerable_login_jwt_session():
    """
    VULNERABLE: Storing sensitive session data in JWT
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username in users and users[username]['password'] == password:
        # VULNERABLE: Sensitive data in JWT payload
        token = jwt.encode({
            'username': username,
            'role': users[username]['role'],
            'password_hash': hashlib.sha256(password.encode()).hexdigest(),  # VULNERABLE
            'session_secret': secrets.token_hex(16),  # VULNERABLE
            'iat': time.time()
        }, app.secret_key, algorithm='HS256')
        
        return jsonify({
            'message': 'Login successful',
            'token': token
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

# ============================================================================
# SECURE EXAMPLE 1: Proper Session Management
# ============================================================================

def generate_secure_session_id():
    """Generate cryptographically secure session ID"""
    return secrets.token_urlsafe(32)

def is_session_expired(session_data, max_age=3600):
    """Check if session has expired (default 1 hour)"""
    if 'created_at' not in session_data:
        return True
    
    return time.time() - session_data['created_at'] > max_age

@app.route('/api/secure/login', methods=['POST'])
def secure_login():
    """
    SECURE: Proper session management with regeneration
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username in users and users[username]['password'] == password:
        # SECURE: Always generate new session ID after authentication
        old_session_id = request.cookies.get('session_id')
        if old_session_id and old_session_id in sessions:
            # Invalidate old session
            del sessions[old_session_id]
        
        session_id = generate_secure_session_id()
        
        # SECURE: Include expiration time
        sessions[session_id] = {
            'username': username,
            'role': users[username]['role'],
            'created_at': time.time(),
            'expires_at': time.time() + 3600,  # 1 hour
            'ip_address': request.remote_addr,  # For additional security
            'user_agent': request.headers.get('User-Agent', '')
        }
        
        response = make_response(jsonify({'message': 'Login successful'}))
        
        # SECURE: Secure cookie settings
        response.set_cookie(
            'session_id',
            session_id,
            max_age=3600,  # 1 hour
            httponly=True,  # Prevent XSS
            secure=True,    # HTTPS only (set to False for HTTP testing)
            samesite='Strict'  # CSRF protection
        )
        
        return response
    
    return jsonify({'error': 'Invalid credentials'}), 401

def require_valid_session(f):
    """Decorator for session validation"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = request.cookies.get('session_id')
        
        if not session_id:
            return jsonify({'error': 'No session cookie'}), 401
        
        if session_id not in sessions:
            return jsonify({'error': 'Invalid session'}), 401
        
        user_session = sessions[session_id]
        
        # SECURE: Check expiration
        if is_session_expired(user_session):
            del sessions[session_id]
            return jsonify({'error': 'Session expired'}), 401
        
        # SECURE: Additional security checks
        if user_session.get('ip_address') != request.remote_addr:
            del sessions[session_id]
            return jsonify({'error': 'Session security violation'}), 401
        
        # Add session data to request context
        request.user_session = user_session
        
        return f(*args, **kwargs)
    
    return decorated_function

@app.route('/api/secure/profile')
@require_valid_session
def secure_profile():
    """
    SECURE: Protected endpoint with proper session validation
    """
    return jsonify({
        'username': request.user_session['username'],
        'role': request.user_session['role'],
        'session_age': time.time() - request.user_session['created_at']
    })

@app.route('/api/secure/logout', methods=['POST'])
@require_valid_session
def secure_logout():
    """
    SECURE: Proper session termination
    """
    session_id = request.cookies.get('session_id')
    
    if session_id and session_id in sessions:
        del sessions[session_id]
    
    response = make_response(jsonify({'message': 'Logout successful'}))
    response.set_cookie('session_id', '', expires=0)  # Clear cookie
    
    return response

# ============================================================================
# SECURE EXAMPLE 2: Redis-based Session Storage
# ============================================================================

@app.route('/api/secure/login-redis', methods=['POST'])
def secure_login_redis():
    """
    SECURE: Redis-based session storage for scalability
    """
    if not redis_available:
        return jsonify({'error': 'Redis not available'}), 500
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username in users and users[username]['password'] == password:
        session_id = generate_secure_session_id()
        
        session_data = {
            'username': username,
            'role': users[username]['role'],
            'created_at': str(time.time()),
            'ip_address': request.remote_addr
        }
        
        # SECURE: Store in Redis with expiration
        redis_client.hmset(f"session:{session_id}", session_data)
        redis_client.expire(f"session:{session_id}", 3600)  # 1 hour TTL
        
        response = make_response(jsonify({'message': 'Login successful'}))
        response.set_cookie(
            'session_id',
            session_id,
            max_age=3600,
            httponly=True,
            secure=True,
            samesite='Strict'
        )
        
        return response
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/secure/profile-redis')
def secure_profile_redis():
    """
    SECURE: Redis-based session validation
    """
    if not redis_available:
        return jsonify({'error': 'Redis not available'}), 500
    
    session_id = request.cookies.get('session_id')
    
    if not session_id:
        return jsonify({'error': 'No session cookie'}), 401
    
    session_data = redis_client.hgetall(f"session:{session_id}")
    
    if not session_data:
        return jsonify({'error': 'Invalid or expired session'}), 401
    
    # Additional security check
    if session_data.get('ip_address') != request.remote_addr:
        redis_client.delete(f"session:{session_id}")
        return jsonify({'error': 'Session security violation'}), 401
    
    return jsonify({
        'username': session_data['username'],
        'role': session_data['role'],
        'session_age': time.time() - float(session_data['created_at'])
    })

# ============================================================================
# SECURE EXAMPLE 3: Session Token Rotation
# ============================================================================

@app.route('/api/secure/refresh-session', methods=['POST'])
@require_valid_session
def refresh_session():
    """
    SECURE: Session token rotation for enhanced security
    """
    old_session_id = request.cookies.get('session_id')
    old_session = sessions[old_session_id]
    
    # Generate new session ID
    new_session_id = generate_secure_session_id()
    
    # Copy session data with updated timestamp
    sessions[new_session_id] = {
        **old_session,
        'created_at': time.time(),
        'expires_at': time.time() + 3600,
        'rotated_from': old_session_id
    }
    
    # Remove old session
    del sessions[old_session_id]
    
    response = make_response(jsonify({
        'message': 'Session refreshed',
        'username': old_session['username']
    }))
    
    response.set_cookie(
        'session_id',
        new_session_id,
        max_age=3600,
        httponly=True,
        secure=True,
        samesite='Strict'
    )
    
    return response

# ============================================================================
# UTILITY ENDPOINTS
# ============================================================================

@app.route('/api/test/session-info')
def session_info():
    """Debug endpoint to show session information"""
    session_id = request.cookies.get('session_id')
    
    if not session_id:
        return jsonify({'error': 'No session cookie'})
    
    if session_id in sessions:
        session_data = sessions[session_id].copy()
        # Don't expose sensitive data
        session_data.pop('password_hash', None)
        return jsonify({
            'session_id': session_id,
            'session_data': session_data,
            'is_expired': is_session_expired(sessions[session_id])
        })
    
    return jsonify({'error': 'Session not found'})

@app.route('/api/test/active-sessions')
def active_sessions():
    """Debug endpoint to show all active sessions"""
    active = []
    current_time = time.time()
    
    for sid, data in sessions.items():
        if not is_session_expired(data):
            active.append({
                'session_id': sid[:8] + '...',  # Truncated for security
                'username': data['username'],
                'role': data['role'],
                'age': current_time - data['created_at']
            })
    
    return jsonify({
        'active_sessions': len(active),
        'sessions': active
    })

# ============================================================================
# SERVER STARTUP
# ============================================================================

if __name__ == '__main__':
    print("Session Security Demo Server")
    print("\nVulnerable Endpoints (for testing):")
    print("- POST /api/vulnerable/login-predictable")
    print("- GET /api/vulnerable/profile-predictable")
    print("- POST /api/vulnerable/login-fixation")
    print("- POST /api/vulnerable/login-no-expiry")
    print("- GET /api/vulnerable/profile-no-expiry")
    print("- POST /api/vulnerable/login-insecure-cookie")
    print("- POST /api/vulnerable/login-jwt-session")
    print("\nSecure Endpoints (production patterns):")
    print("- POST /api/secure/login")
    print("- GET /api/secure/profile")
    print("- POST /api/secure/logout")
    print("- POST /api/secure/login-redis")
    print("- GET /api/secure/profile-redis")
    print("- POST /api/secure/refresh-session")
    print("\nUtility Endpoints:")
    print("- GET /api/test/session-info")
    print("- GET /api/test/active-sessions")
    print("\nTest Credentials:")
    print("- admin:admin123 (admin role)")
    print("- user:user123 (user role)")
    print("- guest:guest123 (guest role)")
    print("\nWARNING: This application contains intentional session vulnerabilities!")
    print("Use only for security testing and educational purposes.")
    
    app.run(debug=True, port=5001)
