#!/usr/bin/env python3
"""
Business Logic Vulnerabilities - Rate Limiting and Resource Abuse

This file demonstrates common business logic vulnerabilities related to rate limiting,
resource abuse, and improper access controls with secure implementations.
"""

import time
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, deque
from functools import wraps
from flask import Flask, request, jsonify
import redis
import threading

app = Flask(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

# In-memory storage for demo (use database/Redis in production)
user_requests = defaultdict(list)
user_balances = {
    'user1': 1000.0,
    'user2': 500.0,
    'admin': 10000.0
}
transfer_history = []
login_attempts = defaultdict(list)

# Redis for distributed rate limiting (optional)
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_available = True
except:
    redis_available = False

# Thread lock for thread-safe operations
lock = threading.Lock()

# ============================================================================
# VULNERABLE EXAMPLE 1: No Rate Limiting
# ============================================================================

@app.route('/api/vulnerable/transfer-no-limit', methods=['POST'])
def vulnerable_transfer_no_limit():
    """
    VULNERABLE: No rate limiting on money transfers
    
    Attack: Rapidly send multiple transfer requests to drain accounts
    """
    data = request.get_json()
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    amount = float(data.get('amount', 0))
    
    if from_user not in user_balances or to_user not in user_balances:
        return jsonify({'error': 'Invalid user'}), 400
    
    if user_balances[from_user] >= amount:
        # VULNERABLE: No rate limiting, race condition possible
        user_balances[from_user] -= amount
        user_balances[to_user] += amount
        
        transfer_history.append({
            'from': from_user,
            'to': to_user,
            'amount': amount,
            'timestamp': time.time(),
            'ip': request.remote_addr
        })
        
        return jsonify({
            'message': 'Transfer successful',
            'new_balance': user_balances[from_user]
        })
    
    return jsonify({'error': 'Insufficient funds'}), 400

@app.route('/api/vulnerable/login-no-limit', methods=['POST'])
def vulnerable_login_no_limit():
    """
    VULNERABLE: No rate limiting on login attempts
    
    Attack: Brute force password attacks
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # VULNERABLE: No rate limiting on failed attempts
    if username == 'admin' and password == 'secret123':
        return jsonify({'message': 'Login successful', 'token': 'admin_token'})
    
    # Log failed attempt but don't limit
    login_attempts[username].append({
        'timestamp': time.time(),
        'ip': request.remote_addr,
        'success': False
    })
    
    return jsonify({'error': 'Invalid credentials'}), 401

# ============================================================================
# VULNERABLE EXAMPLE 2: Bypassable Rate Limiting
# ============================================================================

simple_rate_limit = defaultdict(list)

@app.route('/api/vulnerable/api-bypassable-limit', methods=['GET'])
def vulnerable_api_bypassable_limit():
    """
    VULNERABLE: Rate limiting that can be bypassed
    
    Attack: Change IP, User-Agent, or use different headers to bypass
    """
    client_ip = request.remote_addr
    current_time = time.time()
    
    # VULNERABLE: Only checks IP address
    if client_ip in simple_rate_limit:
        # Remove old requests (1 minute window)
        simple_rate_limit[client_ip] = [
            req_time for req_time in simple_rate_limit[client_ip]
            if current_time - req_time < 60
        ]
        
        # VULNERABLE: Simple limit that can be bypassed
        if len(simple_rate_limit[client_ip]) >= 10:
            return jsonify({'error': 'Rate limit exceeded'}), 429
    
    simple_rate_limit[client_ip].append(current_time)
    
    return jsonify({
        'message': 'API response',
        'data': f'Request from {client_ip}',
        'requests_count': len(simple_rate_limit[client_ip])
    })

# ============================================================================
# VULNERABLE EXAMPLE 3: Race Condition in Resource Access
# ============================================================================

@app.route('/api/vulnerable/withdraw-race', methods=['POST'])
def vulnerable_withdraw_race():
    """
    VULNERABLE: Race condition in withdrawal logic
    
    Attack: Send multiple simultaneous withdrawal requests
    """
    data = request.get_json()
    user = data.get('user')
    amount = float(data.get('amount', 0))
    
    if user not in user_balances:
        return jsonify({'error': 'Invalid user'}), 400
    
    # VULNERABLE: Race condition - check and modify not atomic
    if user_balances[user] >= amount:
        # Simulate processing delay
        time.sleep(0.1)
        
        # VULNERABLE: Balance could have changed during delay
        user_balances[user] -= amount
        
        return jsonify({
            'message': 'Withdrawal successful',
            'amount': amount,
            'new_balance': user_balances[user]
        })
    
    return jsonify({'error': 'Insufficient funds'}), 400

# ============================================================================
# VULNERABLE EXAMPLE 4: Resource Exhaustion
# ============================================================================

expensive_operations = []

@app.route('/api/vulnerable/expensive-operation', methods=['POST'])
def vulnerable_expensive_operation():
    """
    VULNERABLE: No protection against resource exhaustion
    
    Attack: Send requests that consume excessive CPU/memory
    """
    data = request.get_json()
    iterations = int(data.get('iterations', 1000))
    
    # VULNERABLE: No limit on expensive operations
    start_time = time.time()
    
    # Simulate expensive computation
    result = 0
    for i in range(iterations):
        result += hashlib.sha256(str(i).encode()).hexdigest()
    
    end_time = time.time()
    
    expensive_operations.append({
        'iterations': iterations,
        'duration': end_time - start_time,
        'timestamp': start_time,
        'ip': request.remote_addr
    })
    
    return jsonify({
        'message': 'Operation completed',
        'iterations': iterations,
        'duration': end_time - start_time,
        'result_length': len(result)
    })

# ============================================================================
# SECURE EXAMPLE 1: Proper Rate Limiting
# ============================================================================

class RateLimiter:
    def __init__(self, max_requests=10, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)
    
    def is_allowed(self, identifier):
        current_time = time.time()
        user_requests = self.requests[identifier]
        
        # Remove old requests outside the window
        while user_requests and current_time - user_requests[0] > self.window_seconds:
            user_requests.popleft()
        
        # Check if under limit
        if len(user_requests) < self.max_requests:
            user_requests.append(current_time)
            return True
        
        return False
    
    def get_reset_time(self, identifier):
        user_requests = self.requests[identifier]
        if user_requests:
            return user_requests[0] + self.window_seconds
        return time.time()

# Different rate limiters for different endpoints
transfer_limiter = RateLimiter(max_requests=5, window_seconds=300)  # 5 transfers per 5 minutes
login_limiter = RateLimiter(max_requests=5, window_seconds=900)     # 5 attempts per 15 minutes
api_limiter = RateLimiter(max_requests=100, window_seconds=60)      # 100 requests per minute

def rate_limit(limiter, identifier_func=None):
    """Decorator for rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if identifier_func:
                identifier = identifier_func()
            else:
                # Default: use IP + User-Agent + endpoint
                identifier = f"{request.remote_addr}:{request.headers.get('User-Agent', '')}:{request.endpoint}"
            
            if not limiter.is_allowed(identifier):
                reset_time = limiter.get_reset_time(identifier)
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'reset_time': reset_time,
                    'retry_after': int(reset_time - time.time())
                }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/secure/transfer', methods=['POST'])
@rate_limit(transfer_limiter, lambda: f"{request.get_json().get('from_user')}:transfer")
def secure_transfer():
    """
    SECURE: Rate limited money transfers with atomic operations
    """
    data = request.get_json()
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    amount = float(data.get('amount', 0))
    
    if from_user not in user_balances or to_user not in user_balances:
        return jsonify({'error': 'Invalid user'}), 400
    
    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400
    
    # SECURE: Atomic operation with lock
    with lock:
        if user_balances[from_user] >= amount:
            user_balances[from_user] -= amount
            user_balances[to_user] += amount
            
            transfer_history.append({
                'from': from_user,
                'to': to_user,
                'amount': amount,
                'timestamp': time.time(),
                'ip': request.remote_addr
            })
            
            return jsonify({
                'message': 'Transfer successful',
                'new_balance': user_balances[from_user]
            })
        else:
            return jsonify({'error': 'Insufficient funds'}), 400

@app.route('/api/secure/login', methods=['POST'])
@rate_limit(login_limiter, lambda: f"{request.remote_addr}:login")
def secure_login():
    """
    SECURE: Rate limited login with progressive delays
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Check for account lockout
    user_attempts = login_attempts[username]
    current_time = time.time()
    
    # Remove old attempts (15 minutes)
    user_attempts[:] = [
        attempt for attempt in user_attempts
        if current_time - attempt['timestamp'] < 900
    ]
    
    # Progressive delay based on failed attempts
    failed_attempts = len([a for a in user_attempts if not a['success']])
    if failed_attempts >= 3:
        delay = min(2 ** (failed_attempts - 3), 60)  # Exponential backoff, max 60s
        return jsonify({
            'error': 'Account temporarily locked',
            'retry_after': delay
        }), 429
    
    # Simulate authentication
    if username == 'admin' and password == 'secret123':
        login_attempts[username].append({
            'timestamp': current_time,
            'ip': request.remote_addr,
            'success': True
        })
        return jsonify({'message': 'Login successful', 'token': 'admin_token'})
    
    # Log failed attempt
    login_attempts[username].append({
        'timestamp': current_time,
        'ip': request.remote_addr,
        'success': False
    })
    
    return jsonify({'error': 'Invalid credentials'}), 401

# ============================================================================
# SECURE EXAMPLE 2: Redis-based Distributed Rate Limiting
# ============================================================================

class RedisRateLimiter:
    def __init__(self, redis_client, max_requests=10, window_seconds=60):
        self.redis = redis_client
        self.max_requests = max_requests
        self.window_seconds = window_seconds
    
    def is_allowed(self, identifier):
        if not self.redis:
            return True  # Fallback if Redis unavailable
        
        key = f"rate_limit:{identifier}"
        current_time = time.time()
        
        # Use Redis pipeline for atomic operations
        pipe = self.redis.pipeline()
        
        # Remove old entries
        pipe.zremrangebyscore(key, 0, current_time - self.window_seconds)
        
        # Count current requests
        pipe.zcard(key)
        
        # Add current request
        pipe.zadd(key, {str(current_time): current_time})
        
        # Set expiration
        pipe.expire(key, self.window_seconds)
        
        results = pipe.execute()
        request_count = results[1]
        
        return request_count < self.max_requests

@app.route('/api/secure/api-redis-limit', methods=['GET'])
def secure_api_redis_limit():
    """
    SECURE: Redis-based distributed rate limiting
    """
    if not redis_available:
        return jsonify({'error': 'Redis not available'}), 500
    
    limiter = RedisRateLimiter(redis_client, max_requests=50, window_seconds=60)
    
    # Use multiple factors for identifier
    identifier = f"{request.remote_addr}:{request.headers.get('User-Agent', '')[:50]}"
    
    if not limiter.is_allowed(identifier):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    return jsonify({
        'message': 'API response',
        'timestamp': time.time(),
        'identifier': hashlib.sha256(identifier.encode()).hexdigest()[:8]
    })

# ============================================================================
# SECURE EXAMPLE 3: Resource Protection
# ============================================================================

class ResourceLimiter:
    def __init__(self, max_concurrent=5, max_duration=30):
        self.max_concurrent = max_concurrent
        self.max_duration = max_duration
        self.active_operations = {}
        self.lock = threading.Lock()
    
    def start_operation(self, identifier):
        with self.lock:
            # Clean up expired operations
            current_time = time.time()
            expired = [
                op_id for op_id, start_time in self.active_operations.items()
                if current_time - start_time > self.max_duration
            ]
            for op_id in expired:
                del self.active_operations[op_id]
            
            # Check concurrent limit
            if len(self.active_operations) >= self.max_concurrent:
                return False
            
            # Start operation
            operation_id = f"{identifier}:{current_time}"
            self.active_operations[operation_id] = current_time
            return operation_id
    
    def end_operation(self, operation_id):
        with self.lock:
            self.active_operations.pop(operation_id, None)

resource_limiter = ResourceLimiter(max_concurrent=3, max_duration=60)

@app.route('/api/secure/expensive-operation', methods=['POST'])
@rate_limit(api_limiter)
def secure_expensive_operation():
    """
    SECURE: Protected expensive operation with resource limits
    """
    data = request.get_json()
    iterations = int(data.get('iterations', 1000))
    
    # SECURE: Limit iterations
    max_iterations = 10000
    if iterations > max_iterations:
        return jsonify({
            'error': f'Iterations limited to {max_iterations}'
        }), 400
    
    # SECURE: Check resource availability
    identifier = f"{request.remote_addr}:{time.time()}"
    operation_id = resource_limiter.start_operation(identifier)
    
    if not operation_id:
        return jsonify({
            'error': 'Server busy, too many concurrent operations'
        }), 503
    
    try:
        start_time = time.time()
        
        # Simulate expensive computation with timeout
        result = 0
        for i in range(iterations):
            # Check for timeout
            if time.time() - start_time > 30:  # 30 second timeout
                return jsonify({
                    'error': 'Operation timeout'
                }), 408
            
            result += len(hashlib.sha256(str(i).encode()).hexdigest())
        
        end_time = time.time()
        
        return jsonify({
            'message': 'Operation completed',
            'iterations': iterations,
            'duration': end_time - start_time,
            'result': result
        })
    
    finally:
        resource_limiter.end_operation(operation_id)

# ============================================================================
# SECURE EXAMPLE 4: Account Lockout Protection
# ============================================================================

class AccountProtection:
    def __init__(self):
        self.failed_attempts = defaultdict(list)
        self.locked_accounts = {}
    
    def record_failed_attempt(self, username, ip):
        current_time = time.time()
        self.failed_attempts[username].append({
            'timestamp': current_time,
            'ip': ip
        })
        
        # Clean old attempts (1 hour)
        self.failed_attempts[username] = [
            attempt for attempt in self.failed_attempts[username]
            if current_time - attempt['timestamp'] < 3600
        ]
        
        # Check for lockout conditions
        recent_attempts = [
            attempt for attempt in self.failed_attempts[username]
            if current_time - attempt['timestamp'] < 900  # 15 minutes
        ]
        
        if len(recent_attempts) >= 5:
            self.locked_accounts[username] = current_time + 1800  # Lock for 30 minutes
    
    def is_locked(self, username):
        if username in self.locked_accounts:
            if time.time() < self.locked_accounts[username]:
                return True
            else:
                del self.locked_accounts[username]
        return False
    
    def get_lockout_time(self, username):
        return self.locked_accounts.get(username, 0)

account_protection = AccountProtection()

@app.route('/api/secure/protected-login', methods=['POST'])
@rate_limit(login_limiter)
def secure_protected_login():
    """
    SECURE: Login with comprehensive account protection
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Check account lockout
    if account_protection.is_locked(username):
        lockout_time = account_protection.get_lockout_time(username)
        return jsonify({
            'error': 'Account locked due to multiple failed attempts',
            'locked_until': lockout_time,
            'retry_after': int(lockout_time - time.time())
        }), 423
    
    # Simulate authentication
    if username == 'admin' and password == 'secret123':
        return jsonify({'message': 'Login successful', 'token': 'admin_token'})
    
    # Record failed attempt
    account_protection.record_failed_attempt(username, request.remote_addr)
    
    return jsonify({'error': 'Invalid credentials'}), 401

# ============================================================================
# UTILITY ENDPOINTS
# ============================================================================

@app.route('/api/test/rate-limit-status')
def rate_limit_status():
    """Check current rate limit status"""
    identifier = f"{request.remote_addr}:{request.headers.get('User-Agent', '')}:{request.endpoint}"
    
    return jsonify({
        'identifier_hash': hashlib.sha256(identifier.encode()).hexdigest()[:8],
        'current_time': time.time(),
        'active_operations': len(resource_limiter.active_operations),
        'locked_accounts': len(account_protection.locked_accounts)
    })

@app.route('/api/test/user-balances')
def user_balances_status():
    """Check current user balances"""
    return jsonify({
        'balances': user_balances,
        'transfer_count': len(transfer_history)
    })

@app.route('/api/test/reset-data', methods=['POST'])
def reset_test_data():
    """Reset test data for clean testing"""
    global user_balances, transfer_history, login_attempts
    
    user_balances = {
        'user1': 1000.0,
        'user2': 500.0,
        'admin': 10000.0
    }
    transfer_history.clear()
    login_attempts.clear()
    account_protection.failed_attempts.clear()
    account_protection.locked_accounts.clear()
    
    return jsonify({'message': 'Test data reset successfully'})

# ============================================================================
# SERVER STARTUP
# ============================================================================

if __name__ == '__main__':
    print("Business Logic Security Demo Server")
    print("\nVulnerable Endpoints (for testing):")
    print("- POST /api/vulnerable/transfer-no-limit")
    print("- POST /api/vulnerable/login-no-limit")
    print("- GET /api/vulnerable/api-bypassable-limit")
    print("- POST /api/vulnerable/withdraw-race")
    print("- POST /api/vulnerable/expensive-operation")
    print("\nSecure Endpoints (production patterns):")
    print("- POST /api/secure/transfer")
    print("- POST /api/secure/login")
    print("- GET /api/secure/api-redis-limit")
    print("- POST /api/secure/expensive-operation")
    print("- POST /api/secure/protected-login")
    print("\nUtility Endpoints:")
    print("- GET /api/test/rate-limit-status")
    print("- GET /api/test/user-balances")
    print("- POST /api/test/reset-data")
    print("\nTest Users:")
    print("- user1: $1000 balance")
    print("- user2: $500 balance")
    print("- admin: $10000 balance")
    print("\nWARNING: This application contains intentional business logic vulnerabilities!")
    print("Use only for security testing and educational purposes.")
    
    app.run(debug=True, port=5002)
