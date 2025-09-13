# 🔐 Authentication Security Audit Checklist

This comprehensive checklist covers all aspects of API authentication security testing. Use this during security audits to ensure thorough coverage of authentication vulnerabilities.

---

## 📋 Pre-Audit Setup

### Environment Preparation
- [ ] **Testing Environment**: Isolated testing environment configured
- [ ] **Test Accounts**: Multiple user accounts with different permission levels created
- [ ] **Testing Tools**: Burp Suite, OWASP ZAP, Postman, custom scripts ready
- [ ] **Documentation**: API documentation and authentication flows reviewed
- [ ] **Authorization**: Written permission obtained for testing

### Authentication Mechanism Identification
- [ ] **JWT Tokens**: JSON Web Tokens implementation identified
- [ ] **API Keys**: API key authentication mechanism documented
- [ ] **OAuth/OAuth2**: OAuth implementation and flows mapped
- [ ] **Session Cookies**: Session-based authentication analyzed
- [ ] **Basic Auth**: HTTP Basic Authentication usage identified
- [ ] **Custom Auth**: Proprietary authentication schemes documented

---

## 🎫 JWT Token Security Testing

### Token Structure Analysis
```bash
# Decode JWT token header and payload
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
echo "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" | base64 -d
```

- [ ] **Algorithm Verification**: Token uses strong signing algorithm (RS256, ES256)
- [ ] **Header Analysis**: No algorithm confusion vulnerabilities (none, HS256 with RSA key)
- [ ] **Payload Inspection**: No sensitive data in JWT payload
- [ ] **Claims Validation**: All required claims present and validated
- [ ] **Signature Verification**: Server properly verifies token signature

### JWT Vulnerability Testing

#### Algorithm Confusion Attack
```bash
# Test 'none' algorithm bypass
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ." \
  https://api.example.com/admin

# Test HS256 with RSA public key
# Change algorithm from RS256 to HS256 and sign with public key
```

- [ ] **None Algorithm**: Server rejects tokens with 'none' algorithm
- [ ] **Algorithm Switching**: Server validates algorithm matches expected type
- [ ] **Key Confusion**: RSA public key cannot be used as HMAC secret
- [ ] **Weak Secrets**: HMAC secrets are cryptographically strong

#### Token Manipulation Testing
```bash
# Test token tampering detection
original_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiSm9obiBEb2UifQ.signature"
modified_payload="eyJ1c2VyIjoiQWRtaW4ifQ"  # Changed user to Admin
tampered_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${modified_payload}.signature"

curl -H "Authorization: Bearer $tampered_token" https://api.example.com/admin
```

- [ ] **Payload Tampering**: Modified tokens are rejected
- [ ] **Signature Validation**: Invalid signatures cause authentication failure
- [ ] **Timestamp Validation**: Expired tokens are rejected (exp claim)
- [ ] **Audience Validation**: Tokens for wrong audience are rejected (aud claim)
- [ ] **Issuer Validation**: Tokens from unauthorized issuers rejected (iss claim)

#### Token Lifecycle Testing
- [ ] **Token Expiration**: Tokens expire within reasonable timeframe
- [ ] **Token Renewal**: Secure token refresh mechanism implemented
- [ ] **Token Revocation**: Ability to invalidate specific tokens
- [ ] **Token Blacklisting**: Revoked tokens are properly blacklisted
- [ ] **Logout Handling**: Tokens invalidated on user logout

---

## 🔑 API Key Security Testing

### API Key Implementation Analysis
```bash
# Test API key in different locations
curl -H "X-API-Key: your-api-key" https://api.example.com/data
curl -H "Authorization: ApiKey your-api-key" https://api.example.com/data
curl -H "Authorization: Bearer your-api-key" https://api.example.com/data
curl "https://api.example.com/data?api_key=your-api-key"
```

- [ ] **Secure Transmission**: API keys transmitted over HTTPS only
- [ ] **Header Location**: API keys in headers, not URL parameters
- [ ] **Key Format**: Keys are sufficiently long and random
- [ ] **Key Scope**: Keys have appropriate permission scope
- [ ] **Key Identification**: Keys can be traced to specific applications/users

### API Key Vulnerability Testing

#### Key Enumeration and Brute Force
```bash
# Test for sequential or predictable keys
for i in {1..1000}; do
  curl -H "X-API-Key: key_$i" https://api.example.com/data -o /dev/null -s -w "%{http_code}\n"
done

# Test common/default API keys
common_keys=("admin" "test" "api_key" "12345" "default")
for key in "${common_keys[@]}"; do
  curl -H "X-API-Key: $key" https://api.example.com/data
done
```

- [ ] **Key Randomness**: API keys are cryptographically random
- [ ] **No Default Keys**: No default or predictable API keys exist
- [ ] **Brute Force Protection**: Rate limiting prevents key enumeration
- [ ] **Key Validation**: Invalid keys return consistent error messages

#### Key Management Testing
- [ ] **Key Rotation**: Regular key rotation process implemented
- [ ] **Key Revocation**: Ability to immediately revoke compromised keys
- [ ] **Key Audit**: Logging and monitoring of API key usage
- [ ] **Key Storage**: Keys stored securely (hashed, encrypted)
- [ ] **Key Distribution**: Secure key distribution to clients

---

## 🔐 OAuth/OAuth2 Security Testing

### OAuth Flow Analysis
```bash
# Authorization Code Flow Testing
# Step 1: Authorization request
curl "https://auth.example.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=CALLBACK_URL&scope=read&state=RANDOM_STATE"

# Step 2: Token exchange
curl -X POST "https://auth.example.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&redirect_uri=CALLBACK_URL"
```

- [ ] **Flow Implementation**: Appropriate OAuth flow for application type
- [ ] **HTTPS Enforcement**: All OAuth endpoints use HTTPS
- [ ] **Client Authentication**: Confidential clients properly authenticated
- [ ] **Scope Validation**: Requested scopes properly validated and enforced

### OAuth Vulnerability Testing

#### State Parameter Validation
```bash
# Test CSRF protection with state parameter
curl "https://auth.example.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=CALLBACK_URL&scope=read"
# Missing state parameter should be rejected

# Test state parameter tampering
curl "https://auth.example.com/oauth/callback?code=AUTH_CODE&state=DIFFERENT_STATE"
```

- [ ] **State Parameter**: State parameter required and validated
- [ ] **State Randomness**: State values are cryptographically random
- [ ] **State Binding**: State parameter tied to user session
- [ ] **CSRF Protection**: State parameter prevents CSRF attacks

#### Redirect URI Validation
```bash
# Test redirect URI validation
curl "https://auth.example.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://evil.com/callback"

# Test subdomain redirect
curl "https://auth.example.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://evil.example.com/callback"

# Test path traversal in redirect
curl "https://auth.example.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://example.com/../evil.com"
```

- [ ] **Exact Match**: Redirect URIs validated against exact registered URLs
- [ ] **No Wildcards**: Wildcard redirect URIs are not allowed
- [ ] **No Open Redirects**: Redirect validation prevents open redirect attacks
- [ ] **Secure Schemes**: Only HTTPS redirect URIs allowed (production)

#### Token Endpoint Security
- [ ] **Client Authentication**: Client credentials properly validated
- [ ] **Grant Type Validation**: Only allowed grant types accepted
- [ ] **Code Validation**: Authorization codes are single-use and time-limited
- [ ] **Rate Limiting**: Token endpoint protected against brute force
- [ ] **Error Handling**: Generic error messages don't reveal sensitive info

---

## 🍪 Session-Based Authentication Testing

### Session Management Analysis
```bash
# Analyze session cookie properties
curl -c cookies.txt -b cookies.txt https://api.example.com/login \
  -d "username=testuser&password=testpass"

# Examine cookie attributes
cat cookies.txt
# Look for Secure, HttpOnly, SameSite attributes
```

- [ ] **Secure Attribute**: Session cookies marked as Secure
- [ ] **HttpOnly Attribute**: Session cookies marked as HttpOnly
- [ ] **SameSite Attribute**: Appropriate SameSite setting (Strict/Lax)
- [ ] **Cookie Expiration**: Reasonable session timeout implemented
- [ ] **Cookie Domain**: Appropriate domain scope for cookies

### Session Vulnerability Testing

#### Session Fixation
```bash
# Test session fixation vulnerability
# Step 1: Get session ID before authentication
curl -c pre_auth_cookies.txt https://api.example.com/

# Step 2: Authenticate with existing session
curl -b pre_auth_cookies.txt -c post_auth_cookies.txt \
  https://api.example.com/login -d "username=user&password=pass"

# Step 3: Check if session ID changed
diff pre_auth_cookies.txt post_auth_cookies.txt
```

- [ ] **Session Regeneration**: New session ID generated after authentication
- [ ] **Old Session Invalidation**: Previous session completely invalidated
- [ ] **Session Binding**: Session tied to user identity
- [ ] **Login Process**: Secure session establishment process

#### Session Hijacking Protection
- [ ] **IP Binding**: Sessions optionally bound to IP addresses
- [ ] **User-Agent Validation**: Session validation includes User-Agent check
- [ ] **Concurrent Sessions**: Policy for multiple concurrent sessions
- [ ] **Session Monitoring**: Unusual session activity detection
- [ ] **Session Encryption**: Session data encrypted if stored server-side

---

## 🚫 Authentication Bypass Testing

### Common Bypass Techniques

#### HTTP Header Manipulation
```bash
# Test X-User-ID header bypass
curl -H "X-User-ID: admin" https://api.example.com/admin/users

# Test X-Forwarded-User bypass
curl -H "X-Forwarded-User: admin" https://api.example.com/admin

# Test X-Remote-User bypass
curl -H "X-Remote-User: administrator" https://api.example.com/admin

# Test custom authentication headers
curl -H "X-Auth-User: admin" -H "X-Auth-Role: admin" https://api.example.com/admin
```

- [ ] **Header Validation**: Authentication headers properly validated
- [ ] **Header Tampering**: Forged headers don't bypass authentication
- [ ] **Proxy Headers**: X-Forwarded-* headers handled securely
- [ ] **Custom Headers**: Application-specific headers validated

#### Parameter Manipulation
```bash
# Test parameter-based authentication bypass
curl "https://api.example.com/admin/users?authenticated=true"
curl "https://api.example.com/users?admin=1"
curl "https://api.example.com/data?user_role=administrator"

# Test JSON parameter injection
curl -X POST https://api.example.com/api/data \
  -H "Content-Type: application/json" \
  -d '{"data": "test", "authenticated": true, "role": "admin"}'
```

- [ ] **Parameter Validation**: Authentication parameters properly validated
- [ ] **Parameter Injection**: Additional parameters don't affect authentication
- [ ] **JSON Injection**: JSON parameter pollution doesn't bypass auth
- [ ] **Hidden Parameters**: No hidden authentication parameters

#### HTTP Method Manipulation
```bash
# Test method override for authentication bypass
curl -X POST https://api.example.com/admin/users -H "X-HTTP-Method-Override: GET"
curl -X GET https://api.example.com/admin/users (if only POST is protected)
curl -X OPTIONS https://api.example.com/admin/users
curl -X HEAD https://api.example.com/admin/users
```

- [ ] **Method Consistency**: Same authentication for all HTTP methods
- [ ] **Method Override**: HTTP method override headers handled securely
- [ ] **OPTIONS Method**: OPTIONS method doesn't bypass authentication
- [ ] **Verb Tampering**: All HTTP verbs properly authenticated

---

## 🔒 Multi-Factor Authentication (MFA) Testing

### MFA Implementation Analysis
- [ ] **MFA Enrollment**: Secure MFA setup process
- [ ] **Factor Types**: Multiple factor types supported (SMS, TOTP, hardware)
- [ ] **Factor Validation**: All factors properly validated
- [ ] **Backup Codes**: Secure backup/recovery codes provided
- [ ] **Factor Management**: Ability to manage enrolled factors

### MFA Bypass Testing

#### TOTP/SMS Code Testing
```bash
# Test TOTP code reuse
curl -X POST https://api.example.com/verify-mfa \
  -d "totp_code=123456"
# Use same code again - should be rejected

# Test old TOTP codes
curl -X POST https://api.example.com/verify-mfa \
  -d "totp_code=OLD_CODE_FROM_PREVIOUS_WINDOW"
```

- [ ] **Code Uniqueness**: TOTP codes are single-use
- [ ] **Time Window**: Appropriate time window for TOTP validation
- [ ] **Code History**: Old codes properly rejected
- [ ] **Rate Limiting**: MFA attempts are rate limited
- [ ] **Brute Force Protection**: Account lockout after failed attempts

#### MFA Bypass Attempts
```bash
# Test MFA bypass with different endpoints
curl https://api.example.com/api/data (protected)
curl https://api.example.com/api/v2/data (might not require MFA)

# Test MFA requirement bypass
curl -H "X-Skip-MFA: true" https://api.example.com/api/data
```

- [ ] **Consistent Enforcement**: MFA required for all sensitive operations
- [ ] **Endpoint Coverage**: All API versions require MFA consistently
- [ ] **Bypass Prevention**: No MFA bypass mechanisms exist
- [ ] **Administrative Override**: Admin MFA bypass properly controlled

---

## 🕵️ Authentication Logic Testing

### Race Condition Testing
```bash
# Test concurrent authentication attempts
for i in {1..10}; do
  curl -X POST https://api.example.com/login \
    -d "username=testuser&password=testpass" &
done
wait
```

- [ ] **Concurrent Logins**: Multiple concurrent authentication attempts handled properly
- [ ] **Account Locking**: Race conditions don't bypass account lockout
- [ ] **Session Creation**: Concurrent sessions handled securely
- [ ] **Resource Contention**: No authentication bypass due to race conditions

### Timing Attack Testing
```python
import time
import requests

def timing_attack_test():
    valid_user = "admin"
    invalid_user = "nonexistent"
    
    # Time authentication with valid username
    start = time.time()
    response1 = requests.post("/login", data={"username": valid_user, "password": "wrong"})
    valid_time = time.time() - start
    
    # Time authentication with invalid username
    start = time.time()
    response2 = requests.post("/login", data={"username": invalid_user, "password": "wrong"})
    invalid_time = time.time() - start
    
    print(f"Valid user time: {valid_time}")
    print(f"Invalid user time: {invalid_time}")
```

- [ ] **Consistent Timing**: Authentication timing consistent regardless of username validity
- [ ] **Response Uniformity**: Same error messages for invalid username/password
- [ ] **Processing Time**: Similar processing time for all authentication attempts
- [ ] **Information Leakage**: No timing-based user enumeration possible

---

## 📊 Authentication Monitoring and Logging

### Logging Requirements
- [ ] **Authentication Attempts**: All authentication attempts logged
- [ ] **Success/Failure**: Clear distinction between success and failure
- [ ] **User Information**: Username/user ID logged (not passwords)
- [ ] **Source Information**: IP address, User-Agent, timestamp logged
- [ ] **Session Information**: Session creation and destruction logged

### Security Event Detection
```bash
# Example log analysis queries
# Failed login attempts
grep "AUTH_FAILED" /var/log/app.log | head -10

# Multiple failures from same IP
grep "AUTH_FAILED" /var/log/app.log | awk '{print $5}' | sort | uniq -c | sort -nr

# Successful login after failures
grep -A 1 "AUTH_FAILED.*user123" /var/log/app.log | grep "AUTH_SUCCESS"
```

- [ ] **Anomaly Detection**: Unusual authentication patterns detected
- [ ] **Brute Force Detection**: Multiple failed attempts trigger alerts
- [ ] **Geographic Anomalies**: Logins from unusual locations flagged
- [ ] **Device Anomalies**: New device logins require additional verification
- [ ] **Time-based Anomalies**: Off-hours access monitored

---

## ✅ Authentication Security Scorecard

### Critical Requirements (Must Have)
- [ ] Strong authentication mechanism implemented
- [ ] HTTPS enforced for all authentication endpoints
- [ ] No authentication bypass vulnerabilities
- [ ] Secure session management
- [ ] Proper error handling (no information leakage)

### High Priority Requirements
- [ ] Multi-factor authentication available
- [ ] Rate limiting and brute force protection
- [ ] Secure password requirements
- [ ] Account lockout mechanisms
- [ ] Comprehensive authentication logging

### Medium Priority Requirements
- [ ] Single sign-on (SSO) integration
- [ ] Adaptive authentication based on risk
- [ ] Biometric authentication options
- [ ] Social media authentication
- [ ] Certificate-based authentication

### Compliance Requirements
- [ ] **GDPR**: User consent and data protection
- [ ] **PCI DSS**: Strong authentication for cardholder data
- [ ] **HIPAA**: Multi-factor auth for PHI access
- [ ] **SOX**: Strong controls for financial data access

---

## 🔄 Continuous Authentication Testing

### Automated Testing Integration
```yaml
# CI/CD pipeline authentication tests
authentication_tests:
  static_analysis:
    - Check for hardcoded credentials
    - Validate authentication flows
    - Review session management code
  
  dynamic_testing:
    - Authentication bypass testing
    - Session security validation
    - Multi-factor authentication testing
  
  integration_testing:
    - End-to-end authentication flows
    - SSO integration testing
    - API authentication validation
```

### Regular Assessment Schedule
- **Daily**: Automated authentication security scans
- **Weekly**: Authentication log analysis and review
- **Monthly**: Authentication mechanism review
- **Quarterly**: Comprehensive authentication penetration testing
- **Annually**: Full authentication security assessment

---

Use this checklist systematically during authentication security audits to ensure comprehensive coverage of all potential vulnerabilities and security concerns. Remember to document all findings and remediation efforts for compliance and continuous improvement purposes.
