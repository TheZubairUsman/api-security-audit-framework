# 📋 Complete API Security Audit Guide

This comprehensive guide provides a systematic approach to auditing API security across 11 critical phases. Use this as your primary reference for conducting thorough API security assessments.

## 🎯 Audit Objectives

- **Identify** exposed API endpoints and vulnerabilities
- **Assess** current security posture and risk levels
- **Prioritize** remediation efforts based on business impact
- **Document** findings for stakeholders and compliance
- **Establish** continuous monitoring processes

## 📊 Audit Phases Overview

| Phase | Focus Area | Duration | Priority |
|-------|------------|----------|----------|
| 1 | [Pre-Audit Preparation](#1-pre-audit-preparation) | 1-2 days | Critical |
| 2 | [Discovery & Enumeration](#2-discovery--enumeration) | 2-3 days | High |
| 3 | [Authentication Testing](#3-authentication-testing) | 1-2 days | Critical |
| 4 | [Authorization Assessment](#4-authorization-assessment) | 1-2 days | Critical |
| 5 | [Data Exposure Analysis](#5-data-exposure-analysis) | 1-2 days | High |
| 6 | [Rate Limiting Evaluation](#6-rate-limiting-evaluation) | 1 day | Medium |
| 7 | [Input Validation Testing](#7-input-validation-testing) | 2-3 days | High |
| 8 | [Business Logic Review](#8-business-logic-review) | 2-3 days | High |
| 9 | [Infrastructure Security](#9-infrastructure-security) | 1-2 days | Medium |
| 10 | [Compliance Assessment](#10-compliance-assessment) | 1-2 days | Variable |
| 11 | [Reporting & Remediation](#11-reporting--remediation) | 1-2 days | Critical |

---

## 1️⃣ Pre-Audit Preparation

### 📚 Information Gathering

**Documentation Collection**
- [ ] API documentation (OpenAPI/Swagger specs)
- [ ] Architecture diagrams and data flow maps
- [ ] Authentication and authorization models
- [ ] Known security controls and policies
- [ ] Previous security assessment reports
- [ ] Compliance requirements and standards

**Environment Mapping**
- [ ] Production environment details
- [ ] Staging/development environments
- [ ] Third-party integrations and dependencies
- [ ] Cloud service configurations
- [ ] Network topology and firewall rules

**Stakeholder Coordination**
- [ ] Security team contacts and responsibilities
- [ ] Development team liaisons
- [ ] Business owner approvals
- [ ] Communication protocols for findings
- [ ] Emergency contact procedures

### 🛠️ Tool Preparation

**Primary Tools Setup**
```bash
# Install security testing tools
sudo apt-get update
sudo apt-get install -y nmap nikto sqlmap dirb gobuster

# Download and configure Burp Suite
# Download OWASP ZAP
# Setup Postman with security collections
```

**Custom Scripts Preparation**
- [ ] Endpoint enumeration scripts
- [ ] Authentication bypass testing
- [ ] Data validation scripts
- [ ] Report generation tools

### ⚖️ Legal and Scope Definition

**Authorization Documentation**
- [ ] Written permission for testing
- [ ] Scope of testing clearly defined
- [ ] Off-limits systems and data identified
- [ ] Testing window and constraints
- [ ] Incident response procedures agreed

---

## 2️⃣ Discovery & Enumeration

### 🔍 Automated Discovery

**Web Application Scanning**
```bash
# Burp Suite Spider configuration
# Target: https://api.example.com
# Scope: Include all subdomains
# Crawl depth: Maximum
# Spider timeout: 30 minutes

# OWASP ZAP Spider
zap-baseline.py -t https://api.example.com -r zap-report.html

# Nikto web server scan
nikto -h https://api.example.com -Format html -output nikto-results.html
```

**Directory and File Enumeration**
```bash
# Gobuster directory brute force
gobuster dir -u https://api.example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Common API paths
gobuster dir -u https://api.example.com -w api-wordlist.txt
# Custom wordlist: api/, v1/, v2/, rest/, graphql/, admin/, management/, actuator/, debug/, test/, dev/

# DNS subdomain enumeration
sublist3r -d example.com -o subdomains.txt
```

**Network Discovery**
```bash
# Port scanning
nmap -sS -sV -O -A api.example.com

# Service enumeration
nmap -sC -sV -p- api.example.com

# UDP scan for common services
nmap -sU --top-ports 1000 api.example.com
```

### 🔍 Manual Discovery

**Source Code Analysis**
- [ ] Review client-side JavaScript for API endpoints
- [ ] Analyze mobile application code (if applicable)
- [ ] Check HTML source for hidden forms and AJAX calls
- [ ] Examine CSS files for URL references
- [ ] Review service worker files

**Documentation Analysis**
- [ ] Search for exposed API documentation (Swagger UI, Postman)
- [ ] Check for API specification files in public repositories
- [ ] Look for configuration files (.env, config.json)
- [ ] Review error pages for information disclosure

**Network Traffic Analysis**
```bash
# Proxy all traffic through Burp Suite
# Monitor WebSocket connections
# Analyze HTTP/2 and HTTP/3 traffic
# Capture mobile app traffic using proxy
```

### 📊 Endpoint Inventory

Create comprehensive endpoint documentation:

| Endpoint | Method | Authentication | Parameters | Data Sensitivity | Risk Level |
|----------|--------|----------------|------------|------------------|------------|
| `/api/users` | GET | JWT Required | ?page=1&limit=10 | PII | High |
| `/api/users/{id}` | GET | JWT Required | id (path) | PII | High |
| `/api/admin/logs` | GET | Admin Role | ?start_date | System Info | Critical |

---

## 3️⃣ Authentication Testing

### 🔐 Authentication Mechanisms Analysis

**JWT Token Testing**
```bash
# Decode JWT tokens
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." | base64 -d

# Test for weak signing algorithms
# Check for missing signature verification
# Test token expiration handling
# Verify refresh token implementation
```

**API Key Security**
```bash
# Test API key in different locations
curl -H "X-API-Key: your-api-key" https://api.example.com/users
curl -H "Authorization: ApiKey your-api-key" https://api.example.com/users
curl "https://api.example.com/users?api_key=your-api-key"

# Test key rotation and revocation
# Verify key scope and permissions
```

**OAuth Implementation**
- [ ] Test authorization code flow
- [ ] Verify state parameter usage
- [ ] Check redirect URI validation
- [ ] Test scope enforcement
- [ ] Validate token endpoint security

### 🚫 Authentication Bypass Testing

**Common Bypass Techniques**
```bash
# Header manipulation
curl -H "X-User-ID: admin" https://api.example.com/admin/users
curl -H "X-Forwarded-User: admin" https://api.example.com/admin/users

# Parameter pollution
curl "https://api.example.com/users?user_id=1&user_id=admin"

# HTTP method tampering
curl -X POST https://api.example.com/users/1 (when only GET is protected)

# Authentication timing attacks
# Race condition testing during authentication
```

**Session Management Testing**
- [ ] Session fixation vulnerabilities
- [ ] Session timeout validation
- [ ] Concurrent session handling
- [ ] Session invalidation on logout
- [ ] Cross-domain session sharing

---

## 4️⃣ Authorization Assessment

### 🎭 Role-Based Access Control

**Privilege Escalation Testing**
```bash
# Horizontal privilege escalation
# Access another user's resources
curl -H "Authorization: Bearer user1-token" https://api.example.com/users/user2/profile

# Vertical privilege escalation
# Access admin functions as regular user
curl -H "Authorization: Bearer user-token" https://api.example.com/admin/delete-user
```

**Direct Object References**
```bash
# Test predictable resource IDs
curl https://api.example.com/documents/1
curl https://api.example.com/documents/2
curl https://api.example.com/documents/99999

# Test GUID predictability
# Test sequential ID enumeration
# Test UUID format validation
```

### 🔒 Access Control Testing

**Function-Level Access Control**
- [ ] Admin panel access with user credentials
- [ ] Sensitive operation execution
- [ ] Resource creation/deletion permissions
- [ ] Configuration modification access

**Resource-Level Permissions**
```bash
# Test resource ownership validation
PUT /api/users/123/profile
{
  "user_id": 456,  # Attempt to modify different user
  "email": "attacker@example.com"
}

# Test bulk operations security
DELETE /api/users/bulk
{
  "user_ids": [1,2,3,4,5]  # Attempt mass deletion
}
```

---

## 5️⃣ Data Exposure Analysis

### 📊 Sensitive Data Identification

**Personal Identifiable Information (PII)**
- [ ] Full names, addresses, phone numbers
- [ ] Social security numbers, national IDs
- [ ] Email addresses and usernames
- [ ] Date of birth and age information
- [ ] Financial account information

**Business Critical Data**
- [ ] Customer lists and contact information
- [ ] Financial records and transaction data
- [ ] Intellectual property and trade secrets
- [ ] Strategic business information
- [ ] Partner and vendor information

**System Information**
- [ ] Internal IP addresses and network topology
- [ ] Database schemas and table structures
- [ ] API keys and secrets
- [ ] System configurations and versions
- [ ] Error messages with stack traces

### 🔍 Over-Exposure Testing

**Excessive Data Retrieval**
```bash
# Test for unnecessary data in responses
curl https://api.example.com/users/profile
# Check if response includes password hashes, internal IDs, etc.

# Test pagination limits
curl "https://api.example.com/users?limit=999999"

# Test field filtering
curl "https://api.example.com/users?fields=*"
```

**Information Leakage Analysis**
- [ ] Debug information in production responses
- [ ] Stack traces in error messages
- [ ] Internal system paths in responses
- [ ] Database query details
- [ ] Third-party service configurations

### 🛡️ Mass Assignment Testing

```bash
# Test parameter injection
POST /api/users/123/profile
{
  "name": "John Doe",
  "email": "john@example.com",
  "role": "admin",        # Attempt privilege escalation
  "is_verified": true,    # Attempt to bypass verification
  "internal_id": 999      # Attempt to set internal fields
}
```

---

## 6️⃣ Rate Limiting Evaluation

### ⚡ Rate Limiting Assessment

**Per-Endpoint Testing**
```bash
# Test endpoint-specific limits
for i in {1..100}; do
  curl -w "Response: %{http_code}\n" https://api.example.com/users
  sleep 0.1
done

# Test different endpoints
for endpoint in users orders products admin; do
  curl https://api.example.com/$endpoint
done
```

**User-Based Limits**
```bash
# Test per-user rate limiting
# Use multiple user tokens
for token in token1 token2 token3; do
  curl -H "Authorization: Bearer $token" https://api.example.com/users
done
```

**IP-Based Limits**
```bash
# Test IP-based throttling
# Use proxy rotation or VPN
curl --proxy proxy1:8080 https://api.example.com/users
curl --proxy proxy2:8080 https://api.example.com/users
```

### 🚫 Rate Limit Bypass Testing

**Header Manipulation**
```bash
# Test X-Forwarded-For bypass
curl -H "X-Forwarded-For: 1.2.3.4" https://api.example.com/users
curl -H "X-Real-IP: 5.6.7.8" https://api.example.com/users

# Test User-Agent rotation
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://api.example.com/users
curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" https://api.example.com/users
```

**Distributed Requests**
- [ ] Multi-IP address testing
- [ ] Parameter variation techniques
- [ ] Request timing manipulation
- [ ] Connection pooling abuse

---

## 7️⃣ Input Validation Testing

### 💉 Injection Attack Testing

**SQL Injection**
```bash
# Classic SQL injection
curl "https://api.example.com/users?id=1' OR '1'='1"

# Union-based attacks
curl "https://api.example.com/users?id=1' UNION SELECT username,password FROM admin_users--"

# Blind SQL injection
curl "https://api.example.com/users?id=1' AND (SELECT COUNT(*) FROM users) > 0--"

# Time-based blind injection
curl "https://api.example.com/users?id=1'; WAITFOR DELAY '00:00:05'--"
```

**NoSQL Injection**
```bash
# MongoDB injection
curl -X POST https://api.example.com/login \
-d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# CouchDB injection
curl "https://api.example.com/users?selector={\"$or\":[{},{\"admin\":true}]}"
```

**Command Injection**
```bash
# OS command injection
curl "https://api.example.com/ping?host=8.8.8.8; cat /etc/passwd"
curl "https://api.example.com/convert?file=test.txt`whoami`"

# Code injection
curl -X POST https://api.example.com/execute \
-d '{"code": "eval(\"process.env\")"}'
```

### 🔍 Data Validation Testing

**Input Boundary Testing**
```bash
# Length validation
curl -X POST https://api.example.com/users \
-d '{"name": "'$(python -c 'print("A"*10000)')'", "email": "test@example.com"}'

# Special character handling
curl -X POST https://api.example.com/users \
-d '{"name": "<script>alert(1)</script>", "email": "test@example.com"}'

# Unicode and encoding tests
curl -X POST https://api.example.com/users \
-d '{"name": "测试用户", "email": "test@example.com"}'
```

**File Upload Security**
- [ ] File type validation bypass
- [ ] Malicious file upload attempts
- [ ] Path traversal in filenames
- [ ] File size limit testing
- [ ] Executable file restrictions

---

## 8️⃣ Business Logic Review

### 🔄 Workflow Testing

**Multi-Step Process Analysis**
```bash
# Test workflow bypass
# Step 1: Create order
curl -X POST https://api.example.com/orders -d '{"product_id": 1, "quantity": 1}'

# Step 2: Skip payment, go directly to fulfillment
curl -X POST https://api.example.com/orders/123/fulfill

# Test state manipulation
curl -X PUT https://api.example.com/orders/123 -d '{"status": "paid"}'
```

**Race Condition Testing**
```bash
# Concurrent request testing
for i in {1..10}; do
  curl -X POST https://api.example.com/wallet/withdraw \
  -d '{"amount": 100}' &
done
wait
```

### 💰 Financial Logic Testing

**Price Manipulation**
```bash
# Negative price testing
curl -X POST https://api.example.com/orders \
-d '{"product_id": 1, "quantity": -1, "price": -50}'

# Currency manipulation
curl -X POST https://api.example.com/orders \
-d '{"product_id": 1, "currency": "INVALID", "amount": 0.01}'

# Discount abuse
curl -X POST https://api.example.com/orders \
-d '{"discount_code": ["SAVE10", "SAVE20", "SAVE30"]}'
```

### 🎯 Business Rule Validation

**Limit Bypasses**
- [ ] Transaction amount limits
- [ ] Daily/monthly usage quotas
- [ ] Feature access restrictions
- [ ] Geographic limitations
- [ ] Time-based constraints

---

## 9️⃣ Infrastructure Security

### 🔒 HTTPS Implementation

**SSL/TLS Configuration Testing**
```bash
# SSL Labs test
sslyze --regular api.example.com

# Certificate validation
openssl s_client -connect api.example.com:443 -servername api.example.com

# Cipher suite analysis
nmap --script ssl-cert,ssl-enum-ciphers -p 443 api.example.com

# HSTS header verification
curl -I https://api.example.com | grep -i "strict-transport-security"
```

**Mixed Content Testing**
- [ ] HTTP resources loaded over HTTPS
- [ ] Insecure external dependencies
- [ ] WebSocket security (wss://)
- [ ] Content Security Policy validation

### 🌐 Network Security

**Server Configuration**
```bash
# Security header analysis
curl -I https://api.example.com

# Expected headers:
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Content-Security-Policy: default-src 'self'
# Referrer-Policy: strict-origin-when-cross-origin
```

**Server Information Disclosure**
- [ ] Server software version exposure
- [ ] Directory listing enabled
- [ ] Debug information leakage
- [ ] Error page information disclosure

---

## 🔟 Compliance Assessment

### 📜 Regulatory Requirements

**GDPR Compliance**
- [ ] Data subject consent mechanisms
- [ ] Right to access implementation
- [ ] Right to erasure ("right to be forgotten")
- [ ] Data portability features
- [ ] Privacy by design principles
- [ ] Data breach notification procedures

**PCI DSS Compliance** (if handling payments)
- [ ] Cardholder data protection
- [ ] Secure transmission protocols
- [ ] Access control measures
- [ ] Regular security testing
- [ ] Vulnerability management program

**HIPAA Compliance** (if handling health data)
- [ ] PHI encryption at rest and in transit
- [ ] Access controls and audit logs
- [ ] Business associate agreements
- [ ] Risk assessment documentation
- [ ] Incident response procedures

### 📊 Compliance Documentation

**Required Documentation**
- [ ] Data processing activities record
- [ ] Privacy impact assessments
- [ ] Security control implementations
- [ ] Audit trail configurations
- [ ] Incident response plans

---

## 1️⃣1️⃣ Reporting & Remediation

### 📋 Vulnerability Assessment

**Risk Rating Matrix**

| Severity | CVSS Score | Criteria | Examples |
|----------|------------|----------|-----------|
| Critical | 9.0-10.0 | Remote code execution, data breach | SQL injection, authentication bypass |
| High | 7.0-8.9 | Significant data exposure | Privilege escalation, PII leakage |
| Medium | 4.0-6.9 | Limited access or impact | Rate limiting issues, information disclosure |
| Low | 0.1-3.9 | Minimal security impact | Documentation gaps, minor configuration issues |

### 📊 Executive Summary Template

**Key Metrics**
- Total endpoints audited: [Number]
- Critical vulnerabilities found: [Number]
- High-risk issues identified: [Number]
- Compliance gaps discovered: [Number]
- Estimated remediation effort: [Hours/Weeks]

**Business Impact Assessment**
- Potential financial impact of breaches
- Regulatory compliance risks
- Reputational damage potential
- Customer trust implications

### 🎯 Remediation Roadmap

**Immediate Actions (0-7 days)**
1. Fix critical authentication bypasses
2. Address SQL injection vulnerabilities
3. Patch remote code execution flaws
4. Implement emergency monitoring

**Short-term Actions (1-4 weeks)**
1. Strengthen input validation
2. Improve authorization controls
3. Enhance logging and monitoring
4. Update security documentation

**Long-term Actions (1-3 months)**
1. Implement comprehensive security testing
2. Establish continuous monitoring
3. Develop security training programs
4. Create incident response procedures

---

## 🔄 Continuous Monitoring

### 📊 Ongoing Security Processes

**Regular Assessment Schedule**
- **Weekly**: Automated vulnerability scanning
- **Monthly**: Security control validation
- **Quarterly**: Comprehensive security review
- **Annually**: Full penetration testing

**Monitoring Implementation**
- Real-time threat detection systems
- API usage analytics and anomaly detection
- Security event correlation and analysis
- Compliance monitoring dashboards

### 📈 Success Metrics

**Security Metrics**
- Mean time to detect (MTTD) security incidents
- Mean time to respond (MTTR) to vulnerabilities
- Number of security issues per release
- Security test coverage percentage

**Compliance Metrics**
- Regulatory audit results
- Policy compliance rates
- Training completion rates
- Incident response effectiveness

---

## 🛠️ Tools and Resources

### Primary Security Testing Tools
- **Burp Suite Professional**: Web application security testing
- **OWASP ZAP**: Free security testing proxy
- **Postman**: API testing and automation
- **SQLMap**: Automated SQL injection testing
- **Nmap**: Network discovery and security auditing
- **Nuclei**: Fast vulnerability scanner

### Specialized API Security Tools
- **42Crunch API Security Audit**: API-specific security testing
- **Astra API Security Scanner**: Automated API vulnerability detection
- **Insomnia**: API testing with security features
- **REST-Assured**: API testing framework for Java

### Cloud Security Tools
- **AWS Inspector**: Automated security assessment
- **Google Cloud Security Scanner**: Web application vulnerability scanner
- **Azure Security Center**: Unified security management

---

## ✅ Final Checklist

Before concluding your audit, ensure:

- [ ] All discovered endpoints have been tested
- [ ] Critical and high-risk vulnerabilities are documented
- [ ] Business stakeholders are informed of major risks
- [ ] Remediation timeline is established and communicated
- [ ] Compliance requirements are addressed
- [ ] Continuous monitoring processes are in place
- [ ] Documentation is complete and accessible
- [ ] Follow-up assessment is scheduled

---

**Remember**: API security is an ongoing process, not a one-time activity. Regular audits, continuous monitoring, and staying updated with emerging threats are essential for maintaining a robust security posture.

---

## 📚 Additional Resources

### Industry Standards and Frameworks
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ISO 27001 Information Security Management](https://www.iso.org/isoiec-27001-information-security.html)
- [CIS Controls](https://www.cisecurity.org/controls/)

### Training and Certification
- OWASP API Security Training
- Certified Ethical Hacker (CEH)
- Certified Information Systems Security Professional (CISSP)
- SANS SEC542: Web App Penetration Testing

### Community Resources
- [OWASP API Security Community](https://owasp.org/www-project-api-security/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne API Security Resources](https://www.hackerone.com/)
- [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/)

This comprehensive audit guide should be customized based on your specific environment, compliance requirements, and risk tolerance. Always ensure you have proper authorization before conducting any security testing activities.