# Common API Vulnerabilities Examples

This directory contains real-world examples of common API security vulnerabilities, their exploitation techniques, and remediation strategies.

## 📁 Directory Structure

```
common-vulnerabilities/
├── README.md                           # This file
├── sql-injection/
│   ├── vulnerable-code.py             # Example vulnerable implementation
│   ├── exploitation-examples.sh       # Attack scenarios
│   ├── secure-implementation.py       # Fixed code examples
│   └── test-payloads.txt              # SQL injection test payloads
├── authentication-bypass/
│   ├── jwt-vulnerabilities.js         # JWT security issues
│   ├── header-manipulation.sh         # Header bypass techniques
│   ├── session-fixation.py           # Session security flaws
│   └── oauth-flaws.md                 # OAuth implementation issues
├── authorization-flaws/
│   ├── privilege-escalation.py       # Vertical privilege escalation
│   ├── horizontal-escalation.sh      # Horizontal privilege escalation
│   ├── idor-examples.py              # Insecure Direct Object References
│   └── rbac-bypass.js                # Role-based access control bypass
├── data-exposure/
│   ├── sensitive-data-leakage.json   # Examples of data over-exposure
│   ├── mass-assignment.py            # Mass assignment vulnerabilities
│   ├── information-disclosure.sh     # Information leakage techniques
│   └── pii-exposure-examples.md      # Personal data exposure cases
├── business-logic/
│   ├── price-manipulation.py         # E-commerce logic flaws
│   ├── race-conditions.js            # Concurrent operation issues
│   ├── workflow-bypass.sh            # Business process bypass
│   └── rate-limit-bypass.py          # Rate limiting circumvention
├── injection-attacks/
│   ├── nosql-injection.js            # NoSQL injection examples
│   ├── command-injection.py          # OS command injection
│   ├── xxe-vulnerabilities.xml       # XML External Entity attacks
│   └── ldap-injection.py             # LDAP injection examples
└── infrastructure/
    ├── ssl-tls-issues.md              # SSL/TLS configuration problems
    ├── cors-misconfiguration.js       # CORS policy issues
    ├── security-headers.md            # Missing security headers
    └── server-misconfig.sh            # Server misconfiguration examples
```

## 🚨 Important Security Notice

⚠️ **WARNING:** The examples in this directory contain actual vulnerability patterns and exploitation techniques. 

**Use Responsibly:**
- Only use these examples for educational purposes and authorized testing
- Never test these techniques against systems you don't own or have explicit permission to test
- Always follow responsible disclosure practices when discovering vulnerabilities
- Ensure you have proper authorization before conducting any security testing

## 📚 How to Use These Examples

### For Security Professionals
1. **Study the vulnerable code** to understand common implementation mistakes
2. **Review exploitation techniques** to understand attacker methodologies
3. **Analyze secure implementations** to learn proper security patterns
4. **Use test payloads** in authorized penetration testing activities

### For Developers  
1. **Learn from mistakes** by studying vulnerable implementations
2. **Understand attack vectors** to write more secure code
3. **Implement security patterns** from the secure code examples
4. **Use as training material** for security awareness programs

### For Security Trainers
1. **Create training scenarios** using the provided examples
2. **Demonstrate real vulnerabilities** in controlled environments
3. **Show before/after comparisons** of vulnerable vs secure code
4. **Build hands-on labs** for security education programs

## 🛡️ Learning Objectives

By studying these examples, you will learn:

- **Common vulnerability patterns** in API implementations
- **Attack methodologies** used by malicious actors
- **Secure coding practices** to prevent vulnerabilities
- **Testing techniques** for identifying security issues
- **Remediation strategies** for fixing discovered vulnerabilities

## 🔍 Vulnerability Categories Covered

### 1. Injection Attacks
- SQL Injection (SQLi)
- NoSQL Injection
- Command Injection
- LDAP Injection
- XML External Entity (XXE)

### 2. Authentication and Session Management
- JWT vulnerabilities
- Session fixation
- Authentication bypass
- Weak password policies
- OAuth implementation flaws

### 3. Authorization Issues
- Privilege escalation
- Insecure Direct Object References (IDOR)
- Role-based access control bypass
- Permission inheritance flaws

### 4. Data Exposure
- Sensitive information leakage
- Mass assignment vulnerabilities
- Over-permissive API responses
- PII exposure in logs and responses

### 5. Business Logic Flaws
- Price manipulation
- Race conditions
- Workflow bypass
- Rate limiting issues
- State manipulation

### 6. Infrastructure Security
- SSL/TLS misconfigurations
- CORS policy issues
- Missing security headers
- Server misconfigurations

## 🧪 Testing Environment Setup

### Local Testing Lab
Create a safe testing environment:

```bash
# Create isolated testing directory
mkdir api-security-lab
cd api-security-lab

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install testing dependencies
pip install flask requests sqlalchemy

# Clone vulnerable applications for testing
git clone https://github.com/OWASP/vulnerable-api-examples.git
```

### Docker Testing Environment
```bash
# Build vulnerable API container
docker build -t vulnerable-api .

# Run in isolated network
docker run -p 8080:8080 --network=isolated vulnerable-api

# Test against local instance only
curl http://localhost:8080/api/test
```

## 📖 Example Scenarios

### Scenario 1: E-commerce API Security Assessment
**Objective:** Identify vulnerabilities in an e-commerce API

**Steps:**
1. Review `business-logic/price-manipulation.py`
2. Test with payloads from `sql-injection/test-payloads.txt`
3. Check for authorization flaws using `authorization-flaws/idor-examples.py`
4. Verify data exposure issues from `data-exposure/sensitive-data-leakage.json`

### Scenario 2: Banking API Penetration Test
**Objective:** Assess security of financial services API

**Focus Areas:**
- Authentication bypass techniques
- Transaction manipulation vulnerabilities
- Data exposure in financial records
- Rate limiting and fraud protection

### Scenario 3: Healthcare API Compliance Review
**Objective:** Ensure HIPAA compliance for healthcare API

**Key Checks:**
- PHI exposure in API responses
- Authentication and authorization controls
- Audit logging implementation
- Data encryption in transit and at rest

## 🔧 Tools and Utilities

### Recommended Testing Tools
- **Burp Suite:** Web application security testing
- **OWASP ZAP:** Free security testing proxy
- **Postman:** API testing and automation
- **SQLMap:** SQL injection testing
- **JWT.io:** JWT token analysis

### Custom Scripts
Each vulnerability category includes:
- **Test scripts** for automated vulnerability detection
- **Payload generators** for creating test cases
- **Verification tools** for confirming fixes
- **Reporting utilities** for documenting findings

## 📊 Vulnerability Impact Matrix

| Vulnerability Type | Frequency | Impact | Detection Difficulty |
|-------------------|-----------|--------|---------------------|
| SQL Injection | High | Critical | Easy |
| Authentication Bypass | Medium | Critical | Medium |
| IDOR | High | High | Easy |
| Business Logic | Medium | High | Hard |
| Data Exposure | High | Medium | Easy |
| Injection (Other) | Medium | High | Medium |

## 🎯 Training Exercises

### Exercise 1: Vulnerability Identification
**Time:** 30 minutes  
**Objective:** Identify vulnerabilities in provided code samples

1. Review code in `sql-injection/vulnerable-code.py`
2. Identify at least 3 security issues
3. Propose remediation strategies
4. Compare with secure implementation

### Exercise 2: Exploitation Practice
**Time:** 45 minutes  
**Objective:** Practice safe exploitation techniques

1. Set up local vulnerable API
2. Use provided exploitation scripts
3. Document successful attacks
4. Measure impact and scope

### Exercise 3: Secure Development
**Time:** 60 minutes  
**Objective:** Implement secure alternatives

1. Take vulnerable code example
2. Implement security controls
3. Test against provided payloads  
4. Verify fix effectiveness

## 🔗 Additional Resources

### Educational Materials
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS API Security Guidelines](https://www.sans.org/white-papers/)

### Practice Platforms
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [Damn Vulnerable Web Services](http://dvws.professionallyevil.com/)
- [VAmPI - Vulnerable API](https://github.com/erev0s/VAmPI)

### Community Resources
- [API Security Community](https://apisecurity.io/)
- [42Crunch API Security Articles](https://42crunch.com/resources/)
- [Security Stack Exchange](https://security.stackexchange.com/)

## ⚖️ Legal and Ethical Guidelines

### Authorized Testing Only
- Only test systems you own or have explicit written permission to test
- Respect scope limitations and testing windows
- Follow responsible disclosure practices
- Document and report findings appropriately

### Educational Use
- Use examples for learning and training purposes only
- Don't use techniques maliciously or against unauthorized systems
- Share knowledge responsibly within the security community
- Contribute back to the community with your own findings and improvements

---

**Remember:** The goal of studying these vulnerabilities is to build better, more secure systems. Always use this knowledge ethically and responsibly.

For questions or contributions, please see the main repository documentation.