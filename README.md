# 🛡️ API Security Audit Framework

A comprehensive, production-ready framework for auditing API endpoints, identifying vulnerabilities, and securing your applications. Covers REST, GraphQL, and modern API architectures with automated testing, compliance validation, and professional reporting.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-1.0.0-green.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-orange.svg)
![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-blue.svg)

## 🚀 Quick Start

1. **Clone and validate the framework**
```bash
git clone https://github.com/TheZubairUsman/api-security-audit-framework.git
cd api-security-audit-framework

# Validate framework installation
chmod +x tools/scripts/validate-framework.sh
./tools/scripts/validate-framework.sh
```

2. **Install dependencies**
```bash
# Core dependencies
sudo apt-get install curl jq openssl bc

# Optional but recommended
npm install -g newman newman-reporter-html
pip3 install flask requests jsonschema pyyaml
```

3. **Choose your audit approach**
   - **🔍 Comprehensive Audit**: [`tools/scripts/comprehensive-scan.sh`](tools/scripts/comprehensive-scan.sh)
   - **⚡ Quick Assessment**: [`tools/scripts/basic-scan.sh`](tools/scripts/basic-scan.sh)
   - **📋 Manual Testing**: Use checklists in [`checklists/`](checklists/)
   - **🎯 GraphQL Focus**: [`docs/graphql-security.md`](docs/graphql-security.md)

4. **Run your first audit**
```bash
# Basic security scan
./tools/scripts/basic-scan.sh https://api.example.com

# Comprehensive audit with all formats
./tools/scripts/comprehensive-scan.sh https://api.example.com --format all

# Postman collection testing
./tools/scripts/run-newman.sh tools/postman-collections/collections_security_tests.json tools/postman/environment.json
```

## 📋 What's Included

### 📚 Documentation
- **[Complete Audit Guide](docs/audit-guide.md)** - Comprehensive 11-phase security audit methodology
- **[Compliance Checklist](docs/compliance-checklist.md)** - GDPR, PCI DSS, HIPAA, SOX requirements
- **[Remediation Priorities](docs/remediation-priorities.md)** - Risk-based fix prioritization
- **[GraphQL Security Guide](docs/graphql-security.md)** - Comprehensive GraphQL security testing methodology

### ✅ Ready-to-Use Checklists
- **[Authentication Audit](checklists/authentication-audit.md)** - JWT, OAuth, API keys testing
- **[Data Exposure Assessment](checklists/data-exposure-checklist.md)** - PII, sensitive data protection
- **[Business Logic Tests](checklists/business-logic-tests.md)** - Workflow and logic vulnerabilities
- **[GraphQL Security Checklist](checklists/graphql-security-checklist.md)** - GraphQL-specific security testing

### 🛠️ Automated Tools & Scripts
- **[Basic Security Scanner](tools/scripts/basic-scan.sh)** - Core vulnerability detection
- **[Comprehensive Audit](tools/scripts/comprehensive-scan.sh)** - Full security assessment with reporting
- **[Newman Integration](tools/scripts/run-newman.sh)** - Postman collection automation
- **[Framework Validator](tools/scripts/validate-framework.sh)** - Installation and dependency validation
- **[GitHub Actions Workflow](.github/workflows/api-security-audit.yml)** - CI/CD security integration

### 📄 Professional Templates
- **[Vulnerability Report](templates/vulnerability-report.md)** - Technical findings documentation
- **[Executive Summary](templates/executive-summary.md)** - C-level reporting template

### 💡 Real-World Examples
- **[SQL Injection Examples](examples/common-vulnerabilities/sql-injection/)** - Vulnerable and secure implementations
- **[Authentication Bypass](examples/common-vulnerabilities/authentication-bypass/)** - JWT and session vulnerabilities
- **[Business Logic Flaws](examples/common-vulnerabilities/business-logic/)** - Rate limiting and resource abuse
- **Test case scenarios** for different API types
- **Before/after security implementations**

## 🎯 Key Features

### 🔍 Comprehensive Coverage
- **11 audit categories** covering all major API security aspects
- **OWASP API Security Top 10** compliance
- **REST and GraphQL** API security testing
- **Automated + Manual testing** methodologies
- **Business logic vulnerability** detection
- **CI/CD integration** with GitHub Actions

### 🏢 Enterprise Ready
- **Compliance frameworks** (GDPR, PCI DSS, HIPAA, SOX)
- **Risk prioritization** matrix
- **Executive reporting** templates
- **Continuous monitoring** strategies

### ⚡ Developer Friendly
- **Step-by-step guides** with examples
- **Copy-paste scripts** for common tasks
- **GitHub Actions workflow** for automated security testing
- **Postman collections** for immediate testing
- **Framework validation** for easy setup
- **Multi-format reporting** (JSON, HTML, PDF, Markdown)

## 🗂️ Repository Structure

```
api-security-audit-framework/
├── 📄 README.md                           # This file
├── 🔄 .github/workflows/                  # CI/CD automation
│   └── api-security-audit.yml            # GitHub Actions workflow
├── 📁 docs/                               # Comprehensive documentation
│   ├── audit-guide.md                    # Complete audit methodology
│   ├── compliance-checklist.md           # Regulatory compliance guide
│   ├── remediation-priorities.md         # Risk-based prioritization
│   └── graphql-security.md               # GraphQL security guide
├── ✅ checklists/                         # Ready-to-use audit checklists
│   ├── authentication-audit.md           # Auth & authorization tests
│   ├── data-exposure-checklist.md        # Data protection assessment
│   ├── business-logic-tests.md           # Business logic vulnerabilities
│   └── graphql-security-checklist.md     # GraphQL security checklist
├── 🛠️ tools/                              # Automation tools
│   ├── scripts/                          # Security testing scripts
│   │   ├── basic-scan.sh                 # Core vulnerability scanner
│   │   ├── comprehensive-scan.sh         # Full audit with reporting
│   │   ├── run-newman.sh                 # Postman automation
│   │   ├── generate-report.sh            # Report generation
│   │   └── validate-framework.sh         # Framework validation
│   ├── postman/                          # Postman environment
│   │   └── environment.json              # Test environment config
│   └── postman-collections/              # API testing collections
│       └── collections_security_tests.json # Security test suite
├── 📄 templates/                          # Professional reporting templates
│   ├── vulnerability-report.md           # Technical vulnerability report
│   └── executive-summary.md              # Executive summary template
└── 💡 examples/                           # Real-world examples
    └── common-vulnerabilities/           # Vulnerability patterns
        ├── sql-injection/                # SQL injection examples
        ├── authentication-bypass/       # Auth bypass examples
        └── business-logic/              # Business logic flaws
```

## 🚨 Critical Security Areas Covered

### 🔐 Authentication & Authorization
- JWT token security and validation (including algorithm confusion)
- OAuth implementation flaws
- API key management and exposure
- Session management vulnerabilities
- Privilege escalation detection
- Multi-factor authentication bypass

### 📊 Data Protection
- PII exposure prevention
- Sensitive data leakage detection
- Over-permissive responses
- Mass assignment vulnerabilities
- Data classification and handling
- GDPR, HIPAA, PCI DSS compliance

### ⚡ Rate Limiting & DDoS
- Per-endpoint throttling
- User-based rate limiting
- DDoS protection testing
- Rate limit bypass techniques
- Resource exhaustion attacks
- Business logic abuse prevention

### 💉 Injection Attacks
- SQL injection prevention (MySQL, PostgreSQL, SQLite)
- NoSQL injection testing (MongoDB, etc.)
- Command injection detection
- XML/JSON injection flaws
- GraphQL injection vulnerabilities
- LDAP and XPath injection

### 🏗️ Infrastructure Security
- HTTPS implementation and TLS configuration
- Server configuration hardening
- Network security assessment
- Security headers validation
- CORS configuration review
- Monitoring and logging effectiveness

## 🎪 Quick Audit Checklist

Use this for immediate security assessment:

- [ ] **Framework Setup**: Run `./tools/scripts/validate-framework.sh`
- [ ] **Discovery**: Enumerate all API endpoints
- [ ] **Authentication**: Test auth bypass techniques  
- [ ] **Authorization**: Check privilege escalation
- [ ] **Data Exposure**: Scan for sensitive data leaks
- [ ] **Rate Limiting**: Verify throttling mechanisms
- [ ] **Input Validation**: Test injection attacks
- [ ] **Business Logic**: Check workflow bypasses
- [ ] **GraphQL Security**: Test GraphQL-specific vulnerabilities
- [ ] **Infrastructure**: Review server security
- [ ] **Compliance**: Validate regulatory requirements
- [ ] **CI/CD Integration**: Set up automated security testing
- [ ] **Documentation**: Update security policies

## 📈 Usage Scenarios

### 🏢 **For Enterprise Security Teams**
```bash
# Validate framework setup
./tools/scripts/validate-framework.sh

# Run comprehensive audit with all formats
./tools/scripts/comprehensive-scan.sh https://api.company.com --format all --output enterprise-audit

# Generate executive report
./tools/scripts/generate-report.sh --input enterprise-audit.json --format executive

# Set up CI/CD monitoring
cp .github/workflows/api-security-audit.yml .github/workflows/
```

### 🚀 **For Startup Founders**
```bash
# Quick security assessment
./tools/scripts/basic-scan.sh https://your-api.com

# Check GraphQL security
./tools/scripts/basic-scan.sh https://your-api.com/graphql --graphql

# Run Postman security tests
./tools/scripts/run-newman.sh tools/postman-collections/collections_security_tests.json
```

### 👨‍💻 **For Developers**
```bash
# Integrate with CI/CD (GitHub Actions)
# Copy .github/workflows/api-security-audit.yml to your repo

# Test during development
./tools/scripts/basic-scan.sh http://localhost:3000/api

# Validate framework after updates
./tools/scripts/validate-framework.sh

# Run vulnerability examples for learning
cd examples/common-vulnerabilities/sql-injection
python3 vulnerable-code.py  # Educational purposes only
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Areas We Need Help With
- [ ] Additional compliance frameworks (ISO 27001, NIST)
- [ ] More automated testing scripts
- [ ] Mobile API security patterns
- [ ] Cloud-specific security checks (AWS, Azure, GCP)
- [ ] API gateway security testing
- [ ] Microservices security patterns
- [ ] WebSocket security testing

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- Security community contributors and researchers

## 📞 Support

- 📧 **Email**: zus3cu@gmail.com
- 💬 **Discord**: [Join our security community](Https://discord.gg/39rhXANK)
- 🐛 **Issues**: [GitHub Issues](https://github.com/TheZubairUsman/api-security-audit-framework/issues)
- 📖 **Wiki**: [Detailed documentation](https://github.com/TheZubairUsman/api-security-audit-framework/wiki)

## ⭐ Star History

If this project helped secure your APIs, please consider giving it a star! ⭐

---

**🔒 Remember**: Security is a journey, not a destination. Regular audits and continuous monitoring are essential for maintaining a strong security posture.

**⚠️ Disclaimer**: This framework is for educational and legitimate security testing purposes only. Always ensure you have proper authorization before testing any systems.