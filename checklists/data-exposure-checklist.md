# 📊 Data Exposure Security Checklist

This comprehensive checklist helps identify and assess data exposure risks in API endpoints. Use this to ensure sensitive data is properly protected and compliant with privacy regulations.

---

## 🔍 Pre-Assessment Data Classification

### Data Sensitivity Categories

#### Public Data
- [ ] **Marketing content**: Publicly available promotional materials
- [ ] **Product information**: Public product catalogs and descriptions
- [ ] **Company information**: Public company details and contact info
- [ ] **Documentation**: Public API documentation and help content

#### Internal Data  
- [ ] **Employee directory**: Internal contact information
- [ ] **Process documentation**: Internal procedures and workflows
- [ ] **System configurations**: Non-sensitive configuration data
- [ ] **Performance metrics**: Internal analytics and reporting data

#### Confidential Data
- [ ] **Customer data**: Non-PII customer information
- [ ] **Business data**: Sales data, partnerships, strategies
- [ ] **Financial data**: Revenue, costs, budgets (non-regulated)
- [ ] **Technical data**: Source code, architecture details

#### Restricted Data
- [ ] **Personal Identifiable Information (PII)**: Names, addresses, phone numbers
- [ ] **Payment data**: Credit card information, bank details
- [ ] **Health information (PHI)**: Medical records, health data
- [ ] **Authentication data**: Passwords, tokens, API keys
- [ ] **Legal data**: Contracts, legal documents, compliance records

---

## 🔎 API Endpoint Discovery and Mapping

### Automated Data Discovery
```bash
# Comprehensive endpoint enumeration
gobuster dir -u https://api.example.com -w /usr/share/wordlists/api-endpoints.txt

# Data-specific endpoint discovery
endpoints_to_test=(
  "/api/users" "/api/customers" "/api/profiles"
  "/api/payments" "/api/orders" "/api/transactions"
  "/api/admin" "/api/internal" "/api/debug"
  "/api/export" "/api/backup" "/api/logs"
)

for endpoint in "${endpoints_to_test[@]}"; do
  echo "Testing: $endpoint"
  curl -s "$endpoint" | jq '.' > "response_${endpoint//\//_}.json"
done
```

### Manual Discovery Techniques
- [ ] **Source Code Analysis**: Review client-side code for API calls
- [ ] **Documentation Review**: Check API documentation for all endpoints
- [ ] **Network Traffic Analysis**: Monitor HTTP/HTTPS traffic for endpoints
- [ ] **Mobile App Analysis**: Decompile mobile apps to find API endpoints
- [ ] **Error Message Analysis**: Extract endpoints from error responses
- [ ] **Sitemap Analysis**: Check robots.txt and sitemaps for API paths

### Data Flow Mapping
```python
# API response data mapping
api_data_map = {
    "/api/users": {
        "data_types": ["PII", "contact_info", "preferences"],
        "sensitivity": "restricted",
        "compliance": ["GDPR", "CCPA"],
        "retention": "7 years"
    },
    "/api/payments": {
        "data_types": ["payment_card", "financial_data"],
        "sensitivity": "restricted", 
        "compliance": ["PCI DSS"],
        "retention": "3 years"
    }
}
```

---

## 👤 Personal Identifiable Information (PII) Assessment

### Direct PII Detection
```bash
# Test user profile endpoints for PII exposure
curl https://api.example.com/users/123 | jq '.'

# Common PII fields to check for:
pii_fields=(
  "name" "full_name" "first_name" "last_name"
  "email" "phone" "mobile" "address" 
  "ssn" "social_security" "passport" "license"
  "date_of_birth" "dob" "birth_date"
  "nationality" "citizenship" "ethnicity"
)

# Check if PII is exposed in responses
for field in "${pii_fields[@]}"; do
  curl -s https://api.example.com/users/123 | grep -i "$field" && echo "Found PII: $field"
done
```

### PII Testing Checklist
- [ ] **Full Names**: First name, last name, full name exposure
- [ ] **Contact Information**: Email addresses, phone numbers, addresses
- [ ] **Identification Numbers**: SSN, passport, driver's license, national ID
- [ ] **Biometric Data**: Fingerprints, facial recognition data, voice prints
- [ ] **Personal Characteristics**: Date of birth, age, gender, nationality
- [ ] **Family Information**: Spouse, children, family member details
- [ ] **Financial Identifiers**: Bank account numbers, credit scores
- [ ] **Online Identifiers**: IP addresses, device IDs, social media handles

### Indirect PII Assessment
```bash
# Test for data that could be used to identify individuals
curl https://api.example.com/analytics/users | jq '.[] | {user_id, location, timestamp, behavior_pattern}'

# Location data analysis
curl https://api.example.com/users/location-history/123

# Behavioral pattern analysis  
curl https://api.example.com/users/activity/123
```

- [ ] **Location Data**: GPS coordinates, addresses, check-ins
- [ ] **Behavioral Patterns**: Browsing history, purchase patterns, preferences
- [ ] **Device Information**: Device fingerprints, MAC addresses, IMEI
- [ ] **Network Information**: IP addresses, network identifiers
- [ ] **Temporal Data**: Login times, activity patterns, schedules
- [ ] **Relationship Data**: Contacts, connections, social graphs

---

## 💳 Financial Data Protection Assessment

### Payment Card Information (PCI)
```bash
# Test for credit card data exposure
sensitive_patterns=(
  "4[0-9]{12}(?:[0-9]{3})?"     # Visa
  "5[1-5][0-9]{14}"             # Mastercard  
  "3[47][0-9]{13}"              # American Express
  "3[0-9]{13}"                  # Diners Club
  "6(?:011|5[0-9]{2})[0-9]{12}" # Discover
)

for pattern in "${sensitive_patterns[@]}"; do
  curl -s https://api.example.com/payments/history | grep -E "$pattern" && echo "Potential CC number found"
done
```

### Financial Data Testing
- [ ] **Primary Account Numbers (PAN)**: Credit/debit card numbers
- [ ] **Card Verification Values**: CVV, CVC, CID codes
- [ ] **Expiration Dates**: Card expiry information
- [ ] **Cardholder Names**: Names associated with payment cards
- [ ] **Magnetic Stripe Data**: Track 1, Track 2 data
- [ ] **PIN Data**: Personal identification numbers
- [ ] **Bank Account Information**: Account numbers, routing numbers
- [ ] **Payment Processor Data**: Transaction IDs, processor-specific data

### Financial Transaction Analysis
```bash
# Test payment transaction endpoints
curl https://api.example.com/transactions/user/123 | jq '.[] | {amount, currency, merchant, timestamp}'

# Check for financial patterns in responses
curl https://api.example.com/users/financial-profile/123
```

- [ ] **Transaction Details**: Amounts, currencies, timestamps
- [ ] **Merchant Information**: Payee details, merchant categories
- [ ] **Account Balances**: Current balances, available credit
- [ ] **Financial History**: Transaction history, payment patterns
- [ ] **Credit Information**: Credit scores, credit limits, payment history
- [ ] **Investment Data**: Portfolio information, trading history

---

## 🏥 Health Information (PHI) Assessment

### Protected Health Information Testing
```bash
# Test healthcare-related endpoints
healthcare_endpoints=(
  "/api/patients" "/api/medical-records" "/api/health-data"
  "/api/diagnoses" "/api/treatments" "/api/prescriptions"
  "/api/appointments" "/api/lab-results" "/api/imaging"
)

for endpoint in "${healthcare_endpoints[@]}"; do
  echo "Testing PHI endpoint: $endpoint"
  curl -s "https://api.example.com$endpoint" | jq '.'
done
```

### PHI Data Categories
- [ ] **Medical Records**: Diagnoses, treatments, medical history
- [ ] **Health Conditions**: Current conditions, disabilities, symptoms  
- [ ] **Medication Information**: Prescriptions, dosages, pharmacy data
- [ ] **Laboratory Results**: Test results, lab values, pathology reports
- [ ] **Imaging Data**: X-rays, MRIs, CT scans, ultrasounds
- [ ] **Mental Health Data**: Psychiatric records, therapy notes
- [ ] **Genetic Information**: DNA data, genetic test results
- [ ] **Biometric Data**: Health-related biometric measurements
- [ ] **Insurance Information**: Health insurance details, claims
- [ ] **Provider Information**: Healthcare provider details, relationships

### Health Data Compliance Testing
- [ ] **HIPAA Compliance**: US healthcare data protection requirements
- [ ] **GDPR Article 9**: EU special category health data protection
- [ ] **State Privacy Laws**: California, Illinois, and other state requirements
- [ ] **Medical Device Regulations**: FDA and international medical device rules

---

## 🔐 Authentication and Security Data Exposure

### Credential Exposure Testing
```bash
# Test for exposed credentials in API responses
credential_patterns=(
  "password" "passwd" "pwd" "secret" "key"
  "token" "api_key" "auth" "session" "jwt"
  "hash" "salt" "cipher" "encrypted"
)

for pattern in "${credential_patterns[@]}"; do
  curl -s https://api.example.com/users/profile | grep -i "$pattern" && echo "Potential credential exposure: $pattern"
done

# Test specific endpoints for credential leakage
curl https://api.example.com/debug/config
curl https://api.example.com/admin/system-info
curl https://api.example.com/.env
```

### Security Information Assessment
- [ ] **Passwords**: Plaintext or hashed passwords
- [ ] **API Keys**: Application programming interface keys
- [ ] **Tokens**: Authentication tokens, session tokens, JWT tokens
- [ ] **Certificates**: SSL/TLS certificates, private keys
- [ ] **Encryption Keys**: Symmetric and asymmetric encryption keys
- [ ] **Salts and Hashes**: Password salts, hash values
- [ ] **Session Data**: Session identifiers, session state
- [ ] **Security Questions**: Password reset questions and answers

### System Information Exposure
```bash
# Test for system information disclosure
curl https://api.example.com/health/status
curl https://api.example.com/actuator/env  
curl https://api.example.com/debug/routes
curl https://api.example.com/info

# Check HTTP headers for information leakage
curl -I https://api.example.com/ | grep -E "(Server|X-Powered-By|X-Version)"
```

- [ ] **Server Information**: Server versions, technology stack
- [ ] **Database Schema**: Table names, column names, relationships  
- [ ] **Configuration Data**: Application settings, environment variables
- [ ] **Error Messages**: Stack traces, internal paths, debug information
- [ ] **Network Information**: Internal IP addresses, network topology
- [ ] **Version Information**: Software versions, build numbers

---

## 📈 Business Data Protection Assessment

### Confidential Business Information
```bash
# Test business-critical endpoints
business_endpoints=(
  "/api/analytics" "/api/reports" "/api/metrics"
  "/api/customers/list" "/api/sales" "/api/revenue"
  "/api/partners" "/api/contracts" "/api/pricing"
)

for endpoint in "${business_endpoints[@]}"; do
  echo "Testing business endpoint: $endpoint"
  curl -s "https://api.example.com$endpoint" | jq '.' | head -20
done
```

### Business Data Categories  
- [ ] **Customer Lists**: Customer databases, contact lists
- [ ] **Sales Data**: Revenue figures, sales performance, forecasts
- [ ] **Pricing Information**: Product pricing, discount structures
- [ ] **Strategic Plans**: Business strategies, roadmaps, initiatives
- [ ] **Partner Information**: Partner agreements, collaboration details
- [ ] **Employee Data**: Employee records, performance data, salaries
- [ ] **Intellectual Property**: Trade secrets, patents, proprietary methods
- [ ] **Market Research**: Competitive intelligence, market analysis
- [ ] **Financial Projections**: Budgets, forecasts, investment plans
- [ ] **Operational Metrics**: KPIs, performance indicators, analytics

### Competitive Intelligence Exposure
```bash
# Test for competitive information exposure
curl https://api.example.com/competitors/analysis
curl https://api.example.com/market/research  
curl https://api.example.com/strategy/roadmap
```

- [ ] **Competitor Analysis**: Competitive positioning, market share data
- [ ] **Product Roadmaps**: Future product plans, development timelines
- [ ] **Marketing Strategies**: Campaign details, target demographics
- [ ] **Technology Stack**: Architecture details, technology choices
- [ ] **Vendor Relationships**: Supplier information, contract terms
- [ ] **Research and Development**: R&D projects, innovation pipelines

---

## 🔍 Data Over-Exposure Testing

### Response Size Analysis
```bash
# Test for excessive data in responses
curl https://api.example.com/users | jq 'length'
curl https://api.example.com/users | jq '.[0] | keys | length'

# Test pagination limits
curl "https://api.example.com/users?limit=10000" | jq 'length'
curl "https://api.example.com/users?page=1&size=999999" | jq 'length'

# Test field filtering
curl "https://api.example.com/users?fields=*" | jq '.[0] | keys'
curl "https://api.example.com/users?select=all" | jq '.[0] | keys'
```

### Over-Exposure Assessment Checklist
- [ ] **Unnecessary Fields**: APIs returning more data than needed
- [ ] **Internal IDs**: Database IDs, internal references exposed
- [ ] **System Metadata**: Creation timestamps, update flags, version numbers
- [ ] **Related Entity Data**: Associated records unnecessarily included
- [ ] **Computed Fields**: Calculated values that reveal business logic
- [ ] **Debug Information**: Development/testing data in production
- [ ] **Audit Fields**: Created_by, modified_by, deletion flags
- [ ] **Configuration Data**: Settings, preferences, feature flags

### Mass Data Extraction Testing
```bash
# Test bulk data extraction capabilities
curl "https://api.example.com/export/users"
curl "https://api.example.com/dump/database"
curl "https://api.example.com/backup/download"

# Test large limit values
curl "https://api.example.com/users?limit=999999999"

# Test enumeration through pagination
for page in {1..1000}; do
  curl "https://api.example.com/users?page=$page" >> all_users.json
done
```

- [ ] **Bulk Export**: Large-scale data extraction endpoints
- [ ] **Backup Access**: Database backup or export functionality
- [ ] **Pagination Abuse**: Excessive pagination limits
- [ ] **Search Wildcards**: Wildcard searches returning all data
- [ ] **Admin Endpoints**: Administrative data access points
- [ ] **Debug Endpoints**: Development/debug data extraction

---

## 🔒 Data Encryption and Protection Assessment

### Encryption in Transit Testing
```bash
# Test HTTPS enforcement
curl -k http://api.example.com/users -w "%{http_code}" -o /dev/null -s

# Test SSL/TLS configuration
nmap --script ssl-enum-ciphers -p 443 api.example.com
sslyze --regular api.example.com

# Test mixed content
curl https://api.example.com/users | grep -E "http://"
```

### Data at Rest Protection
```bash
# Test for unencrypted sensitive data in responses
curl https://api.example.com/users/profile | jq '.password'
curl https://api.example.com/payments/methods | jq '.card_number'

# Check database connection encryption
curl https://api.example.com/debug/database-config
```

### Encryption Assessment Checklist
- [ ] **HTTPS Enforcement**: All sensitive endpoints use HTTPS
- [ ] **TLS Version**: Modern TLS version (1.2 or higher)
- [ ] **Certificate Validity**: Valid SSL/TLS certificates
- [ ] **Perfect Forward Secrecy**: Proper key exchange mechanisms  
- [ ] **Data at Rest**: Sensitive data encrypted in storage
- [ ] **Key Management**: Proper encryption key lifecycle
- [ ] **Hashing Algorithms**: Strong hashing for passwords (bcrypt, scrypt)
- [ ] **Salting**: Proper salt usage for password hashing

---

## 📋 Mass Assignment and Parameter Pollution

### Mass Assignment Testing
```bash
# Test mass assignment vulnerabilities
curl -X POST https://api.example.com/users/profile \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "role": "admin",
    "is_verified": true,
    "account_type": "premium",
    "credits": 999999
  }'

# Test with additional sensitive fields
curl -X PUT https://api.example.com/users/123 \
  -d '{
    "name": "Updated Name",
    "internal_id": 999,
    "created_at": "2020-01-01",
    "system_role": "administrator"
  }'
```

### Parameter Pollution Testing
```bash
# HTTP Parameter Pollution (HPP) testing
curl "https://api.example.com/users?user_id=123&user_id=456"
curl "https://api.example.com/search?query=test&role=user&role=admin"

# JSON Parameter Pollution
curl -X POST https://api.example.com/api/data \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 123,
    "user_id": 456,
    "data": "test",
    "admin": false,
    "admin": true
  }'
```

### Protection Assessment
- [ ] **Input Whitelisting**: Only expected fields processed
- [ ] **Parameter Binding**: Controlled parameter-to-object binding
- [ ] **Field Validation**: Individual field validation and sanitization
- [ ] **Read-Only Fields**: System fields marked as read-only
- [ ] **Role-Based Fields**: Sensitive fields restricted by user role
- [ ] **Audit Logging**: Parameter modification attempts logged

---

## 📊 Data Classification and Labeling

### Automated Data Classification
```python
# Data classification script example
import re
import json

def classify_api_response(response_data):
    classification = {
        "public": [],
        "internal": [],
        "confidential": [],
        "restricted": []
    }
    
    # PII patterns
    pii_patterns = {
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b\d{3}-\d{3}-\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"
    }
    
    for field, value in response_data.items():
        if any(re.search(pattern, str(value)) for pattern in pii_patterns.values()):
            classification["restricted"].append(field)
        elif field in ["password", "token", "api_key"]:
            classification["restricted"].append(field)
        elif field in ["internal_id", "system_config"]:
            classification["internal"].append(field)
        else:
            classification["public"].append(field)
    
    return classification
```

### Manual Classification Review
- [ ] **Data Inventory**: Complete inventory of all data types
- [ ] **Sensitivity Labeling**: Appropriate sensitivity labels applied
- [ ] **Regulatory Mapping**: Data mapped to regulatory requirements
- [ ] **Retention Policies**: Data retention periods defined
- [ ] **Access Controls**: Access controls aligned with classification
- [ ] **Encryption Requirements**: Encryption applied based on classification

---

## 🚨 Data Breach Impact Assessment

### Breach Scenario Planning
```bash
# Simulate different breach scenarios
echo "Scenario 1: User profile data exposure"
curl https://api.example.com/users | jq '.[0] | keys' > user_data_exposure.json

echo "Scenario 2: Payment data exposure" 
curl https://api.example.com/payments | jq '.[0] | keys' > payment_data_exposure.json

echo "Scenario 3: Admin data exposure"
curl https://api.example.com/admin/users | jq '.[0] | keys' > admin_data_exposure.json
```

### Impact Assessment Matrix
| Data Type | Volume | Regulatory Impact | Financial Impact | Reputational Impact |
|-----------|--------|------------------|------------------|-------------------|
| User PII | 100K records | GDPR fines (€20M) | High | Severe |
| Payment Data | 50K cards | PCI fines ($500K) | Very High | Severe |
| Health Records | 25K patients | HIPAA fines ($1.5M) | Very High | Severe |
| Business Data | Confidential | Competitive loss | Medium | High |

### Breach Response Planning
- [ ] **Detection Systems**: Automated breach detection capabilities
- [ ] **Response Procedures**: Documented incident response procedures
- [ ] **Notification Requirements**: Regulatory notification procedures
- [ ] **Customer Communication**: Customer breach notification processes
- [ ] **Forensic Capabilities**: Digital forensic investigation capabilities
- [ ] **Recovery Procedures**: Data recovery and business continuity plans

---

## ✅ Data Protection Compliance Verification

### GDPR Compliance Checklist
- [ ] **Data Minimization**: Only necessary data collected and processed
- [ ] **Purpose Limitation**: Data used only for stated purposes
- [ ] **Storage Limitation**: Data retention periods defined and enforced
- [ ] **Accuracy**: Data accuracy maintained and corrections possible
- [ ] **Security**: Appropriate technical and organizational measures
- [ ] **Accountability**: Data processing activities documented

### PCI DSS Compliance (if applicable)
- [ ] **Cardholder Data Protection**: CHD properly protected and encrypted
- [ ] **Access Controls**: Restricted access to cardholder data
- [ ] **Network Security**: Secure network architecture
- [ ] **Vulnerability Management**: Regular security testing and updates
- [ ] **Monitoring**: Comprehensive logging and monitoring
- [ ] **Policy Maintenance**: Information security policies maintained

### HIPAA Compliance (if applicable)
- [ ] **PHI Protection**: Protected health information secured
- [ ] **Access Controls**: Minimum necessary access principle
- [ ] **Audit Trails**: Comprehensive audit logging
- [ ] **Encryption**: PHI encrypted in transit and at rest
- [ ] **Business Associates**: BAAs with third-party vendors
- [ ] **Risk Assessment**: Regular risk assessments conducted

---

## 📈 Continuous Data Protection Monitoring

### Automated Monitoring Setup
```yaml
# Data protection monitoring configuration
data_monitoring:
  sensitive_data_detection:
    - pattern: "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"
      type: "credit_card"
      severity: "critical"
    - pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"  
      type: "ssn"
      severity: "critical"
    - pattern: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"
      type: "email"
      severity: "medium"
      
  response_monitoring:
    max_response_size: "10MB"
    max_records_returned: 1000
    sensitive_field_detection: true
    
  compliance_monitoring:
    gdpr_data_subjects: true
    pci_cardholder_data: true
    hipaa_phi_data: true
```

### Regular Assessment Schedule
- **Daily**: Automated data exposure scanning
- **Weekly**: Data classification review and updates  
- **Monthly**: Data protection control effectiveness review
- **Quarterly**: Comprehensive data protection assessment
- **Annually**: Full data protection audit and compliance review

---

This comprehensive data exposure checklist should be used systematically to identify, assess, and protect sensitive data in API endpoints. Regular assessment and monitoring ensure ongoing data protection and regulatory compliance.