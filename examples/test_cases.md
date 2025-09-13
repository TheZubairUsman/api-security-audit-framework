# API Security Test Cases and Scenarios

This directory contains comprehensive test cases, scenarios, and methodologies for testing API security across different industries and use cases.

## 📁 Directory Structure

```
test-cases/
├── README.md                          # This file
├── e-commerce/
│   ├── shopping-cart-tests.json      # Shopping cart security tests
│   ├── payment-flow-scenarios.py     # Payment processing tests
│   ├── product-catalog-tests.sh      # Product API security tests
│   └── user-account-tests.md         # User management test cases
├── financial-services/
│   ├── banking-api-tests.py          # Banking API security tests
│   ├── payment-gateway-tests.json   # Payment gateway scenarios
│   ├── fraud-detection-tests.sh     # Fraud prevention tests
│   └── compliance-tests.md          # Financial compliance tests
├── healthcare/
│   ├── patient-data-tests.py        # PHI protection tests
│   ├── hipaa-compliance-tests.json  # HIPAA compliance scenarios
│   ├── medical-device-tests.sh      # Medical device API tests
│   └── provider-portal-tests.md     # Healthcare provider tests
├── saas-platforms/
│   ├── multi-tenant-tests.py        # Multi-tenancy security tests
│   ├── subscription-tests.json      # Subscription management tests
│   ├── api-rate-limiting-tests.sh   # Rate limiting scenarios
│   └── integration-tests.md         # Third-party integration tests
├── mobile-backends/
│   ├── mobile-auth-tests.py         # Mobile authentication tests
│   ├── device-management-tests.json # Device registration tests
│   ├── push-notification-tests.sh   # Push notification security
│   └── offline-sync-tests.md        # Offline synchronization tests
├── iot-platforms/
│   ├── device-provisioning-tests.py # IoT device provisioning
│   ├── telemetry-tests.json         # Device telemetry security
│   ├── firmware-update-tests.sh     # OTA update security
│   └── device-identity-tests.md     # Device identity management
└── microservices/
    ├── service-mesh-tests.py        # Service mesh security tests
    ├── api-gateway-tests.json       # API gateway scenarios
    ├── inter-service-tests.sh       # Inter-service communication
    └── container-security-tests.md  # Container security tests
```

## 🎯 Test Case Categories

### 1. Functional Security Testing
Test cases that verify security controls work as intended:
- Authentication mechanisms
- Authorization enforcement
- Input validation
- Output encoding
- Session management

### 2. Negative Security Testing
Test cases designed to break security controls:
- Boundary value testing
- Invalid input testing
- Error condition testing
- Bypass attempt testing
- Stress testing

### 3. Business Logic Testing
Industry-specific business logic security tests:
- Workflow integrity
- Data consistency
- Financial transaction security
- Compliance requirement validation
- Business rule enforcement

### 4. Integration Security Testing
Test cases for API integrations:
- Third-party service security
- Data flow security
- Trust boundary validation
- API composition security
- Legacy system integration

## 🏭 Industry-Specific Scenarios

### E-commerce Platform Testing

#### Shopping Cart Security Test Suite
```python
# Example test case structure
test_cases = {
    "cart_manipulation": {
        "description": "Test price and quantity manipulation in shopping cart",
        "severity": "High",
        "test_steps": [
            "Add item to cart with normal price",
            "Intercept request and modify price to negative value", 
            "Submit modified request",
            "Verify system rejects invalid price"
        ],
        "expected_result": "System should reject negative prices",
        "actual_result": "TBD",
        "status": "Not Tested"
    }
}
```

#### Key Test Scenarios:
- **Price Manipulation:** Negative prices, currency conversion exploits
- **Inventory Bypass:** Purchasing out-of-stock items
- **Discount Abuse:** Stacking discount codes, expired coupon usage
- **Cart Persistence:** Session hijacking, cart manipulation across sessions
- **Payment Bypass:** Skipping payment steps, amount manipulation

### Financial Services Testing

#### Banking API Security Tests
```json
{
  "account_enumeration": {
    "test_id": "BANK-001",
    "category": "Information Disclosure",
    "description": "Test for account number enumeration vulnerabilities",
    "risk_level": "High",
    "test_method": "Sequential account number testing",
    "payloads": [
      {"account_id": "1000000001"},
      {"account_id": "1000000002"}, 
      {"account_id": "1000000003"}
    ],
    "success_criteria": "System should not reveal valid account numbers",
    "compliance_frameworks": ["PCI DSS", "SOX", "GDPR"]
  }
}
```

#### Key Test Scenarios:
- **Transaction Manipulation:** Amount modification, currency exploits
- **Account Enumeration:** Valid account number discovery
- **Authorization Bypass:** Access to other customer accounts
- **Race Conditions:** Concurrent transaction processing
- **Fraud Detection:** Testing fraud prevention mechanisms

### Healthcare API Testing

#### HIPAA Compliance Test Cases
```bash
#!/bin/bash
# PHI Exposure Test Script

echo "Testing PHI exposure in API responses..."

# Test 1: Patient data without proper authorization
curl -X GET "https://api.hospital.com/patients/123" \
  -H "Authorization: Bearer invalid_token" \
  -o patient_data_test.json

# Check if PHI is exposed in unauthorized response
if grep -q "ssn\|social_security\|dob" patient_data_test.json; then
    echo "FAIL: PHI exposed without proper authorization"
else
    echo "PASS: PHI properly protected"
fi

# Test 2: Bulk patient data access
curl -X GET "https://api.hospital.com/patients?limit=1000" \
  -H "Authorization: Bearer limited_access_token" \
  -o bulk_patient_test.json

# Verify bulk access restrictions
patient_count=$(jq '. | length' bulk_patient_test.json)
if [ "$patient_count" -gt 10 ]; then
    echo "FAIL: Excessive patient data returned"
else  
    echo "PASS: Bulk access properly limited"
fi
```

#### Key Test Scenarios:
- **PHI Protection:** Unauthorized access to health information
- **Audit Logging:** Proper logging of PHI access attempts
- **Data Minimization:** Limiting data returned to necessary information
- **Consent Management:** Proper consent verification for data access
- **Provider Authentication:** Strong authentication for healthcare providers

## 🧪 Test Case Templates

### Security Test Case Template
```yaml
test_case:
  id: "TC-{CATEGORY}-{NUMBER}"
  title: "Descriptive test case title"
  category: "Authentication|Authorization|Input Validation|Business Logic"
  priority: "Critical|High|Medium|Low"
  
  description: |
    Detailed description of what the test case is validating
    
  preconditions:
    - "System is deployed and accessible"
    - "Test user accounts are available" 
    - "Required test data is prepared"
    
  test_steps:
    - step: 1
      action: "Specific action to perform"
      expected: "Expected system response"
    - step: 2  
      action: "Next action based on previous result"
      expected: "Expected response for this step"
      
  test_data:
    - name: "test_user_credentials"
      value: "username: testuser, password: testpass123"
    - name: "malicious_payload"
      value: "'; DROP TABLE users; --"
      
  expected_result: "What should happen when test passes"
  
  validation_criteria:
    - "HTTP response code should be 400 or 403"
    - "Error message should not reveal system details"
    - "Request should be logged in security audit log"
    
  risk_assessment:
    likelihood: "High|Medium|Low"
    impact: "Critical|High|Medium|Low"
    cvss_score: "0.0 - 10.0"
    
  compliance_mapping:
    - framework: "OWASP API Top 10"
      control: "API1:2023 Broken Object Level Authorization"
    - framework: "NIST CSF"
      control: "PR.AC-1 Identity Management"
      
  automation:
    automated: true|false
    tool: "pytest|postman|custom_script"
    script_location: "path/to/automation/script"
    
  reporting:
    evidence_collection: "Screenshots, logs, response data"
    documentation: "Link to detailed test documentation"
    
  maintenance:
    created_by: "Test author name"
    created_date: "YYYY-MM-DD"
    last_updated: "YYYY-MM-DD"
    review_frequency: "Monthly|Quarterly|Annually"
```

### Automated Test Case Example
```python
import requests
import pytest
import json
from datetime import datetime

class TestAPIAuthentication:
    """Authentication security test cases"""
    
    def setup_method(self):
        """Setup test environment"""
        self.base_url = "https://api.example.com"
        self.valid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        self.invalid_token = "invalid_token_example"
        
    @pytest.mark.security
    @pytest.mark.critical
    def test_authentication_bypass_with_invalid_token(self):
        """
        Test Case: TC-AUTH-001
        Verify that invalid tokens are rejected
        """
        # Test data
        endpoint = f"{self.base_url}/api/users/profile"
        headers = {"Authorization": f"Bearer {self.invalid_token}"}
        
        # Execute test
        response = requests.get(endpoint, headers=headers)
        
        # Assertions
        assert response.status_code in [401, 403], f"Expected 401/403, got {response.status_code}"
        assert "error" in response.json(), "Error message should be present"
        assert "unauthorized" in response.json()["error"].lower(), "Should indicate unauthorized access"
        
        # Log test result
        self._log_test_result("TC-AUTH-001", "PASS", response)
    
    @pytest.mark.security  
    @pytest.mark.high
    def test_jwt_algorithm_confusion(self):
        """
        Test Case: TC-AUTH-002
        Test JWT algorithm confusion vulnerability
        """
        # Create JWT with 'none' algorithm
        malicious_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
        
        endpoint = f"{self.base_url}/api/admin/users"
        headers = {"Authorization": f"Bearer {malicious_token}"}
        
        response = requests.get(endpoint, headers=headers)
        
        # Should reject 'none' algorithm tokens
        assert response.status_code in [401, 403], "None algorithm should be rejected"
        
        self._log_test_result("TC-AUTH-002", "PASS", response)
    
    def _log_test_result(self, test_id, status, response):
        """Log test results for reporting"""
        result = {
            "test_id": test_id,
            "timestamp": datetime.now().isoformat(),
            "status": status,
            "response_code": response.status_code,
            "response_body": response.text[:500]  # First 500 chars
        }
        
        with open("test_results.json", "a") as f:
            f.write(json.dumps(result) + "\n")
```

## 📋 Test Execution Framework

### Test Planning and Organization

#### Test Suite Organization
```
test_suite/
├── critical/           # Critical security tests (must pass)
├── high/              # High priority tests 
├── medium/            # Medium priority tests
├── low/               # Low priority tests  
├── compliance/        # Regulatory compliance tests
├── performance/       # Security performance tests
└── exploratory/       # Manual exploratory tests
```

#### Test Execution Matrix
| Test Category | Frequency | Environment | Automation Level |
|---------------|-----------|-------------|------------------|
| **Critical Security** | Every commit | CI/CD Pipeline | 100% Automated |
| **High Priority** | Daily | Staging | 90% Automated |
| **Medium Priority** | Weekly | Staging | 70% Automated |
| **Low Priority** | Monthly | Staging | 50% Automated |
| **Compliance** | Quarterly | Production-like | Manual + Automated |
| **Penetration** | Annually | Production-like | Manual |

### Continuous Integration Integration

#### GitHub Actions Example
```yaml
name: API Security Testing

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-tests:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
        
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-html
        
    - name: Run Critical Security Tests
      run: |
        pytest tests/critical/ -v --html=reports/critical-security-report.html
        
    - name: Run OWASP ZAP Baseline Scan  
      uses: zaproxy/action-baseline@v0.7.0
      with:
        target: 'http://api.example.com'
        
    - name: Upload Security Reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: security-reports
        path: reports/
```

#### Jenkins Pipeline Example
```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Test Preparation') {
            steps {
                script {
                    // Start test environment
                    sh 'docker-compose up -d test-api'
                    sh 'sleep 30'  // Wait for API to start
                }
            }
        }
        
        stage('Critical Security Tests') {
            steps {
                script {
                    def testResult = sh(
                        script: 'pytest tests/critical/ --junitxml=results/critical.xml',
                        returnStatus: true
                    )
                    
                    if (testResult != 0) {
                        currentBuild.result = 'FAILURE'
                        error("Critical security tests failed")
                    }
                }
            }
            post {
                always {
                    junit 'results/critical.xml'
                }
            }
        }
        
        stage('Automated Penetration Testing') {
            steps {
                sh '''
                    # Run OWASP ZAP
                    zap-baseline.py -t http://test-api:8080 -r zap-report.html
                    
                    # Run Nikto scan
                    nikto -h http://test-api:8080 -output nikto-report.txt
                    
                    # Custom security tests
                    python3 scripts/custom-security-scan.py --target http://test-api:8080
                '''
            }
        }
    }
    
    post {
        always {
            // Cleanup
            sh 'docker-compose down'
            
            // Archive reports
            archiveArtifacts artifacts: '**/*-report.*', allowEmptyArchive: true
            
            // Send notifications
            emailext (
                subject: "Security Test Results - ${currentBuild.fullDisplayName}",
                body: "Security test results are available at ${BUILD_URL}",
                to: "${SECURITY_TEAM_EMAIL}"
            )
        }
    }
}
```

## 🎯 Specialized Test Scenarios

### API Rate Limiting Test Suite
```python
import asyncio
import aiohttp
import time
from concurrent.futures import ThreadPoolExecutor

class RateLimitingTests:
    """Comprehensive rate limiting security tests"""
    
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key
    
    async def test_concurrent_requests(self, endpoint, request_count=100):
        """Test rate limiting under concurrent load"""
        
        async with aiohttp.ClientSession() as session:
            # Create concurrent requests
            tasks = []
            for i in range(request_count):
                task = self._make_request(session, endpoint)
                tasks.append(task)
            
            # Execute all requests simultaneously
            start_time = time.time()
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            end_time = time.time()
            
            # Analyze results
            status_codes = [r.status for r in responses if hasattr(r, 'status')]
            rate_limited_count = status_codes.count(429)
            successful_count = status_codes.count(200)
            
            results = {
                "total_requests": request_count,
                "successful_requests": successful_count,
                "rate_limited_requests": rate_limited_count,
                "duration": end_time - start_time,
                "requests_per_second": request_count / (end_time - start_time)
            }
            
            return results
    
    async def _make_request(self, session, endpoint):
        """Make individual API request"""
        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with session.get(f"{self.base_url}{endpoint}", headers=headers) as response:
            return response
    
    def test_rate_limit_bypass_techniques(self):
        """Test various rate limit bypass methods"""
        
        bypass_techniques = [
            {"name": "X-Forwarded-For Header", "headers": {"X-Forwarded-For": "192.168.1.100"}},
            {"name": "X-Real-IP Header", "headers": {"X-Real-IP": "10.0.0.1"}},
            {"name": "User-Agent Rotation", "headers": {"User-Agent": "Mozilla/5.0 (Different Browser)"}},
            {"name": "Origin Header", "headers": {"Origin": "https://trusted-domain.com"}},
        ]
        
        results = {}
        
        for technique in bypass_techniques:
            # Test bypass technique
            success_count = self._test_bypass_technique(technique)
            results[technique["name"]] = {
                "successful_bypasses": success_count,
                "bypass_effective": success_count > 0
            }
        
        return results

    def _test_bypass_technique(self, technique):
        """Test a specific bypass technique"""
        endpoint = "/api/data"
        base_headers = {"Authorization": f"Bearer {self.api_key}"}
        test_headers = {**base_headers, **technique["headers"]}
        
        # First, exhaust rate limit with normal requests
        self._exhaust_rate_limit(endpoint, base_headers)
        
        # Then try bypass technique
        bypass_response = requests.get(f"{self.base_url}{endpoint}", headers=test_headers)
        
        # Return 1 if bypass worked (got 200 instead of 429), 0 otherwise
        return 1 if bypass_response.status_code == 200 else 0
```

### Business Logic Test Framework
```python
class BusinessLogicTests:
    """Business logic security test framework"""
    
    def test_price_manipulation_scenarios(self):
        """Test various price manipulation attacks"""
        
        test_scenarios = [
            {
                "name": "Negative Price Test",
                "payload": {"product_id": 1, "price": -100.00, "quantity": 1},
                "expected_behavior": "reject_negative_price"
            },
            {
                "name": "Zero Price Test", 
                "payload": {"product_id": 1, "price": 0.00, "quantity": 10},
                "expected_behavior": "reject_zero_price"
            },
            {
                "name": "Extreme Precision Test",
                "payload": {"product_id": 1, "price": 99.999999999999, "quantity": 1},
                "expected_behavior": "handle_precision_properly"
            },
            {
                "name": "Currency Overflow Test",
                "payload": {"product_id": 1, "price": 999999999999.99, "quantity": 1},
                "expected_behavior": "prevent_overflow"
            }
        ]
        
        results = []
        for scenario in test_scenarios:
            result = self._execute_business_logic_test(scenario)
            results.append(result)
            
        return results
    
    def test_workflow_bypass_scenarios(self):
        """Test business workflow bypass attempts"""
        
        # Test skipping payment step
        order_id = self._create_test_order()
        
        # Attempt to fulfill order without payment
        bypass_result = self._attempt_workflow_bypass(
            order_id, 
            skip_step="payment",
            target_step="fulfillment"
        )
        
        assert bypass_result["bypassed"] == False, "Workflow bypass should be prevented"
        
        return bypass_result

    def test_race_condition_vulnerabilities(self):
        """Test for race condition vulnerabilities"""
        
        # Test concurrent withdrawal from same account
        account_id = "test_account_123"
        initial_balance = self._get_account_balance(account_id)
        withdrawal_amount = initial_balance  # Try to withdraw full balance
        
        # Execute concurrent withdrawals
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for i in range(10):
                future = executor.submit(self._attempt_withdrawal, account_id, withdrawal_amount)
                futures.append(future)
            
            # Collect results
            results = [future.result() for future in futures]
        
        # Check if race condition was exploited
        successful_withdrawals = sum(1 for r in results if r["success"])
        final_balance = self._get_account_balance(account_id)
        
        race_condition_detected = successful_withdrawals > 1 or final_balance < 0
        
        return {
            "initial_balance": initial_balance,
            "successful_withdrawals": successful_withdrawals,
            "final_balance": final_balance,
            "race_condition_exploited": race_condition_detected
        }
```

## 📊 Test Reporting and Metrics

### Security Test Dashboard
```python
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime, timedelta

class SecurityTestDashboard:
    """Generate security testing reports and visualizations"""
    
    def __init__(self, test_results_file):
        self.results_df = pd.read_json(test_results_file, lines=True)
    
    def generate_security_summary(self):
        """Generate executive summary of security test results"""
        
        total_tests = len(self.results_df)
        passed_tests = len(self.results_df[self.results_df['status'] == 'PASS'])
        failed_tests = len(self.results_df[self.results_df['status'] == 'FAIL'])
        
        # Group by severity
        severity_counts = self.results_df['severity'].value_counts()
        
        # Calculate metrics
        pass_rate = (passed_tests / total_tests) * 100
        
        summary = {
            "total_tests_executed": total_tests,
            "tests_passed": passed_tests,
            "tests_failed": failed_tests,
            "overall_pass_rate": f"{pass_rate:.1f}%",
            "critical_failures": severity_counts.get('Critical', 0),
            "high_failures": severity_counts.get('High', 0),
            "medium_failures": severity_counts.get('Medium', 0),
            "low_failures": severity_counts.get('Low', 0)
        }
        
        return summary
    
    def generate_trend_analysis(self, days=30):
        """Generate security test trends over time"""
        
        # Filter last N days
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_results = self.results_df[
            pd.to_datetime(self.results_df['timestamp']) >= cutoff_date
        ]
        
        # Group by date
        daily_stats = recent_results.groupby(
            pd.to_datetime(recent_results['timestamp']).dt.date
        ).agg({
            'status': lambda x: (x == 'PASS').sum() / len(x) * 100,
            'test_id': 'count'
        }).rename(columns={'status': 'pass_rate', 'test_id': 'total_tests'})
        
        return daily_stats
    
    def create_security_charts(self):
        """Create visual charts for security test results"""
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        
        # Chart 1: Pass/Fail Distribution
        pass_fail_counts = self.results_df['status'].value_counts()
        ax1.pie(pass_fail_counts.values, labels=pass_fail_counts.index, autopct='%1.1f%%')
        ax1.set_title('Test Results Distribution')
        
        # Chart 2: Issues by Severity
        severity_counts = self.results_df[self.results_df['status'] == 'FAIL']['severity'].value_counts()
        ax2.bar(severity_counts.index, severity_counts.values, color=['red', 'orange', 'yellow', 'blue'])
        ax2.set_title('Failed Tests by Severity')
        ax2.set_ylabel('Number of Failures')
        
        # Chart 3: Test Categories
        category_counts = self.results_df['category'].value_counts()
        ax3.barh(category_counts.index, category_counts.values)
        ax3.set_title('Tests by Category')
        ax3.set_xlabel('Number of Tests')
        
        # Chart 4: Trend Over Time
        trend_data = self.generate_trend_analysis()
        ax4.plot(trend_data.index, trend_data['pass_rate'], marker='o')
        ax4.set_title('Pass Rate Trend (Last 30 Days)')
        ax4.set_ylabel('Pass Rate (%)')
        ax4.set_ylim(0, 100)
        
        plt.tight_layout()
        plt.savefig('security_test_dashboard.png', dpi=300, bbox_inches='tight')
        
        return 'security_test_dashboard.png'
```

### Test Results Format
```json
{
  "test_execution": {
    "execution_id": "exec_20240115_143022",
    "start_time": "2024-01-15T14:30:22Z",
    "end_time": "2024-01-15T14:45:18Z",
    "total_duration": "14m 56s",
    "environment": "staging",
    "target_system": "https://api.example.com"
  },
  "summary": {
    "total_tests": 156,
    "passed": 134,
    "failed": 18,
    "skipped": 4,
    "pass_rate": 85.9,
    "critical_failures": 2,
    "high_failures": 6,
    "medium_failures": 8,
    "low_failures": 2
  },
  "test_results": [
    {
      "test_id": "TC-AUTH-001",
      "test_name": "Authentication Bypass Test",
      "category": "Authentication",
      "severity": "Critical",
      "status": "FAIL",
      "execution_time": "2.3s",
      "error_message": "Invalid token was accepted",
      "evidence": {
        "request": "GET /api/admin/users HTTP/1.1\nAuthorization: Bearer invalid_token",
        "response": "HTTP/1.1 200 OK\n{\"users\": [...]}",
        "screenshot": "evidence/auth_bypass_001.png"
      },
      "remediation": "Implement proper JWT token validation"
    }
  ],
  "compliance_results": {
    "owasp_api_top_10": {
      "covered": 10,
      "total": 10,
      "compliance_percentage": 100,
      "failed_controls": ["API1:2023 - Broken Object Level Authorization"]
    },
    "pci_dss": {
      "applicable": true,
      "compliance_percentage": 78,
      "failed_requirements": ["6.3.1", "11.2.1"]
    }
  }
}
```

## 🔄 Continuous Improvement Process

### Test Case Maintenance
- **Monthly Reviews:** Update test cases based on new vulnerabilities
- **Quarterly Assessments:** Review test coverage and effectiveness  
- **Annual Overhauls:** Complete test suite review and modernization
- **Incident-Driven Updates:** Add test cases based on production incidents

### Community Contributions
- **Template Sharing:** Contribute test case templates to the community
- **Vulnerability Patterns:** Share new vulnerability patterns discovered
- **Tool Integration:** Contribute automation scripts and tool integrations
- **Best Practices:** Document lessons learned and best practices

---

This comprehensive test case library provides a solid foundation for API security testing across various industries and scenarios. Regular updates and community contributions help keep the test cases current with evolving threat landscapes and security best practices.