# GraphQL Security Audit Checklist

## Overview

This checklist provides a systematic approach to auditing GraphQL API security. Use this alongside the [GraphQL Security Guide](../docs/graphql-security.md) for comprehensive testing.

## Pre-Audit Setup

### Environment Preparation
- [ ] **Testing Environment**: Confirm testing authorization and scope
- [ ] **Tools Setup**: Install GraphQL testing tools (GraphQL Cop, InQL, etc.)
- [ ] **Documentation**: Gather available GraphQL schema documentation
- [ ] **Credentials**: Obtain test accounts with different privilege levels
- [ ] **Baseline**: Document normal application behavior

### Scope Definition
- [ ] **Endpoints**: Identify all GraphQL endpoints
- [ ] **Operations**: Map queries, mutations, and subscriptions
- [ ] **Data Types**: Catalog sensitive data handled by API
- [ ] **User Roles**: Define different user privilege levels
- [ ] **Compliance**: Note applicable regulations (GDPR, HIPAA, PCI DSS)

## Discovery Phase

### Endpoint Discovery
- [ ] **Common Paths**: Test standard GraphQL endpoints
  - `/graphql`
  - `/graphiql`
  - `/api/graphql`
  - `/v1/graphql`
  - `/query`
  - `/api/query`
- [ ] **HTTP Methods**: Test GET and POST methods
- [ ] **Content Types**: Test `application/json` and `application/graphql`
- [ ] **Alternative Endpoints**: Check for development/debug endpoints

### Schema Discovery
- [ ] **Introspection Query**: Test if introspection is enabled
  ```graphql
  query IntrospectionQuery {
    __schema {
      types {
        name
        fields {
          name
          type {
            name
          }
        }
      }
    }
  }
  ```
- [ ] **Schema Extraction**: Extract complete schema if introspection enabled
- [ ] **Type Analysis**: Identify custom types and their relationships
- [ ] **Sensitive Fields**: Flag PII, financial, and admin-only fields
- [ ] **Deprecated Fields**: Check for deprecated but accessible fields

### Operation Discovery
- [ ] **Query Operations**: Identify all available queries
- [ ] **Mutation Operations**: Map state-changing operations
- [ ] **Subscription Operations**: Test real-time subscription endpoints
- [ ] **Custom Directives**: Identify custom schema directives
- [ ] **Input Types**: Catalog all input type definitions

## Authentication Testing

### Authentication Bypass
- [ ] **No Authentication**: Test queries without authentication
- [ ] **Invalid Tokens**: Test with malformed authentication tokens
- [ ] **Expired Tokens**: Test with expired authentication tokens
- [ ] **Token Manipulation**: Test with modified token payloads
- [ ] **Alternative Auth Methods**: Test different authentication mechanisms

### Token Security
- [ ] **JWT Vulnerabilities**: Test for JWT-specific vulnerabilities
  - Algorithm confusion (RS256 to HS256)
  - None algorithm acceptance
  - Weak signing secrets
- [ ] **Token Storage**: Check for tokens in logs or error messages
- [ ] **Token Expiration**: Verify proper token expiration handling
- [ ] **Token Revocation**: Test token invalidation mechanisms

### Session Management
- [ ] **Session Fixation**: Test for session fixation vulnerabilities
- [ ] **Session Hijacking**: Test session token security
- [ ] **Concurrent Sessions**: Test multiple session handling
- [ ] **Session Timeout**: Verify proper session expiration

## Authorization Testing

### Field-Level Authorization
- [ ] **Horizontal Escalation**: Test access to other users' data
  ```graphql
  query TestHorizontalEscalation {
    user(id: "other_user_id") {
      personalData {
        ssn
        creditCard
      }
    }
  }
  ```
- [ ] **Vertical Escalation**: Test access to higher privilege data
  ```graphql
  query TestVerticalEscalation {
    adminUsers {
      id
      permissions
      sensitiveData
    }
  }
  ```
- [ ] **Field Restrictions**: Test access to restricted fields
- [ ] **Nested Object Authorization**: Test authorization in nested objects
- [ ] **Cross-Entity Access**: Test access across different entity types

### Operation Authorization
- [ ] **Query Authorization**: Test unauthorized query execution
- [ ] **Mutation Authorization**: Test unauthorized data modification
- [ ] **Subscription Authorization**: Test unauthorized subscription access
- [ ] **Admin Operations**: Test access to administrative operations
- [ ] **Bulk Operations**: Test authorization for bulk data operations

### Role-Based Access Control
- [ ] **Role Verification**: Test different user role restrictions
- [ ] **Permission Inheritance**: Test hierarchical permission models
- [ ] **Dynamic Permissions**: Test context-dependent permissions
- [ ] **Resource-Based Access**: Test object-level permissions

## Input Validation Testing

### Injection Attacks
- [ ] **SQL Injection**: Test SQL injection in all parameters
  ```graphql
  query SQLInjectionTest($userId: String!) {
    user(id: $userId) { name email }
  }
  # Variables: {"userId": "1' OR '1'='1"}
  ```
- [ ] **NoSQL Injection**: Test NoSQL injection patterns
  ```graphql
  mutation NoSQLTest($filter: String!) {
    users(filter: $filter) { id }
  }
  # Variables: {"filter": "{\"$where\": \"this.password.match(/.*/)\"}"}
  ```
- [ ] **Command Injection**: Test OS command injection
- [ ] **LDAP Injection**: Test LDAP injection if applicable
- [ ] **XPath Injection**: Test XPath injection if XML processing used

### Cross-Site Scripting (XSS)
- [ ] **Reflected XSS**: Test XSS in query responses
- [ ] **Stored XSS**: Test XSS in mutations that store data
- [ ] **DOM XSS**: Test client-side XSS vulnerabilities
- [ ] **Template Injection**: Test server-side template injection

### Input Validation Bypass
- [ ] **Type Confusion**: Test sending wrong data types
- [ ] **Null Byte Injection**: Test null byte handling
- [ ] **Unicode Bypass**: Test Unicode normalization issues
- [ ] **Length Limits**: Test input length restrictions
- [ ] **Special Characters**: Test handling of special characters

## Denial of Service Testing

### Query Complexity Attacks
- [ ] **Deep Nesting**: Test deeply nested queries
  ```graphql
  query DeepQuery {
    user {
      posts {
        comments {
          author {
            posts {
              comments {
                title
              }
            }
          }
        }
      }
    }
  }
  ```
- [ ] **Query Aliases**: Test multiple aliased operations
  ```graphql
  query AliasAttack {
    a: users { id name email }
    b: users { id name email }
    c: users { id name email }
    # ... repeat many times
  }
  ```
- [ ] **Circular References**: Test circular query patterns
- [ ] **Large Result Sets**: Test queries returning large datasets
- [ ] **Complex Filters**: Test resource-intensive filtering operations

### Resource Exhaustion
- [ ] **Memory Consumption**: Test memory-intensive operations
- [ ] **CPU Usage**: Test CPU-intensive queries
- [ ] **Database Load**: Test database-heavy operations
- [ ] **Network Bandwidth**: Test large response payloads
- [ ] **Connection Exhaustion**: Test connection pool limits

### Batch Query Attacks
- [ ] **Batch Size Limits**: Test batch query size restrictions
  ```json
  [
    {"query": "query { users { id } }"},
    {"query": "query { users { id } }"},
    // ... repeat many times
  ]
  ```
- [ ] **Batch Complexity**: Combine batching with complex queries
- [ ] **Rate Limit Bypass**: Test if batching bypasses rate limits

### Subscription Abuse
- [ ] **Connection Limits**: Test subscription connection limits
- [ ] **Complex Subscriptions**: Test resource-intensive subscriptions
- [ ] **Subscription Bombing**: Test multiple subscription creation
- [ ] **Memory Leaks**: Test for subscription memory leaks

## Information Disclosure Testing

### Schema Information Leakage
- [ ] **Introspection Enabled**: Check if introspection is disabled in production
- [ ] **Schema Documentation**: Test for exposed schema documentation
- [ ] **GraphiQL Interface**: Check for exposed GraphiQL playground
- [ ] **Schema Versioning**: Test for multiple schema versions

### Error Message Analysis
- [ ] **Verbose Errors**: Test for detailed error messages
- [ ] **Stack Traces**: Check for exposed stack traces
- [ ] **Database Errors**: Test for database error exposure
- [ ] **Internal Paths**: Check for internal file path disclosure
- [ ] **Debug Information**: Test for debug mode indicators

### Data Leakage
- [ ] **Sensitive Field Exposure**: Test for unintended sensitive data exposure
- [ ] **Metadata Leakage**: Check for system metadata in responses
- [ ] **Timing Attacks**: Test for timing-based information disclosure
- [ ] **Cache Poisoning**: Test for cache-based data leakage

## Rate Limiting and Throttling

### Rate Limit Testing
- [ ] **Request Rate Limits**: Test API request rate limiting
- [ ] **Query-Specific Limits**: Test operation-specific rate limits
- [ ] **User-Based Limits**: Test per-user rate limiting
- [ ] **IP-Based Limits**: Test IP-based rate limiting
- [ ] **Resource-Based Limits**: Test resource consumption limits

### Rate Limit Bypass
- [ ] **Header Manipulation**: Test X-Forwarded-For and similar headers
- [ ] **User-Agent Rotation**: Test User-Agent based bypasses
- [ ] **Distributed Requests**: Test from multiple IP addresses
- [ ] **Batch Query Bypass**: Test if batching bypasses limits
- [ ] **Subscription Bypass**: Test if subscriptions bypass limits

### Throttling Mechanisms
- [ ] **Progressive Delays**: Test exponential backoff implementation
- [ ] **Circuit Breakers**: Test circuit breaker functionality
- [ ] **Queue Management**: Test request queuing mechanisms
- [ ] **Priority Handling**: Test request priority systems

## Business Logic Testing

### Workflow Bypass
- [ ] **State Manipulation**: Test improper state transitions
- [ ] **Process Skipping**: Test bypassing required workflow steps
- [ ] **Concurrent Operations**: Test race conditions in business logic
- [ ] **Transaction Integrity**: Test transaction rollback mechanisms

### Data Consistency
- [ ] **Referential Integrity**: Test data relationship consistency
- [ ] **Constraint Validation**: Test business rule enforcement
- [ ] **Data Synchronization**: Test data consistency across operations
- [ ] **Audit Trail**: Test audit logging completeness

### Financial Logic (if applicable)
- [ ] **Price Manipulation**: Test price calculation logic
- [ ] **Currency Handling**: Test multi-currency operations
- [ ] **Transaction Limits**: Test financial transaction limits
- [ ] **Refund Logic**: Test refund and reversal operations

## Subscription Security Testing

### WebSocket Security
- [ ] **Connection Authentication**: Test WebSocket authentication
- [ ] **Origin Validation**: Test WebSocket origin restrictions
- [ ] **Protocol Security**: Test WebSocket protocol implementation
- [ ] **Message Validation**: Test subscription message validation

### Subscription Authorization
- [ ] **Subscription Access Control**: Test subscription authorization
- [ ] **Data Filtering**: Test subscription data filtering
- [ ] **Real-time Authorization**: Test dynamic permission changes
- [ ] **Cross-User Subscriptions**: Test subscription data isolation

### Resource Management
- [ ] **Connection Limits**: Test concurrent subscription limits
- [ ] **Memory Usage**: Test subscription memory consumption
- [ ] **Cleanup Mechanisms**: Test subscription cleanup on disconnect
- [ ] **Heartbeat Implementation**: Test connection keep-alive mechanisms

## File Upload Testing (if applicable)

### Upload Security
- [ ] **File Type Validation**: Test file type restrictions
- [ ] **File Size Limits**: Test file size restrictions
- [ ] **Malicious Files**: Test malicious file upload prevention
- [ ] **Path Traversal**: Test directory traversal in file operations

### Content Validation
- [ ] **Magic Number Validation**: Test file content validation
- [ ] **Virus Scanning**: Test malware detection capabilities
- [ ] **Content Sanitization**: Test file content sanitization
- [ ] **Metadata Stripping**: Test file metadata removal

## Integration Security

### Third-Party Services
- [ ] **API Key Exposure**: Test for exposed third-party API keys
- [ ] **Service Authentication**: Test third-party service authentication
- [ ] **Data Validation**: Test third-party data validation
- [ ] **Error Handling**: Test third-party service error handling

### Database Security
- [ ] **Connection Security**: Test database connection security
- [ ] **Query Optimization**: Test for query performance issues
- [ ] **Data Encryption**: Test data encryption at rest
- [ ] **Backup Security**: Test backup data protection

## Compliance Testing

### GDPR Compliance
- [ ] **Data Minimization**: Test data collection minimization
- [ ] **Consent Management**: Test consent tracking and management
- [ ] **Right to Access**: Test data portability features
- [ ] **Right to Deletion**: Test data deletion capabilities
- [ ] **Data Processing Logs**: Test audit trail completeness

### HIPAA Compliance (if applicable)
- [ ] **PHI Protection**: Test protected health information security
- [ ] **Access Logging**: Test healthcare data access logging
- [ ] **Encryption Requirements**: Test healthcare data encryption
- [ ] **Audit Controls**: Test healthcare audit mechanisms

### PCI DSS Compliance (if applicable)
- [ ] **Cardholder Data**: Test payment card data protection
- [ ] **Data Transmission**: Test secure payment data transmission
- [ ] **Access Controls**: Test payment system access controls
- [ ] **Monitoring**: Test payment transaction monitoring

## Security Headers and Configuration

### HTTP Security Headers
- [ ] **Content Security Policy**: Test CSP implementation
- [ ] **HSTS**: Test HTTP Strict Transport Security
- [ ] **X-Frame-Options**: Test clickjacking protection
- [ ] **X-Content-Type-Options**: Test MIME type sniffing protection
- [ ] **Referrer Policy**: Test referrer information leakage

### CORS Configuration
- [ ] **Origin Validation**: Test CORS origin restrictions
- [ ] **Credential Handling**: Test CORS credential policies
- [ ] **Method Restrictions**: Test allowed HTTP methods
- [ ] **Header Restrictions**: Test allowed custom headers

### TLS Configuration
- [ ] **Certificate Validation**: Test SSL/TLS certificate validity
- [ ] **Protocol Versions**: Test supported TLS versions
- [ ] **Cipher Suites**: Test encryption cipher strength
- [ ] **Perfect Forward Secrecy**: Test PFS implementation

## Logging and Monitoring

### Audit Logging
- [ ] **Query Logging**: Test GraphQL query logging
- [ ] **Authentication Events**: Test authentication event logging
- [ ] **Authorization Failures**: Test authorization failure logging
- [ ] **Data Access Logging**: Test sensitive data access logging
- [ ] **Error Logging**: Test error event logging

### Security Monitoring
- [ ] **Anomaly Detection**: Test unusual activity detection
- [ ] **Rate Limit Violations**: Test rate limit violation alerts
- [ ] **Failed Authentication**: Test failed login monitoring
- [ ] **Suspicious Queries**: Test malicious query detection
- [ ] **Data Exfiltration**: Test large data access monitoring

## Post-Testing Activities

### Documentation
- [ ] **Vulnerability Report**: Document all identified vulnerabilities
- [ ] **Risk Assessment**: Assess business impact of findings
- [ ] **Remediation Plan**: Provide fix recommendations
- [ ] **Compliance Gaps**: Document compliance requirement gaps

### Verification
- [ ] **Fix Validation**: Re-test after vulnerability fixes
- [ ] **Regression Testing**: Test for new issues after fixes
- [ ] **Performance Impact**: Test security fix performance impact
- [ ] **User Experience**: Test security fix user experience impact

### Knowledge Transfer
- [ ] **Developer Training**: Provide security training to development team
- [ ] **Security Guidelines**: Update development security guidelines
- [ ] **Testing Procedures**: Document ongoing security testing procedures
- [ ] **Incident Response**: Update incident response procedures

## Risk Assessment Matrix

| Severity | Criteria | Examples |
|----------|----------|----------|
| **Critical** | Complete system compromise possible | Introspection enabled in production, No authentication required |
| **High** | Significant data breach or DoS possible | Authorization bypass, SQL injection, Query complexity attacks |
| **Medium** | Limited data exposure or service degradation | Information disclosure, Weak rate limiting |
| **Low** | Minimal security impact | Verbose error messages, Missing security headers |

## Remediation Priorities

1. **Immediate (Critical/High)**
   - Disable introspection in production
   - Fix authentication/authorization bypasses
   - Implement query complexity limits
   - Fix injection vulnerabilities

2. **Short-term (Medium)**
   - Implement proper rate limiting
   - Fix information disclosure issues
   - Improve error handling
   - Add security headers

3. **Long-term (Low)**
   - Enhance logging and monitoring
   - Improve security documentation
   - Implement advanced security features
   - Regular security training

---

**Note**: This checklist should be customized based on the specific GraphQL implementation and business requirements. Regular updates are recommended as GraphQL security best practices evolve.
