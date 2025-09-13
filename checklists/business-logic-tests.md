# 🏗️ Business Logic Vulnerability Testing Checklist

This comprehensive checklist focuses on identifying business logic flaws in API endpoints that could lead to financial loss, operational disruption, or security breaches through workflow manipulation and rule circumvention.

---

## 🎯 Business Logic Testing Overview

### Common Business Logic Vulnerabilities
- **Workflow Bypasses**: Skipping required steps in multi-step processes
- **Price Manipulation**: Altering prices, quantities, or currencies
- **Race Conditions**: Exploiting timing windows in concurrent operations
- **State Manipulation**: Forcing invalid state transitions
- **Limit Bypasses**: Circumventing business rules and restrictions
- **Authorization Logic Flaws**: Exploiting complex permission systems
- **Data Validation Issues**: Business rule validation failures

### Testing Methodology
1. **Business Process Mapping**: Document all business workflows
2. **Logic Flow Analysis**: Identify decision points and validation rules
3. **Edge Case Testing**: Test boundary conditions and unusual scenarios
4. **Concurrency Testing**: Test race conditions and timing attacks
5. **State Manipulation**: Test invalid state transitions
6. **Rule Circumvention**: Test business rule bypass techniques

---

## 💰 Financial Transaction Logic Testing

### E-commerce Order Processing

#### Price Manipulation Testing
```bash
# Test negative price values
curl -X POST https://api.example.com/orders \
  -H "Content-Type: application/json" \
  -d '{
    "product_id": 1,
    "quantity": 1,
    "price": -100.00,
    "currency": "USD"
  }'

# Test zero price manipulation
curl -X POST https://api.example.com/orders \
  -d '{
    "product_id": 1,
    "quantity": 1,
    "price": 0.00
  }'

# Test quantity manipulation with negative values
curl -X POST https://api.example.com/orders \
  -d '{
    "product_id": 1,
    "quantity": -5,
    "price": 100.00
  }'
```

#### Currency Conversion Exploitation
```bash
# Test currency arbitrage
curl -X POST https://api.example.com/orders \
  -d '{
    "product_id": 1,
    "price": 1,
    "currency": "JPY",
    "convert_to": "USD"
  }'

# Test invalid currency codes
curl -X POST https://api.example.com/orders \
  -d '{
    "product_id": 1,
    "price": 100,
    "currency": "XXX"
  }'

# Test cryptocurrency manipulation
curl -X POST https://api.example.com/orders \
  -d '{
    "product_id": 1,
    "price": 0.000001,
    "currency": "BTC"
  }'
```

### Financial Transaction Checklist
- [ ] **Price Validation**: Negative prices rejected
- [ ] **Quantity Limits**: Reasonable quantity limits enforced
- [ ] **Currency Validation**: Only valid currencies accepted
- [ ] **Conversion Rates**: Real-time exchange rates used
- [ ] **Precision Handling**: Proper decimal precision maintained
- [ ] **Overflow Protection**: Large number handling
- [ ] **Rounding Logic**: Consistent rounding rules applied
- [ ] **Tax Calculation**: Accurate tax computation
- [ ] **Discount Validation**: Discount code limits enforced
- [ ] **Refund Logic**: Proper refund amount validation

---

## 🔄 Workflow Bypass Testing

### Multi-Step Process Analysis

#### Payment Process Bypass
```bash
# Standard payment flow:
# 1. Create order
ORDER_ID=$(curl -X POST https://api.example.com/orders \
  -d '{"product_id": 1, "quantity": 1}' | jq -r '.id')

# 2. Process payment
curl -X POST https://api.example.com/orders/$ORDER_ID/payment \
  -d '{"payment_method": "credit_card", "amount": 100}'

# 3. Fulfill order
curl -X POST https://api.example.com/orders/$ORDER_ID/fulfill

# Test bypass: Skip payment step
curl -X POST https://api.example.com/orders/$ORDER_ID/fulfill
# Should fail without payment confirmation

# Test bypass: Direct status manipulation
curl -X PUT https://api.example.com/orders/$ORDER_ID \
  -d '{"status": "paid"}'
```

#### Account Verification Bypass
```bash
# Test account verification bypass
curl -X POST https://api.example.com/users/create \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "verified": true,
    "verification_token": "bypassed"
  }'

# Test premium feature access without subscription
curl -X POST https://api.example.com/premium/feature \
  -H "Authorization: Bearer unverified_user_token" \
  -d '{"action": "premium_action"}'

# Test approval workflow bypass
curl -X POST https://api.example.com/documents/publish \
  -d '{
    "document_id": 123,
    "status": "approved",
    "approved_by": "auto-approved"
  }'
```

### Workflow Testing Checklist
- [ ] **Sequential Steps**: Each step validates previous completion
- [ ] **State Validation**: Current state verified before transitions
- [ ] **Authorization Checks**: User permissions validated at each step
- [ ] **Data Consistency**: Related data remains consistent across steps
- [ ] **Rollback Mechanisms**: Failed steps properly roll back changes
- [ ] **Timeout Handling**: Incomplete workflows have timeout logic
- [ ] **Audit Trails**: All workflow steps logged for audit
- [ ] **Error Handling**: Proper error handling for failed steps

---

## 🏃‍♂️ Race Condition Testing

### Concurrent Operation Testing

#### Double Spending Attack
```bash
# Test concurrent withdrawal attempts
USER_ID="user123"
AMOUNT="100"

# Launch multiple concurrent requests
for i in {1..10}; do
  curl -X POST https://api.example.com/wallet/withdraw \
    -H "Authorization: Bearer $USER_TOKEN" \
    -d "{\"user_id\": \"$USER_ID\", \"amount\": $AMOUNT}" &
done
wait

# Check final balance
curl https://api.example.com/wallet/balance/$USER_ID
```

#### Inventory Race Conditions
```bash
# Test concurrent purchase of limited inventory
PRODUCT_ID="limited_item"

for i in {1..20}; do
  curl -X POST https://api.example.com/orders \
    -d "{\"product_id\": \"$PRODUCT_ID\", \"quantity\": 1}" &
done
wait

# Check if overselling occurred
curl https://api.example.com/products/$PRODUCT_ID/inventory
```

#### Account Creation Race Conditions
```bash
# Test concurrent account creation with same email
EMAIL="test@example.com"

for i in {1..5}; do
  curl -X POST https://api.example.com/users/register \
    -d "{\"email\": \"$EMAIL\", \"password\": \"pass$i\"}" &
done
wait

# Check if multiple accounts created
curl https://api.example.com/admin/users/search?email=$EMAIL
```

### Race Condition Testing Checklist
- [ ] **Resource Locking**: Critical resources properly locked
- [ ] **Transaction Isolation**: Database transactions isolated
- [ ] **Atomic Operations**: Multi-step operations are atomic
- [ ] **Idempotency**: Operations can be safely retried
- [ ] **Sequence Numbers**: Sequential operations use proper ordering
- [ ] **Timeout Handling**: Locks have appropriate timeouts
- [ ] **Deadlock Prevention**: Deadlock detection and prevention
- [ ] **Consistency Checks**: Post-operation consistency validation

---

## 📊 Business Rule Validation Testing

### Limit and Quota Bypass

#### Transaction Limits
```bash
# Test daily transaction limit bypass
USER_TOKEN="user_token_here"

# Method 1: Multiple small transactions
for i in {1..100}; do
  curl -X POST https://api.example.com/transfers \
    -H "Authorization: Bearer $USER_TOKEN" \
    -d '{"recipient": "user456", "amount": 10}'
done

# Method 2: Single large transaction
curl -X POST https://api.example.com/transfers \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"recipient": "user456", "amount": 100000}'

# Method 3: Midnight reset exploitation
curl -X POST https://api.example.com/transfers \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"recipient": "user456", "amount": 5000, "scheduled_time": "23:59:59"}'
```

#### API Rate Limit Bypass
```bash
# Test rate limit bypass techniques
API_KEY="your_api_key"

# Method 1: Header manipulation
curl -H "X-API-Key: $API_KEY" -H "X-Forwarded-For: 1.1.1.1" https://api.example.com/data
curl -H "X-API-Key: $API_KEY" -H "X-Real-IP: 2.2.2.2" https://api.example.com/data

# Method 2: User-Agent rotation
user_agents=("Mozilla/5.0 (Windows NT 10.0)" "Mozilla/5.0 (Macintosh)" "Mozilla/5.0 (X11; Linux)")
for ua in "${user_agents[@]}"; do
  curl -H "X-API-Key: $API_KEY" -H "User-Agent: $ua" https://api.example.com/data
done

# Method 3: Parameter variation
curl -H "X-API-Key: $API_KEY" "https://api.example.com/data?v=1&format=json"
curl -H "X-API-Key: $API_KEY" "https://api.example.com/data?version=1&format=xml"
```

#### Usage Quota Exploitation
```bash
# Test subscription limits bypass
PREMIUM_TOKEN="premium_user_token"

# Test feature usage beyond subscription limits
for i in {1..1000}; do
  curl -H "Authorization: Bearer $PREMIUM_TOKEN" \
    https://api.example.com/premium/advanced-feature
done

# Test bandwidth limit bypass
curl -H "Authorization: Bearer $PREMIUM_TOKEN" \
  "https://api.example.com/download/large-file?compress=false&quality=max"

# Test storage limit bypass
curl -X POST https://api.example.com/files/upload \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -F "file=@huge_file.zip"
```

### Business Rule Testing Checklist
- [ ] **Daily Limits**: Daily transaction/usage limits enforced
- [ ] **Monthly Quotas**: Monthly subscription quotas respected
- [ ] **User Tier Limits**: Different limits for different user tiers
- [ ] **Geographic Restrictions**: Location-based restrictions enforced
- [ ] **Time-based Rules**: Time-sensitive rules properly validated
- [ ] **Cumulative Limits**: Aggregate limits calculated correctly
- [ ] **Reset Logic**: Limit reset mechanisms work properly
- [ ] **Exception Handling**: Business rule exceptions handled securely

---

## 🎭 Authorization Logic Complexity Testing

### Role-Based Access Control Flaws

#### Role Escalation Testing
```bash
# Test role manipulation in requests
curl -X POST https://api.example.com/users/promote \
  -H "Authorization: Bearer regular_user_token" \
  -d '{
    "user_id": "regular_user_123",
    "new_role": "admin",
    "promoted_by": "self"
  }'

# Test role inheritance flaws
curl -X GET https://api.example.com/admin/reports \
  -H "Authorization: Bearer manager_token" \
  -H "X-Assume-Role: admin"

# Test group membership manipulation
curl -X PUT https://api.example.com/users/123/groups \
  -d '{"groups": ["admins", "superusers", "developers"]}'
```

#### Permission Boundary Testing
```bash
# Test cross-tenant access
TENANT_A_TOKEN="tenant_a_token"
TENANT_B_USER="tenant_b_user_123"

curl -H "Authorization: Bearer $TENANT_A_TOKEN" \
  https://api.example.com/users/$TENANT_B_USER/profile

# Test resource ownership bypass
curl -X DELETE https://api.example.com/documents/456 \
  -H "Authorization: Bearer user_who_doesnt_own_document"

# Test permission aggregation
curl -X POST https://api.example.com/sensitive-operation \
  -H "Authorization: Bearer limited_permissions_token" \
  -d '{"permissions": ["read", "write", "admin"]}'
```

### Complex Authorization Scenarios
```bash
# Test time-based access control
curl -X GET https://api.example.com/reports/financial \
  -H "Authorization: Bearer business_hours_token" \
  # Test during off-hours

# Test location-based access
curl -X GET https://api.example.com/sensitive-data \
  -H "Authorization: Bearer geo_restricted_token" \
  -H "X-Client-IP: 192.168.1.1"  # Internal IP
  # vs external IP

# Test device-based restrictions
curl -X GET https://api.example.com/admin/panel \
  -H "Authorization: Bearer mobile_restricted_token" \
  -H "User-Agent: Mobile-App/1.0"
```

### Authorization Testing Checklist
- [ ] **Role Validation**: User roles properly validated
- [ ] **Permission Inheritance**: Role inheritance works correctly  
- [ ] **Resource Ownership**: Resource ownership properly enforced
- [ ] **Tenant Isolation**: Multi-tenant data properly isolated
- [ ] **Contextual Access**: Context-based access controls work
- [ ] **Permission Caching**: Permission caches properly invalidated
- [ ] **Default Deny**: Unknown permissions default to deny
- [ ] **Audit Logging**: Authorization decisions properly logged

---

## 🔢 Data Validation and Business Rule Testing

### Input Validation Logic Flaws

#### Numerical Validation Bypass
```bash
# Test integer overflow
curl -X POST https://api.example.com/account/deposit \
  -d '{"amount": 9999999999999999999999}'

# Test floating point precision issues
curl -X POST https://api.example.com/orders \
  -d '{"price": 99.999999999999999}'

# Test negative number handling
curl -X POST https://api.example.com/inventory/adjust \
  -d '{"product_id": 123, "quantity_change": -999999}'

# Test special number values
curl -X POST https://api.example.com/calculations \
  -d '{"value": "Infinity"}'

curl -X POST https://api.example.com/calculations \
  -d '{"value": "NaN"}'
```

#### String Validation Bypass
```bash
# Test length limit bypass
LONG_STRING=$(python3 -c "print('A' * 10000)")
curl -X POST https://api.example.com/users/profile \
  -d "{\"bio\": \"$LONG_STRING\"}"

# Test encoding bypass
curl -X POST https://api.example.com/comments \
  -d '{"text": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}'

# Test null byte injection
curl -X POST https://api.example.com/files/name \
  -d '{"filename": "innocent.txt\u0000.exe"}'
```

#### Business Logic Validation
```bash
# Test age validation bypass
curl -X POST https://api.example.com/users/register \
  -d '{
    "name": "Test User",
    "birthdate": "2050-01-01",
    "age": 25
  }'

# Test date logic flaws
curl -X POST https://api.example.com/events/create \
  -d '{
    "name": "Test Event",
    "start_date": "2024-12-31",
    "end_date": "2024-01-01"
  }'

# Test business hour validation
curl -X POST https://api.example.com/appointments \
  -d '{
    "datetime": "2024-01-01T03:00:00Z",
    "service": "business_consultation"
  }'
```

### Data Validation Testing Checklist
- [ ] **Type Validation**: Data types properly validated
- [ ] **Range Validation**: Numeric ranges enforced
- [ ] **Length Validation**: String length limits enforced
- [ ] **Format Validation**: Data formats properly validated
- [ ] **Cross-Field Validation**: Related fields validated together
- [ ] **Business Rule Validation**: Domain-specific rules enforced
- [ ] **Encoding Validation**: Character encoding properly handled
- [ ] **Null Handling**: Null values properly handled

---

## 🎪 Complex Business Scenario Testing

### Multi-Step Business Processes

#### Loyalty Points System
```bash
# Test points calculation manipulation
curl -X POST https://api.example.com/purchases \
  -d '{
    "items": [
      {"id": 1, "price": 100, "points_multiplier": 10},
      {"id": 2, "price": -50, "points_multiplier": 5}
    ]
  }'

# Test points redemption race condition
POINTS_BALANCE=1000
for i in {1..5}; do
  curl -X POST https://api.example.com/loyalty/redeem \
    -d "{\"points_to_redeem\": $POINTS_BALANCE}" &
done
wait

# Test points transfer limits
curl -X POST https://api.example.com/loyalty/transfer \
  -d '{
    "to_user": "friend123",
    "points": 999999,
    "transfer_fee": 0
  }'
```

#### Subscription Management
```bash
# Test subscription upgrade/downgrade logic
curl -X POST https://api.example.com/subscriptions/change \
  -d '{
    "current_plan": "premium",
    "new_plan": "basic", 
    "effective_date": "2020-01-01",
    "proration": false
  }'

# Test billing cycle manipulation
curl -X POST https://api.example.com/subscriptions/123/billing \
  -d '{
    "cycle_start": "2024-01-01",
    "cycle_end": "2024-01-02",
    "amount": 0.01
  }'

# Test cancellation logic
curl -X DELETE https://api.example.com/subscriptions/123 \
  -d '{
    "cancel_immediately": true,
    "refund_amount": 999.99,
    "reason": "system_error"
  }'
```

#### Referral and Reward Systems
```bash
# Test self-referral prevention
curl -X POST https://api.example.com/referrals \
  -H "Authorization: Bearer user123_token" \
  -d '{
    "referred_user": "user123",
    "referral_code": "USER123REF"
  }'

# Test referral loop creation
curl -X POST https://api.example.com/referrals \
  -d '{
    "referrer": "userA",
    "referred": "userB",
    "chain": ["userB", "userC", "userA"]
  }'

# Test reward multiplication
curl -X POST https://api.example.com/rewards/claim \
  -d '{
    "reward_id": 123,
    "multiplier": 10,
    "bonus_eligible": true
  }'
```

### Complex Scenario Testing Checklist
- [ ] **Multi-User Interactions**: Cross-user operations properly validated
- [ ] **Temporal Logic**: Time-based business rules enforced
- [ ] **Cascading Effects**: Chain reactions properly handled
- [ ] **State Dependencies**: Dependent state changes validated
- [ ] **Rollback Scenarios**: Failed operations properly rolled back
- [ ] **Notification Logic**: Business event notifications accurate
- [ ] **Audit Requirements**: Complex operations properly audited
- [ ] **Performance Impact**: Complex logic doesn't create performance issues

---

## 🎯 State Machine and Workflow Testing

### State Transition Validation

#### Order Status Manipulation
```bash
# Test invalid state transitions
ORDER_ID="order123"

# Try to ship before payment
curl -X PUT https://api.example.com/orders/$ORDER_ID/status \
  -d '{"status": "shipped", "previous_status": "pending"}'

# Try to cancel after shipped
curl -X PUT https://api.example.com/orders/$ORDER_ID/status \
  -d '{"status": "cancelled", "previous_status": "shipped"}'

# Try to skip states
curl -X PUT https://api.example.com/orders/$ORDER_ID/status \
  -d '{"status": "delivered", "previous_status": "pending"}'
```

#### Account Status Logic
```bash
# Test account status bypass
curl -X POST https://api.example.com/login \
  -d '{
    "username": "suspended_user",
    "password": "correct_password",
    "force_login": true
  }'

# Test status inheritance
curl -X POST https://api.example.com/users/create-child-account \
  -H "Authorization: Bearer banned_user_token" \
  -d '{"child_user_data": {...}}'
```

### Workflow State Testing Checklist
- [ ] **Valid Transitions**: Only valid state transitions allowed
- [ ] **State Validation**: Current state verified before changes
- [ ] **Business Rules**: State-specific business rules enforced
- [ ] **Rollback States**: Ability to rollback to previous states
- [ ] **Final States**: Terminal states properly handled
- [ ] **Concurrent Updates**: Race conditions in state changes prevented
- [ ] **State History**: State change history maintained
- [ ] **Error States**: Error states and recovery handled

---

## 🔄 Idempotency and Duplicate Prevention

### Duplicate Operation Testing

#### Payment Deduplication
```bash
# Test duplicate payment prevention
PAYMENT_DATA='{
  "amount": 100.00,
  "card_token": "card_123",
  "order_id": "order_456"
}'

# Submit same payment multiple times
for i in {1..5}; do
  curl -X POST https://api.example.com/payments \
    -H "Content-Type: application/json" \
    -d "$PAYMENT_DATA"
done

# Test with idempotency key
IDEMPOTENCY_KEY="payment_$(date +%s)"
for i in {1..5}; do
  curl -X POST https://api.example.com/payments \
    -H "Idempotency-Key: $IDEMPOTENCY_KEY" \
    -d "$PAYMENT_DATA"
done
```

#### Account Creation Deduplication
```bash
# Test duplicate account creation
USER_DATA='{
  "email": "unique@example.com",
  "username": "uniqueuser",
  "phone": "+1234567890"
}'

# Rapid account creation attempts
for i in {1..3}; do
  curl -X POST https://api.example.com/users/register \
    -d "$USER_DATA" &
done
wait
```

### Idempotency Testing Checklist
- [ ] **Idempotency Keys**: Proper idempotency key support
- [ ] **Duplicate Detection**: Duplicate operations detected
- [ ] **Response Consistency**: Same response for duplicate requests
- [ ] **Side Effect Prevention**: Duplicate operations don't cause side effects
- [ ] **Key Expiration**: Idempotency keys have appropriate expiration
- [ ] **Key Uniqueness**: Idempotency keys are properly unique
- [ ] **Error Handling**: Duplicate detection errors handled gracefully
- [ ] **Performance**: Duplicate detection doesn't impact performance

---

## 📊 Business Logic Monitoring and Detection

### Anomaly Detection Setup

#### Financial Transaction Monitoring
```python
# Business logic anomaly detection patterns
anomaly_patterns = {
    "unusual_transactions": {
        "large_amounts": "amount > user_avg_transaction * 10",
        "frequent_transactions": "transaction_count > daily_avg * 5", 
        "unusual_times": "transaction_hour < 6 OR transaction_hour > 22",
        "geographic_anomalies": "transaction_country != user_country"
    },
    "account_behavior": {
        "rapid_account_creation": "accounts_created_per_ip > 5 per hour",
        "privilege_escalation": "role_changes > 0 per user per day",
        "bulk_operations": "bulk_operation_size > normal_threshold"
    }
}
```

#### Business Rule Violations
```bash
# Monitor for business logic violations
curl https://api.example.com/admin/violations/summary | jq '.recent_violations[]'

# Check for unusual patterns
curl https://api.example.com/analytics/business-logic | jq '{
  price_manipulations: .price_violations,
  workflow_bypasses: .workflow_violations,
  limit_bypasses: .limit_violations
}'
```

### Monitoring Implementation Checklist
- [ ] **Real-time Detection**: Business logic violations detected in real-time
- [ ] **Pattern Recognition**: Unusual business patterns identified
- [ ] **Threshold Alerts**: Business metric thresholds trigger alerts
- [ ] **Fraud Detection**: Financial fraud patterns monitored
- [ ] **Behavioral Analysis**: User behavior anomalies detected
- [ ] **Automated Response**: Automatic response to violations
- [ ] **Investigation Tools**: Tools for investigating business logic issues
- [ ] **Reporting Dashboards**: Business logic security dashboards

---

## 📋 Business Logic Testing Summary

### Critical Business Logic Vulnerabilities
1. **Price Manipulation**: Negative prices, currency manipulation
2. **Workflow Bypass**: Skipping required process steps  
3. **Race Conditions**: Concurrent operation exploitation
4. **State Manipulation**: Invalid state transitions
5. **Limit Bypass**: Circumventing business rules
6. **Authorization Flaws**: Complex permission system issues

### Testing Best Practices
- [ ] **Business Process Documentation**: Document all business workflows
- [ ] **Edge Case Testing**: Test boundary conditions thoroughly
- [ ] **Concurrent Testing**: Test race conditions and timing issues
- [ ] **Real-world Scenarios**: Test actual business use cases
- [ ] **Cross-functional Testing**: Test interactions between features
- [ ] **Negative Testing**: Test what should fail
- [ ] **Performance Impact**: Ensure security doesn't impact performance
- [ ] **Monitoring Integration**: Implement detection and alerting

### Remediation Priorities
1. **Financial Impact**: Fix money-related vulnerabilities first
2. **Data Integrity**: Address data consistency issues
3. **Business Continuity**: Fix workflow disruption issues
4. **Compliance Risk**: Address regulatory compliance violations
5. **User Experience**: Fix issues affecting user experience

---

Use this comprehensive business logic testing checklist to identify vulnerabilities that traditional security testing might miss. Business logic flaws often have the highest business impact and require deep understanding of application workflows and business rules.