#!/bin/bash

# API Security Basic Scan Script
# Usage: ./basic-scan.sh <target-url> [options]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/../../reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$OUTPUT_DIR/basic_scan_$TIMESTAMP.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
TIMEOUT=30
USER_AGENT="API-Security-Scanner/1.0"
MAX_REDIRECTS=5
VERBOSE=false
SAVE_RESPONSES=false

# Help function
show_help() {
    cat << EOF
API Security Basic Scanner

Usage: $0 <target-url> [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -t, --timeout SECONDS   Request timeout (default: 30)
    -o, --output FILE       Output report file
    -s, --save-responses    Save HTTP responses to files
    -u, --user-agent UA     Custom User-Agent string
    --max-redirects NUM     Maximum redirects to follow (default: 5)

EXAMPLES:
    $0 https://api.example.com
    $0 https://api.example.com -v -t 60 -o custom_report.json
    $0 https://api.example.com --save-responses

ENVIRONMENT VARIABLES:
    API_AUTH_TOKEN         Authentication token for API requests
    PROXY_URL             HTTP/HTTPS proxy URL
EOF
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[VERBOSE]${NC} $1"
    fi
}

# Initialize report structure
init_report() {
    local target_url="$1"
    
    mkdir -p "$OUTPUT_DIR"
    
    cat > "$REPORT_FILE" << EOF
{
  "scan_info": {
    "target": "$target_url",
    "timestamp": "$(date -Iseconds)",
    "scanner_version": "1.0.0"
  },
  "results": {
    "endpoint_discovery": {},
    "security_headers": {},
    "authentication_tests": {},
    "common_vulnerabilities": {},
    "summary": {}
  }
}
EOF
}

# Make HTTP request with error handling
make_request() {
    local url="$1"
    local method="${2:-GET}"
    local headers="${3:-}"
    local data="${4:-}"
    local response_file="$OUTPUT_DIR/response_$(echo "$url" | sed 's|[^a-zA-Z0-9]|_|g')_$TIMESTAMP.txt"
    
    local curl_cmd="curl -s -w 'HTTP_CODE:%{http_code}|TIME:%{time_total}|SIZE:%{size_download}' --max-time $TIMEOUT --max-redirs $MAX_REDIRECTS -H 'User-Agent: $USER_AGENT'"
    
    # Add proxy if configured
    if [[ -n "${PROXY_URL:-}" ]]; then
        curl_cmd="$curl_cmd --proxy $PROXY_URL"
    fi
    
    # Add authentication if configured
    if [[ -n "${API_AUTH_TOKEN:-}" ]]; then
        curl_cmd="$curl_cmd -H 'Authorization: Bearer $API_AUTH_TOKEN'"
    fi
    
    # Add custom headers
    if [[ -n "$headers" ]]; then
        curl_cmd="$curl_cmd $headers"
    fi
    
    # Add request data for POST/PUT
    if [[ -n "$data" ]]; then
        curl_cmd="$curl_cmd -X $method -d '$data'"
    else
        curl_cmd="$curl_cmd -X $method"
    fi
    
    # Save response if requested
    if [[ "$SAVE_RESPONSES" == "true" ]]; then
        curl_cmd="$curl_cmd -o '$response_file'"
    fi
    
    log_verbose "Executing: $curl_cmd '$url'"
    
    # Execute request
    local response
    if response=$(eval "$curl_cmd '$url'" 2>/dev/null); then
        echo "$response"
    else
        log_warning "Request failed for $url"
        echo "HTTP_CODE:000|TIME:0|SIZE:0"
    fi
}

# Extract HTTP status code from response
get_http_code() {
    local response="$1"
    echo "$response" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2
}

# Extract response time from response
get_response_time() {
    local response="$1"
    echo "$response" | grep -o "TIME:[0-9.]*" | cut -d: -f2
}

# Endpoint discovery
discover_endpoints() {
    local base_url="$1"
    log_info "Starting endpoint discovery..."
    
    # Common API paths to test
    local endpoints=(
        "/api/v1/users"
        "/api/v2/users"
        "/api/users"
        "/api/v1/admin"
        "/api/admin"
        "/api/health"
        "/api/status"
        "/api/info"
        "/api/version"
        "/api/config"
        "/api/debug"
        "/api/swagger"
        "/api/docs"
        "/api/openapi.json"
        "/api/v1/auth"
        "/api/auth"
        "/api/login"
        "/api/register"
        "/health"
        "/status"
        "/info"
        "/debug"
        "/actuator/health"
        "/actuator/info"
        "/actuator/env"
        "/.well-known/security.txt"
        "/robots.txt"
    )
    
    local discovered_endpoints=()
    local total_endpoints=${#endpoints[@]}
    local current=0
    
    for endpoint in "${endpoints[@]}"; do
        current=$((current + 1))
        log_verbose "Testing endpoint [$current/$total_endpoints]: $endpoint"
        
        local full_url="$base_url$endpoint"
        local response=$(make_request "$full_url")
        local http_code=$(get_http_code "$response")
        
        if [[ "$http_code" != "404" && "$http_code" != "000" ]]; then
            discovered_endpoints+=("$endpoint:$http_code")
            log_success "Found: $endpoint (HTTP $http_code)"
        fi
    done
    
    # Update report
    local endpoint_json="["
    for i in "${!discovered_endpoints[@]}"; do
        IFS=':' read -r path code <<< "${discovered_endpoints[$i]}"
        endpoint_json+="{\"path\":\"$path\",\"status_code\":$code}"
        if [[ $i -lt $((${#discovered_endpoints[@]} - 1)) ]]; then
            endpoint_json+=","
        fi
    done
    endpoint_json+="]"
    
    # Update JSON report using jq
    jq ".results.endpoint_discovery.discovered = $endpoint_json | .results.endpoint_discovery.total_found = ${#discovered_endpoints[@]}" "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
    
    log_success "Discovered ${#discovered_endpoints[@]} endpoints"
}

# Security headers analysis
analyze_security_headers() {
    local base_url="$1"
    log_info "Analyzing security headers..."
    
    local response=$(make_request "$base_url" "HEAD" "-I")
    
    # Expected security headers
    declare -A security_headers=(
        ["X-Frame-Options"]="Clickjacking protection"
        ["X-Content-Type-Options"]="MIME type sniffing protection"
        ["X-XSS-Protection"]="XSS filtering"
        ["Strict-Transport-Security"]="HTTPS enforcement"
        ["Content-Security-Policy"]="Content injection protection"
        ["Referrer-Policy"]="Referrer information control"
        ["X-Permitted-Cross-Domain-Policies"]="Flash/PDF policy control"
        ["Feature-Policy"]="Browser feature control"
        ["Permissions-Policy"]="Browser permissions control"
    )
    
    local present_headers=()
    local missing_headers=()
    
    for header in "${!security_headers[@]}"; do
        if echo "$response" | grep -qi "sql\|mysql\|oracle\|sqlite\|syntax error\|ORA-\|mysql_fetch"; then
            vulnerabilities+=("Potential SQL Injection with payload: $payload")
            log_warning "Potential SQL Injection detected with payload: $payload"
        fi
    done
    
    # XSS basic test
    log_verbose "Testing for XSS..."
    local xss_payloads=("<script>alert(1)</script>" "javascript:alert(1)" "'\"><script>alert(1)</script>")
    for payload in "${xss_payloads[@]}"; do
        local response=$(make_request "$base_url/api/search?q=$payload")
        if echo "$response" | grep -q "$payload"; then
            vulnerabilities+=("Potential XSS with payload: $payload")
            log_warning "Potential XSS detected with payload: $payload"
        fi
    done
    
    # Directory traversal test
    log_verbose "Testing for directory traversal..."
    local traversal_payloads=("../../../etc/passwd" "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts" "....//....//....//etc/passwd")
    for payload in "${traversal_payloads[@]}"; do
        local response=$(make_request "$base_url/api/file?path=$payload")
        if echo "$response" | grep -qi "root:\|administrator\|windows"; then
            vulnerabilities+=("Potential Directory Traversal with payload: $payload")
            log_warning "Potential Directory Traversal detected with payload: $payload"
        fi
    done
    
    # Command injection test
    log_verbose "Testing for command injection..."
    local cmd_payloads=("; ls" "| whoami" "&& cat /etc/passwd" "\`id\`")
    for payload in "${cmd_payloads[@]}"; do
        local response=$(make_request "$base_url/api/ping?host=8.8.8.8$payload")
        if echo "$response" | grep -qi "uid=\|gid=\|root\|administrator"; then
            vulnerabilities+=("Potential Command Injection with payload: $payload")
            log_warning "Potential Command Injection detected with payload: $payload"
        fi
    done
    
    # XXE basic test
    log_verbose "Testing for XXE..."
    local xxe_payload='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>'
    local response=$(make_request "$base_url/api/xml" "POST" "-H 'Content-Type: application/xml'" "$xxe_payload")
    if echo "$response" | grep -qi "root:\|administrator"; then
        vulnerabilities+=("Potential XXE vulnerability")
        log_warning "Potential XXE vulnerability detected"
    fi
    
    # Update report
    local vuln_json=$(printf '%s\n' "${vulnerabilities[@]}" | jq -R . | jq -s .)
    jq ".results.common_vulnerabilities.findings = $vuln_json | .results.common_vulnerabilities.total = ${#vulnerabilities[@]}" "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
    
    if [[ ${#vulnerabilities[@]} -eq 0 ]]; then
        log_success "No obvious common vulnerabilities detected"
    else
        log_warning "Found ${#vulnerabilities[@]} potential vulnerabilities"
    fi
}

# SSL/TLS security check
check_ssl_security() {
    local target_url="$1"
    local hostname=$(echo "$target_url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
    
    if [[ "$target_url" =~ ^https:// ]]; then
        log_info "Checking SSL/TLS security for $hostname..."
        
        local ssl_results=()
        
        # Check SSL certificate
        local cert_info=$(echo | timeout 10 openssl s_client -servername "$hostname" -connect "$hostname:443" 2>/dev/null)
        
        if [[ $? -eq 0 ]]; then
            # Extract certificate details
            local cert_subject=$(echo "$cert_info" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
            local cert_issuer=$(echo "$cert_info" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
            local cert_expiry=$(echo "$cert_info" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
            
            ssl_results+=("Certificate Subject: $cert_subject")
            ssl_results+=("Certificate Issuer: $cert_issuer")
            ssl_results+=("Certificate Expiry: $cert_expiry")
            
            # Check for weak protocols
            if echo "$cert_info" | grep -qi "Protocol.*TLSv1\.0\|Protocol.*SSLv"; then
                ssl_results+=("WARNING: Weak protocol detected")
                log_warning "Weak SSL/TLS protocol detected"
            fi
            
            # Check for weak ciphers
            if echo "$cert_info" | grep -qi "Cipher.*RC4\|Cipher.*DES\|Cipher.*MD5"; then
                ssl_results+=("WARNING: Weak cipher detected")
                log_warning "Weak cipher suite detected"
            fi
            
            log_success "SSL certificate is valid"
        else
            ssl_results+=("ERROR: Could not retrieve SSL certificate")
            log_error "Could not retrieve SSL certificate for $hostname"
        fi
        
        # Update report
        local ssl_json=$(printf '%s\n' "${ssl_results[@]}" | jq -R . | jq -s .)
        jq ".results.ssl_security = $ssl_json" "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
    else
        log_warning "Target is not using HTTPS - SSL/TLS check skipped"
        jq '.results.ssl_security = ["WARNING: Target not using HTTPS"]' "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
    fi
}

# Generate summary
generate_summary() {
    log_info "Generating scan summary..."
    
    # Count findings
    local total_endpoints=$(jq '.results.endpoint_discovery.total_found // 0' "$REPORT_FILE")
    local missing_headers=$(jq '.results.security_headers.missing | length' "$REPORT_FILE")
    local potential_bypasses=$(jq '.results.authentication_tests.potential_bypasses | length' "$REPORT_FILE")
    local vulnerabilities=$(jq '.results.common_vulnerabilities.total // 0' "$REPORT_FILE")
    
    # Calculate risk score
    local risk_score=$((missing_headers * 1 + potential_bypasses * 3 + vulnerabilities * 5))
    local risk_level
    
    if [[ $risk_score -eq 0 ]]; then
        risk_level="LOW"
    elif [[ $risk_score -le 10 ]]; then
        risk_level="MEDIUM"
    elif [[ $risk_score -le 20 ]]; then
        risk_level="HIGH"
    else
        risk_level="CRITICAL"
    fi
    
    # Create summary
    local summary="{
        \"total_endpoints_found\": $total_endpoints,
        \"missing_security_headers\": $missing_headers,
        \"potential_auth_bypasses\": $potential_bypasses,
        \"potential_vulnerabilities\": $vulnerabilities,
        \"risk_score\": $risk_score,
        \"risk_level\": \"$risk_level\",
        \"scan_duration\": \"$(date -d @$(($(date +%s) - START_TIME)) -u +%H:%M:%S)\"
    }"
    
    jq ".results.summary = $summary" "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
    
    # Display summary
    echo
    log_info "=== SCAN SUMMARY ==="
    echo -e "Target: $TARGET_URL"
    echo -e "Endpoints found: $total_endpoints"
    echo -e "Missing security headers: $missing_headers"
    echo -e "Potential auth bypasses: $potential_bypasses"
    echo -e "Potential vulnerabilities: $vulnerabilities"
    echo -e "Risk Score: $risk_score ($risk_level)"
    echo -e "Report saved to: $REPORT_FILE"
    echo
}

# Main execution
main() {
    local START_TIME=$(date +%s)
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -o|--output)
                REPORT_FILE="$2"
                shift 2
                ;;
            -s|--save-responses)
                SAVE_RESPONSES=true
                shift
                ;;
            -u|--user-agent)
                USER_AGENT="$2"
                shift 2
                ;;
            --max-redirects)
                MAX_REDIRECTS="$2"
                shift 2
                ;;
            -*)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                TARGET_URL="$1"
                shift
                ;;
        esac
    done
    
    # Validate target URL
    if [[ -z "${TARGET_URL:-}" ]]; then
        log_error "Target URL is required"
        show_help
        exit 1
    fi
    
    # Validate URL format
    if ! echo "$TARGET_URL" | grep -Eq '^https?://[^/]+'; then
        log_error "Invalid URL format. Must start with http:// or https://"
        exit 1
    fi
    
    # Remove trailing slash from URL
    TARGET_URL="${TARGET_URL%/}"
    
    log_info "Starting API Security Basic Scan"
    log_info "Target: $TARGET_URL"
    log_info "Timeout: ${TIMEOUT}s"
    log_info "Report: $REPORT_FILE"
    echo
    
    # Initialize report
    init_report "$TARGET_URL"
    
    # Run security tests
    discover_endpoints "$TARGET_URL"
    analyze_security_headers "$TARGET_URL"
    test_authentication_bypass "$TARGET_URL"
    test_common_vulnerabilities "$TARGET_URL"
    check_ssl_security "$TARGET_URL"
    
    # Generate final summary
    generate_summary
    
    log_success "Scan completed successfully!"
}

# Trap signals for cleanup
trap 'log_error "Scan interrupted"; exit 1' INT TERM

# Run main function
main "$@" | grep -qi "^$header:"; then
            present_headers+=("$header")
            log_success "Present: $header"
        else
            missing_headers+=("$header")
            log_warning "Missing: $header - ${security_headers[$header]}"
        fi
    done
    
    # Check for information disclosure headers
    local disclosure_headers=("Server" "X-Powered-By" "X-AspNet-Version" "X-AspNetMvc-Version")
    local disclosed_info=()
    
    for header in "${disclosure_headers[@]}"; do
        local header_value=$(echo "$response" | grep -i "^$header:" | cut -d: -f2- | sed 's/^ *//')
        if [[ -n "$header_value" ]]; then
            disclosed_info+=("$header: $header_value")
            log_warning "Information disclosure: $header: $header_value"
        fi
    done
    
    # Update report
    local present_json=$(printf '%s\n' "${present_headers[@]}" | jq -R . | jq -s .)
    local missing_json=$(printf '%s\n' "${missing_headers[@]}" | jq -R . | jq -s .)
    local disclosure_json=$(printf '%s\n' "${disclosed_info[@]}" | jq -R . | jq -s .)
    
    jq ".results.security_headers.present = $present_json | .results.security_headers.missing = $missing_json | .results.security_headers.information_disclosure = $disclosure_json" "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
}

# Authentication bypass testing
test_authentication_bypass() {
    local base_url="$1"
    log_info "Testing authentication bypass techniques..."
    
    # Test endpoints that might require authentication
    local auth_endpoints=("/api/admin" "/api/users" "/api/profile" "/admin" "/dashboard")
    local bypass_techniques=(
        "" # No additional headers
        "-H 'X-Forwarded-User: admin'"
        "-H 'X-Remote-User: administrator'"
        "-H 'X-User-ID: 1'"
        "-H 'X-Roles: admin'"
        "-H 'Authorization: Bearer fake-token'"
    )
    
    local bypass_results=()
    
    for endpoint in "${auth_endpoints[@]}"; do
        local full_url="$base_url$endpoint"
        
        for technique in "${bypass_techniques[@]}"; do
            local response=$(make_request "$full_url" "GET" "$technique")
            local http_code=$(get_http_code "$response")
            
            # Check for potential bypasses (non-401/403 responses)
            if [[ "$http_code" != "401" && "$http_code" != "403" && "$http_code" != "404" && "$http_code" != "000" ]]; then
                local bypass_desc="$endpoint with headers: ${technique:-'(none)'}"
                bypass_results+=("$bypass_desc -> HTTP $http_code")
                log_warning "Potential bypass: $bypass_desc -> HTTP $http_code"
            fi
        done
    done
    
    # Update report
    local bypass_json=$(printf '%s\n' "${bypass_results[@]}" | jq -R . | jq -s .)
    jq ".results.authentication_tests.potential_bypasses = $bypass_json" "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
}

# Common vulnerability checks
test_common_vulnerabilities() {
    local base_url="$1"
    log_info "Testing for common vulnerabilities..."
    
    local vulnerabilities=()
    
    # SQL Injection basic test
    log_verbose "Testing for SQL injection..."
    local sqli_payloads=("'" "1' OR '1'='1" "'; DROP TABLE users; --")
    for payload in "${sqli_payloads[@]}"; do
        local response=$(make_request "$base_url/api/users?id=$payload")
        local http_code=$(get_http_code "$response")
        
        if echo "$response"