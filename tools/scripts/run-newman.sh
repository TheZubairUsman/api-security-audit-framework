#!/bin/bash

# Newman Runner Script for API Security Testing
# Usage: ./run-newman.sh <target-url> [options]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTMAN_DIR="$SCRIPT_DIR/../postman"
OUTPUT_DIR="$SCRIPT_DIR/../../reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
NEWMAN_REPORT="$OUTPUT_DIR/newman_report_$TIMESTAMP"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
ITERATIONS=1
TIMEOUT=30000
DELAY_REQUEST=0
VERBOSE=false
ENVIRONMENT_FILE="$POSTMAN_DIR/environment.json"
COLLECTION_FILE="$POSTMAN_DIR/security-tests.json"

# Help function
show_help() {
    cat << EOF
Newman API Security Test Runner

Usage: $0 <target-url> [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -i, --iterations NUM    Number of iterations to run (default: 1)
    -t, --timeout MS        Request timeout in milliseconds (default: 30000)
    -d, --delay MS          Delay between requests in milliseconds (default: 0)
    -e, --environment FILE  Custom environment file (default: environment.json)
    -c, --collection FILE   Custom collection file (default: security-tests.json)
    -o, --output DIR        Output directory for reports (default: ../../reports)
    --no-color              Disable colored output
    --bail                  Stop on first test failure

EXAMPLES:
    $0 https://api.example.com
    $0 https://api.example.com -v -i 3 -d 1000
    $0 https://api.example.com -e custom-env.json -c custom-tests.json

ENVIRONMENT VARIABLES:
    API_AUTH_TOKEN         Authentication token for API requests
    ADMIN_TOKEN           Admin token for privilege escalation tests
    API_KEY               API key for authentication tests
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

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check if newman is installed
    if ! command -v newman &> /dev/null; then
        log_error "Newman is not installed. Please install it with: npm install -g newman"
        exit 1
    fi
    
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        log_error "jq is not installed. Please install jq for JSON processing"
        exit 1
    fi
    
    log_success "All dependencies are available"
}

# Validate files
validate_files() {
    log_info "Validating input files..."
    
    # Check collection file
    if [[ ! -f "$COLLECTION_FILE" ]]; then
        log_error "Collection file not found: $COLLECTION_FILE"
        exit 1
    fi
    
    # Validate collection JSON
    if ! jq empty "$COLLECTION_FILE" 2>/dev/null; then
        log_error "Invalid JSON in collection file: $COLLECTION_FILE"
        exit 1
    fi
    
    # Check environment file
    if [[ ! -f "$ENVIRONMENT_FILE" ]]; then
        log_error "Environment file not found: $ENVIRONMENT_FILE"
        exit 1
    fi
    
    # Validate environment JSON
    if ! jq empty "$ENVIRONMENT_FILE" 2>/dev/null; then
        log_error "Invalid JSON in environment file: $ENVIRONMENT_FILE"
        exit 1
    fi
    
    log_success "All files validated successfully"
}

# Update environment with target URL
update_environment() {
    local target_url="$1"
    local temp_env="$OUTPUT_DIR/temp_environment_$TIMESTAMP.json"
    
    log_info "Updating environment with target URL: $target_url"
    
    # Create temporary environment file with updated baseUrl
    jq --arg url "$target_url" '.values = (.values | map(if .key == "baseUrl" then .value = $url else . end))' "$ENVIRONMENT_FILE" > "$temp_env"
    
    # Update with environment variables if available
    if [[ -n "${API_AUTH_TOKEN:-}" ]]; then
        jq --arg token "$API_AUTH_TOKEN" '.values = (.values | map(if .key == "authToken" then .value = $token else . end))' "$temp_env" > "${temp_env}.tmp" && mv "${temp_env}.tmp" "$temp_env"
        log_verbose "Updated authToken from environment variable"
    fi
    
    if [[ -n "${ADMIN_TOKEN:-}" ]]; then
        jq --arg token "$ADMIN_TOKEN" '.values = (.values | map(if .key == "adminToken" then .value = $token else . end))' "$temp_env" > "${temp_env}.tmp" && mv "${temp_env}.tmp" "$temp_env"
        log_verbose "Updated adminToken from environment variable"
    fi
    
    if [[ -n "${API_KEY:-}" ]]; then
        jq --arg key "$API_KEY" '.values = (.values | map(if .key == "apiKey" then .value = $key else . end))' "$temp_env" > "${temp_env}.tmp" && mv "${temp_env}.tmp" "$temp_env"
        log_verbose "Updated apiKey from environment variable"
    fi
    
    ENVIRONMENT_FILE="$temp_env"
    log_success "Environment updated successfully"
}

# Run Newman tests
run_newman_tests() {
    local target_url="$1"
    
    log_info "Starting Newman security tests..."
    log_info "Target: $target_url"
    log_info "Collection: $COLLECTION_FILE"
    log_info "Environment: $ENVIRONMENT_FILE"
    log_info "Iterations: $ITERATIONS"
    
    mkdir -p "$OUTPUT_DIR"
    
    # Build Newman command
    local newman_cmd="newman run '$COLLECTION_FILE'"
    newman_cmd="$newman_cmd --environment '$ENVIRONMENT_FILE'"
    newman_cmd="$newman_cmd --iteration-count $ITERATIONS"
    newman_cmd="$newman_cmd --timeout-request $TIMEOUT"
    newman_cmd="$newman_cmd --delay-request $DELAY_REQUEST"
    
    # Add reporters
    newman_cmd="$newman_cmd --reporters cli,json,html"
    newman_cmd="$newman_cmd --reporter-json-export '${NEWMAN_REPORT}.json'"
    newman_cmd="$newman_cmd --reporter-html-export '${NEWMAN_REPORT}.html'"
    
    # Add verbose flag if enabled
    if [[ "$VERBOSE" == "true" ]]; then
        newman_cmd="$newman_cmd --verbose"
    fi
    
    # Add bail flag if specified
    if [[ "${BAIL:-false}" == "true" ]]; then
        newman_cmd="$newman_cmd --bail"
    fi
    
    # Add no-color flag if specified
    if [[ "${NO_COLOR:-false}" == "true" ]]; then
        newman_cmd="$newman_cmd --no-color"
    fi
    
    log_verbose "Executing: $newman_cmd"
    
    # Execute Newman
    if eval "$newman_cmd"; then
        log_success "Newman tests completed successfully"
        return 0
    else
        local exit_code=$?
        log_warning "Newman tests completed with issues (exit code: $exit_code)"
        return $exit_code
    fi
}

# Process Newman results
process_results() {
    log_info "Processing Newman test results..."
    
    local json_report="${NEWMAN_REPORT}.json"
    
    if [[ ! -f "$json_report" ]]; then
        log_error "Newman JSON report not found: $json_report"
        return 1
    fi
    
    # Extract key metrics
    local total_tests=$(jq '.run.stats.tests.total // 0' "$json_report")
    local passed_tests=$(jq '.run.stats.tests.passed // 0' "$json_report")
    local failed_tests=$(jq '.run.stats.tests.failed // 0' "$json_report")
    local total_assertions=$(jq '.run.stats.assertions.total // 0' "$json_report")
    local passed_assertions=$(jq '.run.stats.assertions.passed // 0' "$json_report")
    local failed_assertions=$(jq '.run.stats.assertions.failed // 0' "$json_report")
    
    # Extract security findings
    local security_failures=$(jq '[.run.executions[] | select(.assertions[]?.error) | {
        name: .item.name,
        method: .request.method,
        url: .request.url.raw,
        failures: [.assertions[] | select(.error) | .assertion]
    }]' "$json_report")
    
    # Create summary report
    local summary_report="$OUTPUT_DIR/newman_summary_$TIMESTAMP.json"
    cat > "$summary_report" << EOF
{
  "summary": {
    "target_url": "$(jq -r '.environment.values[] | select(.key == "baseUrl") | .value' "$ENVIRONMENT_FILE")",
    "timestamp": "$(date -Iseconds)",
    "total_tests": $total_tests,
    "passed_tests": $passed_tests,
    "failed_tests": $failed_tests,
    "total_assertions": $total_assertions,
    "passed_assertions": $passed_assertions,
    "failed_assertions": $failed_assertions,
    "success_rate": $(echo "scale=2; $passed_tests * 100 / $total_tests" | bc -l 2>/dev/null || echo "0")
  },
  "security_findings": $security_failures,
  "reports": {
    "json": "$json_report",
    "html": "${NEWMAN_REPORT}.html",
    "summary": "$summary_report"
  }
}
EOF
    
    # Display summary
    echo
    log_info "=== NEWMAN TEST SUMMARY ==="
    echo -e "Total Tests: $total_tests"
    echo -e "Passed: $passed_tests"
    echo -e "Failed: $failed_tests"
    echo -e "Total Assertions: $total_assertions"
    echo -e "Passed Assertions: $passed_assertions"
    echo -e "Failed Assertions: $failed_assertions"
    echo -e "Success Rate: $(echo "scale=1; $passed_tests * 100 / $total_tests" | bc -l 2>/dev/null || echo "0")%"
    echo -e "JSON Report: $json_report"
    echo -e "HTML Report: ${NEWMAN_REPORT}.html"
    echo -e "Summary Report: $summary_report"
    echo
    
    if [[ $failed_tests -gt 0 ]]; then
        log_warning "Security issues detected - review failed tests"
    else
        log_success "All security tests passed"
    fi
}

# Cleanup temporary files
cleanup() {
    log_verbose "Cleaning up temporary files..."
    
    # Remove temporary environment file if it exists
    if [[ -f "$OUTPUT_DIR/temp_environment_$TIMESTAMP.json" ]]; then
        rm -f "$OUTPUT_DIR/temp_environment_$TIMESTAMP.json"
        log_verbose "Removed temporary environment file"
    fi
}

# Main execution
main() {
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
            -i|--iterations)
                ITERATIONS="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -d|--delay)
                DELAY_REQUEST="$2"
                shift 2
                ;;
            -e|--environment)
                ENVIRONMENT_FILE="$2"
                shift 2
                ;;
            -c|--collection)
                COLLECTION_FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --no-color)
                NO_COLOR=true
                shift
                ;;
            --bail)
                BAIL=true
                shift
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
    
    # Set up trap for cleanup
    trap cleanup EXIT
    
    # Run the test pipeline
    check_dependencies
    validate_files
    update_environment "$TARGET_URL"
    
    local exit_code=0
    if ! run_newman_tests "$TARGET_URL"; then
        exit_code=$?
    fi
    
    process_results
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "Newman security testing completed successfully!"
    else
        log_warning "Newman security testing completed with issues"
    fi
    
    exit $exit_code
}

# Run main function
main "$@"
