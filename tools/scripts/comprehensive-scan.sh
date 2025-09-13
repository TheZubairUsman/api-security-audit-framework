#!/bin/bash

# Comprehensive API Security Scan Script
# Master orchestration script that runs complete security audit pipeline
# Usage: ./comprehensive-scan.sh <target-url> [options]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/../../reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FINAL_REPORT="$OUTPUT_DIR/comprehensive_scan_$TIMESTAMP"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default configuration
VERBOSE=false
SKIP_BASIC=false
SKIP_NEWMAN=false
TIMEOUT=30
ITERATIONS=1
DELAY_REQUEST=0

# Help function
show_help() {
    cat << EOF
Comprehensive API Security Scanner

This script orchestrates a complete API security assessment by running:
1. Basic security scan (endpoint discovery, headers, vulnerabilities)
2. Newman/Postman collection tests (structured security tests)
3. Report aggregation and analysis

Usage: $0 <target-url> [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -t, --timeout SECONDS   Request timeout for basic scan (default: 30)
    -i, --iterations NUM    Newman iterations (default: 1)
    -d, --delay MS          Delay between Newman requests (default: 0)
    -o, --output DIR        Output directory (default: ../../reports)
    --skip-basic            Skip basic security scan
    --skip-newman           Skip Newman/Postman tests
    --basic-only            Run only basic scan
    --newman-only           Run only Newman tests

EXAMPLES:
    $0 https://api.example.com
    $0 https://api.example.com -v -t 60 -i 3
    $0 https://api.example.com --skip-newman
    $0 https://api.example.com --basic-only

ENVIRONMENT VARIABLES:
    API_AUTH_TOKEN         Authentication token for API requests
    ADMIN_TOKEN           Admin token for privilege escalation tests
    API_KEY               API key for authentication tests
    PROXY_URL             HTTP/HTTPS proxy URL

REPORTS GENERATED:
    - Basic scan JSON report
    - Newman JSON and HTML reports
    - Comprehensive merged report (JSON, HTML, PDF, Markdown)
    - Executive summary
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

log_step() {
    echo -e "${PURPLE}[STEP]${NC} $1"
}

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${CYAN}[VERBOSE]${NC} $1"
    fi
}

# Progress tracking
show_progress() {
    local current=$1
    local total=$2
    local description=$3
    
    local percentage=$((current * 100 / total))
    local filled=$((percentage / 5))
    local empty=$((20 - filled))
    
    printf "\r${BLUE}[PROGRESS]${NC} ["
    printf "%*s" $filled | tr ' ' '='
    printf "%*s" $empty | tr ' ' '-'
    printf "] %d%% - %s" $percentage "$description"
    
    if [[ $current -eq $total ]]; then
        echo
    fi
}

# Check dependencies
check_dependencies() {
    log_step "Checking dependencies..."
    
    local missing_deps=()
    
    # Check required tools
    local required_tools=("curl" "jq" "bc")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_deps+=("$tool")
        fi
    done
    
    # Check Newman if not skipping
    if [[ "$SKIP_NEWMAN" != "true" ]]; then
        if ! command -v newman &> /dev/null; then
            missing_deps+=("newman")
        fi
    fi
    
    # Check report generation tools
    if command -v wkhtmltopdf &> /dev/null; then
        log_verbose "PDF generation available (wkhtmltopdf found)"
    else
        log_warning "PDF generation not available (wkhtmltopdf not found)"
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        echo "Please install missing tools:"
        for dep in "${missing_deps[@]}"; do
            case $dep in
                newman) echo "  npm install -g newman" ;;
                wkhtmltopdf) echo "  apt-get install wkhtmltopdf (or equivalent)" ;;
                *) echo "  Install $dep using your package manager" ;;
            esac
        done
        exit 1
    fi
    
    log_success "All required dependencies available"
}

# Initialize comprehensive report
init_comprehensive_report() {
    local target_url="$1"
    
    mkdir -p "$OUTPUT_DIR"
    
    cat > "${FINAL_REPORT}.json" << EOF
{
  "scan_info": {
    "target": "$target_url",
    "timestamp": "$(date -Iseconds)",
    "scanner_version": "1.0.0",
    "scan_type": "comprehensive"
  },
  "results": {
    "basic_scan": {},
    "newman_tests": {},
    "summary": {},
    "recommendations": []
  },
  "reports": {
    "basic_scan_report": "",
    "newman_json_report": "",
    "newman_html_report": "",
    "comprehensive_json": "${FINAL_REPORT}.json",
    "comprehensive_html": "${FINAL_REPORT}.html",
    "comprehensive_pdf": "${FINAL_REPORT}.pdf",
    "comprehensive_markdown": "${FINAL_REPORT}.md"
  }
}
EOF
}

# Run basic security scan
run_basic_scan() {
    local target_url="$1"
    
    log_step "Running basic security scan..."
    show_progress 1 4 "Basic security scan"
    
    local basic_script="$SCRIPT_DIR/basic-scan.sh"
    if [[ ! -f "$basic_script" ]]; then
        log_error "Basic scan script not found: $basic_script"
        return 1
    fi
    
    # Build basic scan command
    local basic_cmd="$basic_script '$target_url'"
    basic_cmd="$basic_cmd --timeout $TIMEOUT"
    basic_cmd="$basic_cmd --output '$OUTPUT_DIR/basic_scan_$TIMESTAMP.json'"
    
    if [[ "$VERBOSE" == "true" ]]; then
        basic_cmd="$basic_cmd --verbose"
    fi
    
    log_verbose "Executing: $basic_cmd"
    
    if eval "$basic_cmd"; then
        log_success "Basic scan completed"
        
        # Update comprehensive report with basic scan results
        local basic_report="$OUTPUT_DIR/basic_scan_$TIMESTAMP.json"
        if [[ -f "$basic_report" ]]; then
            jq --slurpfile basic "$basic_report" '.results.basic_scan = $basic[0].results | .reports.basic_scan_report = "'$basic_report'"' "${FINAL_REPORT}.json" > "${FINAL_REPORT}.json.tmp" && mv "${FINAL_REPORT}.json.tmp" "${FINAL_REPORT}.json"
        fi
        
        return 0
    else
        log_warning "Basic scan completed with issues"
        return 1
    fi
}

# Run Newman tests
run_newman_tests() {
    local target_url="$1"
    
    log_step "Running Newman security tests..."
    show_progress 2 4 "Newman security tests"
    
    local newman_script="$SCRIPT_DIR/run-newman.sh"
    if [[ ! -f "$newman_script" ]]; then
        log_error "Newman script not found: $newman_script"
        return 1
    fi
    
    # Build Newman command
    local newman_cmd="$newman_script '$target_url'"
    newman_cmd="$newman_cmd --iterations $ITERATIONS"
    newman_cmd="$newman_cmd --delay $DELAY_REQUEST"
    newman_cmd="$newman_cmd --output '$OUTPUT_DIR'"
    
    if [[ "$VERBOSE" == "true" ]]; then
        newman_cmd="$newman_cmd --verbose"
    fi
    
    log_verbose "Executing: $newman_cmd"
    
    if eval "$newman_cmd"; then
        log_success "Newman tests completed"
        
        # Update comprehensive report with Newman results
        local newman_summary=$(find "$OUTPUT_DIR" -name "newman_summary_*.json" -newer "${FINAL_REPORT}.json" | head -1)
        if [[ -f "$newman_summary" ]]; then
            jq --slurpfile newman "$newman_summary" '.results.newman_tests = $newman[0] | .reports.newman_json_report = $newman[0].reports.json | .reports.newman_html_report = $newman[0].reports.html' "${FINAL_REPORT}.json" > "${FINAL_REPORT}.json.tmp" && mv "${FINAL_REPORT}.json.tmp" "${FINAL_REPORT}.json"
        fi
        
        return 0
    else
        log_warning "Newman tests completed with issues"
        return 1
    fi
}

# Aggregate and analyze results
aggregate_results() {
    log_step "Aggregating and analyzing results..."
    show_progress 3 4 "Result aggregation"
    
    # Calculate comprehensive metrics
    local basic_endpoints=$(jq '.results.basic_scan.endpoint_discovery.total_found // 0' "${FINAL_REPORT}.json")
    local basic_vulnerabilities=$(jq '.results.basic_scan.common_vulnerabilities.total // 0' "${FINAL_REPORT}.json")
    local basic_missing_headers=$(jq '.results.basic_scan.security_headers.missing | length' "${FINAL_REPORT}.json")
    local basic_auth_bypasses=$(jq '.results.basic_scan.authentication_tests.potential_bypasses | length' "${FINAL_REPORT}.json")
    
    local newman_failed_tests=$(jq '.results.newman_tests.summary.failed_tests // 0' "${FINAL_REPORT}.json")
    local newman_failed_assertions=$(jq '.results.newman_tests.summary.failed_assertions // 0' "${FINAL_REPORT}.json")
    local newman_success_rate=$(jq '.results.newman_tests.summary.success_rate // 100' "${FINAL_REPORT}.json")
    
    # Calculate overall risk score
    local risk_score=$((basic_vulnerabilities * 10 + basic_missing_headers * 2 + basic_auth_bypasses * 5 + newman_failed_tests * 3))
    
    local risk_level
    if [[ $risk_score -eq 0 ]]; then
        risk_level="LOW"
    elif [[ $risk_score -le 20 ]]; then
        risk_level="MEDIUM"
    elif [[ $risk_score -le 50 ]]; then
        risk_level="HIGH"
    else
        risk_level="CRITICAL"
    fi
    
    # Generate recommendations
    local recommendations=()
    
    if [[ $basic_missing_headers -gt 0 ]]; then
        recommendations+=("Implement missing security headers to prevent common attacks")
    fi
    
    if [[ $basic_vulnerabilities -gt 0 ]]; then
        recommendations+=("Address identified vulnerabilities through input validation and secure coding practices")
    fi
    
    if [[ $basic_auth_bypasses -gt 0 ]]; then
        recommendations+=("Review and strengthen authentication mechanisms to prevent bypass attempts")
    fi
    
    if [[ $newman_failed_tests -gt 0 ]]; then
        recommendations+=("Review failed security test cases and implement appropriate controls")
    fi
    
    if [[ $(echo "$newman_success_rate < 95" | bc -l) -eq 1 ]]; then
        recommendations+=("Improve API security posture to achieve >95% test success rate")
    fi
    
    if [[ ${#recommendations[@]} -eq 0 ]]; then
        recommendations+=("Maintain current security posture and implement continuous monitoring")
    fi
    
    # Create comprehensive summary
    local recommendations_json=$(printf '%s\n' "${recommendations[@]}" | jq -R . | jq -s .)
    local summary="{
        \"overall_risk_score\": $risk_score,
        \"overall_risk_level\": \"$risk_level\",
        \"endpoints_discovered\": $basic_endpoints,
        \"vulnerabilities_found\": $basic_vulnerabilities,
        \"missing_security_headers\": $basic_missing_headers,
        \"auth_bypass_attempts\": $basic_auth_bypasses,
        \"newman_test_success_rate\": $newman_success_rate,
        \"newman_failed_tests\": $newman_failed_tests,
        \"scan_timestamp\": \"$(date -Iseconds)\",
        \"total_recommendations\": ${#recommendations[@]}
    }"
    
    jq ".results.summary = $summary | .results.recommendations = $recommendations_json" "${FINAL_REPORT}.json" > "${FINAL_REPORT}.json.tmp" && mv "${FINAL_REPORT}.json.tmp" "${FINAL_REPORT}.json"
    
    log_success "Results aggregated successfully"
}

# Generate comprehensive reports
generate_reports() {
    log_step "Generating comprehensive reports..."
    show_progress 4 4 "Report generation"
    
    # Generate HTML report
    generate_html_report
    
    # Generate Markdown report
    generate_markdown_report
    
    # Generate PDF report if possible
    if command -v wkhtmltopdf &> /dev/null; then
        generate_pdf_report
    else
        log_warning "Skipping PDF generation (wkhtmltopdf not available)"
    fi
    
    log_success "All reports generated successfully"
}

# Generate HTML report
generate_html_report() {
    local html_file="${FINAL_REPORT}.html"
    local target_url=$(jq -r '.scan_info.target' "${FINAL_REPORT}.json")
    local timestamp=$(jq -r '.scan_info.timestamp' "${FINAL_REPORT}.json")
    local risk_level=$(jq -r '.results.summary.overall_risk_level' "${FINAL_REPORT}.json")
    local risk_score=$(jq -r '.results.summary.overall_risk_score' "${FINAL_REPORT}.json")
    
    cat > "$html_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprehensive API Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .risk-low { color: #28a745; }
        .risk-medium { color: #ffc107; }
        .risk-high { color: #fd7e14; }
        .risk-critical { color: #dc3545; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .metric { display: inline-block; margin: 10px; padding: 10px; background: #f8f9fa; border-radius: 3px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .recommendations { background: #e7f3ff; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Comprehensive API Security Report</h1>
        <p><strong>Target:</strong> $target_url</p>
        <p><strong>Scan Date:</strong> $timestamp</p>
        <p><strong>Overall Risk Level:</strong> <span class="risk-$(echo $risk_level | tr '[:upper:]' '[:lower:]')">$risk_level</span> (Score: $risk_score)</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="metric">
            <strong>Endpoints Discovered:</strong> $(jq -r '.results.summary.endpoints_discovered' "${FINAL_REPORT}.json")
        </div>
        <div class="metric">
            <strong>Vulnerabilities Found:</strong> $(jq -r '.results.summary.vulnerabilities_found' "${FINAL_REPORT}.json")
        </div>
        <div class="metric">
            <strong>Missing Security Headers:</strong> $(jq -r '.results.summary.missing_security_headers' "${FINAL_REPORT}.json")
        </div>
        <div class="metric">
            <strong>Newman Test Success Rate:</strong> $(jq -r '.results.summary.newman_test_success_rate' "${FINAL_REPORT}.json")%
        </div>
    </div>

    <div class="section">
        <h2>Security Test Results</h2>
        <h3>Basic Security Scan</h3>
        <p>Endpoint discovery, security headers analysis, and common vulnerability detection.</p>
        
        <h3>Newman/Postman Tests</h3>
        <p>Structured security test cases covering authentication, authorization, and business logic.</p>
    </div>

    <div class="recommendations">
        <h2>Recommendations</h2>
        <ul>
EOF

    # Add recommendations
    jq -r '.results.recommendations[]' "${FINAL_REPORT}.json" | while read -r recommendation; do
        echo "            <li>$recommendation</li>" >> "$html_file"
    done

    cat >> "$html_file" << EOF
        </ul>
    </div>

    <div class="section">
        <h2>Detailed Reports</h2>
        <p><strong>Basic Scan JSON:</strong> $(jq -r '.reports.basic_scan_report' "${FINAL_REPORT}.json")</p>
        <p><strong>Newman HTML Report:</strong> $(jq -r '.reports.newman_html_report' "${FINAL_REPORT}.json")</p>
        <p><strong>Comprehensive JSON:</strong> ${FINAL_REPORT}.json</p>
    </div>

    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
        <p>Generated by API Security Audit Framework v1.0.0</p>
    </footer>
</body>
</html>
EOF
}

# Generate Markdown report
generate_markdown_report() {
    local md_file="${FINAL_REPORT}.md"
    local target_url=$(jq -r '.scan_info.target' "${FINAL_REPORT}.json")
    local timestamp=$(jq -r '.scan_info.timestamp' "${FINAL_REPORT}.json")
    local risk_level=$(jq -r '.results.summary.overall_risk_level' "${FINAL_REPORT}.json")
    local risk_score=$(jq -r '.results.summary.overall_risk_score' "${FINAL_REPORT}.json")
    
    cat > "$md_file" << EOF
# Comprehensive API Security Report

## Scan Information

- **Target:** $target_url
- **Scan Date:** $timestamp
- **Overall Risk Level:** $risk_level (Score: $risk_score)

## Executive Summary

| Metric | Value |
|--------|-------|
| Endpoints Discovered | $(jq -r '.results.summary.endpoints_discovered' "${FINAL_REPORT}.json") |
| Vulnerabilities Found | $(jq -r '.results.summary.vulnerabilities_found' "${FINAL_REPORT}.json") |
| Missing Security Headers | $(jq -r '.results.summary.missing_security_headers' "${FINAL_REPORT}.json") |
| Auth Bypass Attempts | $(jq -r '.results.summary.auth_bypass_attempts' "${FINAL_REPORT}.json") |
| Newman Test Success Rate | $(jq -r '.results.summary.newman_test_success_rate' "${FINAL_REPORT}.json")% |
| Newman Failed Tests | $(jq -r '.results.summary.newman_failed_tests' "${FINAL_REPORT}.json") |

## Security Test Results

### Basic Security Scan
- Endpoint discovery and enumeration
- Security headers analysis
- Common vulnerability detection
- Authentication bypass testing
- SSL/TLS security assessment

### Newman/Postman Tests
- Structured security test cases
- Authentication and authorization testing
- Business logic security validation
- Input validation and injection testing

## Recommendations

EOF

    # Add recommendations
    jq -r '.results.recommendations[]' "${FINAL_REPORT}.json" | while read -r recommendation; do
        echo "- $recommendation" >> "$md_file"
    done

    cat >> "$md_file" << EOF

## Detailed Reports

- **Basic Scan JSON:** $(jq -r '.reports.basic_scan_report' "${FINAL_REPORT}.json")
- **Newman HTML Report:** $(jq -r '.reports.newman_html_report' "${FINAL_REPORT}.json")
- **Comprehensive JSON:** ${FINAL_REPORT}.json
- **Comprehensive HTML:** ${FINAL_REPORT}.html

---

*Generated by API Security Audit Framework v1.0.0*
EOF
}

# Generate PDF report
generate_pdf_report() {
    local pdf_file="${FINAL_REPORT}.pdf"
    local html_file="${FINAL_REPORT}.html"
    
    if wkhtmltopdf --page-size A4 --margin-top 0.75in --margin-right 0.75in --margin-bottom 0.75in --margin-left 0.75in "$html_file" "$pdf_file" 2>/dev/null; then
        log_success "PDF report generated: $pdf_file"
    else
        log_warning "Failed to generate PDF report"
    fi
}

# Display final summary
display_final_summary() {
    local target_url=$(jq -r '.scan_info.target' "${FINAL_REPORT}.json")
    local risk_level=$(jq -r '.results.summary.overall_risk_level' "${FINAL_REPORT}.json")
    local risk_score=$(jq -r '.results.summary.overall_risk_score' "${FINAL_REPORT}.json")
    local endpoints=$(jq -r '.results.summary.endpoints_discovered' "${FINAL_REPORT}.json")
    local vulnerabilities=$(jq -r '.results.summary.vulnerabilities_found' "${FINAL_REPORT}.json")
    local success_rate=$(jq -r '.results.summary.newman_test_success_rate' "${FINAL_REPORT}.json")
    
    echo
    echo "========================================"
    log_info "COMPREHENSIVE SCAN COMPLETED"
    echo "========================================"
    echo -e "Target: $target_url"
    echo -e "Overall Risk: $risk_level (Score: $risk_score)"
    echo -e "Endpoints Found: $endpoints"
    echo -e "Vulnerabilities: $vulnerabilities"
    echo -e "Test Success Rate: $success_rate%"
    echo
    echo "Generated Reports:"
    echo -e "  JSON: ${FINAL_REPORT}.json"
    echo -e "  HTML: ${FINAL_REPORT}.html"
    echo -e "  Markdown: ${FINAL_REPORT}.md"
    if [[ -f "${FINAL_REPORT}.pdf" ]]; then
        echo -e "  PDF: ${FINAL_REPORT}.pdf"
    fi
    echo "========================================"
    echo
}

# Main execution
main() {
    local start_time=$(date +%s)
    
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
            -i|--iterations)
                ITERATIONS="$2"
                shift 2
                ;;
            -d|--delay)
                DELAY_REQUEST="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --skip-basic)
                SKIP_BASIC=true
                shift
                ;;
            --skip-newman)
                SKIP_NEWMAN=true
                shift
                ;;
            --basic-only)
                SKIP_NEWMAN=true
                shift
                ;;
            --newman-only)
                SKIP_BASIC=true
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
    
    log_info "Starting Comprehensive API Security Scan"
    log_info "Target: $TARGET_URL"
    echo
    
    # Run the comprehensive scan pipeline
    check_dependencies
    init_comprehensive_report "$TARGET_URL"
    
    local exit_code=0
    
    # Run basic scan unless skipped
    if [[ "$SKIP_BASIC" != "true" ]]; then
        if ! run_basic_scan "$TARGET_URL"; then
            exit_code=1
        fi
    fi
    
    # Run Newman tests unless skipped
    if [[ "$SKIP_NEWMAN" != "true" ]]; then
        if ! run_newman_tests "$TARGET_URL"; then
            exit_code=1
        fi
    fi
    
    # Always aggregate results and generate reports
    aggregate_results
    generate_reports
    
    # Display final summary
    display_final_summary
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log_info "Total scan duration: $(date -d @$duration -u +%H:%M:%S)"
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "Comprehensive security scan completed successfully!"
    else
        log_warning "Comprehensive security scan completed with some issues"
    fi
    
    exit $exit_code
}

# Trap signals for cleanup
trap 'log_error "Scan interrupted"; exit 1' INT TERM

# Run main function
main "$@"
