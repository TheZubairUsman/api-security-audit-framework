#!/bin/bash

# API Security Report Generator
# Converts JSON scan results to various report formats

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_DIR="$SCRIPT_DIR/../../reports"
TEMPLATES_DIR="$SCRIPT_DIR/../../templates"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
INPUT_FILE=""
OUTPUT_FORMAT="html"
OUTPUT_FILE=""
TEMPLATE=""
INCLUDE_DETAILS=true
COMPANY_NAME="Your Company"
VERBOSE=false

# Help function
show_help() {
    cat << EOF
API Security Report Generator

Usage: $0 -i <input-file> [OPTIONS]

OPTIONS:
    -i, --input FILE        Input JSON report file (required)
    -f, --format FORMAT     Output format: html, pdf, markdown, csv (default: html)
    -o, --output FILE       Output file name (auto-generated if not specified)
    -t, --template FILE     Custom template file
    -c, --company NAME      Company name for reports (default: "Your Company")
    -s, --summary           Generate summary report only (exclude details)
    -v, --verbose           Enable verbose output
    -h, --help              Show this help message

FORMATS:
    html                    Interactive HTML report with charts
    pdf                     Professional PDF report (requires wkhtmltopdf)
    markdown                Markdown report for documentation
    csv                     CSV export for data analysis
    json                    Enhanced JSON with additional analysis

EXAMPLES:
    $0 -i scan_results.json
    $0 -i scan_results.json -f pdf -c "Acme Corp"
    $0 -i scan_results.json -f markdown -o security_report.md
    $0 -i scan_results.json -f csv --summary
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

# Validate dependencies
check_dependencies() {
    local deps=("jq")
    
    case "$OUTPUT_FORMAT" in
        pdf)
            deps+=("wkhtmltopdf")
            ;;
        html)
            deps+=("python3")
            ;;
    esac
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "Required dependency '$dep' not found"
            log_error "Please install $dep and try again"
            exit 1
        fi
    done
    
    log_verbose "All dependencies satisfied"
}

# Validate input file
validate_input() {
    if [[ ! -f "$INPUT_FILE" ]]; then
        log_error "Input file '$INPUT_FILE' not found"
        exit 1
    fi
    
    # Validate JSON format
    if ! jq empty "$INPUT_FILE" 2>/dev/null; then
        log_error "Invalid JSON format in input file"
        exit 1
    fi
    
    # Check for required fields
    local required_fields=(".scan_info.target" ".results")
    for field in "${required_fields[@]}"; do
        if ! jq -e "$field" "$INPUT_FILE" >/dev/null 2>&1; then
            log_error "Required field '$field' not found in input file"
            exit 1
        fi
    done
    
    log_verbose "Input file validated successfully"
}

# Extract data from JSON report
extract_data() {
    log_verbose "Extracting data from JSON report..."
    
    # Basic scan info
    TARGET=$(jq -r '.scan_info.target' "$INPUT_FILE")
    SCAN_DATE=$(jq -r '.scan_info.timestamp' "$INPUT_FILE")
    SCANNER_VERSION=$(jq -r '.scan_info.scanner_version // "Unknown"' "$INPUT_FILE")
    
    # Results
    ENDPOINTS_FOUND=$(jq -r '.results.endpoint_discovery.total_found // 0' "$INPUT_FILE")
    MISSING_HEADERS=$(jq -r '.results.security_headers.missing | length' "$INPUT_FILE")
    AUTH_BYPASSES=$(jq -r '.results.authentication_tests.potential_bypasses | length' "$INPUT_FILE")
    VULNERABILITIES=$(jq -r '.results.common_vulnerabilities.total // 0' "$INPUT_FILE")
    RISK_LEVEL=$(jq -r '.results.summary.risk_level // "UNKNOWN"' "$INPUT_FILE")
    RISK_SCORE=$(jq -r '.results.summary.risk_score // 0' "$INPUT_FILE")
    
    log_verbose "Data extraction completed"
}

# Generate HTML report
generate_html_report() {
    local output_file="$1"
    
    log_info "Generating HTML report..."
    
    cat > "$output_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Assessment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #333;
            margin: 0;
            font-size: 2.5em;
        }
        .header .subtitle {
            color: #666;
            font-size: 1.2em;
            margin-top: 5px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #007acc;
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #333;
        }
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #007acc;
        }
        .risk-critical { color: #dc3545; border-left-color: #dc3545; }
        .risk-high { color: #fd7e14; border-left-color: #fd7e14; }
        .risk-medium { color: #ffc107; border-left-color: #ffc107; }
        .risk-low { color: #28a745; border-left-color: #28a745; }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
        }
        .section h2 {
            color: #333;
            border-bottom: 2px solid #007acc;
            padding-bottom: 10px;
            margin-top: 0;
        }
        .finding {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .finding.high {
            background: #f8d7da;
            border-color: #f5c6cb;
        }
        .finding.medium {
            background: #fff3cd;
            border-color: #ffeaa7;
        }
        .finding.low {
            background: #d1ecf1;
            border-color: #bee5eb;
        }
        .endpoint-list {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 10px;
            font-family: monospace;
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        th {
            background-color: #007acc;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }
        .chart-container {
            margin: 20px 0;
            text-align: center;
        }
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>API Security Assessment Report</h1>
            <div class="subtitle">COMPANY_NAME_PLACEHOLDER</div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Target</h3>
                <div class="value" style="font-size: 1.2em;">TARGET_PLACEHOLDER</div>
            </div>
            <div class="summary-card">
                <h3>Scan Date</h3>
                <div class="value" style="font-size: 1.2em;">SCAN_DATE_PLACEHOLDER</div>
            </div>
            <div class="summary-card risk-RISK_CLASS_PLACEHOLDER">
                <h3>Risk Level</h3>
                <div class="value">RISK_LEVEL_PLACEHOLDER</div>
            </div>
            <div class="summary-card">
                <h3>Risk Score</h3>
                <div class="value">RISK_SCORE_PLACEHOLDER</div>
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>Endpoints Found</h3>
                <div class="value">ENDPOINTS_FOUND_PLACEHOLDER</div>
            </div>
            <div class="summary-card">
                <h3>Missing Headers</h3>
                <div class="value">MISSING_HEADERS_PLACEHOLDER</div>
            </div>
            <div class="summary-card">
                <h3>Auth Issues</h3>
                <div class="value">AUTH_BYPASSES_PLACEHOLDER</div>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilities</h3>
                <div class="value">VULNERABILITIES_PLACEHOLDER</div>
            </div>
        </div>

        <div class="section">
            <h2>Risk Assessment</h2>
            <div class="chart-container">
                <canvas id="riskChart" width="400" height="200"></canvas>
            </div>
            <p>The overall risk assessment is based on discovered vulnerabilities, missing security controls, and potential attack vectors.</p>
        </div>

        <div class="section">
            <h2>Discovered Endpoints</h2>
            <div id="endpoints-section">
                ENDPOINTS_CONTENT_PLACEHOLDER
            </div>
        </div>

        <div class="section">
            <h2>Security Headers Analysis</h2>
            <div id="headers-section">
                HEADERS_CONTENT_PLACEHOLDER
            </div>
        </div>

        <div class="section">
            <h2>Authentication Testing</h2>
            <div id="auth-section">
                AUTH_CONTENT_PLACEHOLDER
            </div>
        </div>

        <div class="section">
            <h2>Vulnerability Assessment</h2>
            <div id="vuln-section">
                VULN_CONTENT_PLACEHOLDER
            </div>
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            <div id="recommendations">
                RECOMMENDATIONS_PLACEHOLDER
            </div>
        </div>

        <div class="footer">
            <p>Report generated on $(date) by API Security Audit Framework v${SCANNER_VERSION}</p>
            <p>This is an automated security assessment. Manual verification of findings is recommended.</p>
        </div>
    </div>

    <script>
        // Risk chart
        const ctx = document.getElementById('riskChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical Issues', 'High Issues', 'Medium Issues', 'Low Issues'],
                datasets: [{
                    data: [CHART_DATA_PLACEHOLDER],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    title: {
                        display: true,
                        text: 'Security Issues by Severity'
                    }
                }
            }
        });
    </script>
</body>
</html>
EOF

    # Replace placeholders with actual data
    local risk_class=$(echo "$RISK_LEVEL" | tr '[:upper:]' '[:lower:]')
    local formatted_date=$(date -d "$SCAN_DATE" "+%B %d, %Y at %H:%M UTC" 2>/dev/null || echo "$SCAN_DATE")
    
    sed -i "s/COMPANY_NAME_PLACEHOLDER/$COMPANY_NAME/g" "$output_file"
    sed -i "s/TARGET_PLACEHOLDER/$TARGET/g" "$output_file"
    sed -i "s/SCAN_DATE_PLACEHOLDER/$formatted_date/g" "$output_file"
    sed -i "s/RISK_LEVEL_PLACEHOLDER/$RISK_LEVEL/g" "$output_file"
    sed -i "s/RISK_CLASS_PLACEHOLDER/$risk_class/g" "$output_file"
    sed -i "s/RISK_SCORE_PLACEHOLDER/$RISK_SCORE/g" "$output_file"
    sed -i "s/ENDPOINTS_FOUND_PLACEHOLDER/$ENDPOINTS_FOUND/g" "$output_file"
    sed -i "s/MISSING_HEADERS_PLACEHOLDER/$MISSING_HEADERS/g" "$output_file"
    sed -i "s/AUTH_BYPASSES_PLACEHOLDER/$AUTH_BYPASSES/g" "$output_file"
    sed -i "s/VULNERABILITIES_PLACEHOLDER/$VULNERABILITIES/g" "$output_file"
    
    # Generate detailed sections
    generate_endpoints_section "$output_file"
    generate_headers_section "$output_file"
    generate_auth_section "$output_file"
    generate_vuln_section "$output_file"
    generate_recommendations "$output_file"
    generate_chart_data "$output_file"
    
    log_success "HTML report generated: $output_file"
}

# Generate endpoints section for HTML
generate_endpoints_section() {
    local output_file="$1"
    local content=""
    
    local endpoints=$(jq -r '.results.endpoint_discovery.discovered[]? | "\(.path)|\(.status_code)"' "$INPUT_FILE")
    
    if [[ -n "$endpoints" ]]; then
        content="<table><thead><tr><th>Endpoint</th><th>Status Code</th><th>Risk Level</th></tr></thead><tbody>"
        while IFS='|' read -r path status_code; do
            local risk="Low"
            if [[ "$path" =~ admin|debug|config|actuator ]]; then
                risk="High"
            elif [[ "$path" =~ api|auth ]]; then
                risk="Medium"
            fi
            content+="<tr><td><code>$path</code></td><td>$status_code</td><td>$risk</td></tr>"
        done <<< "$endpoints"
        content+="</tbody></table>"
    else
        content="<p>No endpoints discovered during the scan.</p>"
    fi
    
    sed -i "s|ENDPOINTS_CONTENT_PLACEHOLDER|$content|g" "$output_file"
}

# Generate headers section for HTML
generate_headers_section() {
    local output_file="$1"
    local content=""
    
    local missing_headers=$(jq -r '.results.security_headers.missing[]?' "$INPUT_FILE")
    local present_headers=$(jq -r '.results.security_headers.present[]?' "$INPUT_FILE")
    
    content="<h3>Missing Security Headers</h3>"
    if [[ -n "$missing_headers" ]]; then
        content+="<ul>"
        while read -r header; do
            [[ -n "$header" ]] && content+="<li class='finding medium'>$header</li>"
        done <<< "$missing_headers"
        content+="</ul>"
    else
        content+="<p class='finding low'>All critical security headers are present.</p>"
    fi
    
    content+="<h3>Present Security Headers</h3>"
    if [[ -n "$present_headers" ]]; then
        content+="<ul>"
        while read -r header; do
            [[ -n "$header" ]] && content+="<li class='finding low'>$header ✓</li>"
        done <<< "$present_headers"
        content+="</ul>"
    fi
    
    sed -i "s|HEADERS_CONTENT_PLACEHOLDER|$content|g" "$output_file"
}

# Generate auth section for HTML
generate_auth_section() {
    local output_file="$1"
    local content=""
    
    local bypasses=$(jq -r '.results.authentication_tests.potential_bypasses[]?' "$INPUT_FILE")
    
    if [[ -n "$bypasses" ]]; then
        content="<h3>Potential Authentication Bypasses</h3><ul>"
        while read -r bypass; do
            [[ -n "$bypass" ]] && content+="<li class='finding high'>$bypass</li>"
        done <<< "$bypasses"
        content+="</ul>"
    else
        content="<p class='finding low'>No obvious authentication bypass vulnerabilities detected.</p>"
    fi
    
    sed -i "s|AUTH_CONTENT_PLACEHOLDER|$content|g" "$output_file"
}

# Generate vulnerability section for HTML
generate_vuln_section() {
    local output_file="$1"
    local content=""
    
    local vulns=$(jq -r '.results.common_vulnerabilities.findings[]?' "$INPUT_FILE")
    
    if [[ -n "$vulns" ]]; then
        content="<h3>Potential Vulnerabilities</h3><ul>"
        while read -r vuln; do
            [[ -n "$vuln" ]] && content+="<li class='finding high'>$vuln</li>"
        done <<< "$vulns"
        content+="</ul>"
    else
        content="<p class='finding low'>No common vulnerabilities detected in basic scan.</p>"
    fi
    
    sed -i "s|VULN_CONTENT_PLACEHOLDER|$content|g" "$output_file"
}

# Generate recommendations
generate_recommendations() {
    local output_file="$1"
    local content="<ul>"
    
    # Generate recommendations based on findings
    if [[ $MISSING_HEADERS -gt 0 ]]; then
        content+="<li><strong>Implement Missing Security Headers:</strong> Add the missing security headers to prevent common attacks like XSS, clickjacking, and MIME sniffing.</li>"
    fi
    
    if [[ $AUTH_BYPASSES -gt 0 ]]; then
        content+="<li><strong>Fix Authentication Issues:</strong> Review and strengthen authentication mechanisms to prevent bypass attempts.</li>"
    fi
    
    if [[ $VULNERABILITIES -gt 0 ]]; then
        content+="<li><strong>Address Vulnerabilities:</strong> Investigate and fix the potential vulnerabilities identified during the scan.</li>"
    fi
    
    if [[ "$TARGET" != https://* ]]; then
        content+="<li><strong>Enable HTTPS:</strong> Ensure all API endpoints use HTTPS to protect data in transit.</li>"
    fi
    
    # General recommendations
    content+="<li><strong>Regular Security Testing:</strong> Implement regular automated security scanning and manual penetration testing.</li>"
    content+="<li><strong>API Documentation:</strong> Maintain up-to-date API documentation and security policies.</li>"
    content+="<li><strong>Monitoring and Logging:</strong> Implement comprehensive logging and monitoring for security events.</li>"
    content+="<li><strong>Rate Limiting:</strong> Implement proper rate limiting to prevent abuse and DoS attacks.</li>"
    content+="<li><strong>Input Validation:</strong> Ensure all user inputs are properly validated and sanitized.</li>"
    content+="</ul>"
    
    sed -i "s|RECOMMENDATIONS_PLACEHOLDER|$content|g" "$output_file"
}

# Generate chart data
generate_chart_data() {
    local output_file="$1"
    
    # Count issues by severity (simplified for demo)
    local critical=0
    local high=$((VULNERABILITIES + AUTH_BYPASSES))
    local medium=$MISSING_HEADERS
    local low=0
    
    if [[ "$RISK_LEVEL" == "CRITICAL" ]]; then
        critical=$((critical + 1))
    fi
    
    local chart_data="$critical, $high, $medium, $low"
    sed -i "s/CHART_DATA_PLACEHOLDER/$chart_data/g" "$output_file"
}

# Generate PDF report
generate_pdf_report() {
    local output_file="$1"
    
    log_info "Generating PDF report..."
    
    # First generate HTML
    local temp_html="${output_file%.pdf}.temp.html"
    generate_html_report "$temp_html"
    
    # Convert to PDF
    if command -v wkhtmltopdf &> /dev/null; then
        wkhtmltopdf --page-size A4 --margin-top 0.75in --margin-right 0.75in --margin-bottom 0.75in --margin-left 0.75in --encoding UTF-8 --quiet "$temp_html" "$output_file"
        rm -f "$temp_html"
        log_success "PDF report generated: $output_file"
    else
        log_error "wkhtmltopdf not found. Cannot generate PDF report."
        log_info "HTML report available at: $temp_html"
    fi
}

# Generate Markdown report
generate_markdown_report() {
    local output_file="$1"
    
    log_info "Generating Markdown report..."
    
    cat > "$output_file" << EOF
# API Security Assessment Report

**Company:** $COMPANY_NAME  
**Target:** $TARGET  
**Scan Date:** $(date -d "$SCAN_DATE" "+%B %d, %Y at %H:%M UTC" 2>/dev/null || echo "$SCAN_DATE")  
**Risk Level:** **$RISK_LEVEL**  
**Risk Score:** $RISK_SCORE

## Executive Summary

This report presents the findings of an automated API security assessment performed on $TARGET. The scan identified $ENDPOINTS_FOUND endpoints and discovered several security issues that require attention.

### Key Findings

- **Endpoints Discovered:** $ENDPOINTS_FOUND
- **Missing Security Headers:** $MISSING_HEADERS
- **Authentication Issues:** $AUTH_BYPASSES
- **Potential Vulnerabilities:** $VULNERABILITIES
- **Overall Risk Level:** $RISK_LEVEL

## Detailed Findings

### Discovered Endpoints

$(if [[ $ENDPOINTS_FOUND -gt 0 ]]; then
    echo "The following API endpoints were discovered during the scan:"
    echo
    jq -r '.results.endpoint_discovery.discovered[]? | "- `\(.path)` (HTTP \(.status_code))"' "$INPUT_FILE"
else
    echo "No endpoints were discovered during the scan."
fi)

### Security Headers Analysis

$(if [[ $MISSING_HEADERS -gt 0 ]]; then
    echo "#### Missing Security Headers"
    echo
    jq -r '.results.security_headers.missing[]? | "- " + .' "$INPUT_FILE"
    echo
fi)

$(if jq -e '.results.security_headers.present | length > 0' "$INPUT_FILE" >/dev/null; then
    echo "#### Present Security Headers"
    echo
    jq -r '.results.security_headers.present[]? | "- " + . + " ✓"' "$INPUT_FILE"
    echo
fi)

### Authentication Testing

$(if [[ $AUTH_BYPASSES -gt 0 ]]; then
    echo "#### Potential Authentication Bypasses"
    echo
    jq -r '.results.authentication_tests.potential_bypasses[]? | "- " + .' "$INPUT_FILE"
    echo
else
    echo "No obvious authentication bypass vulnerabilities were detected."
    echo
fi)

### Vulnerability Assessment

$(if [[ $VULNERABILITIES -gt 0 ]]; then
    echo "#### Potential Vulnerabilities"
    echo
    jq -r '.results.common_vulnerabilities.findings[]? | "- " + .' "$INPUT_FILE"
    echo
else
    echo "No common vulnerabilities were detected in the basic scan."
    echo
fi)

## Risk Assessment

Based on the findings, the overall risk level is assessed as **$RISK_LEVEL** with a risk score of **$RISK_SCORE**.

### Risk Factors

- **Missing Security Controls:** $MISSING_HEADERS missing security headers
- **Authentication Issues:** $AUTH_BYPASSES potential bypass methods
- **Known Vulnerabilities:** $VULNERABILITIES potential vulnerability patterns
- **Endpoint Exposure:** $ENDPOINTS_FOUND discoverable endpoints

## Recommendations

### Immediate Actions Required

$(if [[ $AUTH_BYPASSES -gt 0 ]]; then
    echo "1. **Fix Authentication Issues:** Review and strengthen authentication mechanisms"
fi)
$(if [[ $VULNERABILITIES -gt 0 ]]; then
    echo "2. **Address Vulnerabilities:** Investigate and remediate potential vulnerabilities"
fi)
$(if [[ $MISSING_HEADERS -gt 3 ]]; then
    echo "3. **Implement Security Headers:** Add missing security headers to prevent common attacks"
fi)

### Security Improvements

1. **Regular Security Testing:** Implement continuous security testing in CI/CD pipeline
2. **API Documentation:** Maintain comprehensive API security documentation
3. **Monitoring and Logging:** Implement security event monitoring and alerting
4. **Rate Limiting:** Add proper rate limiting to prevent abuse
5. **Input Validation:** Ensure comprehensive input validation and sanitization
6. **HTTPS Enforcement:** Ensure all endpoints use HTTPS with proper TLS configuration
7. **Access Controls:** Implement proper authentication and authorization controls
8. **Error Handling:** Implement secure error handling to prevent information disclosure

### Compliance Considerations

- Review findings against applicable compliance frameworks (GDPR, PCI DSS, HIPAA)
- Ensure proper data protection measures are in place
- Document security controls and procedures
- Regular compliance assessments and audits

## Technical Details

### Scan Configuration

- **Scanner Version:** $SCANNER_VERSION
- **Scan Type:** Automated Basic Security Scan
- **Coverage:** Endpoint discovery, security headers, authentication, common vulnerabilities
- **Limitations:** This is a basic automated scan. Manual testing recommended for comprehensive assessment.

### Next Steps

1. **Manual Verification:** Manually verify and validate automated findings
2. **Comprehensive Testing:** Conduct detailed penetration testing
3. **Code Review:** Perform security-focused code review
4. **Architecture Review:** Review overall security architecture
5. **Monitoring Implementation:** Set up continuous security monitoring

---

**Report Generated:** $(date)  
**Generated By:** API Security Audit Framework v$SCANNER_VERSION

*This is an automated security assessment report. Manual verification of findings is recommended.*
EOF

    log_success "Markdown report generated: $output_file"
}

# Generate CSV report
generate_csv_report() {
    local output_file="$1"
    
    log_info "Generating CSV report..."
    
    # Create CSV header
    echo "Category,Item,Status,Risk Level,Details" > "$output_file"
    
    # Add endpoint data
    jq -r '.results.endpoint_discovery.discovered[]? | "Endpoint,\(.path),Discovered,Medium,HTTP \(.status_code)"' "$INPUT_FILE" >> "$output_file"
    
    # Add missing headers
    jq -r '.results.security_headers.missing[]? | "Security Header," + . + ",Missing,Medium,Security header not implemented"' "$INPUT_FILE" >> "$output_file"
    
    # Add present headers
    jq -r '.results.security_headers.present[]? | "Security Header," + . + ",Present,Low,Security header implemented"' "$INPUT_FILE" >> "$output_file"
    
    # Add authentication issues
    jq -r '.results.authentication_tests.potential_bypasses[]? | "Authentication," + . + ",Issue,High,Potential authentication bypass"' "$INPUT_FILE" >> "$output_file"
    
    # Add vulnerabilities
    jq -r '.results.common_vulnerabilities.findings[]? | "Vulnerability," + . + ",Found,High,Potential security vulnerability"' "$INPUT_FILE" >> "$output_file"
    
    log_success "CSV report generated: $output_file"
}

# Generate enhanced JSON report
generate_json_report() {
    local output_file="$1"
    
    log_info "Generating enhanced JSON report..."
    
    # Add additional analysis to the JSON
    jq ". + {
        \"report_metadata\": {
            \"generated_at\": \"$(date -Iseconds)\",
            \"generated_by\": \"API Security Report Generator\",
            \"company\": \"$COMPANY_NAME\",
            \"format_version\": \"1.0\"
        },
        \"analysis\": {
            \"risk_factors\": [
                $(if [[ $MISSING_HEADERS -gt 0 ]]; then echo "\"Missing security headers ($MISSING_HEADERS found)\","; fi)
                $(if [[ $AUTH_BYPASSES -gt 0 ]]; then echo "\"Authentication bypass potential ($AUTH_BYPASSES found)\","; fi)
                $(if [[ $VULNERABILITIES -gt 0 ]]; then echo "\"Potential vulnerabilities ($VULNERABILITIES found)\","; fi)
                \"Endpoint exposure ($ENDPOINTS_FOUND discoverable endpoints)\"
            ],
            \"recommendations\": [
                \"Implement comprehensive security testing\",
                \"Add missing security headers\",
                \"Review authentication mechanisms\",
                \"Enable HTTPS if not already active\",
                \"Implement proper input validation\",
                \"Add rate limiting and monitoring\"
            ]
        }
    }" "$INPUT_FILE" > "$output_file"
    
    log_success "Enhanced JSON report generated: $output_file"
}

# Main execution
main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--input)
                INPUT_FILE="$2"
                shift 2
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -t|--template)
                TEMPLATE="$2"
                shift 2
                ;;
            -c|--company)
                COMPANY_NAME="$2"
                shift 2
                ;;
            -s|--summary)
                INCLUDE_DETAILS=false
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$INPUT_FILE" ]]; then
        log_error "Input file is required (-i option)"
        show_help
        exit 1
    fi
    
    # Generate output filename if not provided
    if [[ -z "$OUTPUT_FILE" ]]; then
        local basename=$(basename "$INPUT_FILE" .json)
        OUTPUT_FILE="$REPORTS_DIR/${basename}_report_$TIMESTAMP.$OUTPUT_FORMAT"
    fi
    
    # Ensure reports directory exists
    mkdir -p "$REPORTS_DIR"
    
    log_info "Generating $OUTPUT_FORMAT report from $INPUT_FILE"
    log_verbose "Output file: $OUTPUT_FILE"
    
    # Check dependencies
    check_dependencies
    
    # Validate input
    validate_input
    
    # Extract data from input
    extract_data
    
    # Generate report based on format
    case "$OUTPUT_FORMAT" in
        html)
            generate_html_report "$OUTPUT_FILE"
            ;;
        pdf)
            generate_pdf_report "$OUTPUT_FILE"
            ;;
        markdown|md)
            generate_markdown_report "$OUTPUT_FILE"
            ;;
        csv)
            generate_csv_report "$OUTPUT_FILE"
            ;;
        json)
            generate_json_report "$OUTPUT_FILE"
            ;;
        *)
            log_error "Unsupported output format: $OUTPUT_FORMAT"
            log_error "Supported formats: html, pdf, markdown, csv, json"
            exit 1
            ;;
    esac
    
    log_success "Report generation completed successfully!"
}

# Run main function
main "$@"