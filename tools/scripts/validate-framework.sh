#!/bin/bash

# API Security Audit Framework Validation Script
# This script validates the framework installation and configuration

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRAMEWORK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_FILE="$FRAMEWORK_ROOT/validation-report.log"

# Initialize log file
echo "API Security Audit Framework Validation Report" > "$LOG_FILE"
echo "Generated: $(date)" >> "$LOG_FILE"
echo "=========================================" >> "$LOG_FILE"

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    echo "[$level] $(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

# Print functions
print_header() {
    echo -e "${BLUE}$1${NC}"
    log_message "INFO" "$1"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    log_message "SUCCESS" "$1"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
    log_message "WARNING" "$1"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    log_message "ERROR" "$1"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
    log_message "INFO" "$1"
}

# Validation counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Check function wrapper
check() {
    local description="$1"
    local command="$2"
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if eval "$command" >/dev/null 2>&1; then
        print_success "$description"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        print_error "$description"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

# Warning check function
check_warning() {
    local description="$1"
    local command="$2"
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if eval "$command" >/dev/null 2>&1; then
        print_success "$description"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        print_warning "$description"
        WARNING_CHECKS=$((WARNING_CHECKS + 1))
        return 1
    fi
}

# Validate system dependencies
validate_system_dependencies() {
    print_header "Validating System Dependencies"
    
    check "curl is installed" "command -v curl"
    check "jq is installed" "command -v jq"
    check "openssl is installed" "command -v openssl"
    check "bc is installed" "command -v bc"
    check "timeout is available" "command -v timeout"
    check "grep is available" "command -v grep"
    check "sed is available" "command -v sed"
    
    check_warning "shellcheck is installed" "command -v shellcheck"
    check_warning "wkhtmltopdf is installed" "command -v wkhtmltopdf"
    check_warning "node is installed" "command -v node"
    check_warning "npm is installed" "command -v npm"
    check_warning "python3 is installed" "command -v python3"
    check_warning "pip3 is installed" "command -v pip3"
}

# Validate framework structure
validate_framework_structure() {
    print_header "Validating Framework Structure"
    
    # Core directories
    check "checklists directory exists" "[ -d '$FRAMEWORK_ROOT/checklists' ]"
    check "docs directory exists" "[ -d '$FRAMEWORK_ROOT/docs' ]"
    check "examples directory exists" "[ -d '$FRAMEWORK_ROOT/examples' ]"
    check "templates directory exists" "[ -d '$FRAMEWORK_ROOT/templates' ]"
    check "tools directory exists" "[ -d '$FRAMEWORK_ROOT/tools' ]"
    check "tools/scripts directory exists" "[ -d '$FRAMEWORK_ROOT/tools/scripts' ]"
    check "tools/postman directory exists" "[ -d '$FRAMEWORK_ROOT/tools/postman' ]"
    check "tools/postman-collections directory exists" "[ -d '$FRAMEWORK_ROOT/tools/postman-collections' ]"
    
    # Core files
    check "README.md exists" "[ -f '$FRAMEWORK_ROOT/README.md' ]"
    check "basic-scan.sh exists" "[ -f '$FRAMEWORK_ROOT/tools/scripts/basic-scan.sh' ]"
    check "comprehensive-scan.sh exists" "[ -f '$FRAMEWORK_ROOT/tools/scripts/comprehensive-scan.sh' ]"
    check "run-newman.sh exists" "[ -f '$FRAMEWORK_ROOT/tools/scripts/run-newman.sh' ]"
    check "environment.json exists" "[ -f '$FRAMEWORK_ROOT/tools/postman/environment.json' ]"
    check "collections_security_tests.json exists" "[ -f '$FRAMEWORK_ROOT/tools/postman-collections/collections_security_tests.json' ]"
}

# Validate script permissions and syntax
validate_scripts() {
    print_header "Validating Scripts"
    
    local scripts=(
        "tools/scripts/basic-scan.sh"
        "tools/scripts/comprehensive-scan.sh"
        "tools/scripts/run-newman.sh"
        "tools/scripts/generate_report.sh"
        "tools/scripts/validate-framework.sh"
    )
    
    for script in "${scripts[@]}"; do
        local script_path="$FRAMEWORK_ROOT/$script"
        if [ -f "$script_path" ]; then
            check "$script is executable" "[ -x '$script_path' ]"
            
            # Make executable if not already
            if [ ! -x "$script_path" ]; then
                chmod +x "$script_path"
                print_info "Made $script executable"
            fi
            
            # Syntax check with shellcheck if available
            if command -v shellcheck >/dev/null 2>&1; then
                check_warning "$script passes shellcheck" "shellcheck '$script_path'"
            fi
        else
            print_error "$script not found"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    done
}

# Validate JSON files
validate_json_files() {
    print_header "Validating JSON Files"
    
    local json_files=(
        "tools/postman/environment.json"
        "tools/postman-collections/collections_security_tests.json"
    )
    
    for json_file in "${json_files[@]}"; do
        local json_path="$FRAMEWORK_ROOT/$json_file"
        if [ -f "$json_path" ]; then
            check "$json_file is valid JSON" "jq empty '$json_path'"
        else
            print_error "$json_file not found"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    done
}

# Validate Python examples
validate_python_examples() {
    print_header "Validating Python Examples"
    
    if command -v python3 >/dev/null 2>&1; then
        local python_files
        mapfile -t python_files < <(find "$FRAMEWORK_ROOT/examples" -name "*.py" 2>/dev/null || true)
        
        for py_file in "${python_files[@]}"; do
            if [ -f "$py_file" ]; then
                local relative_path="${py_file#$FRAMEWORK_ROOT/}"
                check_warning "$relative_path syntax is valid" "python3 -m py_compile '$py_file'"
            fi
        done
    else
        print_warning "Python3 not available - skipping Python validation"
    fi
}

# Validate Node.js dependencies
validate_nodejs_dependencies() {
    print_header "Validating Node.js Dependencies"
    
    if command -v node >/dev/null 2>&1; then
        local js_files
        mapfile -t js_files < <(find "$FRAMEWORK_ROOT/examples" -name "*.js" 2>/dev/null || true)
        
        for js_file in "${js_files[@]}"; do
            if [ -f "$js_file" ]; then
                local relative_path="${js_file#$FRAMEWORK_ROOT/}"
                check_warning "$relative_path syntax is valid" "node -c '$js_file'"
            fi
        done
        
        # Check for Newman if Node.js is available
        check_warning "newman is installed globally" "command -v newman"
    else
        print_warning "Node.js not available - skipping JavaScript validation"
    fi
}

# Validate documentation
validate_documentation() {
    print_header "Validating Documentation"
    
    local doc_files=(
        "README.md"
        "docs/audit_guide.md"
        "docs/compliance_checklist.md"
        "docs/remediation-priorities.md"
        "docs/graphql-security.md"
        "checklists/authentication-audit.md"
        "checklists/business-logic-tests.md"
        "checklists/data-exposure-checklist.md"
        "checklists/graphql-security-checklist.md"
        "templates/executive_summary.md"
        "templates/vulnerability_report.md"
    )
    
    for doc_file in "${doc_files[@]}"; do
        local doc_path="$FRAMEWORK_ROOT/$doc_file"
        check "$doc_file exists" "[ -f '$doc_path' ]"
        
        if [ -f "$doc_path" ]; then
            # Check if file is not empty
            check "$doc_file is not empty" "[ -s '$doc_path' ]"
            
            # Check for basic markdown structure
            if grep -q "^#" "$doc_path" 2>/dev/null; then
                print_success "$doc_file has markdown headers"
            else
                print_warning "$doc_file may be missing markdown headers"
                WARNING_CHECKS=$((WARNING_CHECKS + 1))
            fi
        fi
    done
}

# Test basic script functionality
test_script_functionality() {
    print_header "Testing Script Functionality"
    
    # Test basic-scan.sh help
    local basic_scan="$FRAMEWORK_ROOT/tools/scripts/basic-scan.sh"
    if [ -x "$basic_scan" ]; then
        check_warning "basic-scan.sh shows help" "$basic_scan --help"
    fi
    
    # Test comprehensive-scan.sh help
    local comprehensive_scan="$FRAMEWORK_ROOT/tools/scripts/comprehensive-scan.sh"
    if [ -x "$comprehensive_scan" ]; then
        check_warning "comprehensive-scan.sh shows help" "$comprehensive_scan --help"
    fi
    
    # Test run-newman.sh help
    local run_newman="$FRAMEWORK_ROOT/tools/scripts/run-newman.sh"
    if [ -x "$run_newman" ]; then
        check_warning "run-newman.sh shows help" "$run_newman --help"
    fi
}

# Validate GitHub Actions workflow
validate_github_actions() {
    print_header "Validating GitHub Actions"
    
    local workflow_file="$FRAMEWORK_ROOT/.github/workflows/api-security-audit.yml"
    check "GitHub Actions workflow exists" "[ -f '$workflow_file' ]"
    
    if [ -f "$workflow_file" ]; then
        # Basic YAML syntax check
        if command -v python3 >/dev/null 2>&1; then
            check_warning "GitHub Actions workflow is valid YAML" "python3 -c 'import yaml; yaml.safe_load(open(\"$workflow_file\"))'"
        fi
    fi
}

# Generate recommendations
generate_recommendations() {
    print_header "Generating Recommendations"
    
    echo "" >> "$LOG_FILE"
    echo "RECOMMENDATIONS:" >> "$LOG_FILE"
    echo "================" >> "$LOG_FILE"
    
    if [ $FAILED_CHECKS -gt 0 ]; then
        echo "CRITICAL ISSUES TO ADDRESS:" >> "$LOG_FILE"
        echo "- $FAILED_CHECKS critical validation checks failed" >> "$LOG_FILE"
        echo "- Review the log above for specific failures" >> "$LOG_FILE"
        echo "- Ensure all required files and dependencies are present" >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"
    fi
    
    if [ $WARNING_CHECKS -gt 0 ]; then
        echo "RECOMMENDED IMPROVEMENTS:" >> "$LOG_FILE"
        echo "- $WARNING_CHECKS optional checks failed" >> "$LOG_FILE"
        echo "- Install optional dependencies for enhanced functionality" >> "$LOG_FILE"
        echo "- Consider installing: shellcheck, wkhtmltopdf, newman, python3" >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"
    fi
    
    echo "GENERAL RECOMMENDATIONS:" >> "$LOG_FILE"
    echo "- Regularly update the framework and dependencies" >> "$LOG_FILE"
    echo "- Run validation before each security audit" >> "$LOG_FILE"
    echo "- Keep documentation up to date" >> "$LOG_FILE"
    echo "- Test scripts in a safe environment before production use" >> "$LOG_FILE"
    echo "- Review and customize checklists for your specific needs" >> "$LOG_FILE"
}

# Main validation function
main() {
    print_header "API Security Audit Framework Validation"
    print_info "Framework root: $FRAMEWORK_ROOT"
    print_info "Log file: $LOG_FILE"
    echo ""
    
    # Run all validation checks
    validate_system_dependencies
    echo ""
    
    validate_framework_structure
    echo ""
    
    validate_scripts
    echo ""
    
    validate_json_files
    echo ""
    
    validate_python_examples
    echo ""
    
    validate_nodejs_dependencies
    echo ""
    
    validate_documentation
    echo ""
    
    test_script_functionality
    echo ""
    
    validate_github_actions
    echo ""
    
    # Generate summary
    print_header "Validation Summary"
    echo "Total checks: $TOTAL_CHECKS"
    echo -e "Passed: ${GREEN}$PASSED_CHECKS${NC}"
    echo -e "Failed: ${RED}$FAILED_CHECKS${NC}"
    echo -e "Warnings: ${YELLOW}$WARNING_CHECKS${NC}"
    
    # Log summary
    echo "" >> "$LOG_FILE"
    echo "VALIDATION SUMMARY:" >> "$LOG_FILE"
    echo "==================" >> "$LOG_FILE"
    echo "Total checks: $TOTAL_CHECKS" >> "$LOG_FILE"
    echo "Passed: $PASSED_CHECKS" >> "$LOG_FILE"
    echo "Failed: $FAILED_CHECKS" >> "$LOG_FILE"
    echo "Warnings: $WARNING_CHECKS" >> "$LOG_FILE"
    
    # Generate recommendations
    generate_recommendations
    
    # Final status
    echo ""
    if [ $FAILED_CHECKS -eq 0 ]; then
        print_success "Framework validation completed successfully!"
        if [ $WARNING_CHECKS -gt 0 ]; then
            print_warning "Some optional features are not available"
            print_info "See $LOG_FILE for recommendations"
        fi
        exit 0
    else
        print_error "Framework validation failed with $FAILED_CHECKS critical issues"
        print_info "See $LOG_FILE for detailed information"
        exit 1
    fi
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "API Security Audit Framework Validation Script"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --version, -v  Show version information"
        echo "  --quiet, -q    Run in quiet mode (minimal output)"
        echo ""
        echo "This script validates the framework installation and configuration."
        echo "It checks for required dependencies, file structure, and basic functionality."
        echo ""
        echo "Exit codes:"
        echo "  0 - Validation successful"
        echo "  1 - Validation failed (critical issues found)"
        echo ""
        exit 0
        ;;
    --version|-v)
        echo "API Security Audit Framework Validation Script v1.0"
        exit 0
        ;;
    --quiet|-q)
        # Redirect output to log file only
        exec > "$LOG_FILE" 2>&1
        ;;
esac

# Run main function
main "$@"
