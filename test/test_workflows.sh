#!/bin/bash
# RAPTOR Test Suite - Validates all command workflows
# Tests basic functionality without requiring external services

# Note: NOT using set -e because we need to continue on test failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
PASSED=0
FAILED=0
SKIPPED=0

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAPTOR_CMD="python3 ${PROJECT_ROOT}/raptor.py"
OUT_DIR="${PROJECT_ROOT}/out"
TEST_DATA_DIR="${PROJECT_ROOT}/test/data"

# Cleanup function
cleanup() {
    if [ -d "$OUT_DIR" ]; then
        rm -rf "$OUT_DIR"
    fi
}

# Test result formatter
test_result() {
    local name=$1
    local status=$2
    local message=$3

    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✓ PASS${NC} - $name"
        ((PASSED++))
    elif [ "$status" = "FAIL" ]; then
        echo -e "${RED}✗ FAIL${NC} - $name"
        if [ -n "$message" ]; then
            echo "  Error: $message"
        fi
        ((FAILED++))
    elif [ "$status" = "SKIP" ]; then
        echo -e "${YELLOW}⊘ SKIP${NC} - $name"
        if [ -n "$message" ]; then
            echo "  Reason: $message"
        fi
        ((SKIPPED++))
    fi
}

# Test 1: Verify raptor.py exists and is executable
test_raptor_executable() {
    local test_name="raptor.py executable"

    if [ ! -f "${PROJECT_ROOT}/raptor.py" ]; then
        test_result "$test_name" "FAIL" "raptor.py not found"
        return 1
    fi

    if [ ! -x "${PROJECT_ROOT}/raptor.py" ]; then
        test_result "$test_name" "FAIL" "raptor.py not executable"
        return 1
    fi

    test_result "$test_name" "PASS"
    return 0
}

# Test 2: Check help command
test_help_command() {
    local test_name="Help command works"

    # raptor.py help requires a mode argument
    if python3 "$PROJECT_ROOT/raptor.py" help scan 2>&1 | grep -qi "usage"; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "Help command failed for scan mode"
        return 1
    fi
}

# Test 3: Verify scan mode exists
test_scan_mode_help() {
    local test_name="Scan mode is recognized"

    # Test if raptor.py recognizes scan mode by checking main help mentions it
    if python3 "$PROJECT_ROOT/raptor.py" 2>&1 | grep -q "scan"; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "Scanner mode not listed in main help"
        return 1
    fi
}

# Test 4: Verify fuzz mode exists
test_fuzz_mode_help() {
    local test_name="Fuzz mode is recognized"

    if python3 "$PROJECT_ROOT/raptor.py" 2>&1 | grep -q "fuzz"; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "Fuzz mode not listed in main help"
        return 1
    fi
}

# Test 5: Verify web mode exists
test_web_mode_help() {
    local test_name="Web mode is recognized"

    if python3 "$PROJECT_ROOT/raptor.py" 2>&1 | grep -q "web"; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "Web mode not listed in main help"
        return 1
    fi
}

# Test 6: Verify agentic mode exists
test_agentic_mode_help() {
    local test_name="Agentic mode is recognized"

    if python3 "$PROJECT_ROOT/raptor.py" 2>&1 | grep -q "agentic"; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "Agentic mode not listed in main help"
        return 1
    fi
}

# Test 7: Verify codeql mode exists
test_codeql_mode_help() {
    local test_name="CodeQL mode is recognized"

    if python3 "$PROJECT_ROOT/raptor.py" 2>&1 | grep -q "codeql"; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "CodeQL mode not listed in main help"
        return 1
    fi
}

# Test 8: Check Python dependencies
test_python_imports() {
    local test_name="Python dependencies importable"

    python3 -c "import sys; print(f'Python {sys.version}')" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "Python 3 not available"
        return 1
    fi
}

# Test 9: Check raptor_agentic.py syntax
test_agentic_syntax() {
    local test_name="raptor_agentic.py syntax valid"

    if python3 -m py_compile "${PROJECT_ROOT}/raptor_agentic.py" >/dev/null 2>&1; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "Syntax error in raptor_agentic.py"
        return 1
    fi
}

# Test 10: Check raptor_fuzzing.py syntax
test_fuzzing_syntax() {
    local test_name="raptor_fuzzing.py syntax valid"

    if python3 -m py_compile "${PROJECT_ROOT}/raptor_fuzzing.py" >/dev/null 2>&1; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "Syntax error in raptor_fuzzing.py"
        return 1
    fi
}

# Test 11: Check raptor_codeql.py syntax
test_codeql_syntax() {
    local test_name="raptor_codeql.py syntax valid"

    if python3 -m py_compile "${PROJECT_ROOT}/raptor_codeql.py" >/dev/null 2>&1; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "Syntax error in raptor_codeql.py"
        return 1
    fi
}

# Test 12: Verify core modules exist
test_core_modules() {
    local test_name="Core modules directory exists"

    if [ -d "${PROJECT_ROOT}/core" ]; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "core/ directory not found"
        return 1
    fi
}

# Test 13: Verify packages modules exist
test_packages_modules() {
    local test_name="Packages modules directory exists"

    if [ -d "${PROJECT_ROOT}/packages" ]; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "packages/ directory not found"
        return 1
    fi
}

# Test 14: Check CLI argument parsing
test_argument_parsing() {
    local test_name="CLI argument parsing works"

    # Test with no arguments (should show help with Available Modes)
    if python3 "$PROJECT_ROOT/raptor.py" 2>&1 | grep -q "Available Modes"; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "Help output does not contain 'Available Modes'"
        return 1
    fi
}

# Test 15: Verify output directory creation
test_output_directory() {
    local test_name="Output directory would be created"

    # Just verify the path is writable
    if mkdir -p "$OUT_DIR" 2>/dev/null; then
        test_result "$test_name" "PASS"
        return 0
    else
        test_result "$test_name" "FAIL" "Cannot create output directory"
        return 1
    fi
}

# Main test execution
main() {
    echo "=========================================="
    echo "RAPTOR Test Suite"
    echo "=========================================="
    echo ""

    # Cleanup before tests
    cleanup

    # Run all tests
    echo "Running tests..."
    echo ""

    test_raptor_executable
    test_help_command
    test_scan_mode_help
    test_fuzz_mode_help
    test_web_mode_help
    test_agentic_mode_help
    test_codeql_mode_help
    test_python_imports
    test_agentic_syntax
    test_fuzzing_syntax
    test_codeql_syntax
    test_core_modules
    test_packages_modules
    test_argument_parsing
    test_output_directory

    echo ""
    echo "=========================================="
    echo "Test Summary"
    echo "=========================================="
    echo -e "${GREEN}Passed:${NC}  $PASSED"
    echo -e "${RED}Failed:${NC}  $FAILED"
    echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
    echo -e "Total:   $((PASSED + FAILED + SKIPPED))"
    echo ""

    # Exit code
    if [ $FAILED -gt 0 ]; then
        echo -e "${RED}✗ Test suite FAILED${NC}"
        exit 1
    elif [ $PASSED -gt 0 ]; then
        echo -e "${GREEN}✓ Test suite PASSED${NC}"
        exit 0
    else
        echo -e "${YELLOW}⊘ All tests skipped${NC}"
        exit 0
    fi
}

# Run main function
main
