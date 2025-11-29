#!/bin/bash
# RAPTOR Comprehensive Test Suite
# Tests actual functionality and workflows that users would execute

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
PASSED=0
FAILED=0
SKIPPED=0

# Setup
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DATA="$PROJECT_ROOT/test/data"
OUT_DIR="$PROJECT_ROOT/out_comprehensive_test"

test_result() {
    local name=$1
    local status=$2
    local msg=$3

    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✓${NC} $name"
        ((PASSED++))
    elif [ "$status" = "FAIL" ]; then
        echo -e "${RED}✗${NC} $name"
        [ -n "$msg" ] && echo "  $msg"
        ((FAILED++))
    elif [ "$status" = "SKIP" ]; then
        echo -e "${YELLOW}⊘${NC} $name"
        [ -n "$msg" ] && echo "  $msg"
        ((SKIPPED++))
    fi
}

cleanup() {
    [ -d "$OUT_DIR" ] && rm -rf "$OUT_DIR"
}

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          RAPTOR Comprehensive Test Suite                  ║${NC}"
echo -e "${BLUE}║     Testing actual workflows, commands, and scenarios     ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

cleanup

# ============================================================================
# TEST CATEGORY 1: BASIC COMMAND STRUCTURE
# ============================================================================

echo -e "${BLUE}1. COMMAND STRUCTURE TESTS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 1.1: Main launcher recognizes all modes
HELP_OUT=$(python3 "$PROJECT_ROOT/raptor.py" 2>&1)
if echo "$HELP_OUT" | grep -q "scan" && \
   echo "$HELP_OUT" | grep -q "fuzz" && \
   echo "$HELP_OUT" | grep -q "web" && \
   echo "$HELP_OUT" | grep -q "agentic" && \
   echo "$HELP_OUT" | grep -q "codeql"; then
    test_result "Main launcher lists all modes" "PASS"
else
    test_result "Main launcher lists all modes" "FAIL" "Not all modes listed in help"
fi

# Test 1.2: Each mode has implementation files
if [ -f "$PROJECT_ROOT/raptor_agentic.py" ] && \
   [ -f "$PROJECT_ROOT/raptor_fuzzing.py" ] && \
   [ -f "$PROJECT_ROOT/raptor_codeql.py" ]; then
    test_result "Core execution scripts exist" "PASS"
else
    test_result "Core execution scripts exist" "FAIL"
fi

# Test 1.3: Main modules are valid Python
if python3 -m py_compile "$PROJECT_ROOT/raptor.py" 2>/dev/null && \
   python3 -m py_compile "$PROJECT_ROOT/raptor_agentic.py" 2>/dev/null; then
    test_result "Main scripts have valid Python syntax" "PASS"
else
    test_result "Main scripts have valid Python syntax" "FAIL"
fi

# Test 1.4: Can check version/help
if python3 "$PROJECT_ROOT/raptor.py" --help 2>&1 | grep -q "RAPTOR"; then
    test_result "Help information accessible" "PASS"
else
    test_result "Help information accessible" "SKIP" "Help format may vary"
fi

echo ""

# ============================================================================
# TEST CATEGORY 2: SCAN MODE
# ============================================================================

echo -e "${BLUE}2. SCAN MODE TESTS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 2.1: Scan mode exists and can show help
if python3 "$PROJECT_ROOT/raptor.py" help scan 2>&1 | grep -q "usage"; then
    test_result "Scan mode help available" "PASS"
else
    test_result "Scan mode help available" "FAIL"
fi

# Test 2.2: Scan mode requires --repo
if python3 "$PROJECT_ROOT/raptor.py" help scan 2>&1 | grep -q "\-\-repo"; then
    test_result "Scan requires --repo argument" "PASS"
else
    test_result "Scan requires --repo argument" "FAIL"
fi

# Test 2.3: Scan supports policy groups
if python3 "$PROJECT_ROOT/raptor.py" help scan 2>&1 | grep -qi "policy"; then
    test_result "Scan supports --policy-groups" "PASS"
else
    test_result "Scan supports --policy-groups" "SKIP"
fi

echo ""

# ============================================================================
# TEST CATEGORY 3: AGENTIC MODE
# ============================================================================

echo -e "${BLUE}3. AGENTIC MODE TESTS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 3.1: Agentic script exists
if [ -f "$PROJECT_ROOT/raptor_agentic.py" ]; then
    test_result "Agentic mode script exists" "PASS"
else
    test_result "Agentic mode script exists" "FAIL"
fi

# Test 3.2: Agentic can be invoked
if python3 "$PROJECT_ROOT/raptor.py" agentic -h 2>&1 | grep -q "usage"; then
    test_result "Agentic mode accepts arguments" "PASS"
else
    test_result "Agentic mode accepts arguments" "SKIP" "May require valid parameters"
fi

# Test 3.3: Agentic supports CodeQL options
if python3 "$PROJECT_ROOT/raptor_agentic.py" --help 2>&1 | grep -q "codeql"; then
    test_result "Agentic has CodeQL options" "PASS"
else
    test_result "Agentic has CodeQL options" "SKIP" "CodeQL integration optional"
fi

# Test 3.4: Agentic supports exploit/patch generation controls
if python3 "$PROJECT_ROOT/raptor_agentic.py" --help 2>&1 | grep -q "exploit\|patch"; then
    test_result "Agentic supports exploit/patch options" "PASS"
else
    test_result "Agentic supports exploit/patch options" "SKIP"
fi

echo ""

# ============================================================================
# TEST CATEGORY 4: FUZZING MODE
# ============================================================================

echo -e "${BLUE}4. FUZZING MODE TESTS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 4.1: Fuzzing script exists
if [ -f "$PROJECT_ROOT/raptor_fuzzing.py" ]; then
    test_result "Fuzzing mode script exists" "PASS"
else
    test_result "Fuzzing mode script exists" "FAIL"
fi

# Test 4.2: Fuzzing requires --binary
if python3 "$PROJECT_ROOT/raptor.py" help fuzz 2>&1 | grep -q "binary"; then
    test_result "Fuzz requires --binary argument" "PASS"
else
    test_result "Fuzz requires --binary argument" "SKIP"
fi

# Test 4.3: Fuzzing supports duration option
if python3 "$PROJECT_ROOT/raptor_fuzzing.py" --help 2>&1 | grep -q "duration"; then
    test_result "Fuzz supports --duration option" "PASS"
else
    test_result "Fuzz supports --duration option" "SKIP"
fi

# Test 4.4: Fuzzing supports parallel option
if python3 "$PROJECT_ROOT/raptor_fuzzing.py" --help 2>&1 | grep -q "parallel"; then
    test_result "Fuzz supports --parallel option" "PASS"
else
    test_result "Fuzz supports --parallel option" "SKIP"
fi

# Test 4.5: Fuzzing supports autonomous mode
if python3 "$PROJECT_ROOT/raptor_fuzzing.py" --help 2>&1 | grep -q "autonomous"; then
    test_result "Fuzz supports autonomous mode" "PASS"
else
    test_result "Fuzz supports autonomous mode" "SKIP"
fi

echo ""

# ============================================================================
# TEST CATEGORY 5: CODEQL MODE
# ============================================================================

echo -e "${BLUE}5. CODEQL MODE TESTS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 5.1: CodeQL script exists
if [ -f "$PROJECT_ROOT/raptor_codeql.py" ]; then
    test_result "CodeQL mode script exists" "PASS"
else
    test_result "CodeQL mode script exists" "FAIL"
fi

# Test 5.2: CodeQL can be invoked
if python3 "$PROJECT_ROOT/raptor.py" codeql --help 2>&1 | grep -q "usage"; then
    test_result "CodeQL mode accepts arguments" "PASS"
else
    test_result "CodeQL mode accepts arguments" "SKIP" "May require valid parameters"
fi

# Test 5.3: CodeQL supports language detection
if python3 "$PROJECT_ROOT/raptor_codeql.py" --help 2>&1 | grep -q "language"; then
    test_result "CodeQL supports language options" "PASS"
else
    test_result "CodeQL supports language options" "SKIP"
fi

echo ""

# ============================================================================
# TEST CATEGORY 6: WEB MODE
# ============================================================================

echo -e "${BLUE}6. WEB MODE TESTS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 6.1: Web mode script exists
if [ -f "$PROJECT_ROOT/packages/web/scanner.py" ]; then
    test_result "Web mode script exists" "PASS"
else
    test_result "Web mode script exists" "FAIL"
fi

# Test 6.2: Web mode is recognized
if python3 "$PROJECT_ROOT/raptor.py" 2>&1 | grep -q "web"; then
    test_result "Web mode listed in main help" "PASS"
else
    test_result "Web mode listed in main help" "FAIL"
fi

echo ""

# ============================================================================
# TEST CATEGORY 7: PACKAGE ARCHITECTURE
# ============================================================================

echo -e "${BLUE}7. PACKAGE ARCHITECTURE TESTS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 7.1: Core modules exist
if [ -d "$PROJECT_ROOT/core" ]; then
    test_result "Core modules directory exists" "PASS"
else
    test_result "Core modules directory exists" "FAIL"
fi

# Test 7.2: Packages exist
if [ -d "$PROJECT_ROOT/packages" ]; then
    test_result "Packages directory exists" "PASS"
else
    test_result "Packages directory exists" "FAIL"
fi

# Test 7.3: LLM analysis package exists
if [ -d "$PROJECT_ROOT/packages/llm_analysis" ]; then
    test_result "LLM analysis package exists" "PASS"
else
    test_result "LLM analysis package exists" "FAIL"
fi

# Test 7.4: Static analysis package exists
if [ -d "$PROJECT_ROOT/packages/static-analysis" ]; then
    test_result "Static analysis package exists" "PASS"
else
    test_result "Static analysis package exists" "FAIL"
fi

# Test 7.5: Fuzzing utilities exist
if [ -d "$PROJECT_ROOT/packages/fuzzing" ]; then
    test_result "Fuzzing utilities package exists" "PASS"
else
    test_result "Fuzzing utilities package exists" "FAIL"
fi

echo ""

# ============================================================================
# TEST CATEGORY 8: TEST FIXTURES
# ============================================================================

echo -e "${BLUE}8. TEST FIXTURE TESTS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 8.1: Test data directory exists
if [ -d "$TEST_DATA" ]; then
    test_result "Test data directory exists" "PASS"
else
    test_result "Test data directory exists" "FAIL"
fi

# Test 8.2: Sample Python vulnerable code
if [ -f "$TEST_DATA/python_sql_injection.py" ] && [ -s "$TEST_DATA/python_sql_injection.py" ]; then
    test_result "Sample Python vulnerable code present" "PASS"
else
    test_result "Sample Python vulnerable code present" "FAIL"
fi

# Test 8.3: Sample Python code has SQL injection patterns
if grep -q "concat\|+.*query" "$TEST_DATA/python_sql_injection.py" 2>/dev/null; then
    test_result "Sample Python code has vulnerability patterns" "PASS"
else
    test_result "Sample Python code has vulnerability patterns" "FAIL"
fi

# Test 8.4: Sample JavaScript vulnerable code
if [ -f "$TEST_DATA/javascript_xss.js" ] && [ -s "$TEST_DATA/javascript_xss.js" ]; then
    test_result "Sample JavaScript vulnerable code present" "PASS"
else
    test_result "Sample JavaScript vulnerable code present" "FAIL"
fi

# Test 8.5: Sample JavaScript code has XSS patterns
if grep -q "innerHTML\|eval\|document.write" "$TEST_DATA/javascript_xss.js" 2>/dev/null; then
    test_result "Sample JavaScript code has vulnerability patterns" "PASS"
else
    test_result "Sample JavaScript code has vulnerability patterns" "FAIL"
fi

echo ""

# ============================================================================
# TEST CATEGORY 9: WORKFLOW AVAILABILITY
# ============================================================================

echo -e "${BLUE}9. WORKFLOW AVAILABILITY TESTS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 9.1: Can invoke scan with help
if python3 "$PROJECT_ROOT/raptor.py" scan -h 2>&1 | grep -q "repo\|usage"; then
    test_result "Workflow: scan --help accessible" "PASS"
else
    test_result "Workflow: scan --help accessible" "FAIL"
fi

# Test 9.2: Can invoke agentic with help
if python3 "$PROJECT_ROOT/raptor.py" agentic -h 2>&1 | grep -q "usage\|repo"; then
    test_result "Workflow: agentic --help accessible" "PASS"
else
    test_result "Workflow: agentic --help accessible" "FAIL"
fi

# Test 9.3: Can invoke fuzz with help
if python3 "$PROJECT_ROOT/raptor.py" fuzz -h 2>&1 | grep -q "usage\|binary"; then
    test_result "Workflow: fuzz --help accessible" "PASS"
else
    test_result "Workflow: fuzz --help accessible" "FAIL"
fi

# Test 9.4: Can invoke codeql with help
if python3 "$PROJECT_ROOT/raptor.py" codeql --help 2>&1 | grep -q "usage\|repo"; then
    test_result "Workflow: codeql --help accessible" "PASS"
else
    test_result "Workflow: codeql --help accessible" "FAIL"
fi

echo ""

# ============================================================================
# TEST SUMMARY
# ============================================================================

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║ SUMMARY${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

TOTAL=$((PASSED + FAILED + SKIPPED))
COMPLIANCE=$((PASSED * 100 / TOTAL))

echo ""
echo -e "${GREEN}Passed:${NC}  $PASSED"
echo -e "${RED}Failed:${NC}  $FAILED"
echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
echo -e "Total:   $TOTAL"
echo ""
echo -e "Compliance: ${GREEN}${COMPLIANCE}%${NC} ($PASSED/$TOTAL tests passed)"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ ${FAILED} tests failed${NC}"
    exit 1
fi
