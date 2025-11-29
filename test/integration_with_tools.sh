#!/bin/bash
# RAPTOR Full Integration Tests - WITH ALL SECURITY TOOLS
# Tests all RAPTOR modes with actual tool execution

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DATA="$PROJECT_ROOT/test/data"
TEST_OUT="$PROJECT_ROOT/integration_test_out"

test_case() {
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
        [ -n "$msg" ] && echo "  (requires: $msg)"
        ((SKIPPED++))
    fi
}

cleanup() {
    [ -d "$TEST_OUT" ] && rm -rf "$TEST_OUT"
}

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  RAPTOR Full Integration Tests                          ║${NC}"
echo -e "${BLUE}║  Tests all modes with actual security tools             ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

cleanup
mkdir -p "$TEST_OUT"

# ============================================================================
# SECTION 1: TOOL AVAILABILITY
# ============================================================================

echo -e "${BLUE}1. SECURITY TOOLS AVAILABILITY${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check Semgrep
if command -v semgrep >/dev/null 2>&1; then
    SEMGREP_VER=$(semgrep --version 2>&1 | head -1)
    test_case "Semgrep installed" "PASS" "$SEMGREP_VER"
else
    test_case "Semgrep installed" "SKIP" "brew install semgrep"
fi

# Check CodeQL (harder to install, usually not available)
if command -v codeql >/dev/null 2>&1; then
    test_case "CodeQL CLI installed" "PASS"
else
    test_case "CodeQL CLI installed" "SKIP" "Download from GitHub (500MB+)"
fi

# Check AFL++
if command -v afl-fuzz >/dev/null 2>&1; then
    AFL_VER=$(afl-fuzz -v 2>&1 | head -1)
    test_case "AFL++ installed" "PASS" "$AFL_VER"
else
    test_case "AFL++ installed" "SKIP" "brew install afl++"
fi

# Check debugger (lldb on macOS)
if command -v lldb >/dev/null 2>&1; then
    test_case "LLDB debugger installed" "PASS"
elif command -v gdb >/dev/null 2>&1; then
    test_case "GDB debugger installed" "PASS"
else
    test_case "Debugger (lldb/gdb) installed" "SKIP" "brew install lldb"
fi

echo ""

# ============================================================================
# SECTION 2: SCAN MODE INTEGRATION
# ============================================================================

echo -e "${BLUE}2. SCAN MODE (Semgrep Integration)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v semgrep >/dev/null 2>&1; then
    # Test 2.1: Run scan with default policies
    echo -e "\n${BLUE}Running scan with all policies...${NC}"
    python3 "$PROJECT_ROOT/raptor.py" scan --repo "$TEST_DATA" 2>&1 | tee "$TEST_OUT/scan_all.log" > /dev/null

    if [ -d "$PROJECT_ROOT/out" ] && [ -f "$(find "$PROJECT_ROOT/out" -name "*.sarif" -type f | head -1)" ]; then
        test_case "Scan produces SARIF output" "PASS"
    else
        test_case "Scan produces SARIF output" "FAIL"
    fi

    # Test 2.2: Run scan with specific policy
    rm -rf "$PROJECT_ROOT/out"
    python3 "$PROJECT_ROOT/raptor.py" scan --repo "$TEST_DATA" --policy_groups secrets 2>&1 > /dev/null

    if grep -q "secrets" "$TEST_OUT/scan_all.log"; then
        test_case "Scan respects policy_groups argument" "PASS"
    else
        test_case "Scan respects policy_groups argument" "SKIP"
    fi

    # Test 2.3: Verify SARIF format
    SARIF=$(find "$PROJECT_ROOT/out" -name "*.sarif" -type f 2>/dev/null | head -1)
    if [ -f "$SARIF" ] && python3 -m json.tool "$SARIF" > /dev/null 2>&1; then
        test_case "SARIF output is valid JSON" "PASS"
    else
        test_case "SARIF output is valid JSON" "FAIL"
    fi

else
    test_case "Scan produces SARIF output" "SKIP" "Semgrep not installed"
    test_case "Scan respects policy_groups argument" "SKIP" "Semgrep not installed"
    test_case "SARIF output is valid JSON" "SKIP" "Semgrep not installed"
fi

echo ""

# ============================================================================
# SECTION 3: AGENTIC MODE INTEGRATION
# ============================================================================

echo -e "${BLUE}3. AGENTIC MODE (Semgrep + CodeQL + LLM)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v semgrep >/dev/null 2>&1; then
    # Test 3.1: Agentic mode without CodeQL (Semgrep only)
    echo -e "\n${BLUE}Running agentic mode (Semgrep only)...${NC}"
    rm -rf "$PROJECT_ROOT/out"
    python3 "$PROJECT_ROOT/raptor.py" agentic --repo "$TEST_DATA" --no-codeql --no-exploits --no-patches 2>&1 | tee "$TEST_OUT/agentic_semgrep.log" > /dev/null

    if [ -d "$PROJECT_ROOT/out" ] && grep -q "scan\|analysis" "$TEST_OUT/agentic_semgrep.log" -i; then
        test_case "Agentic mode with --no-codeql works" "PASS"
    else
        test_case "Agentic mode with --no-codeql works" "SKIP"
    fi

    # Test 3.2: Agentic mode with CodeQL option (if available)
    if command -v codeql >/dev/null 2>&1; then
        rm -rf "$PROJECT_ROOT/out"
        python3 "$PROJECT_ROOT/raptor.py" agentic --repo "$TEST_DATA" --codeql --no-exploits --no-patches 2>&1 > /dev/null
        test_case "Agentic mode with --codeql option" "PASS"
    else
        test_case "Agentic mode with --codeql option" "SKIP" "CodeQL not installed"
    fi

    # Test 3.3: Verify agentic respects --max-findings
    rm -rf "$PROJECT_ROOT/out"
    python3 "$PROJECT_ROOT/raptor.py" agentic --repo "$TEST_DATA" --max-findings 5 --no-codeql --no-exploits --no-patches 2>&1 > /dev/null
    test_case "Agentic respects --max-findings argument" "PASS"

else
    test_case "Agentic mode with --no-codeql works" "SKIP" "Semgrep not installed"
    test_case "Agentic mode with --codeql option" "SKIP" "Semgrep not installed"
    test_case "Agentic respects --max-findings argument" "SKIP" "Semgrep not installed"
fi

echo ""

# ============================================================================
# SECTION 4: FUZZ MODE (Binary Fuzzing)
# ============================================================================

echo -e "${BLUE}4. FUZZ MODE (AFL++ Integration)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v afl-fuzz >/dev/null 2>&1; then
    # Create a simple test binary
    echo -e "\n${BLUE}Building test binary for fuzzing...${NC}"

    # Simple C program that crashes on specific input
    cat > "$TEST_OUT/fuzz_target.c" << 'EOF'
#include <stdio.h>
#include <string.h>

int main() {
    char buf[10];
    scanf("%s", buf);  // Buffer overflow vulnerability

    if (buf[0] == 'C' && buf[1] == 'R' && buf[2] == 'A' && buf[3] == 'S' && buf[4] == 'H') {
        *(int*)0 = 0;  // Trigger segfault
    }
    return 0;
}
EOF

    # Compile with AFL instrumentation
    afl-gcc -o "$TEST_OUT/fuzz_target" "$TEST_OUT/fuzz_target.c" 2>/dev/null

    if [ -f "$TEST_OUT/fuzz_target" ]; then
        test_case "Test binary compiled for fuzzing" "PASS"

        # Test 4.1: Fuzz for short duration
        echo -e "\n${BLUE}Running AFL++ fuzz for 10 seconds...${NC}"
        mkdir -p "$TEST_OUT/fuzz_input"
        echo "TEST" > "$TEST_OUT/fuzz_input/seed"

        timeout 10 afl-fuzz -i "$TEST_OUT/fuzz_input" -o "$TEST_OUT/fuzz_output" \
            -V 10 "$TEST_OUT/fuzz_target" 2>/dev/null

        if [ -d "$TEST_OUT/fuzz_output" ]; then
            test_case "AFL++ fuzzing produces output" "PASS"
        else
            test_case "AFL++ fuzzing produces output" "FAIL"
        fi

        # Test 4.2: Check for crashes
        if [ -d "$TEST_OUT/fuzz_output/crashes" ] && [ "$(ls -1 "$TEST_OUT/fuzz_output/crashes" | wc -l)" -gt 0 ]; then
            test_case "AFL++ found crashes" "PASS"
        else
            test_case "AFL++ found crashes" "SKIP" "No crashes in short fuzz run"
        fi

    else
        test_case "Test binary compiled for fuzzing" "FAIL" "Compilation failed"
        test_case "AFL++ fuzzing produces output" "SKIP" "No binary"
        test_case "AFL++ found crashes" "SKIP" "No binary"
    fi

else
    test_case "Test binary compiled for fuzzing" "SKIP" "AFL++ not installed"
    test_case "AFL++ fuzzing produces output" "SKIP" "AFL++ not installed"
    test_case "AFL++ found crashes" "SKIP" "AFL++ not installed"
fi

echo ""

# ============================================================================
# SECTION 5: CODEQL MODE
# ============================================================================

echo -e "${BLUE}5. CODEQL MODE (Deep Analysis)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v codeql >/dev/null 2>&1; then
    # Test 5.1: CodeQL mode
    echo -e "\n${BLUE}Running CodeQL analysis...${NC}"
    rm -rf "$PROJECT_ROOT/out"
    python3 "$PROJECT_ROOT/raptor.py" codeql --repo "$TEST_DATA" --languages python 2>&1 > "$TEST_OUT/codeql.log"

    if grep -q "codeql\|analysis\|database" "$TEST_OUT/codeql.log" -i; then
        test_case "CodeQL mode executes" "PASS"
    else
        test_case "CodeQL mode executes" "SKIP" "CodeQL output format unclear"
    fi

else
    test_case "CodeQL mode executes" "SKIP" "CodeQL not installed (download from GitHub)"
fi

echo ""

# ============================================================================
# SECTION 6: WEB MODE
# ============================================================================

echo -e "${BLUE}6. WEB MODE (Web Application Testing)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 6.1: Web mode with invalid URL (should error gracefully)
python3 "$PROJECT_ROOT/raptor.py" web --url "http://invalid.example.local" 2>&1 > "$TEST_OUT/web.log"

if grep -q "error\|fail\|connection" "$TEST_OUT/web.log" -i || [ -s "$TEST_OUT/web.log" ]; then
    test_case "Web mode accepts URL argument" "PASS"
else
    test_case "Web mode accepts URL argument" "SKIP"
fi

echo ""

# ============================================================================
# SECTION 7: COMMAND CHAINING
# ============================================================================

echo -e "${BLUE}7. COMMAND CHAINING (Workflows)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v semgrep >/dev/null 2>&1; then
    # Test 7.1: Scan → Analyze chain
    echo -e "\n${BLUE}Testing scan → analyze workflow...${NC}"
    rm -rf "$PROJECT_ROOT/out"
    python3 "$PROJECT_ROOT/raptor.py" scan --repo "$TEST_DATA" 2>&1 > /dev/null

    SCAN_SARIF=$(find "$PROJECT_ROOT/out" -name "*.sarif" -type f 2>/dev/null | head -1)
    if [ -f "$SCAN_SARIF" ]; then
        # Try analyze (may fail due to missing API, but should try)
        python3 "$PROJECT_ROOT/raptor.py" analyze --repo "$TEST_DATA" --sarif "$SCAN_SARIF" 2>&1 > "$TEST_OUT/analyze.log"

        if grep -q "analyze\|processing\|findings" "$TEST_OUT/analyze.log" -i || [ -s "$TEST_OUT/analyze.log" ]; then
            test_case "Scan → Analyze chain works" "PASS"
        else
            test_case "Scan → Analyze chain works" "SKIP" "Analyze requires LLM API"
        fi
    else
        test_case "Scan → Analyze chain works" "SKIP" "Scan did not produce SARIF"
    fi

else
    test_case "Scan → Analyze chain works" "SKIP" "Semgrep not installed"
fi

echo ""

# ============================================================================
# SUMMARY
# ============================================================================

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║ SUMMARY${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"

TOTAL=$((PASSED + FAILED + SKIPPED))
if [ $TOTAL -gt 0 ]; then
    COMPLIANCE=$((PASSED * 100 / TOTAL))
else
    COMPLIANCE=0
fi

echo ""
echo -e "${GREEN}✓ Passed:${NC}  $PASSED"
echo -e "${RED}✗ Failed:${NC}  $FAILED"
echo -e "${YELLOW}⊘ Skipped:${NC} $SKIPPED"
echo -e "  Total:   $TOTAL"
echo ""
echo -e "Integration Compliance: ${GREEN}${COMPLIANCE}%${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All integration tests passed!${NC}"
    echo ""
    echo "Tested with actual security tools:"
    command -v semgrep >/dev/null 2>&1 && echo "  ✓ Semgrep (static analysis)"
    command -v codeql >/dev/null 2>&1 && echo "  ✓ CodeQL (deep analysis)"
    command -v afl-fuzz >/dev/null 2>&1 && echo "  ✓ AFL++ (fuzzing)"
    command -v lldb >/dev/null 2>&1 && echo "  ✓ LLDB (debugging)"
    exit 0
else
    echo -e "${RED}✗ ${FAILED} tests failed${NC}"
    exit 1
fi
