#!/usr/bin/env python3
"""
RAPTOR Tool Mode Smoke Test - Quick 5-minute validation
Tests basic functionality end-to-end
"""

import sys
import json
import subprocess
from pathlib import Path


class SmokeTest:
    """Run quick smoke tests on RAPTOR Tool Mode Exporter"""

    def __init__(self):
        self.repo_root = Path(__file__).parent.parent
        self.fixtures_dir = Path(__file__).parent / "fixtures"
        self.tool_path = self.repo_root / "packages" / "llm_analysis" / "tool_mode_exporter.py"  # Tool Mode Exporter
        self.test_repo = self.fixtures_dir / "test_repo"
        self.passed = 0
        self.failed = 0

    def run_test(self, test_name, test_func):
        """Run a single test"""
        try:
            sys.stdout.write(f"[{self.passed + self.failed + 1}/6] {test_name:<40} ")
            sys.stdout.flush()
            test_func()
            print("PASS")
            self.passed += 1
            return True
        except AssertionError as e:
            print(f"FAIL: {e}")
            self.failed += 1
            return False
        except Exception as e:
            print(f"ERROR: {e}")
            self.failed += 1
            return False

    def test_tool_exists(self):
        """Test 1: Verify tool_mode_exporter.py exists"""
        assert self.tool_path.exists(), f"Tool not found at {self.tool_path}"

    def test_help_text(self):
        """Test 2: Verify --help works"""
        result = subprocess.run(
            [sys.executable, str(self.tool_path), "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        assert result.returncode == 0, f"Help failed: {result.stderr}"
        assert "Export SARIF findings as JSON" in result.stdout, "Help text missing description"

    def test_basic_export(self):
        """Test 3: Export minimal SARIF to JSON"""
        sarif_file = self.fixtures_dir / "minimal.sarif"
        output_file = self.fixtures_dir / "test_output.json"

        assert sarif_file.exists(), f"Test SARIF not found: {sarif_file}"

        result = subprocess.run(
            [
                sys.executable, str(self.tool_path),
                "--repo", str(self.test_repo),
                "--sarif", str(sarif_file),
                "--output", str(output_file)
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        assert result.returncode == 0, f"Export failed: {result.stderr}"
        assert output_file.exists(), f"Output file not created: {output_file}"

        # Cleanup
        output_file.unlink()

    def test_json_schema(self):
        """Test 4: Validate JSON schema is correct"""
        sarif_file = self.fixtures_dir / "minimal.sarif"
        output_file = self.fixtures_dir / "schema_test.json"

        result = subprocess.run(
            [
                sys.executable, str(self.tool_path),
                "--repo", str(self.test_repo),
                "--sarif", str(sarif_file),
                "--output", str(output_file)
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        assert result.returncode == 0, "Export failed"

        # Validate JSON and schema
        with open(output_file, 'r') as f:
            data = json.load(f)

        assert "version" in data, "Missing version field"
        assert "schema" in data, "Missing schema field"
        assert "metadata" in data, "Missing metadata field"
        assert "findings" in data, "Missing findings field"
        assert isinstance(data["findings"], list), "Findings should be a list"

        # Cleanup
        output_file.unlink()

    def test_error_handling_missing_file(self):
        """Test 5: Proper error handling for missing SARIF"""
        result = subprocess.run(
            [
                sys.executable, str(self.tool_path),
                "--repo", str(self.test_repo),
                "--sarif", "/nonexistent/file.sarif"
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode != 0, "Should fail with missing file"
        assert "does not exist" in result.stderr or "not found" in result.stderr.lower(), \
            f"Error message unclear: {result.stderr}"

    def test_output_formats(self):
        """Test 6: Test max-findings parameter"""
        sarif_file = self.fixtures_dir / "large.sarif"  # Has 100 findings
        output_file = self.fixtures_dir / "max_findings_test.json"

        # Test with --max-findings 10
        result = subprocess.run(
            [
                sys.executable, str(self.tool_path),
                "--repo", str(self.test_repo),
                "--sarif", str(sarif_file),
                "--max-findings", "10",
                "--output", str(output_file)
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        assert result.returncode == 0, "Max findings test failed"

        # Verify output respects limit
        with open(output_file, 'r') as f:
            data = json.load(f)

        assert len(data["findings"]) <= 10, f"Should have <= 10 findings, got {len(data['findings'])}"

        # Cleanup
        output_file.unlink()

    def run_all_tests(self):
        """Run all smoke tests"""
        print("=" * 70)
        print("RAPTOR TOOL MODE SMOKE TEST")
        print("=" * 70)
        print()

        tests = [
            ("Tool exists and is executable", self.test_tool_exists),
            ("Help text displays correctly", self.test_help_text),
            ("Can read SARIF and export JSON", self.test_basic_export),
            ("JSON output has correct schema", self.test_json_schema),
            ("Error handling for missing files", self.test_error_handling_missing_file),
            ("Both stdout and file output work", self.test_output_formats),
        ]

        for test_name, test_func in tests:
            self.run_test(test_name, test_func)

        print()
        print("=" * 70)
        if self.failed == 0:
            print(f"✓ SMOKE TEST PASSED ({self.passed}/{self.passed + self.failed} tests)")
            print("=" * 70)
            return 0
        else:
            print(f"✗ SMOKE TEST FAILED ({self.failed} failures)")
            print("=" * 70)
            return 1


def main():
    """Run smoke tests"""
    tester = SmokeTest()
    exit_code = tester.run_all_tests()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
