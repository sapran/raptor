#!/usr/bin/env python3
"""Generate SARIF test fixtures for RAPTOR testing"""

import json
from pathlib import Path


def create_minimal_sarif():
    """Create minimal SARIF with 1 finding"""
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "TestScanner",
                        "version": "1.0.0"
                    }
                },
                "results": [
                    {
                        "ruleId": "SQL001",
                        "level": "error",
                        "message": {
                            "text": "SQL injection vulnerability detected"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "test.py"
                                    },
                                    "region": {
                                        "startLine": 10,
                                        "endLine": 12
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }


def create_medium_sarif():
    """Create SARIF with 10 findings"""
    results = []
    for i in range(10):
        results.append({
            "ruleId": f"VULN{i:03d}",
            "level": "error" if i % 2 == 0 else "warning",
            "message": {"text": f"Vulnerability {i}: {['SQL Injection', 'XSS', 'Command Injection', 'Path Traversal', 'SSRF'][i % 5]}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"file{i % 3}.py"},
                    "region": {"startLine": 10 + i, "endLine": 12 + i}
                }
            }]
        })

    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Scanner", "version": "1.0"}},
            "results": results
        }]
    }


def create_large_sarif():
    """Create SARIF with 100 findings"""
    results = []
    for i in range(100):
        results.append({
            "ruleId": f"VULN{i:04d}",
            "level": ["error", "warning", "note"][i % 3],
            "message": {"text": f"Issue {i}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"file{i % 10}.py"},
                    "region": {"startLine": 10 + i, "endLine": 11 + i}
                }
            }]
        })

    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Scanner", "version": "1.0"}},
            "results": results
        }]
    }


def create_empty_sarif():
    """Create valid SARIF with no findings"""
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Scanner", "version": "1.0"}},
            "results": []
        }]
    }


def create_malformed_sarif():
    """Create intentionally malformed SARIF"""
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Scanner"}},
            "results": [
                {
                    "ruleId": "TEST",
                    # Missing required "message" field
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "test.py"},
                            # Missing "region" startLine
                            "region": {"endLine": 10}
                        }
                    }]
                }
            ]
        }]
    }


def create_vulnerable_code_files():
    """Create sample vulnerable code files"""
    files = {
        "test_repo/vuln.py": """import sqlite3

def search_users(query):
    # SQL injection vulnerability
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(sql)  # VULNERABLE
    return cursor.fetchall()

def bad_eval(user_input):
    # Code injection
    result = eval(user_input)  # VULNERABLE
    return result
""",
        "test_repo/vuln.js": """function processData(userInput) {
    // XSS vulnerability
    document.getElementById('output').innerHTML = userInput;  // VULNERABLE
}

function unsafeJsonParse(jsonStr) {
    // Dangerous eval-like operation
    return eval('(' + jsonStr + ')');  // VULNERABLE
}
""",
        "test_repo/vuln.c": """#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void processInput(const char* input) {
    char buffer[10];
    strcpy(buffer, input);  // VULNERABLE: Buffer overflow
}

void execute_command(const char* cmd) {
    system(cmd);  // VULNERABLE: Command injection
}
"""
    }

    return files


def main():
    """Generate all test fixtures"""
    fixtures_dir = Path(__file__).parent / "fixtures"
    fixtures_dir.mkdir(exist_ok=True)

    print("=" * 70)
    print("Generating SARIF Test Fixtures")
    print("=" * 70)

    # Generate SARIF files
    sarifs = {
        "minimal.sarif": create_minimal_sarif(),
        "medium.sarif": create_medium_sarif(),
        "large.sarif": create_large_sarif(),
        "empty.sarif": create_empty_sarif(),
        "malformed.sarif": create_malformed_sarif(),
    }

    for filename, sarif_data in sarifs.items():
        filepath = fixtures_dir / filename
        with open(filepath, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        print(f"✓ Created {filename}")

    # Generate vulnerable code files
    code_files = create_vulnerable_code_files()
    test_repo_dir = fixtures_dir / "test_repo"
    test_repo_dir.mkdir(exist_ok=True)

    for filepath_str, content in code_files.items():
        filepath = fixtures_dir / filepath_str
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"✓ Created {filepath_str}")

    print("\n" + "=" * 70)
    print(f"✓ Generated test fixtures in {fixtures_dir}")
    print("=" * 70)


if __name__ == "__main__":
    main()
