# Automatic radare2 Installation

RAPTOR automatically installs radare2 when not found on your system.

## Supported Platforms

- **macOS**: Homebrew (brew install radare2)
- **Ubuntu/Debian**: apt (sudo apt install radare2)
- **Fedora/RHEL**: dnf (sudo dnf install radare2)
- **Arch Linux**: pacman (sudo pacman -S radare2)

## Installation Modes

### Background Installation
If objdump is available as a fallback, radare2 installs in the background:
```python
analyser = CrashAnalyser(binary_path, use_radare2=True)
# Uses objdump temporarily while radare2 installs in background
# Check if ready: analyser.is_radare2_ready()
# Reload after install: analyser.reload_radare2()
```

### Foreground Installation
If no fallback is available, installation runs synchronously:
```python
analyser = CrashAnalyser(binary_path, use_radare2=True)
# Blocks until radare2 is installed (30-300 seconds)
```

## Disabling Auto-Install

Set environment variable to disable automatic installation:

```bash
export RAPTOR_NO_AUTO_INSTALL=1
```

Or install radare2 manually before running RAPTOR:

```bash
# macOS
brew install radare2

# Ubuntu/Debian
sudo apt install -y radare2

# Fedora/RHEL
sudo dnf install -y radare2

# Arch Linux
sudo pacman -S radare2
```

## CI/CD Integration

Automatic installation is automatically disabled in CI environments when sudo is required.

### GitHub Actions

```yaml
- name: Install radare2
  run: brew install radare2  # macOS
  # or: sudo apt-get install -y radare2  # Linux

- name: Run tests
  env:
    RAPTOR_NO_AUTO_INSTALL: 1
  run: pytest
```

### GitLab CI

```yaml
before_script:
  - apt-get update && apt-get install -y radare2

test:
  variables:
    RAPTOR_NO_AUTO_INSTALL: "1"
  script:
    - pytest
```

### Docker

```dockerfile
# Install radare2 in Dockerfile
RUN apt-get update && apt-get install -y radare2

# Disable auto-install
ENV RAPTOR_NO_AUTO_INSTALL=1
```

## API Reference

### is_radare2_ready()
Check if radare2 is available and initialized:
```python
if analyser.is_radare2_ready():
    # Use radare2 features
else:
    # Wait or use fallback
```

### reload_radare2()
Attempt to initialize radare2 after background installation:
```python
analyser = CrashAnalyser(binary_path, use_radare2=True)
time.sleep(60)  # Wait for background install

if analyser.reload_radare2():
    # radare2 now available
    print("Enhanced features enabled")
```

## Troubleshooting

### Installation Fails

Check:
1. Internet connection available
2. Package manager is installed and working (brew, apt, dnf, pacman)
3. Sufficient disk space (500MB minimum)
4. sudo password entered if prompted (Linux only)

### Installation Hangs in CI

Solution: Install radare2 manually in your CI setup and set RAPTOR_NO_AUTO_INSTALL=1

### radare2 Installed But Not Detected

Solution: Ensure radare2 (or r2) is in your PATH:
```bash
which r2  # Should show path to radare2
echo $PATH  # Should include /usr/local/bin or similar
```

## Security Considerations

### Sudo Usage (Linux)

Automatic installation on Linux requires sudo privileges:
```bash
sudo apt install -y radare2  # Prompts for password
```

If you don't want to provide sudo access:
1. Install radare2 manually before running RAPTOR
2. Disable auto-install: export RAPTOR_NO_AUTO_INSTALL=1

### CI/CD Safety

In CI environments, sudo installation is automatically skipped to prevent:
- Password prompts that hang the pipeline
- Unexpected privilege escalation
- Installation failures in restricted environments

Detected CI environments:
- GitHub Actions (GITHUB_ACTIONS)
- GitLab CI (GITLAB_CI)
- CircleCI (CIRCLECI)
- Travis CI (TRAVIS)
- Jenkins (JENKINS_HOME)
- And others (CI, CONTINUOUS_INTEGRATION)

## Implementation Details

### Installation Process

1. Platform detection (macOS, Linux, Windows)
2. Package manager detection (brew, apt, dnf, pacman)
3. CI environment check (skip sudo if CI detected)
4. Installation execution (with 5-minute timeout)
5. Verification (r2 -v check)

### Code Duplication Eliminated

All platform-specific installation logic uses a single `_install_package()` helper method, reducing duplication from 80% to near 0%.

### Error Handling

- Timeouts after 5 minutes
- Graceful fallback to objdump
- Clear error messages with manual installation URLs
- No crashes on installation failure

## Test Coverage

Comprehensive test suite (24 tests) covering:
- Environment variable handling (RAPTOR_NO_AUTO_INSTALL)
- CI detection (GitHub Actions, GitLab CI, CircleCI, etc.)
- Package installation (brew, apt, dnf, pacman)
- Installation verification
- Reload functionality
- Background vs foreground modes
- Error scenarios (timeout, failure, no package manager)

Run tests:
```bash
pytest test/test_crash_analyser_install.py -v
```
