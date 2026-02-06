# Software-Enumerator

A security-focused Windows 11 software auditing CLI tool for security professionals and system administrators.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Output Formats](#output-formats)
- [Security Considerations](#security-considerations)
- [Architecture](#architecture)
- [API Rate Limits](#api-rate-limits)
- [Testing](#testing)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Overview

Software-Enumerator discovers and catalogs installed software from multiple sources, checks for available updates, audits browser extensions, and scans for known vulnerabilities (CVEs). It's designed for security auditing, compliance reporting, and change detection in enterprise environments.

## Features

### Software Discovery
- **Windows Registry** - Traditional Win32 programs from standard uninstall registry keys (HKLM 64-bit, HKLM 32-bit WOW6432Node, HKCU)
- **Microsoft Store** - UWP/MSIX apps installed via the Microsoft Store
- **Portable Applications** - Executables in common portable app locations (`C:\PortableApps`, `C:\Tools`, `%LOCALAPPDATA%\Programs`)

### Security Auditing
- **Update Checking** - Queries winget for available software updates
- **Browser Extension Scanning** - Enumerates extensions from Chrome, Edge, and Firefox with permission analysis
- **CVE Scanning** - Queries the NIST NVD database for known vulnerabilities in installed software
- **Baseline Comparison** - Save snapshots and detect changes (new/removed/updated software)

### Export & Integration
- **Multiple Output Formats** - Table, JSON, or CSV output for SIEM integration
- **Audit Logging** - Detailed logs with timestamps for compliance reporting

## Requirements

- Windows 11 (or Windows 10 with PowerShell 5.1+)
- Python 3.10+
- winget (Windows Package Manager, for update checking)
- Internet connection (for CVE scanning via NIST NVD API)

### Optional
- NVD API Key - For faster vulnerability scanning (50 requests/30s vs 5 requests/30s)

## Installation

1. Clone or download this repository:
   ```bash
   git clone https://github.com/yourusername/Software-Enumerator.git
   cd Software-Enumerator
   ```

2. No additional dependencies required - uses Python standard library only.

3. (Optional) Set your NVD API key as an environment variable:
   ```powershell
   $env:NVD_API_KEY = "your-api-key-here"
   ```

## Usage

```
python Software_Enumerator.py [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--source {registry,store,portable,all}` | Source to scan (default: all) |
| `--search TERM` | Filter results by name, publisher, or version |
| `--sort {name,version,publisher,source}` | Sort results by field (default: name) |
| `--output {table,json,csv}` | Output format (default: table) |
| `--save-baseline FILE` | Save current state as baseline JSON file |
| `--diff FILE` | Compare current state against a baseline file |
| `--check-updates` | Check for available updates via winget |
| `--extensions` | List browser extensions with permission analysis |
| `--check-vulns` | Scan for known CVEs in installed software |
| `--nvd-api-key KEY` | NVD API key for faster vulnerability scanning |
| `--cve-limit N` | Max software items to CVE-check (default: 20, max: 100) |
| `--log-file FILE` | Path to audit log file (rotated at 5 MB, 3 backups) |
| `--verbose` | Enable verbose/debug logging |

### Examples

```bash
# List all installed software
python Software_Enumerator.py

# List only Microsoft Store apps
python Software_Enumerator.py --source store

# Search for Chrome-related software
python Software_Enumerator.py --search chrome

# Export to JSON
python Software_Enumerator.py --output json > software.json

# Export to CSV
python Software_Enumerator.py --output csv > software.csv

# Save a baseline snapshot
python Software_Enumerator.py --save-baseline baseline.json

# Compare against baseline (detect changes)
python Software_Enumerator.py --diff baseline.json

# Diff output as JSON (for automation)
python Software_Enumerator.py --diff baseline.json --output json

# Check for available updates
python Software_Enumerator.py --check-updates

# Audit browser extensions
python Software_Enumerator.py --extensions

# Scan for known vulnerabilities
python Software_Enumerator.py --check-vulns

# Use NVD API key for faster scanning
python Software_Enumerator.py --check-vulns --nvd-api-key YOUR_KEY

# Scan more software for CVEs (default is 20, max 100)
python Software_Enumerator.py --check-vulns --cve-limit 50

# Enable audit logging (log files rotate at 5 MB, keeping 3 backups)
python Software_Enumerator.py --log-file audit.log --verbose

# Combined security audit
python Software_Enumerator.py --check-updates --extensions --check-vulns --log-file audit.log
```

## Output Formats

### Software List (Table)
Displays a formatted table with: Name, Version, Publisher, Source, Install Date

### JSON Export
```json
{
  "metadata": {
    "generated_at": "2026-01-18T10:30:00",
    "hostname": "WORKSTATION",
    "user": "admin",
    "total_count": 142
  },
  "software": [
    {"name": "...", "version": "...", "publisher": "...", "source": "...", "install_date": "...", "install_location": "..."}
  ]
}
```

### CSV Export
Standard CSV with headers: `name,version,publisher,install_date,source,install_location`

### Baseline Comparison
Shows added, removed, and version-changed software since baseline was created:
- `[+] ADDED` - New software not in baseline
- `[-] REMOVED` - Software that was uninstalled
- `[~] CHANGED` - Version changes (upgrades/downgrades)

### Update Check
Shows available updates with current/available versions and winget package IDs

### Browser Extensions
Lists extensions with version, browser, and flags extensions with sensitive permissions (access to all URLs, cookies, history, storage, notifications, bookmarks, geolocation, local file access, etc.)

### Vulnerability Scan
Reports CVEs found with severity ratings (CRITICAL/HIGH/MEDIUM), CVSS scores, and remediation recommendations

## Security Considerations

### Output Data Sensitivity
The output of this tool contains sensitive system information:
- Complete software inventory with versions (useful for attackers to identify vulnerable software)
- Browser extensions and their permissions
- CVE vulnerability data specific to your system

**Recommendations:**
- Do not commit output files (JSON, CSV, logs) to version control
- Store baseline files securely with appropriate access controls
- Encrypt audit logs if storing long-term
- Redact sensitive data before sharing reports

### Built-in Security Features
- **Output Sanitization** - Removes ANSI escape sequences and control characters to prevent terminal injection
- **Audit Logging** - File-based logging with restricted permissions (0o600) and automatic rotation (5 MB max, 3 backups)
- **Symlink Protection** - Skips symlinks to prevent directory traversal attacks
- **File Count Safety Limit** - Portable app scanning caps at 500 executables to prevent memory exhaustion
- **Sliding-Window Rate Limiter** - Tracks API request timestamps in a rolling window with automatic 429 retry
- **CVE Scan Limit** - Configurable cap (max 100) prevents accidental API abuse
- **Generic Error Messages** - Prevents information leakage in error output
- **Generic User-Agent** - Does not identify the scanner tool in API requests
- **No Hardcoded Credentials** - API keys are passed via environment variables or CLI arguments

### API Key Security
- Store your NVD API key in an environment variable, not in scripts
- Never commit API keys to version control
- The `.gitignore` includes patterns to prevent accidental credential commits

## Architecture

### Components
- **RegistryScanner** - Scans Windows Registry uninstall keys
- **StoreAppScanner** - Enumerates Microsoft Store apps via PowerShell
- **PortableAppScanner** - Finds executables in portable app locations
- **WingetUpdateChecker** - Queries winget for available updates
- **BrowserExtensionScanner** - Scans Chrome, Edge, Firefox extensions
- **VulnerabilityScanner** - Queries NIST NVD API for CVEs
- **BaselineManager** - Handles baseline snapshots and comparisons
- **SoftwareExporter** - Multi-format output (table, JSON, CSV)

### Data Classes
- `SoftwareInfo` - Installed software metadata
- `UpdateInfo` - Available update information
- `BrowserExtensionInfo` - Browser extension details
- `CVEInfo` - Vulnerability information
- `VulnerabilityResult` - Scan results per software

### Dependencies
This tool uses only Python standard library modules:
- `argparse`, `csv`, `json` - CLI and data handling
- `winreg`, `subprocess` - Windows integration
- `urllib` - HTTP requests to NVD API
- `logging`, `logging.handlers` - Audit trail with log rotation
- `collections` - Sliding-window rate limiter (deque)
- `dataclasses` - Data structures
- `pathlib`, `os` - File system operations

## API Rate Limits

The CVE scanner uses the NIST NVD API with a sliding-window rate limiter:
- **Without API key**: 5 requests per 30-second window
- **With API key**: 50 requests per 30-second window
- **HTTP 429 handling**: Automatic single retry after a cooldown period

By default, the scanner checks up to 20 software items. Use `--cve-limit N` to increase this (max 100).

Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key

## Testing

Run the security test suite:
```bash
python test_security.py
```

The test suite covers:
- Output sanitization (ANSI codes, control characters)
- API key handling (environment variables, CLI arguments)
- Symlink protection
- Error message sanitization
- Audit logging functionality
- Log rotation configuration
- CVE scan limit (default, custom, and cap validation)
- Portable app file count safety limit
- Sliding-window rate limiter and HTTP 429 retry
- Enhanced browser extension permission detection (including Firefox top-level permissions)

## Acknowledgments

This project was developed with assistance from [Claude Code](https://claude.ai/claude-code), Anthropic's AI coding assistant. Claude Code helped with code review, security hardening, bug fixes, and documentation but the core functionality and architecture were human-designed and directed.

## License

See [LICENSE](LICENSE) for details.
