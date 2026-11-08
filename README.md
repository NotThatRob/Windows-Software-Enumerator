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
- [Exit Codes](#exit-codes)
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
| `--source {registry,store,portable,all}` | Source to scan (default: all; registry for `--check-vulns`) |
| `--search TERM` | Filter results by name, publisher, or version |
| `--exclude PATTERNS` | Exclude software matching patterns (comma-separated) |
| `--sort {name,version,publisher,source}` | Sort results by field (default: name) |
| `--output {table,json,csv}` | Output format (default: table) |
| `--save-baseline FILE` | Save current state as baseline JSON file (an existing file is kept unless `--overwrite` is given) |
| `--overwrite` | Let `--save-baseline` replace an existing file |
| `--diff FILE` | Compare current state against a baseline file |
| `--check-updates` | Check for available updates via winget |
| `--extensions` | List browser extensions with permission analysis |
| `--check-vulns` | Scan for known CVEs in installed software |
| `--nvd-api-key KEY` | NVD API key for faster vulnerability scanning |
| `--cve-limit N` | Max programs to CVE-check, 1–100 (default: 20) |
| `--log-file FILE` | Path to audit log file (rotated at 5 MB, 3 backups) |
| `--verbose` | Enable verbose/debug logging |
| `--quiet` | Suppress progress output, print only results |

### Examples

```bash
# List all installed software
python Software_Enumerator.py

# List only Microsoft Store apps
python Software_Enumerator.py --source store

# Search for Chrome-related software
python Software_Enumerator.py --search chrome

# Exclude noisy entries (comma-separated patterns)
python Software_Enumerator.py --exclude "redistributable,.NET Runtime"

# Combine search and exclude
python Software_Enumerator.py --search microsoft --exclude "redistributable,framework"

# Export to JSON
python Software_Enumerator.py --output json > software.json

# Export to CSV
python Software_Enumerator.py --output csv > software.csv

# Save a baseline snapshot
python Software_Enumerator.py --save-baseline baseline.json

# Replace an existing baseline (e.g. in a scheduled job)
python Software_Enumerator.py --save-baseline baseline.json --overwrite

# Compare against baseline (detect changes)
python Software_Enumerator.py --diff baseline.json

# Compare, leaving out noisy runtime entries (in the baseline and the current scan)
python Software_Enumerator.py --diff baseline.json --exclude "redistributable,.NET Runtime"

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

# Quiet mode for scripting (results only, no progress output)
python Software_Enumerator.py --quiet --output json > inventory.json
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

Cells that begin with `=`, `+`, `-` or `@` are prefixed with a single quote (`'`) so spreadsheet apps show them as text instead of running them as formulas (CSV injection protection). This also applies to `--diff ... --output csv`.

### Baseline Comparison
Shows added, removed, and version-changed software since baseline was created:
- `[+] ADDED` - New software not in baseline
- `[-] REMOVED` - Software that was uninstalled
- `[~] CHANGED` - Version changes (upgrades/downgrades)

A baseline is always a full snapshot, so `--save-baseline` can't be combined with `--search` or `--exclude`. Use them with `--diff` instead: they then choose which programs are compared, in the baseline and in the current scan alike. (A baseline saved with `--search` or `--exclude` by an older version of the tool makes `--diff` report everything outside that filter as added; save it again.)

### Update Check
Shows available updates with current/available versions and winget package IDs. If winget isn't installed, times out or reports an error, the output says the update check couldn't be done (never "up to date") and the exit code is 3

### Browser Extensions
Lists extensions with version, browser, and flags extensions with sensitive permissions (access to all URLs, cookies, history, storage, notifications, bookmarks, geolocation, local file access, etc.)

### Vulnerability Scan
For each installed program with a known CPE name (the product name NVD uses), asks NVD which CVEs affect that exact version, and reports:
- **What was checked** - how many programs were checked, and how many were not (no CPE mapping, framework/update packages, no usable version, duplicates, over `--cve-limit`) or failed. A clean result reads "No known CVEs affect the N program(s) checked", never a bare all-clear
- **Affected programs** - CVEs with severity and CVSS score: NVD's own score first, newest CVSS version first (a score from the CVE's assigner is labelled `CNA`); CVEs not scored yet are kept. CVEs in CISA's Known Exploited Vulnerabilities catalog are marked `[KEV: known exploited]` and listed first
- **Listed for every version** - CVEs that NVD records for all versions of a product, with no version range (often old, or about the product in general). Listed separately with their dates, never counted
- **Unconfirmed** - recent CVEs (last 119 days) that mention the program but that NVD hasn't analysed yet, so it can't say which versions they affect. Listed separately for you to check, never counted

Programs come from the registry unless `--source` is given, are checked in name order (once per product and version), and `--search` / `--exclude` apply. Some installer version formats are translated to the form NVD uses (e.g. Python `3.11.4150.0` → `3.11.4`, Java `8.0.4010.10` → `1.8.0 update 401`).

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
- **Output Sanitization** - Removes terminal escape sequences (7-bit and 8-bit), control characters, and Unicode bidi/format characters to prevent terminal injection. Line breaks and tabs inside names are replaced with spaces, so a name can't overwrite itself on screen or inject fake table rows. Applied to table, JSON, CSV, and baseline-diff output
- **CSV Formula-Injection Guard** - Exported cells that a spreadsheet would treat as a formula are prefixed with `'`
- **Trusted Executable Paths** - PowerShell and winget are launched by absolute path (System32 from the OS, winget's per-user alias), never by bare name, so a planted `powershell.exe`/`winget.exe` in the current folder can't run in their place
- **Malformed-Data Resilience** - Registry values with unexpected types are converted to text (and reported with a warning) instead of hiding the entry or aborting the scan; malformed browser extension files are handled per entry, so one bad file can't crash the extension scan
- **Audit Logging** - File-based logging with automatic rotation (5 MB max, 3 backups). Log files, including rotated copies, get an owner-only Windows access list (you and SYSTEM; nothing inherited from the folder). New log files are created with it already in place. The tool refuses (exit code 4) to write to an existing log file that is owned by another account, is a symbolic link, or has other hard links, since someone else could read it. If the drive doesn't support access lists (e.g. FAT32/exFAT), a warning is shown and logging continues
- **Symlink Protection** - Skips symlinks to prevent directory traversal attacks
- **File Count Safety Limit** - Portable app scanning caps at 500 executables to prevent memory exhaustion
- **Baseline Size Limits** - Rejects baseline files larger than 50 MB or containing more than 50,000 entries
- **Sliding-Window Rate Limiter** - Tracks API request timestamps in a rolling window with automatic 429 retry
- **CVE Scan Limit** - Configurable cap (max 100) prevents accidental API abuse
- **Literal Search Matching** - Search and exclude filters use literal substring matching (not regex) to prevent regex injection
- **Generic Error Messages** - Prevents information leakage in error output
- **Generic User-Agent** - Does not identify the scanner tool in API requests
- **No Hardcoded Credentials** - API keys are passed via environment variables, CLI arguments, or local `.env` files

### API Key Security
- Store your NVD API key in an environment variable or a local `api.env` (or `.env`) file containing `NVD_API_KEY=...`, placed **next to `Software_Enumerator.py`** (or next to the `.exe` for packaged builds). It is auto-loaded at startup
- Only `NVD_API_KEY` is read from these files, and files in the current working directory are ignored, so a file planted where the tool is run from can't change its settings (e.g. proxy or certificate variables)
- Never commit API keys to version control
- The `.gitignore` includes patterns to prevent accidental credential commits (`*.env`, `api.env`)

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
- `concurrent.futures` - Parallel source scanning
- `collections` - Sliding-window rate limiter (deque)
- `dataclasses` - Data structures
- `pathlib`, `os` - File system operations

## API Rate Limits

The CVE scanner uses the NIST NVD API with a sliding-window rate limiter:
- **Without API key**: 5 requests per 30-second window
- **With API key**: 50 requests per 30-second window
- **HTTP 429 handling**: Automatic single retry after a cooldown period

By default, the scanner checks up to 20 programs. Use `--cve-limit N` to change this (1–100; other values are rejected). Each program takes about two requests (more for very outdated browsers, which can be affected by thousands of CVEs), so 20 programs take roughly 25 seconds with an API key and about 4 minutes without.

Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key

## Exit Codes

Structured exit codes for scripting and CI/CD integration:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Generic error |
| 2 | No software found |
| 3 | Check incomplete: `--check-vulns` couldn't query NVD for some programs, or `--check-updates` couldn't run winget (results incomplete) |
| 4 | Permission denied (e.g. the `--log-file` can't be written, or is owned by another account or linked) |
| 5 | Changes found: `--diff` found programs added, removed or changed since the baseline |

## Testing

Run the security test suite:
```bash
python test_security.py

# Run a single test class
python -m unittest test_security.TestWingetUpdateChecker

# Run a single test method
python -m unittest test_security.TestOutputSanitization.test_removes_ansi_color_codes
```

The test suite covers:
- Output sanitization (ANSI/8-bit escape sequences, control characters, carriage-return overwrite, Unicode bidi overrides, baseline-diff exports)
- CSV formula-injection guard (export and diff CSV)
- Malformed registry values and browser extension files (wrong types, null fields, invalid UTF-8, deeply nested JSON)
- Absolute executable paths (incl. a planted-binary integration test)
- Owner-only log file access lists (set at creation, on rotated files, and on pre-existing files), and refusal of log files owned by another account or reached through a link
- API key handling (environment variables, CLI arguments, `.env` file loading: allowlisted key only, tool folder only, values never logged)
- Symlink protection
- Error message sanitization
- Audit logging functionality
- Log rotation configuration
- CVE scan limit (default, custom, and cap validation)
- Portable app file count safety limit
- Sliding-window rate limiter and HTTP 429 retry
- Enhanced browser extension permission detection (including Firefox top-level permissions)
- Baseline size limits, save/load roundtrip, and change detection
- Winget output parsing (header detection, column extraction, edge cases)
- Store app CSV parsing and publisher cleanup
- Exclude filter (single/multiple terms, publisher matching, combined with search)
- Structured exit code constants
- Parallel source scanning (all sources, single source, error isolation)
- Quiet mode (progress suppression)

## Acknowledgments

This project was developed with assistance from [Claude Code](https://claude.ai/claude-code), Anthropic's AI coding assistant. Claude Code helped with code review, security hardening, bug fixes, and documentation but the core functionality and architecture were human-designed and directed.

## License

See [LICENSE](LICENSE) for details.
