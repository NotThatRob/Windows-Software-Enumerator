# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Windows Software Enumerator — a single-file Python CLI tool for security auditing on Windows. It discovers installed software from the registry, Microsoft Store, and portable app locations, then optionally checks for updates (winget), scans browser extensions, and queries NIST NVD for CVEs. Zero external dependencies (Python stdlib only, requires Python 3.10+).

## Commands

```bash
# Run the tool
python Software_Enumerator.py [OPTIONS]

# Run security tests
python test_security.py

# Common usage examples
python Software_Enumerator.py --source registry --output json
python Software_Enumerator.py --check-updates --extensions --check-vulns --log-file audit.log
python Software_Enumerator.py --save-baseline baseline.json
python Software_Enumerator.py --diff baseline.json
```

## Architecture

Everything lives in `Software_Enumerator.py` (~2500 lines). Key classes:

**Data classes** (`@dataclass`): `SoftwareInfo`, `UpdateInfo`, `BrowserExtensionInfo`, `CVEInfo`, `VulnerabilityResult`

**Scanners** (each has a `scan()` method returning lists):
- `RegistryScanner` — reads HKLM (64/32-bit) and HKCU uninstall keys via `winreg`
- `StoreAppScanner` — runs PowerShell `Get-AppxPackage` and parses CSV output
- `PortableAppScanner` — walks common dirs with `os.scandir()`, skips symlinks, caps at 500 files
- `WingetUpdateChecker` — runs `winget upgrade` subprocess
- `BrowserExtensionScanner` — reads Chrome/Edge/Firefox extension manifests from disk
- `VulnerabilityScanner` — queries NIST NVD REST API with sliding-window rate limiter

**Orchestration & Output**:
- `SoftwareEnumerator` — orchestrates all scanners based on CLI args
- `SoftwareExporter` — formats output as table, JSON, or CSV
- `BaselineManager` / `BaselineDiff` — save/load/diff JSON baselines

**Top-level functions**: `setup_logging()`, `sanitize_output()`, `log_audit_event()`, `main()`

## Key Design Decisions

- **No dependencies**: Uses only Python stdlib (`winreg`, `subprocess`, `urllib`, `csv`, `logging.handlers.RotatingFileHandler`, `dataclasses`, etc.)
- **Security-first**: Output sanitization strips ANSI/control chars; symlink protection; generic error messages hide internal details; generic User-Agent; file count safety limits; restricted log permissions (0o600)
- **Rate limiting**: Sliding-window rate limiter using `collections.deque` with automatic HTTP 429 retry. Without API key: 5 req/30s; with key: 50 req/30s
- **CVE limit**: Default 20, max 100 (`--cve-limit`). Prevents accidental API abuse
- **Search uses literal matching** (not regex) to avoid regex injection via `matches_search()`
- **`SOFTWARE_MAPPINGS` dict** in `VulnerabilityScanner`: maps normalized software names to `(vendor, product)` tuples for NVD CPE queries

## Testing

Tests are in `test_security.py` using `unittest`. Import the main module as `import Software_Enumerator as se`. Tests use `unittest.mock.patch` extensively to mock Windows APIs and network calls. Run with `python test_security.py` — no test framework installation needed.

## Important Constraints

- Windows-only: uses `winreg`, `ctypes`, PowerShell subprocesses
- Console encoding is set to UTF-8 at startup (`setup_console_encoding()`)
- NVD API key via `--nvd-api-key` CLI arg or `NVD_API_KEY` env var (CLI takes precedence)
- Never commit output files (JSON/CSV/logs/baselines) — `.gitignore` excludes them
