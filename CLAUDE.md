# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Windows Software Enumerator — a single-file Python CLI tool for security auditing on Windows. It discovers installed software from the registry, Microsoft Store, and portable app locations, then optionally checks for updates (winget), scans browser extensions, and queries NIST NVD for CVEs. Zero external dependencies (Python stdlib only, requires Python 3.10+).

## Commands

```bash
# Run the tool
python Software_Enumerator.py [OPTIONS]

# Run all security tests
python test_security.py

# Run a single test class
python -m unittest test_security.TestOutputSanitization

# Run a single test method
python -m unittest test_security.TestOutputSanitization.test_removes_ansi_color_codes

# Common usage examples
python Software_Enumerator.py --source registry --output json
python Software_Enumerator.py --check-updates --extensions --check-vulns --log-file audit.log
python Software_Enumerator.py --save-baseline baseline.json
python Software_Enumerator.py --diff baseline.json
python Software_Enumerator.py --quiet --output json    # suppress progress output, print only results
python Software_Enumerator.py --exclude "redistributable,.NET Runtime"  # filter out noisy entries
```

## Architecture

Everything lives in `Software_Enumerator.py` (~2600 lines). Key classes:

**Data classes** (`@dataclass`): `SoftwareInfo`, `UpdateInfo`, `BrowserExtensionInfo`, `CVEInfo`, `VulnerabilityResult`

**Scanners** (each has a `scan()` method returning lists):
- `RegistryScanner` — reads HKLM (64/32-bit) and HKCU uninstall keys via `winreg`. Pre-compiles skip patterns (regex) at `__init__` time for filtering framework/runtime entries
- `StoreAppScanner` — runs PowerShell `Get-AppxPackage` and parses CSV output
- `PortableAppScanner` — walks common dirs with `os.scandir()`, skips symlinks, caps at 500 files
- `WingetUpdateChecker` — runs `winget upgrade` subprocess
- `BrowserExtensionScanner` — reads Chrome/Edge/Firefox extension manifests from disk
- `VulnerabilityScanner` — queries NIST NVD REST API with sliding-window rate limiter

**Orchestration & Output**:
- `SoftwareEnumerator` — orchestrates scanners; uses `concurrent.futures.ThreadPoolExecutor` for parallel source scanning when `--source all`
- `SoftwareExporter` — formats output as table, JSON, or CSV
- `BaselineManager` / `BaselineDiff` — save/load/diff JSON baselines. Rejects files >50 MB or >50,000 entries

**UI helpers**: `ProgressBar`, `Spinner` — write progress/status to stderr (not stdout), so piped output stays clean. Suppressed by `--quiet`

**Top-level functions**: `setup_logging()`, `sanitize_output()`, `log_audit_event()`, `_load_env_file()`, `main()`

## Key Design Decisions

- **No dependencies**: Uses only Python stdlib (`winreg`, `subprocess`, `urllib`, `csv`, `logging.handlers.RotatingFileHandler`, `dataclasses`, `concurrent.futures`, etc.)
- **Security-first**: Output sanitization strips ANSI/control chars and Unicode bidi overrides; symlink protection; generic error messages hide internal details; generic User-Agent; file count safety limits; restricted log permissions (0o600)
- **stderr/stdout separation**: All progress bars, spinners, and status messages go to stderr. Only final results (table/JSON/CSV) go to stdout. This allows clean piping (`--output json > file.json`)
- **Rate limiting**: Sliding-window rate limiter using `collections.deque` with automatic HTTP 429 retry. Without API key: 5 req/30s; with key: 50 req/30s
- **CVE limit**: Default 20, max 100 (`--cve-limit`). Prevents accidental API abuse
- **Search and exclude use literal matching** (not regex) to avoid regex injection via `matches_search()` and `matches_exclude()`. `--exclude` is comma-separated and matches against name and publisher
- **Structured exit codes**: `EXIT_SUCCESS=0`, `EXIT_ERROR=1`, `EXIT_NO_SOFTWARE=2`, `EXIT_API_FAILURE=3`, `EXIT_PERMISSION_DENIED=4` — defined as module-level constants for CI/CD scripting
- **`SOFTWARE_MAPPINGS` dict** in `VulnerabilityScanner`: maps normalized software names to `(vendor, product)` tuples for NVD CPE queries
- **Env file loading**: `_load_env_file()` loads `api.env` or `.env` from the script directory or CWD at startup. Does not overwrite existing env vars. The `api.env` file in the repo root is gitignored and is the intended place for NVD API keys during local development

## Testing

Tests are in `test_security.py` using `unittest`. Import the main module as `import Software_Enumerator as se`. Tests use `unittest.mock.patch` extensively to mock Windows APIs and network calls. Run with `python test_security.py` — no test framework installation needed.

Test classes are organized by feature area (e.g., `TestOutputSanitization`, `TestSlidingWindowRateLimit`, `TestBaselineManagerRoundtrip`, `TestParallelScanning`, `TestQuietMode`). The `SecurityTestSuite` class at the bottom defines the canonical test ordering.

## Important Constraints

- Windows-only: uses `winreg`, `ctypes`, PowerShell subprocesses
- Console encoding is set to UTF-8 at startup (`setup_console_encoding()`)
- NVD API key via `--nvd-api-key` CLI arg, `NVD_API_KEY` env var, or `api.env` file (CLI > env var > file)
- Never commit output files (JSON/CSV/logs/baselines) — `.gitignore` excludes them
- The `.gitignore` also excludes `*.env` and `api.env` — use these for local API keys only
