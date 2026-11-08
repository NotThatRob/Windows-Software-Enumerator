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
python Software_Enumerator.py --check-updates --log-file audit.log
python Software_Enumerator.py --extensions
python Software_Enumerator.py --check-vulns
# Note: --check-updates, --extensions and --check-vulns can't be combined yet: main() runs
# the first one given and returns (README's "Combined security audit" example is wrong).
python Software_Enumerator.py --save-baseline baseline.json
python Software_Enumerator.py --diff baseline.json
python Software_Enumerator.py --quiet --output json    # suppress progress output, print only results
python Software_Enumerator.py --exclude "redistributable,.NET Runtime"  # filter out noisy entries
```

## Architecture

Everything lives in `Software_Enumerator.py` (~3,260 lines). Key classes:

**Data classes** (`@dataclass`): `SoftwareInfo`, `UpdateInfo`, `BrowserExtensionInfo`, `CVEInfo`, `VulnerabilityResult`

**Scanners** (no shared base class or `scan()` method; each has its own entry point returning a list):
- `RegistryScanner` (`get_all_registry_software()`) — reads HKLM (64/32-bit) and HKCU uninstall keys via `winreg`. Converts values to text by type per entry and warns once per scan if a text field had an unexpected type
- `StoreAppScanner` (`get_store_apps()`) — runs PowerShell `Get-AppxPackage` and parses CSV output
- `PortableAppScanner` (`get_all_portable_apps()`) — walks common dirs with `os.scandir()`, skips symlinks, caps at 500 files
- `WingetUpdateChecker` (`check_for_updates()`) — runs `winget upgrade` subprocess
- `BrowserExtensionScanner` (`get_all_extensions()`) — reads Chrome/Edge/Firefox extension manifests from disk
- `VulnerabilityScanner` (`scan_software_list()`) — queries NIST NVD REST API with sliding-window rate limiter. Pre-compiles its skip patterns (regex, `SKIP_PATTERNS`) at `__init__` time to leave out framework/runtime entries

**Orchestration & Output**:
- `SoftwareEnumerator` — orchestrates scanners; uses `concurrent.futures.ThreadPoolExecutor` for parallel source scanning when `--source all`
- `SoftwareExporter` — formats output as table, JSON, or CSV
- `BaselineManager` / `BaselineDiff` — save/load/diff JSON baselines. Rejects files >50 MB or >50,000 entries

**UI helpers**: `ProgressBar`, `Spinner` — write progress/status to stderr (not stdout), so piped output stays clean. Suppressed by `--quiet`

**Top-level functions**: `setup_logging()`, `sanitize_output()`, `csv_safe_cell()`, `log_audit_event()`, `_load_env_file()`, `_system_dir()` / `_powershell_path()` / `_winget_path()`, `_harden_process_environment()`, `main()`

## Key Design Decisions

- **No dependencies**: Uses only Python stdlib (`winreg`, `subprocess`, `urllib`, `csv`, `logging.handlers.RotatingFileHandler`, `dataclasses`, `concurrent.futures`, etc.)
- **Security-first**: Output sanitization strips escape sequences, control chars and Unicode format/bidi chars, and turns line breaks/tabs into spaces; CSV cells that would run as spreadsheet formulas are prefixed with `'`; malformed registry/extension data is converted per entry rather than allowed to hide software; symlink protection; generic error messages hide internal details; generic User-Agent; file count safety limits; owner-only log file ACL (`_RestrictedRotatingFileHandler`, SDDL `D:P(A;;FA;;;OW)(A;;FA;;;SY)`; `os.chmod` can't restrict access on Windows). `_open_log_handle()` opens the file once with `CreateFileW` and the stream wraps that handle (never reopened by name; no `FILE_SHARE_DELETE`, so the file and its folder can't be swapped while open). New files: `CREATE_NEW` with the DACL in place. Existing files: opened with `FILE_FLAG_OPEN_REPARSE_POINT` and refused with `LogFileOwnershipError` → exit 4 if a reparse point, hard-linked, or owned by another account (other than SYSTEM/Administrators), otherwise restricted on the handle (`_restrict_handle_to_owner()`). The owner check runs whenever the owner can be read, regardless of the drive check (an unreadable owner on an ACL drive is refused, fail closed); drives without ACLs (`_volume_supports_acls()` false, e.g. FAT32) then only warn once. Win32 calls go through `_win32()` (private DLL handles with argtypes)
- **Absolute executable paths**: Subprocesses are launched by absolute path (`_powershell_path()`, `_winget_path()`), never by bare name, because Windows searches the current directory before PATH. There is no fallback to the bare name. `main()` also sets `NoDefaultCurrentDirectoryInExePath=1`. New subprocess calls must follow this
- **stderr/stdout separation**: All progress bars, spinners, and status messages go to stderr. Only final results (table/JSON/CSV) go to stdout. This allows clean piping (`--output json > file.json`)
- **Rate limiting**: Sliding-window rate limiter using `collections.deque` with automatic HTTP 429 retry. Without API key: 5 req/30s; with key: 50 req/30s
- **CVE limit**: Default 20, max 100 (`--cve-limit`). Prevents accidental API abuse
- **Search and exclude use literal matching** (not regex) to avoid regex injection via `matches_search()` and `matches_exclude()`. `--exclude` is comma-separated and matches against name and publisher
- **Structured exit codes**: `EXIT_SUCCESS=0`, `EXIT_ERROR=1`, `EXIT_NO_SOFTWARE=2`, `EXIT_API_FAILURE=3`, `EXIT_PERMISSION_DENIED=4` — defined as module-level constants for CI/CD scripting. Exit 4 is currently raised for `--log-file` problems; `EXIT_API_FAILURE` is not yet wired up
- **`SOFTWARE_MAPPINGS` dict** in `VulnerabilityScanner`: maps normalized software names to CPE-style `(vendor, product)` tuples. **Known problem:** `_query_nvd_api()` currently sends them as free-text `keywordSearch`, not as a CPE query. CPE tokens such as `vlc_media_player` never appear in CVE descriptions, and NVD returns results oldest-first (20 per request, no paging), so the CVE check misses most real CVEs
- **Env file loading**: `_load_env_file()` reads `api.env` (then `.env`) only from the tool's own folder (`_env_search_dirs()`: the script's folder, or the `.exe`'s folder when frozen) — never the CWD — and only accepts keys in `_ENV_FILE_ALLOWED_KEYS` (`NVD_API_KEY`). Other keys are ignored and logged by name, never by value. Does not overwrite existing env vars. The `api.env` file in the repo root is gitignored and is the intended place for NVD API keys during local development. Tests must patch `_env_search_dirs()` so the real `api.env` is never read

## Testing

Tests are in `test_security.py` using `unittest`. Import the main module as `import Software_Enumerator as se`. Tests use `unittest.mock.patch` extensively to mock Windows APIs and network calls. Run with `python test_security.py` — no test framework installation needed.

Test classes are organized by feature area (e.g., `TestOutputSanitization`, `TestSlidingWindowRateLimit`, `TestBaselineManagerRoundtrip`, `TestParallelScanning`, `TestQuietMode`). `run_security_tests()` collects every `TestCase` class in the module automatically (`loadTestsFromModule`, alphabetical order), so a new class needs no registration. Tests must not depend on running in a particular order.

## Important Constraints

- Windows-only: uses `winreg`, `ctypes`, PowerShell subprocesses
- Console encoding is set to UTF-8 at startup (`setup_console_encoding()`)
- NVD API key via `--nvd-api-key` CLI arg, `NVD_API_KEY` env var, or `api.env` file (CLI > env var > file)
- Never commit output files (JSON/CSV/logs/baselines) — `.gitignore` excludes them
- The `.gitignore` also excludes `*.env` and `api.env` — use these for local API keys only
