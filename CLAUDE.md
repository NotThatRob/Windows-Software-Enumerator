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
python Software_Enumerator.py --check-updates --extensions --check-vulns   # all three, always in this order
python Software_Enumerator.py --save-baseline baseline.json
python Software_Enumerator.py --diff baseline.json
python Software_Enumerator.py --quiet --output json    # suppress progress output, print only results
python Software_Enumerator.py --exclude "redistributable,.NET Runtime"  # filter out noisy entries
```

## Architecture

Everything lives in `Software_Enumerator.py` (~3,800 lines). Key classes:

**Data classes** (`@dataclass`): `SoftwareInfo`, `UpdateInfo`, `BrowserExtensionInfo`, `CVEInfo`, `VulnerabilityResult`, `VulnScanPlan`

**Scanners** (no shared base class or `scan()` method; each has its own entry point returning a list):
- `RegistryScanner` (`get_all_registry_software()`) — reads HKLM (64/32-bit) and HKCU uninstall keys via `winreg`. Converts values to text by type per entry and warns once per scan if a text field had an unexpected type
- `StoreAppScanner` (`get_store_apps()`) — runs PowerShell `Get-AppxPackage` and parses CSV output
- `PortableAppScanner` (`get_all_portable_apps()`) — walks common dirs with `os.scandir()`, skips symlinks, caps at 500 files
- `WingetUpdateChecker` (`check_for_updates()`) — runs `winget upgrade` subprocess. Sets `error` when winget is missing, times out, can't start, or exits with anything but 0 or `WINGET_NO_PACKAGES_FOUND` (`0x8A150014`; list mode exits 0 with or without upgrades), so a failed check is never shown as "up to date"
- `BrowserExtensionScanner` (`get_all_extensions()`) — reads Chrome/Edge/Firefox extension manifests from disk
- `VulnerabilityScanner` (`plan_scan()` then `scan_plan()`; `scan_software_list()` does both) — queries the NIST NVD REST API with a sliding-window rate limiter. `plan_scan()` picks mapped programs in name order, once per product + version, and counts what it leaves out (`VulnScanPlan`). `scan_software()` asks NVD `cpeName=cpe:2.3:a:<vendor>:<product>:<version>&isVulnerable&noRejected` (all pages, capped at `MAX_PAGES`) and trusts NVD's version matching (there is no local version matcher). CVEs whose NVD product data has no version at all ("every version") go to `all_versions`, and for products in `SEARCH_PHRASES` recent CVEs without NVD product data go to `unconfirmed`; neither is counted. All requests go through `_nvd_request()`, which raises `NvdApiError` with generic messages. Pre-compiles its skip patterns (regex, `SKIP_PATTERNS`) at `__init__` time to leave out framework/runtime entries

**Orchestration & Output**:
- `SoftwareEnumerator` — orchestrates scanners; uses `concurrent.futures.ThreadPoolExecutor` for parallel source scanning when `--source all`
- `SoftwareExporter` — formats output as table, JSON, or CSV
- `BaselineManager` / `BaselineDiff` — save/load/diff JSON baselines. Rejects files >50 MB or >50,000 entries. `load_baseline()` treats the file as untrusted: checks its shape and rejects a malformed file as a whole (`ValueError`; skipping an entry would fake an added/removed program); numbers in text fields are read as text (older baselines have them). `save_baseline()` creates the file exclusively (`"x"`) unless `overwrite=True` (`--overwrite`)

**UI helpers**: `ProgressBar`, `Spinner` — write progress/status to stderr (not stdout), so piped output stays clean. Suppressed by `--quiet`

**Top-level functions**: `setup_logging()`, `sanitize_output()`, `csv_safe_cell()`, `log_audit_event()`, `_load_env_file()`, `_system_dir()` / `_powershell_path()` / `_winget_path()`, `_harden_process_environment()`, `_apply_filters()`, `_check_option_combinations()`, `_run_update_check()` / `_run_extension_scan()` / `_run_cve_check()` (listed in `_AUDIT_CHECKS`), `main()`

## Key Design Decisions

- **No dependencies**: Uses only Python stdlib (`winreg`, `subprocess`, `urllib`, `csv`, `logging.handlers.RotatingFileHandler`, `dataclasses`, `concurrent.futures`, etc.)
- **Security-first**: Output sanitization strips escape sequences, control chars and Unicode format/bidi chars, and turns line breaks/tabs into spaces; CSV cells that would run as spreadsheet formulas are prefixed with `'`; malformed registry/extension data is converted per entry rather than allowed to hide software; symlink protection; generic error messages hide internal details; generic User-Agent; file count safety limits; owner-only log file ACL (`_RestrictedRotatingFileHandler`, SDDL `D:P(A;;FA;;;OW)(A;;FA;;;SY)`; `os.chmod` can't restrict access on Windows). `_open_log_handle()` opens the file once with `CreateFileW` and the stream wraps that handle (never reopened by name; no `FILE_SHARE_DELETE`, so the file and its folder can't be swapped while open). New files: `CREATE_NEW` with the DACL in place. Existing files: opened with `FILE_FLAG_OPEN_REPARSE_POINT` and refused with `LogFileOwnershipError` → exit 4 if a reparse point, hard-linked, or owned by another account (other than SYSTEM/Administrators), otherwise restricted on the handle (`_restrict_handle_to_owner()`). The owner check runs whenever the owner can be read, regardless of the drive check (an unreadable owner on an ACL drive is refused, fail closed); drives without ACLs (`_volume_supports_acls()` false, e.g. FAT32) then only warn once. Win32 calls go through `_win32()` (private DLL handles with argtypes)
- **Absolute executable paths**: Subprocesses are launched by absolute path (`_powershell_path()`, `_winget_path()`), never by bare name, because Windows searches the current directory before PATH. There is no fallback to the bare name. `main()` also sets `NoDefaultCurrentDirectoryInExePath=1`. New subprocess calls must follow this
- **stderr/stdout separation**: All progress bars, spinners, and status messages go to stderr. Only final results (table/JSON/CSV) go to stdout. This allows clean piping (`--output json > file.json`)
- **Rate limiting**: Sliding-window rate limiter using `collections.deque` with automatic HTTP 429 retry. Without API key: 5 req/30s; with key: 50 req/30s
- **CVE limit**: `--cve-limit` = number of programs checked, 1–100 (default 20); other values are a usage error, not clamped. Prevents accidental API abuse
- **Search and exclude use literal matching** (not regex) to avoid regex injection via `matches_search()` and `matches_exclude()`, applied by `_apply_filters()`. `--exclude` is comma-separated (empty terms ignored, `_parse_exclude_terms()`) and matches against name and publisher (updates: name or winget ID; extensions: name or extension ID). `--check-vulns` honours `--search`, `--exclude` and `--source` (default: registry); `--check-updates` and `--extensions` honour `--search` and `--exclude`. `--diff` applies them to the baseline and the current scan alike; `--save-baseline` refuses them (a baseline is always a full snapshot)
- **No option is silently ignored**: `_check_option_combinations()` runs right after `parse_args()` and refuses, with a usage error before anything is scanned, what `main()` can't honour. The audit checks combine and run in `_AUDIT_CHECKS` order (updates, extensions, CVEs); the software list, `--save-baseline` and `--diff` run alone; `--output json`/`csv` isn't available for the audit checks yet; `--overwrite` needs `--save-baseline`. Reports never say "up to date" or "none found" when the tool couldn't look or a filter hid the results
- **Structured exit codes**: `EXIT_SUCCESS=0`, `EXIT_ERROR=1`, `EXIT_NO_SOFTWARE=2`, `EXIT_API_FAILURE=3`, `EXIT_PERMISSION_DENIED=4`, `EXIT_CHANGES_FOUND=5` — defined as module-level constants for CI/CD scripting. Exit 3 when `--check-vulns` couldn't query NVD for some program or `--check-updates` couldn't run winget (results incomplete); exit 4 for `--log-file` problems and denied access to a baseline file; exit 5 when `--diff` found changes. argparse usage errors also exit 2
- **`SOFTWARE_MAPPINGS` dict** in `VulnerabilityScanner`: maps display-name keys to CPE `(vendor, product)` pairs exactly as NVD's CPE dictionary names them. Keys match whole words of the normalised name, longest key first (`_find_mapping()`). Every pair must exist in NVD's CPE dictionary (a wrong pair makes the check silently find nothing); unmapped programs are reported as "not checked", never guessed. Installer version quirks (Python `3.11.4150.0`, Java 8 `8.0.4010.10`, PostgreSQL `17.11-5`) are translated via `VERSION_TRANSLATORS`
- **The CVE report states its coverage**: it always says how many programs were checked and why others weren't; it never prints a bare "no vulnerabilities" when it couldn't look. NVD's own (`Primary`) CVSS score is preferred, newest CVSS version first; unscored and LOW CVEs are kept; KEV CVEs (CISA known exploited, from NVD's `cisaExploitAdd` field) are flagged and listed first
- **Env file loading**: `_load_env_file()` reads `api.env` (then `.env`) only from the tool's own folder (`_env_search_dirs()`: the script's folder, or the `.exe`'s folder when frozen) — never the CWD — and only accepts keys in `_ENV_FILE_ALLOWED_KEYS` (`NVD_API_KEY`). Other keys are ignored and logged by name, never by value. Does not overwrite existing env vars. The `api.env` file in the repo root is gitignored and is the intended place for NVD API keys during local development. Tests must patch `_env_search_dirs()` so the real `api.env` is never read

## Testing

Tests are in `test_security.py` using `unittest`. Import the main module as `import Software_Enumerator as se`. Tests use `unittest.mock.patch` extensively to mock Windows APIs and network calls. Run with `python test_security.py` — no test framework installation needed.

Test classes are organized by feature area (e.g., `TestOutputSanitization`, `TestSlidingWindowRateLimit`, `TestBaselineManagerRoundtrip`, `TestParallelScanning`, `TestQuietMode`). `run_security_tests()` collects every `TestCase` class in the module automatically (`loadTestsFromModule`, alphabetical order), so a new class needs no registration. Tests must not depend on running in a particular order.

To test behaviour through `main()` (argv in, output and exit code out), mix in `_MainHarness` (e.g. `class TestX(_MainHarness, unittest.TestCase)`): its `run_main(*argv)` mocks the scanners, winget and NVD and returns the exit code, stdout, stderr and the mocks, to check which scanners ran.

CI (`.github/workflows/tests.yml`) runs `python test_security.py` plus one real CLI smoke run on `windows-latest` with Python 3.10 and 3.14, for every PR and every push to `master`. Actions are pinned to full commit SHAs (version in a comment); keep it that way when bumping them.

## Important Constraints

- Windows-only: uses `winreg`, `ctypes`, PowerShell subprocesses
- Console encoding is set to UTF-8 at startup (`setup_console_encoding()`)
- NVD API key via `--nvd-api-key` CLI arg, `NVD_API_KEY` env var, or `api.env` file (CLI > env var > file)
- Never commit output files (JSON/CSV/logs/baselines) — `.gitignore` excludes them
- The `.gitignore` also excludes `*.env` and `api.env` — use these for local API keys only
