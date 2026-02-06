"""
Software Enumerator - Windows 11 Software Auditing Tool

Enumerates installed software from multiple sources:
- Windows Registry (traditional Win32 programs)
- Microsoft Store Apps (UWP/MSIX)
- Portable Applications (common locations)
"""

import argparse
import csv
import ctypes
import getpass
import io
import json
import logging
import os
import re
import subprocess
import sys
import time
import unicodedata
import urllib.request
import urllib.parse
import urllib.error
import winreg
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

# Module-level logger
logger = logging.getLogger("software_enumerator")


def setup_console_encoding():
    """Configure console for UTF-8 output on Windows."""
    if sys.platform == "win32":
        try:
            # Set console output to UTF-8
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass


def setup_logging(log_file: str = None, verbose: bool = False) -> None:
    """Configure logging for audit trail.

    Args:
        log_file: Path to log file. If None, logging is minimal (warnings only to stderr).
        verbose: If True, include DEBUG level messages with detailed information.
    """
    log_format = "%(asctime)s | %(levelname)-8s | %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Clear any existing handlers to prevent accumulation on repeated calls
    logger.handlers.clear()

    # Set base logging level
    level = logging.DEBUG if verbose else logging.INFO

    if log_file:
        # Ensure log file has restricted permissions on creation
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Configure file handler
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(log_format, date_format))
        logger.addHandler(file_handler)

        # Try to set restrictive permissions (owner read/write only)
        try:
            os.chmod(log_file, 0o600)
        except (OSError, AttributeError):
            pass  # Windows may not support chmod, or file doesn't exist yet

    # Always add a stderr handler for warnings/errors (but not info/debug)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(stderr_handler)

    logger.setLevel(level)


def log_audit_event(event_type: str, details: str = "", **kwargs) -> None:
    """Log an audit event with structured information.

    Args:
        event_type: Type of event (SCAN_START, SCAN_END, ERROR, etc.)
        details: Human-readable details
        **kwargs: Additional key-value pairs to log
    """
    extra_info = " | ".join(f"{k}={v}" for k, v in kwargs.items()) if kwargs else ""
    message = f"[{event_type}] {details}"
    if extra_info:
        message += f" | {extra_info}"
    logger.info(message)


def sanitize_output(text: str) -> str:
    """Remove ANSI escape sequences and control characters from text.

    Prevents malicious software from manipulating terminal output
    or hiding its presence in listings via escape sequences.
    """
    if not text:
        return text
    # Remove ANSI escape sequences (colors, cursor movement, etc.)
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    # Remove other escape sequences (OSC, etc.)
    text = re.sub(r'\x1b\][^\x07]*\x07', '', text)
    # Remove remaining control characters except newline and tab
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text


class ProgressBar:
    """A simple console progress bar."""

    def __init__(
        self,
        total: int = 100,
        prefix: str = "",
        width: int = 40,
        fill: str = "█",
        empty: str = "░",
    ):
        self.total = total
        self.prefix = prefix
        self.width = width
        self.fill = fill
        self.empty = empty
        self.current = 0
        self.start_time = time.time()
        self._last_line_length = 0

    def update(self, current: int = None, status: str = ""):
        """Update the progress bar."""
        if current is not None:
            self.current = current
        else:
            self.current += 1

        # Calculate progress
        progress = min(self.current / self.total, 1.0) if self.total > 0 else 1.0
        filled_width = int(self.width * progress)
        empty_width = self.width - filled_width

        # Build progress bar
        bar = f"{self.fill * filled_width}{self.empty * empty_width}"
        percent = f"{progress * 100:5.1f}%"

        # Calculate ETA
        elapsed = time.time() - self.start_time
        if progress > 0 and progress < 1:
            eta = elapsed / progress * (1 - progress)
            eta_str = f"ETA: {self._format_time(eta)}"
        elif progress >= 1:
            eta_str = f"Done in {self._format_time(elapsed)}"
        else:
            eta_str = "ETA: --:--"

        # Truncate status if too long
        max_status_len = 30
        if len(status) > max_status_len:
            status = status[:max_status_len-3] + "..."

        # Build line
        line = f"\r{self.prefix} |{bar}| {percent} [{self.current}/{self.total}] {eta_str}"
        if status:
            line += f" - {status}"

        # Pad with spaces to clear previous content
        padding = max(0, self._last_line_length - len(line))
        line += " " * padding

        self._last_line_length = len(line) - padding

        # Print without newline
        sys.stdout.write(line)
        sys.stdout.flush()

    def _format_time(self, seconds: float) -> str:
        """Format seconds as MM:SS or HH:MM:SS."""
        if seconds < 0:
            return "--:--"
        seconds = int(seconds)
        if seconds >= 3600:
            h, remainder = divmod(seconds, 3600)
            m, s = divmod(remainder, 60)
            return f"{h}:{m:02d}:{s:02d}"
        else:
            m, s = divmod(seconds, 60)
            return f"{m:02d}:{s:02d}"

    def finish(self, message: str = ""):
        """Complete the progress bar and move to next line."""
        self.update(self.total, message)
        print()  # Move to next line


class Spinner:
    """A simple console spinner for indeterminate progress."""

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    # Fallback for consoles that don't support unicode
    FRAMES_ASCII = ["|", "/", "-", "\\"]

    def __init__(self, message: str = "Loading"):
        self.message = message
        self.frame_idx = 0
        self.start_time = time.time()
        self._last_line_length = 0
        # Test if unicode works
        try:
            sys.stdout.write("\r⠋\r ")
            self.frames = self.FRAMES
        except UnicodeEncodeError:
            self.frames = self.FRAMES_ASCII

    def spin(self, status: str = ""):
        """Update the spinner."""
        frame = self.frames[self.frame_idx]
        self.frame_idx = (self.frame_idx + 1) % len(self.frames)

        elapsed = time.time() - self.start_time
        elapsed_str = f"{elapsed:.1f}s"

        # Truncate status if too long
        max_status_len = 40
        if len(status) > max_status_len:
            status = status[:max_status_len-3] + "..."

        line = f"\r{frame} {self.message} ({elapsed_str})"
        if status:
            line += f" - {status}"

        # Pad with spaces to clear previous content
        padding = max(0, self._last_line_length - len(line))
        line += " " * padding

        self._last_line_length = len(line) - padding

        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self, message: str = ""):
        """Complete the spinner."""
        elapsed = time.time() - self.start_time
        final_msg = message or f"{self.message} completed"
        line = f"\r✓ {final_msg} ({elapsed:.1f}s)"
        padding = max(0, self._last_line_length - len(line))
        line += " " * padding
        print(line)


@dataclass
class SoftwareInfo:
    """Represents information about an installed software."""
    name: str
    version: str = ""
    publisher: str = ""
    install_date: str = ""
    source: str = ""
    install_location: str = ""

    def matches_search(self, search_term: str) -> bool:
        """Check if the software matches a search term."""
        search_lower = search_term.lower()
        return (
            search_lower in self.name.lower()
            or search_lower in self.publisher.lower()
            or search_lower in self.version.lower()
        )


@dataclass
class UpdateInfo:
    """Represents available update information for a software."""
    name: str
    current_version: str
    available_version: str
    winget_id: str = ""


@dataclass
class BrowserExtensionInfo:
    """Represents information about a browser extension."""
    name: str
    version: str
    browser: str
    extension_id: str
    description: str = ""
    permissions: list = field(default_factory=list)
    enabled: bool = True

    def has_sensitive_permissions(self) -> bool:
        """Check if extension has potentially dangerous permissions."""
        sensitive = [
            "<all_urls>",
            "http://*/*",
            "https://*/*",
            "*://*/*",
            "webRequest",
            "webRequestBlocking",
            "nativeMessaging",
            "debugger",
            "cookies",
            "history",
            "tabs",
            "management",
            "privacy",
            "proxy",
            "downloads",
            "clipboardRead",
            "clipboardWrite",
        ]
        return any(
            any(s in p for s in sensitive)
            for p in self.permissions
        )


@dataclass
class CVEInfo:
    """Represents a CVE (Common Vulnerabilities and Exposures) entry."""
    cve_id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    cvss_score: float
    published_date: str
    references: list = field(default_factory=list)

    @property
    def severity_color(self) -> str:
        """Get severity indicator for display."""
        indicators = {
            "CRITICAL": "[!!!!]",
            "HIGH": "[!!!]",
            "MEDIUM": "[!!]",
            "LOW": "[!]",
            "UNKNOWN": "[?]",
        }
        return indicators.get(self.severity, "[?]")


@dataclass
class VulnerabilityResult:
    """Represents vulnerability scan results for a software."""
    software_name: str
    software_version: str
    cves: list[CVEInfo] = field(default_factory=list)
    error: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for c in self.cves if c.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for c in self.cves if c.severity == "HIGH")

    @property
    def total_count(self) -> int:
        return len(self.cves)


class RegistryScanner:
    """Scans Windows Registry for installed software."""

    REGISTRY_PATHS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    def scan_registry_key(self, hive: int, path: str) -> list[SoftwareInfo]:
        """Scan a specific registry key for installed software."""
        software_list = []

        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except FileNotFoundError:
            return software_list
        except PermissionError:
            return software_list

        try:
            subkey_count = winreg.QueryInfoKey(key)[0]

            for i in range(subkey_count):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey_path = f"{path}\\{subkey_name}"
                    subkey = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)

                    try:
                        name = self._get_registry_value(subkey, "DisplayName")
                        if not name:
                            continue

                        # Skip system components and updates
                        system_component = self._get_registry_value(subkey, "SystemComponent")
                        if system_component == 1:
                            continue

                        software = SoftwareInfo(
                            name=name,
                            version=self._get_registry_value(subkey, "DisplayVersion") or "",
                            publisher=self._get_registry_value(subkey, "Publisher") or "",
                            install_date=self._format_install_date(
                                self._get_registry_value(subkey, "InstallDate")
                            ),
                            source="Registry",
                            install_location=self._get_registry_value(subkey, "InstallLocation") or "",
                        )
                        software_list.append(software)

                    finally:
                        winreg.CloseKey(subkey)

                except (FileNotFoundError, PermissionError, OSError):
                    continue

        finally:
            winreg.CloseKey(key)

        return software_list

    def _get_registry_value(self, key, value_name: str):
        """Get a value from a registry key, returning None if not found."""
        try:
            value, _ = winreg.QueryValueEx(key, value_name)
            return value
        except FileNotFoundError:
            return None

    def _format_install_date(self, date_str: Optional[str]) -> str:
        """Format install date from YYYYMMDD to readable format."""
        if not date_str or len(date_str) != 8:
            return ""
        try:
            date = datetime.strptime(date_str, "%Y%m%d")
            return date.strftime("%Y-%m-%d")
        except ValueError:
            return ""

    def get_all_registry_software(self) -> list[SoftwareInfo]:
        """Get all software from all registry locations."""
        all_software = []
        seen_names = set()

        for hive, path in self.REGISTRY_PATHS:
            software_list = self.scan_registry_key(hive, path)
            for software in software_list:
                # Deduplicate by name (same app might appear in multiple registry locations)
                if software.name not in seen_names:
                    seen_names.add(software.name)
                    all_software.append(software)

        return all_software


class StoreAppScanner:
    """Scans for Microsoft Store (UWP/MSIX) applications."""

    def get_store_apps(self) -> list[SoftwareInfo]:
        """Get all Microsoft Store apps using PowerShell."""
        software_list = []

        try:
            # Use PowerShell to get AppxPackages
            # -NoLogo: Skip the copyright banner (minor startup speedup)
            # -NoProfile: Skip loading user profile scripts
            cmd = [
                "powershell",
                "-NoLogo",
                "-NoProfile",
                "-Command",
                "Get-AppxPackage | Select-Object Name, Version, Publisher, InstallLocation | ConvertTo-Csv -NoTypeInformation"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode != 0:
                return software_list

            lines = result.stdout.strip().split("\n")
            if len(lines) <= 1:
                return software_list

            # Skip header line
            for line in lines[1:]:
                try:
                    # Parse CSV line (handling quoted values)
                    parts = self._parse_csv_line(line)
                    if len(parts) >= 4:
                        name = parts[0].strip('"')
                        version = parts[1].strip('"')
                        publisher = parts[2].strip('"')
                        install_location = parts[3].strip('"')

                        # Clean up publisher (remove CN= prefix if present)
                        if publisher.startswith("CN="):
                            publisher = publisher[3:].split(",")[0]

                        # Skip framework packages and system components
                        if self._is_framework_package(name):
                            continue

                        software = SoftwareInfo(
                            name=self._format_app_name(name),
                            version=version,
                            publisher=publisher,
                            install_date="",
                            source="Store",
                            install_location=install_location,
                        )
                        software_list.append(software)

                except (ValueError, IndexError):
                    continue

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return software_list

    def _parse_csv_line(self, line: str) -> list[str]:
        """Parse a CSV line, handling quoted values."""
        parts = []
        current = ""
        in_quotes = False

        for char in line:
            if char == '"':
                in_quotes = not in_quotes
                current += char
            elif char == ',' and not in_quotes:
                parts.append(current)
                current = ""
            else:
                current += char

        parts.append(current)
        return parts

    def _is_framework_package(self, name: str) -> bool:
        """Check if the package is a framework or system component."""
        framework_indicators = [
            "Microsoft.NET",
            "Microsoft.VCLibs",
            "Microsoft.UI",
            "Microsoft.Services",
            "Microsoft.DirectX",
            "Windows.PrintDialog",
            "Microsoft.Windows",
            "Microsoft.DesktopAppInstaller",
            "Microsoft.Advertising",
            ".NET",
            "InputApp",
            "HEIFImageExtension",
            "VP9VideoExtensions",
            "WebMediaExtensions",
            "AV1VideoExtension",
            "HEVCVideoExtension",
            "RawImageExtension",
            "WebpImageExtension",
        ]
        return any(indicator in name for indicator in framework_indicators)

    def _format_app_name(self, name: str) -> str:
        """Format app name to be more readable."""
        # Remove common prefixes
        prefixes = ["Microsoft.", "Windows.", "MicrosoftCorporationII."]
        for prefix in prefixes:
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        return name


class PortableAppScanner:
    """Scans for portable applications in common locations."""

    def __init__(self):
        self.scan_locations = self._get_scan_locations()

    def _get_scan_locations(self) -> list[Path]:
        """Get list of directories to scan for portable apps."""
        locations = []

        # User-specific locations
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            programs_path = Path(local_app_data) / "Programs"
            if programs_path.exists():
                locations.append(programs_path)

        app_data = os.environ.get("APPDATA")
        if app_data:
            app_data_path = Path(app_data)
            if app_data_path.exists():
                locations.append(app_data_path)

        # Common portable app locations
        portable_paths = [
            Path("C:/PortableApps"),
            Path("C:/Tools"),
        ]

        for path in portable_paths:
            if path.exists():
                locations.append(path)

        return locations

    def scan_directory(self, directory: Path, max_depth: int = 2) -> list[SoftwareInfo]:
        """Scan a directory for executable files."""
        software_list = []
        seen_apps = set()

        try:
            for exe_path in self._find_executables(directory, max_depth):
                try:
                    # Use parent directory name as app name
                    app_name = exe_path.parent.name
                    if app_name in seen_apps:
                        continue

                    # Skip common system/utility executables
                    if self._should_skip_exe(exe_path):
                        continue

                    version = self._get_file_version(str(exe_path))
                    publisher = self._get_file_publisher(str(exe_path))

                    if app_name and not app_name.startswith("."):
                        seen_apps.add(app_name)
                        software = SoftwareInfo(
                            name=app_name,
                            version=version,
                            publisher=publisher,
                            install_date="",
                            source="Portable",
                            install_location=str(exe_path.parent),
                        )
                        software_list.append(software)

                except (PermissionError, OSError):
                    continue

        except (PermissionError, OSError):
            pass

        return software_list

    def _find_executables(self, directory: Path, max_depth: int) -> list[Path]:
        """Find executable files in a directory up to a certain depth.

        Symlinks are skipped to prevent traversal attacks where a symlink
        could point to sensitive system locations outside the scan area.

        Uses os.scandir() for performance - DirEntry objects cache stat info
        from the directory listing, avoiding separate system calls for
        is_symlink(), is_file(), and is_dir() checks.
        """
        executables = []
        # Resolve the base directory to compare against for symlink validation
        base_resolved = directory.resolve()

        def scan_dir(path: Path, depth: int):
            if depth > max_depth:
                return

            try:
                # Use os.scandir() instead of Path.iterdir() for performance.
                # DirEntry objects cache file type info from the directory
                # listing itself, avoiding extra stat() calls per file.
                with os.scandir(path) as entries:
                    for entry in entries:
                        # DirEntry.is_symlink() uses cached info - no syscall
                        if entry.is_symlink():
                            continue

                        name = entry.name
                        # DirEntry.is_file() and is_dir() use cached info
                        if entry.is_file(follow_symlinks=False) and name.lower().endswith(".exe"):
                            # Verify the resolved path is still under the base directory
                            try:
                                item_path = Path(entry.path)
                                resolved = item_path.resolve()
                                if base_resolved in resolved.parents or resolved.parent == base_resolved:
                                    executables.append(item_path)
                            except (OSError, ValueError):
                                continue
                        elif entry.is_dir(follow_symlinks=False) and not name.startswith("."):
                            scan_dir(Path(entry.path), depth + 1)
            except (PermissionError, OSError):
                pass

        scan_dir(directory, 0)
        return executables

    def _should_skip_exe(self, exe_path: Path) -> bool:
        """Check if the executable should be skipped."""
        skip_names = [
            "uninstall", "uninst", "setup", "install", "update",
            "updater", "helper", "crash", "reporter", "launcher"
        ]
        exe_name = exe_path.stem.lower()
        return any(skip in exe_name for skip in skip_names)

    def _get_file_version(self, file_path: str) -> str:
        """Get the version of an executable file using Windows API."""
        try:
            size = ctypes.windll.version.GetFileVersionInfoSizeW(file_path, None)
            if size == 0:
                return ""

            buffer = ctypes.create_string_buffer(size)
            if not ctypes.windll.version.GetFileVersionInfoW(file_path, 0, size, buffer):
                return ""

            # Query for file version
            val_ptr = ctypes.c_void_p()
            val_size = ctypes.c_uint()

            if ctypes.windll.version.VerQueryValueW(
                buffer, "\\", ctypes.byref(val_ptr), ctypes.byref(val_size)
            ):
                if val_size.value:
                    # VS_FIXEDFILEINFO structure
                    class VS_FIXEDFILEINFO(ctypes.Structure):
                        _fields_ = [
                            ("dwSignature", ctypes.c_uint32),
                            ("dwStrucVersion", ctypes.c_uint32),
                            ("dwFileVersionMS", ctypes.c_uint32),
                            ("dwFileVersionLS", ctypes.c_uint32),
                            ("dwProductVersionMS", ctypes.c_uint32),
                            ("dwProductVersionLS", ctypes.c_uint32),
                            ("dwFileFlagsMask", ctypes.c_uint32),
                            ("dwFileFlags", ctypes.c_uint32),
                            ("dwFileOS", ctypes.c_uint32),
                            ("dwFileType", ctypes.c_uint32),
                            ("dwFileSubtype", ctypes.c_uint32),
                            ("dwFileDateMS", ctypes.c_uint32),
                            ("dwFileDateLS", ctypes.c_uint32),
                        ]

                    info = ctypes.cast(val_ptr, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
                    ms = info.dwFileVersionMS
                    ls = info.dwFileVersionLS

                    version = f"{(ms >> 16) & 0xFFFF}.{ms & 0xFFFF}.{(ls >> 16) & 0xFFFF}.{ls & 0xFFFF}"
                    return version

        except Exception:
            pass

        return ""

    def _get_file_publisher(self, file_path: str) -> str:
        """Get the publisher/company name from an executable file."""
        try:
            size = ctypes.windll.version.GetFileVersionInfoSizeW(file_path, None)
            if size == 0:
                return ""

            buffer = ctypes.create_string_buffer(size)
            if not ctypes.windll.version.GetFileVersionInfoW(file_path, 0, size, buffer):
                return ""

            # Try common language/codepage combinations
            lang_codepages = [
                "040904B0",  # US English, Unicode
                "040904E4",  # US English, Windows Multilingual
                "000004B0",  # Neutral, Unicode
            ]

            for lang_cp in lang_codepages:
                query = f"\\StringFileInfo\\{lang_cp}\\CompanyName"
                val_ptr = ctypes.c_void_p()
                val_size = ctypes.c_uint()

                if ctypes.windll.version.VerQueryValueW(
                    buffer, query, ctypes.byref(val_ptr), ctypes.byref(val_size)
                ):
                    if val_size.value:
                        return ctypes.wstring_at(val_ptr, val_size.value - 1)

        except Exception:
            pass

        return ""

    def get_all_portable_apps(self) -> list[SoftwareInfo]:
        """Get all portable applications from configured locations."""
        all_software = []
        seen_names = set()

        for location in self.scan_locations:
            software_list = self.scan_directory(location)
            for software in software_list:
                if software.name not in seen_names:
                    seen_names.add(software.name)
                    all_software.append(software)

        return all_software


class WingetUpdateChecker:
    """Checks for available software updates using winget."""

    def check_for_updates(self) -> list[UpdateInfo]:
        """Query winget for available updates."""
        updates = []

        try:
            # Run winget upgrade to get list of available updates
            cmd = [
                "winget", "upgrade",
                "--include-unknown",
                "--disable-interactivity",
                "--accept-source-agreements"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=subprocess.CREATE_NO_WINDOW,
                encoding='utf-8',
                errors='replace'
            )

            # Parse the output (winget outputs a table format)
            updates = self._parse_winget_output(result.stdout)

        except subprocess.TimeoutExpired:
            print("Warning: winget command timed out.")
        except FileNotFoundError:
            print("Warning: winget not found. Please ensure Windows Package Manager is installed.")
        except Exception:
            print("Warning: Failed to check for updates.")

        return updates

    def _parse_winget_output(self, output: str) -> list[UpdateInfo]:
        """Parse winget upgrade output into UpdateInfo objects."""
        updates = []
        lines = output.strip().split('\n')

        # Find the header line to determine column positions
        header_idx = -1
        for i, line in enumerate(lines):
            if 'Name' in line and 'Version' in line and 'Available' in line:
                header_idx = i
                break

        if header_idx == -1:
            return updates

        header_line = lines[header_idx]

        # Find column positions based on header
        name_pos = header_line.find('Name')
        id_pos = header_line.find('Id')
        version_pos = header_line.find('Version')
        available_pos = header_line.find('Available')
        source_pos = header_line.find('Source')

        if any(pos == -1 for pos in [name_pos, version_pos, available_pos]):
            return updates

        # Skip header and separator line
        data_start = header_idx + 1
        for line in lines[data_start:]:
            # Skip separator lines and empty lines
            if not line.strip() or line.startswith('-') or line.startswith('─'):
                continue

            # Skip footer lines (like "X upgrades available")
            line_lower = line.lower()
            if 'upgrades available' in line_lower or ('upgrade' in line_lower and 'available' in line_lower):
                continue

            try:
                # Extract fields based on column positions
                name = line[name_pos:id_pos].strip() if id_pos > name_pos else line[name_pos:version_pos].strip()
                winget_id = line[id_pos:version_pos].strip() if id_pos != -1 else ""
                current_version = line[version_pos:available_pos].strip()

                if source_pos != -1:
                    available_version = line[available_pos:source_pos].strip()
                else:
                    available_version = line[available_pos:].strip()

                # Skip if we don't have valid data
                if not name or not available_version or available_version == 'Unknown':
                    continue

                # Skip if current equals available (no update needed)
                if current_version == available_version:
                    continue

                updates.append(UpdateInfo(
                    name=name,
                    current_version=current_version,
                    available_version=available_version,
                    winget_id=winget_id,
                ))

            except (IndexError, ValueError):
                continue

        return updates

    def display_updates_table(self, updates: list[UpdateInfo]) -> None:
        """Display available updates as a formatted table."""
        if not updates:
            print("All software is up to date! (according to winget)")
            return

        # Calculate column widths
        headers = ["Name", "Current Version", "Available Version", "Winget ID"]
        col_widths = [len(h) for h in headers]

        for u in updates:
            col_widths[0] = max(col_widths[0], min(len(u.name), 40))
            col_widths[1] = max(col_widths[1], min(len(u.current_version), 20))
            col_widths[2] = max(col_widths[2], min(len(u.available_version), 20))
            col_widths[3] = max(col_widths[3], min(len(u.winget_id), 40))

        # Print header
        header_fmt = " | ".join(f"{{:<{w}}}" for w in col_widths)
        separator = "-+-".join("-" * w for w in col_widths)

        print(header_fmt.format(*headers))
        print(separator)

        # Print rows
        for u in updates:
            row = [
                sanitize_output(u.name)[:40],
                sanitize_output(u.current_version)[:20],
                sanitize_output(u.available_version)[:20],
                sanitize_output(u.winget_id)[:40],
            ]
            print(header_fmt.format(*row))

        print(f"\nTotal: {len(updates)} updates available.")
        print("\nTo update a specific package, run:")
        print("  winget upgrade <package-id>")
        print("\nTo update all packages, run:")
        print("  winget upgrade --all")


class BrowserExtensionScanner:
    """Scans for browser extensions across Chrome, Firefox, and Edge."""

    def __init__(self):
        self.local_app_data = os.environ.get("LOCALAPPDATA", "")
        self.app_data = os.environ.get("APPDATA", "")

    def get_all_extensions(self) -> list[BrowserExtensionInfo]:
        """Get all browser extensions from supported browsers."""
        extensions = []
        extensions.extend(self._scan_chrome_extensions())
        extensions.extend(self._scan_edge_extensions())
        extensions.extend(self._scan_firefox_extensions())
        return extensions

    def _scan_chrome_extensions(self) -> list[BrowserExtensionInfo]:
        """Scan Chrome extensions."""
        extensions = []
        chrome_base = Path(self.local_app_data) / "Google" / "Chrome" / "User Data"

        if not chrome_base.exists():
            return extensions

        # Scan Default profile and any numbered profiles
        profiles = ["Default"] + [f"Profile {i}" for i in range(1, 10)]

        for profile in profiles:
            extensions_dir = chrome_base / profile / "Extensions"
            if extensions_dir.exists():
                extensions.extend(
                    self._scan_chromium_extensions_dir(extensions_dir, "Chrome")
                )

        return extensions

    def _scan_edge_extensions(self) -> list[BrowserExtensionInfo]:
        """Scan Microsoft Edge extensions."""
        extensions = []
        edge_base = Path(self.local_app_data) / "Microsoft" / "Edge" / "User Data"

        if not edge_base.exists():
            return extensions

        profiles = ["Default"] + [f"Profile {i}" for i in range(1, 10)]

        for profile in profiles:
            extensions_dir = edge_base / profile / "Extensions"
            if extensions_dir.exists():
                extensions.extend(
                    self._scan_chromium_extensions_dir(extensions_dir, "Edge")
                )

        return extensions

    def _scan_chromium_extensions_dir(
        self, extensions_dir: Path, browser: str
    ) -> list[BrowserExtensionInfo]:
        """Scan a Chromium-based browser's extensions directory."""
        extensions = []

        try:
            for ext_id_dir in extensions_dir.iterdir():
                if not ext_id_dir.is_dir():
                    continue

                ext_id = ext_id_dir.name

                # Skip the Temp directory
                if ext_id.lower() == "temp":
                    continue

                # Find the latest version directory
                version_dirs = [d for d in ext_id_dir.iterdir() if d.is_dir()]
                if not version_dirs:
                    continue

                # Get the most recent version (by directory name)
                latest_version_dir = max(version_dirs, key=lambda d: d.name)
                manifest_path = latest_version_dir / "manifest.json"

                # Directly attempt to parse - _parse_chromium_manifest handles missing files
                ext_info = self._parse_chromium_manifest(
                    manifest_path, ext_id, browser
                )
                if ext_info:
                    extensions.append(ext_info)

        except (PermissionError, OSError):
            pass

        return extensions

    def _parse_chromium_manifest(
        self, manifest_path: Path, ext_id: str, browser: str
    ) -> Optional[BrowserExtensionInfo]:
        """Parse a Chromium extension's manifest.json file."""
        try:
            with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
                manifest = json.load(f)

            name = manifest.get("name", "Unknown")
            # Handle localized names (they start with __MSG_)
            if name.startswith("__MSG_"):
                name = self._get_localized_name(manifest_path.parent, name) or name

            version = manifest.get("version", "")
            description = manifest.get("description", "")
            if description.startswith("__MSG_"):
                description = ""  # Skip localized descriptions for simplicity

            # Gather permissions from multiple sources
            permissions = []
            permissions.extend(manifest.get("permissions", []))
            permissions.extend(manifest.get("host_permissions", []))
            permissions.extend(manifest.get("optional_permissions", []))

            # Get content script matches as well (these are effectively permissions)
            for content_script in manifest.get("content_scripts", []):
                permissions.extend(content_script.get("matches", []))

            return BrowserExtensionInfo(
                name=name,
                version=version,
                browser=browser,
                extension_id=ext_id,
                description=description[:100] if description else "",
                permissions=permissions,
            )

        except (json.JSONDecodeError, KeyError, OSError):
            return None

    def _get_localized_name(self, ext_dir: Path, msg_key: str) -> Optional[str]:
        """Try to get the localized name from _locales directory."""
        # Extract the message key (remove __MSG_ prefix and __ suffix)
        key = msg_key.replace("__MSG_", "").rstrip("_")

        # Try English locales first
        locale_dirs = ["en", "en_US", "en_GB"]

        for locale in locale_dirs:
            messages_path = ext_dir / "_locales" / locale / "messages.json"
            try:
                with open(messages_path, "r", encoding="utf-8") as f:
                    messages = json.load(f)
                # Try both lowercase and original case
                for k in [key, key.lower()]:
                    if k in messages and "message" in messages[k]:
                        return messages[k]["message"]
            except (json.JSONDecodeError, OSError):
                # File doesn't exist or can't be parsed - try next locale
                continue

        return None

    def _scan_firefox_extensions(self) -> list[BrowserExtensionInfo]:
        """Scan Firefox extensions."""
        extensions = []
        firefox_base = Path(self.app_data) / "Mozilla" / "Firefox" / "Profiles"

        if not firefox_base.exists():
            return extensions

        try:
            # Iterate through all Firefox profiles
            for profile_dir in firefox_base.iterdir():
                if not profile_dir.is_dir():
                    continue

                # Directly attempt to parse - _parse_firefox_extensions_json handles missing files
                extensions_json = profile_dir / "extensions.json"
                extensions.extend(
                    self._parse_firefox_extensions_json(extensions_json)
                )

        except (PermissionError, OSError):
            pass

        return extensions

    def _parse_firefox_extensions_json(
        self, extensions_json: Path
    ) -> list[BrowserExtensionInfo]:
        """Parse Firefox's extensions.json file."""
        extensions = []

        try:
            with open(extensions_json, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)

            for addon in data.get("addons", []):
                # Skip system/built-in addons
                if addon.get("location") in ["app-system-defaults", "app-builtin"]:
                    continue

                addon_type = addon.get("type", "")
                if addon_type != "extension":
                    continue

                name = addon.get("defaultLocale", {}).get("name", "")
                if not name:
                    name = addon.get("id", "Unknown")

                version = addon.get("version", "")
                ext_id = addon.get("id", "")
                description = addon.get("defaultLocale", {}).get("description", "")
                active = addon.get("active", True)

                # Firefox stores permissions differently
                permissions = addon.get("userPermissions", {}).get("permissions", [])
                origins = addon.get("userPermissions", {}).get("origins", [])
                permissions.extend(origins)

                extensions.append(BrowserExtensionInfo(
                    name=name,
                    version=version,
                    browser="Firefox",
                    extension_id=ext_id,
                    description=description[:100] if description else "",
                    permissions=permissions,
                    enabled=active,
                ))

        except (json.JSONDecodeError, KeyError, OSError):
            pass

        return extensions

    def display_extensions_table(
        self, extensions: list[BrowserExtensionInfo], show_all_permissions: bool = False
    ) -> None:
        """Display browser extensions as a formatted table."""
        if not extensions:
            print("No browser extensions found.")
            return

        # Sort by browser, then by name
        extensions = sorted(extensions, key=lambda e: (e.browser, e.name.lower()))

        # Calculate column widths
        headers = ["Name", "Version", "Browser", "Sensitive Perms", "Extension ID"]
        col_widths = [len(h) for h in headers]

        for e in extensions:
            col_widths[0] = max(col_widths[0], min(len(e.name), 35))
            col_widths[1] = max(col_widths[1], min(len(e.version), 15))
            col_widths[2] = max(col_widths[2], len(e.browser))
            col_widths[4] = max(col_widths[4], min(len(e.extension_id), 40))

        # Print header
        header_fmt = " | ".join(f"{{:<{w}}}" for w in col_widths)
        separator = "-+-".join("-" * w for w in col_widths)

        print(header_fmt.format(*headers))
        print(separator)

        # Count extensions with sensitive permissions
        sensitive_count = 0

        # Print rows
        for e in extensions:
            has_sensitive = e.has_sensitive_permissions()
            if has_sensitive:
                sensitive_count += 1

            sensitive_marker = "YES" if has_sensitive else "no"

            row = [
                sanitize_output(e.name)[:35],
                sanitize_output(e.version)[:15],
                e.browser,
                sensitive_marker,
                sanitize_output(e.extension_id)[:40],
            ]
            print(header_fmt.format(*row))

        print(f"\nTotal: {len(extensions)} extensions found.")
        if sensitive_count > 0:
            print(f"Warning: {sensitive_count} extension(s) have sensitive permissions.")
            print("\nSensitive permissions include: access to all websites, cookies,")
            print("browsing history, downloads, clipboard, and network requests.")


class VulnerabilityScanner:
    """Scans for known CVEs using the NIST NVD API."""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Software name mappings to improve CVE search accuracy
    # Maps common software names to their CPE vendor/product names
    SOFTWARE_MAPPINGS = {
        "google chrome": ("google", "chrome"),
        "mozilla firefox": ("mozilla", "firefox"),
        "firefox": ("mozilla", "firefox"),
        "microsoft edge": ("microsoft", "edge"),
        "vlc media player": ("videolan", "vlc_media_player"),
        "vlc": ("videolan", "vlc_media_player"),
        "7-zip": ("7-zip", "7-zip"),
        "notepad++": ("notepad-plus-plus", "notepad\\+\\+"),
        "python": ("python", "python"),
        "git": ("git-scm", "git"),
        "nodejs": ("nodejs", "node.js"),
        "node.js": ("nodejs", "node.js"),
        "java": ("oracle", "jre"),
        "openvpn": ("openvpn", "openvpn"),
        "putty": ("putty", "putty"),
        "wireshark": ("wireshark", "wireshark"),
        "filezilla": ("filezilla-project", "filezilla_client"),
        "obs studio": ("obsproject", "obs_studio"),
        "discord": ("discord", "discord"),
        "zoom": ("zoom", "zoom"),
        "steam": ("valvesoftware", "steam_client"),
        "spotify": ("spotify", "spotify"),
        "vscode": ("microsoft", "visual_studio_code"),
        "visual studio code": ("microsoft", "visual_studio_code"),
    }

    # Software to skip (system components, frameworks, etc.)
    SKIP_PATTERNS = [
        r"microsoft visual c\+\+",
        r"\.net framework",
        r"\.net runtime",
        r"windows sdk",
        r"sql server",
        r"redistributable",
        r"update for",
        r"hotfix",
        r"security update",
        r"service pack",
    ]

    def __init__(self, api_key: str = None):
        """Initialize scanner with optional NVD API key for higher rate limits.

        API key can be provided directly or via NVD_API_KEY environment variable.
        Direct parameter takes precedence over environment variable.
        """
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.request_count = 0
        self.last_request_time = 0

    def _rate_limit(self):
        """Implement rate limiting for NVD API (5 requests per 30 seconds without API key)."""
        if self.api_key:
            # With API key: 50 requests per 30 seconds
            min_interval = 0.6
        else:
            # Without API key: 5 requests per 30 seconds
            min_interval = 6.0

        elapsed = time.time() - self.last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)

        self.last_request_time = time.time()

    def _should_skip_software(self, name: str) -> bool:
        """Check if software should be skipped from vulnerability scanning."""
        name_lower = name.lower()
        return any(re.search(pattern, name_lower) for pattern in self.SKIP_PATTERNS)

    def _normalize_software_name(self, name: str) -> str:
        """Normalize software name for better CVE matching."""
        # Remove version numbers from the name
        name = re.sub(r'\s*\d+(\.\d+)*\s*', ' ', name)
        # Remove common suffixes
        name = re.sub(r'\s*\((x64|x86|64-bit|32-bit)\)\s*', '', name, flags=re.IGNORECASE)
        # Remove trailing/leading whitespace and normalize
        name = ' '.join(name.split()).lower()
        return name

    def _get_search_terms(self, software: SoftwareInfo) -> tuple[str, str]:
        """Get vendor and product search terms for a software."""
        name_lower = self._normalize_software_name(software.name)

        # Check if we have a known mapping
        for key, (vendor, product) in self.SOFTWARE_MAPPINGS.items():
            if key in name_lower:
                return vendor, product

        # Fall back to using the software name as both vendor and product keyword
        # Extract likely product name (first significant word)
        words = name_lower.split()
        if words:
            return "", words[0]

        return "", name_lower

    def _query_nvd_api(self, keyword: str, vendor: str = "") -> list[dict]:
        """Query the NVD API for CVEs matching a keyword."""
        self._rate_limit()

        params = {
            "resultsPerPage": 20,
            "keywordSearch": keyword,
        }

        if vendor:
            # Use CPE match string for more accurate results
            params["keywordSearch"] = f"{vendor} {keyword}"

        url = f"{self.NVD_API_URL}?{urllib.parse.urlencode(params)}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        }

        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))
                return data.get("vulnerabilities", [])
        except urllib.error.HTTPError as e:
            if e.code == 403:
                raise Exception("NVD API rate limit exceeded. Try again later or use an API key.")
            elif e.code == 404:
                raise Exception("NVD API endpoint not found.")
            else:
                raise Exception(f"NVD API request failed (HTTP {e.code}).")
        except urllib.error.URLError:
            raise Exception("Network error: Unable to reach NVD API.")

    def _parse_cve(self, vuln_data: dict) -> Optional[CVEInfo]:
        """Parse a CVE entry from NVD API response."""
        try:
            cve = vuln_data.get("cve", {})
            cve_id = cve.get("id", "")

            # Get description (English preferred)
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # Get CVSS score and severity
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"

            # Try CVSS 3.1 first, then 3.0, then 2.0
            for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if cvss_version in metrics and metrics[cvss_version]:
                    cvss_data = metrics[cvss_version][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    if cvss_version == "cvssMetricV2":
                        # CVSS 2.0 uses different severity names
                        severity = self._cvss2_to_severity(cvss_score)
                    break

            # Get published date
            published = cve.get("published", "")[:10]  # Just the date part

            # Get references (limit to 3)
            refs = cve.get("references", [])
            references = [r.get("url", "") for r in refs[:3]]

            return CVEInfo(
                cve_id=cve_id,
                description=description[:200] + "..." if len(description) > 200 else description,
                severity=severity.upper(),
                cvss_score=cvss_score,
                published_date=published,
                references=references,
            )
        except (KeyError, TypeError):
            return None

    def _cvss2_to_severity(self, score: float) -> str:
        """Convert CVSS 2.0 score to severity label."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "UNKNOWN"

    def _version_matches(self, cve_desc: str, installed_version: str) -> bool:
        """
        Basic heuristic to check if the CVE might apply to installed version.
        Returns True if we can't determine (conservative approach).
        """
        if not installed_version:
            return True  # Can't determine, assume it might apply

        # Extract version numbers mentioned in CVE description
        desc_versions = re.findall(r'(\d+\.\d+(?:\.\d+)*)', cve_desc.lower())

        if not desc_versions:
            return True  # No version mentioned, might apply

        # Simple check: if installed version is mentioned, it might apply
        installed_base = installed_version.split()[0]  # Remove build numbers etc
        for v in desc_versions:
            if installed_base.startswith(v) or v.startswith(installed_base.split('.')[0]):
                return True

        return True  # Conservative: assume it might apply

    def scan_software(self, software: SoftwareInfo) -> VulnerabilityResult:
        """Scan a single software for known CVEs."""
        result = VulnerabilityResult(
            software_name=software.name,
            software_version=software.version,
        )

        if self._should_skip_software(software.name):
            return result

        try:
            vendor, product = self._get_search_terms(software)
            vulnerabilities = self._query_nvd_api(product, vendor)

            for vuln in vulnerabilities:
                cve = self._parse_cve(vuln)
                if cve and cve.severity in ["CRITICAL", "HIGH", "MEDIUM"]:
                    result.cves.append(cve)

            # Sort by severity (CRITICAL first)
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
            result.cves.sort(key=lambda c: (severity_order.get(c.severity, 4), -c.cvss_score))

        except Exception as e:
            result.error = str(e)

        return result

    def scan_software_list(
        self, software_list: list[SoftwareInfo], progress_callback=None
    ) -> list[VulnerabilityResult]:
        """Scan a list of software for vulnerabilities."""
        results = []

        # Filter to scannable software
        scannable = [s for s in software_list if not self._should_skip_software(s.name)]

        # Limit to most important software to avoid excessive API calls
        # Prioritize by having a version number (more likely to be main apps)
        scannable = [s for s in scannable if s.version][:20]

        for i, software in enumerate(scannable):
            if progress_callback:
                progress_callback(i + 1, len(scannable), software.name)

            result = self.scan_software(software)
            if result.cves or result.error:
                results.append(result)

        return results

    def display_results(self, results: list[VulnerabilityResult]) -> None:
        """Display vulnerability scan results."""
        if not results:
            print("No vulnerabilities found in scanned software.")
            print("\nNote: This scan checks common software against the NVD database.")
            print("It may not cover all installed software or all vulnerabilities.")
            return

        total_cves = sum(r.total_count for r in results)
        critical_count = sum(r.critical_count for r in results)
        high_count = sum(r.high_count for r in results)

        print(f"{'='*80}")
        print(f"VULNERABILITY SCAN RESULTS")
        print(f"{'='*80}")
        print(f"Software scanned with potential vulnerabilities: {len(results)}")
        print(f"Total CVEs found: {total_cves}")
        print(f"  CRITICAL: {critical_count}")
        print(f"  HIGH: {high_count}")
        print(f"{'='*80}\n")

        for result in results:
            if result.error:
                print(f"[ERROR] {sanitize_output(result.software_name)}: Query failed")
                continue

            if not result.cves:
                continue

            print(f"\n{sanitize_output(result.software_name)} (v{sanitize_output(result.software_version)})")
            print(f"  Found {result.total_count} potential CVE(s):")

            for cve in result.cves[:5]:  # Show top 5 per software
                print(f"\n  {cve.severity_color} {cve.cve_id} (CVSS: {cve.cvss_score})")
                print(f"      Severity: {cve.severity}")
                print(f"      Published: {cve.published_date}")
                # Wrap description
                safe_desc = sanitize_output(cve.description)
                desc_lines = [safe_desc[i:i+60] for i in range(0, len(safe_desc), 60)]
                for line in desc_lines:
                    print(f"      {line}")

            if len(result.cves) > 5:
                print(f"\n  ... and {len(result.cves) - 5} more CVE(s)")

        print(f"\n{'='*80}")
        print("RECOMMENDATIONS:")
        print("  1. Update software to the latest versions")
        print("  2. Review critical/high severity CVEs for your specific versions")
        print("  3. Check vendor advisories for patches and mitigations")
        print("  4. Consider removing software that is no longer maintained")
        print(f"{'='*80}")
        print("\nNote: Results are based on keyword matching and may include")
        print("CVEs that don't apply to your specific version. Always verify")
        print("against official vendor advisories.")


class SoftwareEnumerator:
    """Main orchestrator for software enumeration."""

    def __init__(self):
        self.registry_scanner = RegistryScanner()
        self.store_scanner = StoreAppScanner()
        self.portable_scanner = PortableAppScanner()

    def scan_all(self, sources: list[str] = None, show_progress: bool = True) -> list[SoftwareInfo]:
        """Scan all or specified sources for installed software."""
        if sources is None:
            sources = ["registry", "store", "portable"]

        all_software = []
        total_sources = len(sources)
        current_source = 0

        if show_progress:
            progress = ProgressBar(total=total_sources, prefix="Scanning")

        if "registry" in sources:
            current_source += 1
            if show_progress:
                progress.update(current_source - 1, "Registry...")
            all_software.extend(self.registry_scanner.get_all_registry_software())
            if show_progress:
                progress.update(current_source, f"Registry: {len(all_software)} found")

        if "store" in sources:
            current_source += 1
            if show_progress:
                progress.update(current_source - 1, "Store apps...")
            store_apps = self.store_scanner.get_store_apps()
            all_software.extend(store_apps)
            if show_progress:
                progress.update(current_source, f"Store: {len(store_apps)} found")

        if "portable" in sources:
            current_source += 1
            if show_progress:
                progress.update(current_source - 1, "Portable apps...")
            portable_apps = self.portable_scanner.get_all_portable_apps()
            all_software.extend(portable_apps)
            if show_progress:
                progress.update(current_source, f"Portable: {len(portable_apps)} found")

        if show_progress:
            progress.finish(f"Complete: {len(all_software)} total")

        return all_software

    def filter_results(
        self, software_list: list[SoftwareInfo], search_term: str = None
    ) -> list[SoftwareInfo]:
        """Filter software list by search term."""
        if not search_term:
            return software_list
        return [s for s in software_list if s.matches_search(search_term)]

    def sort_results(
        self, software_list: list[SoftwareInfo], sort_by: str = "name"
    ) -> list[SoftwareInfo]:
        """Sort software list by specified field."""
        sort_keys = {
            "name": lambda s: s.name.lower(),
            "version": lambda s: s.version.lower(),
            "publisher": lambda s: s.publisher.lower(),
            "source": lambda s: s.source.lower(),
        }

        key_func = sort_keys.get(sort_by, sort_keys["name"])
        return sorted(software_list, key=key_func)

    def display_table(self, software_list: list[SoftwareInfo]) -> None:
        """Display software list as a formatted table."""
        if not software_list:
            print("No software found.")
            return

        # Calculate column widths
        headers = ["Name", "Version", "Publisher", "Source", "Install Date"]
        col_widths = [len(h) for h in headers]

        for s in software_list:
            col_widths[0] = max(col_widths[0], min(len(s.name), 50))
            col_widths[1] = max(col_widths[1], min(len(s.version), 20))
            col_widths[2] = max(col_widths[2], min(len(s.publisher), 30))
            col_widths[3] = max(col_widths[3], len(s.source))
            col_widths[4] = max(col_widths[4], len(s.install_date))

        # Print header
        header_fmt = " | ".join(f"{{:<{w}}}" for w in col_widths)
        separator = "-+-".join("-" * w for w in col_widths)

        print(header_fmt.format(*headers))
        print(separator)

        # Print rows
        for s in software_list:
            row = [
                sanitize_output(s.name)[:50],
                sanitize_output(s.version)[:20],
                sanitize_output(s.publisher)[:30],
                s.source,
                s.install_date,
            ]
            print(header_fmt.format(*row))

        print(f"\nTotal: {len(software_list)} software items found.")


class SoftwareExporter:
    """Handles exporting software lists to various formats."""

    @staticmethod
    def _sanitize_software_dict(software: SoftwareInfo) -> dict:
        """Convert SoftwareInfo to dict with sanitized string fields."""
        return {
            "name": sanitize_output(software.name),
            "version": sanitize_output(software.version),
            "publisher": sanitize_output(software.publisher),
            "install_date": software.install_date,
            "source": software.source,
            "install_location": sanitize_output(software.install_location),
        }

    @staticmethod
    def to_json(software_list: list[SoftwareInfo], pretty: bool = True) -> str:
        """Export software list to JSON format.

        Args:
            software_list: List of SoftwareInfo objects
            pretty: If True, format with indentation

        Returns:
            JSON string representation
        """
        data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "hostname": os.environ.get("COMPUTERNAME", "unknown"),
                "user": getpass.getuser(),
                "total_count": len(software_list),
            },
            "software": [SoftwareExporter._sanitize_software_dict(s) for s in software_list]
        }
        if pretty:
            return json.dumps(data, indent=2, ensure_ascii=False)
        return json.dumps(data, ensure_ascii=False)

    @staticmethod
    def to_csv(software_list: list[SoftwareInfo]) -> str:
        """Export software list to CSV format.

        Args:
            software_list: List of SoftwareInfo objects

        Returns:
            CSV string representation
        """
        output = io.StringIO()
        fieldnames = ["name", "version", "publisher", "install_date", "source", "install_location"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for software in software_list:
            writer.writerow({
                "name": sanitize_output(software.name),
                "version": sanitize_output(software.version),
                "publisher": sanitize_output(software.publisher),
                "install_date": software.install_date,
                "source": software.source,
                "install_location": sanitize_output(software.install_location),
            })

        return output.getvalue()

    @staticmethod
    def export(software_list: list[SoftwareInfo], format: str, output_file: str = None) -> None:
        """Export software list to specified format.

        Args:
            software_list: List of SoftwareInfo objects
            format: Output format ('json', 'csv', 'table')
            output_file: Optional file path to write to (prints to stdout if None)
        """
        if format == "json":
            content = SoftwareExporter.to_json(software_list)
        elif format == "csv":
            content = SoftwareExporter.to_csv(software_list)
        else:
            raise ValueError(f"Unsupported format: {format}")

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
            log_audit_event("EXPORT", f"Exported to {format}", file=output_file, count=len(software_list))
        else:
            print(content)


@dataclass
class BaselineDiff:
    """Represents differences between current state and baseline."""
    added: list[SoftwareInfo] = field(default_factory=list)
    removed: list[SoftwareInfo] = field(default_factory=list)
    changed: list[tuple[SoftwareInfo, SoftwareInfo]] = field(default_factory=list)  # (baseline, current)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.removed) + len(self.changed)


class BaselineManager:
    """Manages software baselines for change detection."""

    BASELINE_VERSION = "1.0"

    @staticmethod
    def save_baseline(software_list: list[SoftwareInfo], filepath: str, sources: list[str] = None) -> None:
        """Save current software state as a baseline.

        Args:
            software_list: Current list of installed software
            filepath: Path to save baseline file
            sources: List of sources used (e.g., ["registry", "store", "portable"])
        """
        baseline = {
            "version": BaselineManager.BASELINE_VERSION,
            "created_at": datetime.now().isoformat(),
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
            "user": getpass.getuser(),
            "sources": sources or [],
            "software_count": len(software_list),
            "software": [asdict(s) for s in software_list]
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2, ensure_ascii=False)

        log_audit_event("BASELINE_SAVE", f"Baseline saved", file=filepath, count=len(software_list))

    @staticmethod
    def load_baseline(filepath: str) -> tuple[list[SoftwareInfo], dict]:
        """Load a baseline from file.

        Args:
            filepath: Path to baseline file

        Returns:
            Tuple of (software_list, metadata)

        Raises:
            FileNotFoundError: If baseline file doesn't exist
            ValueError: If baseline format is invalid or incompatible version
        """
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "version" not in data or "software" not in data:
            raise ValueError("Invalid baseline format: missing required fields")

        # Validate baseline version compatibility
        baseline_version = data.get("version", "")
        if not baseline_version.startswith("1."):
            raise ValueError(
                f"Incompatible baseline version: {baseline_version}. "
                f"Expected version 1.x, got {baseline_version}. "
                f"Please create a new baseline with the current tool version."
            )

        software_list = []
        for item in data["software"]:
            software_list.append(SoftwareInfo(
                name=item.get("name", ""),
                version=item.get("version", ""),
                publisher=item.get("publisher", ""),
                install_date=item.get("install_date", ""),
                source=item.get("source", ""),
                install_location=item.get("install_location", ""),
            ))

        metadata = {
            "version": data.get("version"),
            "created_at": data.get("created_at"),
            "hostname": data.get("hostname"),
            "user": data.get("user"),
            "sources": data.get("sources", []),
            "software_count": data.get("software_count"),
        }

        return software_list, metadata

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize a software name for comparison.

        Handles unicode normalization to prevent false positives from
        different encodings of the same character (e.g., ™ vs TM).
        """
        # Normalize unicode to NFC form (canonical composition)
        normalized = unicodedata.normalize('NFC', name)
        # Case-insensitive comparison
        return normalized.lower()

    @staticmethod
    def compare(baseline: list[SoftwareInfo], current: list[SoftwareInfo]) -> BaselineDiff:
        """Compare current software state against baseline.

        Args:
            baseline: Baseline software list
            current: Current software list

        Returns:
            BaselineDiff object with added, removed, and changed software
        """
        diff = BaselineDiff()

        # Create lookup dictionaries by normalized name (case-insensitive, unicode-normalized)
        baseline_by_name = {BaselineManager._normalize_name(s.name): s for s in baseline}
        current_by_name = {BaselineManager._normalize_name(s.name): s for s in current}

        # Find added software (in current but not in baseline)
        for name, software in current_by_name.items():
            if name not in baseline_by_name:
                diff.added.append(software)

        # Find removed software (in baseline but not in current)
        for name, software in baseline_by_name.items():
            if name not in current_by_name:
                diff.removed.append(software)

        # Find changed software (same name, different version)
        for name, current_software in current_by_name.items():
            if name in baseline_by_name:
                baseline_software = baseline_by_name[name]
                if current_software.version != baseline_software.version:
                    diff.changed.append((baseline_software, current_software))

        # Sort results by name for consistent output
        diff.added.sort(key=lambda s: s.name.lower())
        diff.removed.sort(key=lambda s: s.name.lower())
        diff.changed.sort(key=lambda t: t[0].name.lower())

        return diff

    @staticmethod
    def display_diff(diff: BaselineDiff, baseline_metadata: dict) -> None:
        """Display baseline comparison results.

        Args:
            diff: BaselineDiff object
            baseline_metadata: Metadata from the baseline file
        """
        print("=" * 70)
        print("BASELINE COMPARISON RESULTS")
        print("=" * 70)
        print(f"Baseline created: {baseline_metadata.get('created_at', 'unknown')}")
        print(f"Baseline host: {baseline_metadata.get('hostname', 'unknown')}")
        print(f"Baseline software count: {baseline_metadata.get('software_count', 'unknown')}")
        print("=" * 70)

        if not diff.has_changes:
            print("\nNo changes detected. System matches baseline.")
            return

        print(f"\nTotal changes: {diff.total_changes}")
        print(f"  Added: {len(diff.added)}")
        print(f"  Removed: {len(diff.removed)}")
        print(f"  Version changed: {len(diff.changed)}")

        if diff.added:
            print("\n" + "-" * 70)
            print("[+] ADDED SOFTWARE (not in baseline)")
            print("-" * 70)
            for software in diff.added:
                print(f"  + {sanitize_output(software.name)}")
                if software.version:
                    print(f"      Version: {sanitize_output(software.version)}")
                if software.publisher:
                    print(f"      Publisher: {sanitize_output(software.publisher)}")
                print(f"      Source: {software.source}")

        if diff.removed:
            print("\n" + "-" * 70)
            print("[-] REMOVED SOFTWARE (was in baseline)")
            print("-" * 70)
            for software in diff.removed:
                print(f"  - {sanitize_output(software.name)}")
                if software.version:
                    print(f"      Version: {sanitize_output(software.version)}")
                if software.publisher:
                    print(f"      Publisher: {sanitize_output(software.publisher)}")

        if diff.changed:
            print("\n" + "-" * 70)
            print("[~] VERSION CHANGES")
            print("-" * 70)
            for baseline_sw, current_sw in diff.changed:
                print(f"  ~ {sanitize_output(current_sw.name)}")
                print(f"      {sanitize_output(baseline_sw.version)} -> {sanitize_output(current_sw.version)}")

        print("\n" + "=" * 70)

        # Security warnings
        if diff.added:
            print("\nWARNING: New software detected. Verify these installations are authorized.")
        if diff.removed:
            print("\nNOTE: Software has been removed since baseline was created.")


def main():
    """Main entry point for the CLI."""
    setup_console_encoding()

    parser = argparse.ArgumentParser(
        description="Enumerate installed software on Windows 11 for security auditing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          List all installed software
  %(prog)s --source registry        List only registry-based software
  %(prog)s --source store           List only Microsoft Store apps
  %(prog)s --source portable        List only portable applications
  %(prog)s --search chrome          Search for software containing 'chrome'
  %(prog)s --sort publisher         Sort results by publisher
  %(prog)s --output json            Output as JSON
  %(prog)s --output csv > list.csv  Export to CSV file
  %(prog)s --save-baseline base.json  Save current state as baseline
  %(prog)s --diff base.json         Compare against baseline
  %(prog)s --check-updates          Check for available updates via winget
  %(prog)s --extensions             List browser extensions (Chrome, Edge, Firefox)
  %(prog)s --check-vulns            Check for known CVEs in installed software
        """,
    )

    parser.add_argument(
        "--source",
        choices=["registry", "store", "portable", "all"],
        default="all",
        help="Source to scan (default: all)",
    )

    parser.add_argument(
        "--search",
        type=str,
        help="Search/filter results by name, publisher, or version",
    )

    parser.add_argument(
        "--sort",
        choices=["name", "version", "publisher", "source"],
        default="name",
        help="Sort results by field (default: name)",
    )

    parser.add_argument(
        "--output", "-o",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )

    parser.add_argument(
        "--save-baseline",
        type=str,
        metavar="FILE",
        help="Save current software state as a baseline JSON file",
    )

    parser.add_argument(
        "--diff",
        type=str,
        metavar="FILE",
        help="Compare current state against a baseline file",
    )

    parser.add_argument(
        "--check-updates",
        action="store_true",
        help="Check for available updates using winget",
    )

    parser.add_argument(
        "--extensions",
        action="store_true",
        help="List browser extensions (Chrome, Edge, Firefox)",
    )

    parser.add_argument(
        "--check-vulns",
        action="store_true",
        help="Check for known CVEs in installed software (queries NVD database)",
    )

    parser.add_argument(
        "--nvd-api-key",
        type=str,
        help="NVD API key for faster vulnerability scanning (optional)",
    )

    parser.add_argument(
        "--log-file",
        type=str,
        help="Path to audit log file (enables detailed logging)",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging (includes debug information)",
    )

    args = parser.parse_args()

    # Setup logging before any operations
    setup_logging(log_file=args.log_file, verbose=args.verbose)

    # Log session start
    log_audit_event(
        "SESSION_START",
        "Software enumeration session started",
        user=getpass.getuser(),
        hostname=os.environ.get("COMPUTERNAME", "unknown"),
    )

    # Handle update checking mode
    if args.check_updates:
        log_audit_event("SCAN_START", "Update check via winget", mode="check-updates")
        spinner = Spinner("Checking for updates via winget")
        spinner.spin()

        update_checker = WingetUpdateChecker()
        updates = update_checker.check_for_updates()

        spinner.finish(f"Found {len(updates)} available updates")
        log_audit_event("SCAN_END", "Update check completed", updates_found=len(updates))
        print()
        update_checker.display_updates_table(updates)
        return

    # Handle browser extensions mode
    if args.extensions:
        log_audit_event("SCAN_START", "Browser extension scan", mode="extensions")
        spinner = Spinner("Scanning browser extensions")
        spinner.spin("Chrome, Edge, Firefox...")

        extension_scanner = BrowserExtensionScanner()
        extensions = extension_scanner.get_all_extensions()

        spinner.finish(f"Found {len(extensions)} extensions")
        sensitive_count = sum(1 for e in extensions if e.has_sensitive_permissions())
        log_audit_event(
            "SCAN_END",
            "Browser extension scan completed",
            extensions_found=len(extensions),
            sensitive_permissions=sensitive_count,
        )
        print()
        extension_scanner.display_extensions_table(extensions)
        return

    # Handle vulnerability scanning mode
    if args.check_vulns:
        log_audit_event("SCAN_START", "Vulnerability scan via NVD", mode="check-vulns")
        print("Scanning for known vulnerabilities (CVEs)...")
        print("This may take a while due to API rate limits.\n")

        # First, enumerate software from registry (most reliable source)
        enumerator = SoftwareEnumerator()
        software_list = enumerator.scan_all(["registry"], show_progress=True)
        print()

        # Filter to scannable software for progress bar
        vuln_scanner = VulnerabilityScanner(api_key=args.nvd_api_key)
        scannable = [s for s in software_list if not vuln_scanner._should_skip_software(s.name)]
        scannable = [s for s in scannable if s.version][:20]

        progress = ProgressBar(total=len(scannable), prefix="CVE Check")

        def progress_callback(current, total, name):
            progress.update(current, name)
            logger.debug(f"Scanning for CVEs: {name}")

        results = vuln_scanner.scan_software_list(software_list, progress_callback=progress_callback)
        progress.finish("Complete")

        total_cves = sum(r.total_count for r in results)
        critical_count = sum(r.critical_count for r in results)
        log_audit_event(
            "SCAN_END",
            "Vulnerability scan completed",
            software_scanned=len(scannable),
            cves_found=total_cves,
            critical_cves=critical_count,
        )

        print()
        vuln_scanner.display_results(results)
        return

    # Determine sources to scan
    if args.source == "all":
        sources = ["registry", "store", "portable"]
    else:
        sources = [args.source]

    # Run enumeration
    log_audit_event(
        "SCAN_START",
        "Software enumeration",
        mode="enumerate",
        sources=",".join(sources),
        search_filter=args.search or "none",
    )

    enumerator = SoftwareEnumerator()
    # Suppress progress output if outputting to JSON/CSV (for clean piping)
    show_progress = args.output == "table" and not args.diff
    software_list = enumerator.scan_all(sources, show_progress=show_progress)
    software_list = enumerator.filter_results(software_list, args.search)
    software_list = enumerator.sort_results(software_list, args.sort)

    log_audit_event(
        "SCAN_END",
        "Software enumeration completed",
        total_software=len(software_list),
    )

    # Handle baseline diff mode
    if args.diff:
        try:
            baseline_list, baseline_metadata = BaselineManager.load_baseline(args.diff)

            # Warn if sources don't match
            baseline_sources = set(baseline_metadata.get("sources", []))
            current_sources = set(sources)
            if baseline_sources and baseline_sources != current_sources:
                print("WARNING: Source mismatch detected!", file=sys.stderr)
                print(f"  Baseline sources: {', '.join(sorted(baseline_sources)) or 'unknown'}", file=sys.stderr)
                print(f"  Current sources:  {', '.join(sorted(current_sources))}", file=sys.stderr)
                print("  Results may include false positives. Consider using matching --source options.", file=sys.stderr)
                print(file=sys.stderr)

            diff = BaselineManager.compare(baseline_list, software_list)

            log_audit_event(
                "BASELINE_DIFF",
                "Baseline comparison completed",
                baseline_file=args.diff,
                added=len(diff.added),
                removed=len(diff.removed),
                changed=len(diff.changed),
            )

            # Output diff in requested format
            if args.output == "json":
                diff_data = {
                    "metadata": {
                        "generated_at": datetime.now().isoformat(),
                        "baseline_file": args.diff,
                        "baseline_created": baseline_metadata.get("created_at"),
                        "baseline_hostname": baseline_metadata.get("hostname"),
                    },
                    "summary": {
                        "added_count": len(diff.added),
                        "removed_count": len(diff.removed),
                        "changed_count": len(diff.changed),
                        "total_changes": diff.total_changes,
                    },
                    "added": [asdict(s) for s in diff.added],
                    "removed": [asdict(s) for s in diff.removed],
                    "changed": [
                        {"baseline": asdict(b), "current": asdict(c)}
                        for b, c in diff.changed
                    ],
                }
                print(json.dumps(diff_data, indent=2, ensure_ascii=False))
            elif args.output == "csv":
                # CSV diff format: change_type, name, baseline_version, current_version
                output = io.StringIO()
                writer = csv.writer(output, quoting=csv.QUOTE_ALL)
                writer.writerow(["change_type", "name", "baseline_version", "current_version", "publisher", "source"])

                for s in diff.added:
                    writer.writerow(["added", s.name, "", s.version, s.publisher, s.source])
                for s in diff.removed:
                    writer.writerow(["removed", s.name, s.version, "", s.publisher, s.source])
                for b, c in diff.changed:
                    writer.writerow(["changed", c.name, b.version, c.version, c.publisher, c.source])

                print(output.getvalue())
            else:
                BaselineManager.display_diff(diff, baseline_metadata)

        except FileNotFoundError:
            print(f"Error: Baseline file not found: {args.diff}", file=sys.stderr)
            sys.exit(1)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error: Invalid baseline file: {e}", file=sys.stderr)
            sys.exit(1)

        return

    # Handle save baseline
    if args.save_baseline:
        if not software_list:
            print("WARNING: No software found to save in baseline!", file=sys.stderr)
            print("The baseline will be empty. This may not be intended.", file=sys.stderr)
            print("Check your --source and --search options.", file=sys.stderr)

        BaselineManager.save_baseline(software_list, args.save_baseline, sources=sources)
        print(f"Baseline saved to: {args.save_baseline}")
        print(f"Software count: {len(software_list)}")
        print(f"Sources: {', '.join(sources)}")
        return

    # Output in requested format
    if args.output == "json":
        SoftwareExporter.export(software_list, "json")
    elif args.output == "csv":
        SoftwareExporter.export(software_list, "csv")
    else:
        enumerator.display_table(software_list)


if __name__ == "__main__":
    main()
