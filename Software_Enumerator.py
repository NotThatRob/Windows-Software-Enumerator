"""
Software Enumerator - Windows 11 Software Auditing Tool

Enumerates installed software from multiple sources:
- Windows Registry (traditional Win32 programs)
- Microsoft Store Apps (UWP/MSIX)
- Portable Applications (common locations)
"""

import argparse
import collections
import concurrent.futures
import csv
import ctypes
from ctypes import wintypes
import functools
import getpass
import io
import json
import logging
from logging.handlers import RotatingFileHandler
import msvcrt
import os
import re
import stat
import subprocess
import sys
import time
import types
import unicodedata
import urllib.request
import urllib.parse
import urllib.error
import winreg
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# Module-level logger
logger = logging.getLogger("software_enumerator")

# Exit codes for scripting/CI-CD integration
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_NO_SOFTWARE = 2
EXIT_API_FAILURE = 3
EXIT_PERMISSION_DENIED = 4


def setup_console_encoding():
    """Configure console for UTF-8 output on Windows."""
    if sys.platform == "win32":
        try:
            # Set console output to UTF-8
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, OSError):
            pass


# --- Executable resolution -----------------------------------------------
# Never launch a program by bare name: Windows searches the current directory before
# PATH, so a planted powershell.exe / winget.exe in the folder the tool is run from
# would execute instead of the real one.

def _system_dir() -> Path:
    """Return the Windows System32 directory as reported by the OS.

    Uses GetSystemDirectoryW rather than %SystemRoot%, which the parent process controls.
    """
    size = 260
    while True:
        buf = ctypes.create_unicode_buffer(size)
        length = ctypes.windll.kernel32.GetSystemDirectoryW(buf, size)
        if length == 0:
            raise OSError("GetSystemDirectoryW failed")
        if length < size:
            return Path(buf.value)
        size = length + 1  # buffer too small; length is the size needed


def _powershell_path() -> Path:
    """Absolute path of Windows PowerShell 5.1 (ships with every Windows 10/11)."""
    return _system_dir() / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def _winget_path() -> Optional[Path]:
    """Absolute path of winget, or None if it isn't installed for this user.

    winget is an app-execution alias (a 0-byte reparse point) that App Installer
    creates in %LOCALAPPDATA%\\Microsoft\\WindowsApps; it runs fine by absolute path.
    There is deliberately no fallback to the bare name.
    """
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        return None
    path = Path(local_app_data) / "Microsoft" / "WindowsApps" / "winget.exe"
    return path if path.is_file() else None


def _harden_process_environment() -> None:
    """Defence in depth: stop Windows searching the current directory for executables,
    for any subprocess this tool (or its children) starts. Leaves an existing value alone."""
    os.environ.setdefault("NoDefaultCurrentDirectoryInExePath", "1")


# Only these keys are read from env files. Anything else (e.g. HTTPS_PROXY or
# SSL_CERT_FILE, which Python's HTTPS stack honours) is ignored, so an env file
# can't redirect or intercept the tool's network traffic.
_ENV_FILE_ALLOWED_KEYS = frozenset({"NVD_API_KEY"})
_ENV_FILENAMES = ("api.env", ".env")


def _env_search_dirs() -> list[Path]:
    """Folders searched for api.env / .env: only the tool's own folder.

    That is the folder of Software_Enumerator.py, or of the .exe for PyInstaller
    builds (whose __file__ points into a temporary extraction folder). The current
    working directory is deliberately not searched: anyone who can drop a file
    where the tool is run from could otherwise configure it.
    """
    if _running_as_frozen_exe():
        return [Path(sys.executable).resolve().parent]
    return [Path(__file__).resolve().parent]


def _load_env_file() -> None:
    """Load NVD_API_KEY from api.env or .env in the tool's own folder.

    - Only keys in _ENV_FILE_ALLOWED_KEYS are read; others are ignored and logged
      by name (never by value) at debug level.
    - Never overwrites a variable that is already set, so explicit env vars and
      CLI args take precedence (CLI > env var > file).
    - Stops after the first file found (api.env before .env).
    """
    for search_dir in _env_search_dirs():
        for filename in _ENV_FILENAMES:
            env_path = search_dir / filename
            try:
                if not env_path.is_file():
                    continue
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        # Skip comments and blank lines
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        key, _, value = line.partition("=")
                        key = key.strip().upper()  # Windows env var names are case-insensitive
                        if key not in _ENV_FILE_ALLOWED_KEYS:
                            if key:
                                logger.debug(f"Ignored {key!r} in {env_path.name}: only "
                                             f"{', '.join(sorted(_ENV_FILE_ALLOWED_KEYS))} is read from env files")
                            continue
                        if key not in os.environ:
                            os.environ[key] = value.strip().strip("'\"")
                logger.debug(f"Loaded env file: {env_path}")
                return  # Stop after first file found
            except (OSError, UnicodeDecodeError) as e:
                logger.debug(f"Could not read {env_path}: {e}")


# Owner-only DACL for log files, as SDDL: "P" = protected (no entries inherited from the
# folder); full access ("FA") for the file's owner ("OW", OWNER RIGHTS S-1-3-4) and SYSTEM ("SY").
# The whole DACL is replaced, so pre-existing explicit entries (e.g. Everyone:Read) go too.
_OWNER_ONLY_SDDL = "D:P(A;;FA;;;OW)(A;;FA;;;SY)"
_SDDL_REVISION_1 = 1
_OWNER_SECURITY_INFORMATION = 0x1
_DACL_SECURITY_INFORMATION = 0x4
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SE_FILE_OBJECT = 1
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_TOKEN_OWNER = 4
_GENERIC_WRITE = 0x40000000
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_FILE_READ_ATTRIBUTES = 0x0080
_LOG_FILE_ACCESS = _GENERIC_WRITE | _WRITE_DAC | _FILE_READ_ATTRIBUTES
_PROBE_ACCESS = _READ_CONTROL | _FILE_READ_ATTRIBUTES
# No FILE_SHARE_DELETE: while the log is open nobody can delete or rename it, or rename
# its folder, so it can't be swapped for another file (e.g. via a directory junction).
_FILE_SHARE_READ_WRITE = 0x3
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000  # open a symlink itself instead of following it
_FILE_PERSISTENT_ACLS = 0x00000008
_ERROR_FILE_NOT_FOUND = 2
_ERROR_ACCESS_DENIED = 5
_ERROR_FILE_EXISTS = 80
_INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
# Owners that can already read every file on the machine, so a log they own leaks nothing new
_ALWAYS_TRUSTED_OWNER_SIDS = frozenset({"S-1-5-18", "S-1-5-32-544"})  # SYSTEM, Administrators


class LogFileOwnershipError(PermissionError):
    """Refusing to write a log file another account could read: it is owned by another
    account, is a symbolic link, or has other hard links."""


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


@functools.lru_cache(maxsize=None)
def _win32() -> types.SimpleNamespace:
    """Win32 security functions with argtypes set, on private DLL handles so the
    shared ctypes.windll objects used elsewhere are left untouched."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    pp = ctypes.POINTER(ctypes.c_void_p)

    def bind(fn, argtypes, restype):
        fn.argtypes, fn.restype = argtypes, restype
        return fn

    return types.SimpleNamespace(
        string_to_sd=bind(advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW,
                          [wintypes.LPCWSTR, wintypes.DWORD, pp, ctypes.c_void_p], wintypes.BOOL),
        sid_to_string=bind(advapi32.ConvertSidToStringSidW,
                           [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)], wintypes.BOOL),
        get_sd_dacl=bind(advapi32.GetSecurityDescriptorDacl,
                         [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), pp, ctypes.POINTER(wintypes.BOOL)],
                         wintypes.BOOL),
        set_security_info=bind(advapi32.SetSecurityInfo,
                               [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], wintypes.DWORD),
        get_volume_information=bind(kernel32.GetVolumeInformationByHandleW,
                                    [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD,
                                     ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                                     ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD],
                                    wintypes.BOOL),
        get_security_info=bind(advapi32.GetSecurityInfo,
                               [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, pp, pp, pp, pp, pp],
                               wintypes.DWORD),
        open_process_token=bind(advapi32.OpenProcessToken,
                                [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)],
                                wintypes.BOOL),
        get_token_information=bind(advapi32.GetTokenInformation,
                                   [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
        get_current_process=bind(kernel32.GetCurrentProcess, [], wintypes.HANDLE),
        create_file=bind(kernel32.CreateFileW,
                         [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                          wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE),
        close_handle=bind(kernel32.CloseHandle, [wintypes.HANDLE], wintypes.BOOL),
        local_free=bind(kernel32.LocalFree, [ctypes.c_void_p], ctypes.c_void_p),
    )


def _owner_only_descriptor() -> ctypes.c_void_p:
    """Build the owner-only security descriptor. The caller must LocalFree() it."""
    descriptor = ctypes.c_void_p()
    if not _win32().string_to_sd(_OWNER_ONLY_SDDL, _SDDL_REVISION_1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return descriptor


def _restrict_handle_to_owner(handle) -> None:
    """Replace an open file's access list with owner + SYSTEM only, protected from
    inheritance. Raises OSError on failure.

    os.chmod(path, 0o600) can't do this on Windows: it only toggles the read-only flag.
    Working on the handle (not the path) guarantees it applies to the file being written.
    """
    api = _win32()
    descriptor = _owner_only_descriptor()
    try:
        present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        if not api.get_sd_dacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        error = api.set_security_info(handle, _SE_FILE_OBJECT,
                                      _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
                                      None, None, dacl, None)
        if error:
            raise ctypes.WinError(error)
    finally:
        api.local_free(descriptor)


def _volume_supports_acls(handle) -> bool:
    """True if the file's drive stores access lists (NTFS/ReFS do; FAT32/exFAT don't, and
    silently ignore the access list requested when a file is created there)."""
    flags = wintypes.DWORD()
    if not _win32().get_volume_information(handle, None, 0, None, None, ctypes.byref(flags), None, 0):
        return False  # can't tell: treat as unprotected so the user is warned
    return bool(flags.value & _FILE_PERSISTENT_ACLS)


def _create_file_handle(path: str, access: int, disposition: int, flags: int,
                        descriptor=None) -> tuple:
    """CreateFileW wrapper. Returns (handle, 0) on success, or (None, Windows error code)."""
    attributes = None
    if descriptor is not None:
        security = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        attributes = ctypes.byref(security)
    handle = _win32().create_file(path, access, _FILE_SHARE_READ_WRITE, attributes, disposition, flags, None)
    if handle == _INVALID_HANDLE_VALUE:
        return None, ctypes.get_last_error()
    return handle, 0


def _open_log_handle(path: str) -> tuple:
    """Open the log file and return (handle, created). The caller writes through this
    handle, so the file is never reopened by name.

    - New file: CreateFileW(CREATE_NEW) with the owner-only access list, so it is protected
      from the instant it exists. CREATE_NEW never opens an existing file.
    - Existing file: CreateFileW(OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT), so a symlink
      at the path is opened as itself (and then refused) rather than followed.

    Raises LogFileOwnershipError if access is denied because another account owns the
    file, or OSError (e.g. PermissionError) for other failures.
    """
    for _ in range(3):  # retry if the file appears or disappears between the two calls
        descriptor = _owner_only_descriptor()
        try:
            handle, error = _create_file_handle(path, _LOG_FILE_ACCESS, _CREATE_NEW,
                                                _FILE_ATTRIBUTE_NORMAL, descriptor)
        finally:
            _win32().local_free(descriptor)
        if handle is not None:
            return handle, True
        if error != _ERROR_FILE_EXISTS:
            raise ctypes.WinError(error)

        handle, error = _create_file_handle(path, _LOG_FILE_ACCESS, _OPEN_EXISTING,
                                            _FILE_FLAG_OPEN_REPARSE_POINT)
        if handle is not None:
            return handle, False
        if error == _ERROR_FILE_NOT_FOUND:
            continue
        if error == _ERROR_ACCESS_DENIED:
            _raise_if_owned_by_another_account(path)
        raise ctypes.WinError(error)
    raise OSError(f"Log file {path} kept changing while it was being opened")


def _raise_if_owned_by_another_account(path: str) -> None:
    """After an access-denied open: raise LogFileOwnershipError if another account owns
    the file, so the user gets that explanation rather than a bare permission error."""
    handle, _ = _create_file_handle(path, _PROBE_ACCESS, _OPEN_EXISTING, _FILE_FLAG_OPEN_REPARSE_POINT)
    if handle is None:
        return
    try:
        owner = _handle_owner_sid(handle)
        trusted = _trusted_owner_sids()
    except OSError:
        return
    finally:
        _win32().close_handle(handle)
    if owner is not None and owner not in trusted:
        raise LogFileOwnershipError(_foreign_owner_message(path))


def _sid_to_string(psid) -> str:
    api = _win32()
    text = wintypes.LPWSTR()
    if not api.sid_to_string(psid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return text.value
    finally:
        api.local_free(text)


def _current_owner_sids() -> frozenset:
    """SIDs that own files this process creates: the token's user and its default
    owner (the Administrators group for some elevated-admin configurations)."""
    api = _win32()
    token = wintypes.HANDLE()
    if not api.open_process_token(api.get_current_process(), _TOKEN_QUERY, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        sids = set()
        for info_class in (_TOKEN_USER, _TOKEN_OWNER):
            needed = wintypes.DWORD()
            api.get_token_information(token, info_class, None, 0, ctypes.byref(needed))
            buffer = ctypes.create_string_buffer(needed.value)
            if not api.get_token_information(token, info_class, buffer, needed, ctypes.byref(needed)):
                raise ctypes.WinError(ctypes.get_last_error())
            # TOKEN_USER and TOKEN_OWNER both begin with a pointer to the SID
            sids.add(_sid_to_string(ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]))
        return frozenset(sids)
    finally:
        api.close_handle(token)


def _trusted_owner_sids() -> frozenset:
    """Owners whose log files we accept: ourselves, plus accounts that can read any file anyway."""
    return _current_owner_sids() | _ALWAYS_TRUSTED_OWNER_SIDS


def _foreign_owner_message(path: str) -> str:
    return (f"Log file {path} already exists and is owned by another account, which could read "
            f"everything written to it. Choose a different --log-file path, or delete the file "
            f"if you trust its owner.")


def _handle_owner_sid(handle) -> Optional[str]:
    """Owner SID of an open file, read from its handle (so it is the file actually opened)."""
    api = _win32()
    owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    error = api.get_security_info(handle, _SE_FILE_OBJECT,
                                  _OWNER_SECURITY_INFORMATION, ctypes.byref(owner), None, None, None,
                                  ctypes.byref(descriptor))
    if error:
        raise ctypes.WinError(error)
    try:
        return _sid_to_string(owner) if owner.value else None
    finally:
        api.local_free(descriptor)


class _RestrictedRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler whose files are accessible only to the current user (and SYSTEM).

    The file is opened once with CreateFileW and the stream wraps that handle; it is
    never reopened by name, and every check below is made on that same handle. While
    it is open, nobody can delete or rename it or its folder (no FILE_SHARE_DELETE),
    so it can't be swapped for another file.

    - A new log file is created with the owner-only access list already in place
      (CREATE_NEW), so it is never unprotected, even briefly.
    - An existing log file is opened without following links and refused with
      LogFileOwnershipError if it is a symbolic link (reparse point), has other hard
      links, or is owned by another account: that account could read what is written.
      Otherwise its access list is replaced with the owner-only one.
    - Rollovers go through the same path; renamed backups keep their access list.
      If a refused file appears during a rollover, logging stops with errors rather
      than writing to it.

    If the drive doesn't store access lists (e.g. FAT32/exFAT, some network shares),
    one warning is printed and logging continues: the audit must not stop over that.
    """

    def __init__(self, *args, **kwargs):
        self._acl_warning_shown = False  # set before super().__init__, which calls _open()
        super().__init__(*args, **kwargs)

    def _warn_unprotected(self) -> None:
        if not self._acl_warning_shown:
            self._acl_warning_shown = True
            # print, not logger: this can run inside emit() during a rollover
            print("Warning: could not restrict log file permissions to the current user; "
                  "the log file uses its folder's permissions.", file=sys.stderr)

    def _open(self):
        handle, created = _open_log_handle(self.baseFilename)
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_APPEND)  # fd now owns the handle
        except OSError:
            _win32().close_handle(handle)
            raise
        try:
            self._secure(fd, handle, created)
        except BaseException:
            os.close(fd)
            raise
        return open(fd, self.mode, encoding=self.encoding, errors=self.errors)

    def _secure(self, fd: int, handle, created: bool) -> None:
        """Checks and access list for the opened file. Raises LogFileOwnershipError if
        another account could read it."""
        path = self.baseFilename
        acl_volume = _volume_supports_acls(handle)
        if not created:
            info = os.fstat(fd)
            if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise LogFileOwnershipError(
                    f"Log file {path} is a symbolic link or other reparse point; refusing to write through it.")
            if info.st_nlink > 1:
                raise LogFileOwnershipError(
                    f"Log file {path} has other hard links, so it may be readable under another name. "
                    f"Choose a different --log-file path.")
            # Ownership is checked whenever it can be read, whatever the drive reports:
            # the drive check only decides whether to warn and apply the access list.
            try:
                owner = _handle_owner_sid(handle)
                trusted = _trusted_owner_sids()
            except OSError:
                if acl_volume:  # fail closed: the drive has owners, but we can't see this one
                    raise LogFileOwnershipError(
                        f"Could not verify who owns log file {path}; refusing to write to it.") from None
                owner = None    # drives without access lists (FAT32/exFAT) have no owners
            if owner is not None and owner not in trusted:
                raise LogFileOwnershipError(_foreign_owner_message(path))

        if not acl_volume:
            self._warn_unprotected()  # e.g. FAT32/exFAT: access lists aren't stored there
            return
        if created:
            return  # created owner-only, and held open since, so it can't have been swapped
        try:
            _restrict_handle_to_owner(handle)
        except OSError:
            self._warn_unprotected()


def setup_logging(log_file: str = None, verbose: bool = False) -> None:
    """Configure logging for audit trail.

    Args:
        log_file: Path to log file. If None, logging is minimal (warnings only to stderr).
        verbose: If True, include DEBUG level messages with detailed information.
    """
    log_format = "%(asctime)s | %(levelname)-8s | %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Remove handlers from an earlier call so they don't accumulate, and close them so an
    # earlier log file isn't left open (and locked against deletion) until the process exits.
    # Closing a StreamHandler doesn't close the stream itself, so stderr stays usable.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    # Set base logging level
    level = logging.DEBUG if verbose else logging.INFO

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Rotating file handler (5 MB max, keep 3 backups); files are owner-only
        file_handler = _RestrictedRotatingFileHandler(
            log_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(log_format, date_format))
        logger.addHandler(file_handler)

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


# Terminal escape sequences, following the ECMA-48 grammar rather than a fixed list:
#   CSI  = ESC[ or 8-bit 0x9B, parameter bytes 0x30-0x3F (incl. "?" as in ESC[?25l),
#          intermediate bytes 0x20-0x2F, one final byte 0x40-0x7E
#   OSC  = ESC] or 8-bit 0x9D ... terminated by BEL, ESC\ (ST) or 8-bit ST 0x9C
#   other two-byte escapes (ESC c, ESC 7, ESC ( B, ...)
_ESCAPE_SEQUENCE_RE = re.compile(
    r'(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]'
    r'|(?:\x1b\]|\x9d)[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)'
    r'|\x1b[ -/]*[0-~]'
)

# Characters that break or move the line. Replaced with a space (not removed) so that
# hidden text becomes visible, e.g. "EvilRAT\rGoogle Chrome" -> "EvilRAT Google Chrome".
_LINE_BREAK_CHARS = frozenset("\t\n\v\f\r\x85  ")


def sanitize_output(text: str) -> str:
    """Make untrusted text safe to print as a single-line field.

    Prevents malicious software from manipulating terminal output or hiding
    its presence in listings:
    - removes terminal escape sequences (7-bit and 8-bit forms)
    - replaces line breaks, carriage returns and tabs with a space, so a name
      can't overwrite itself on screen or inject fake table rows
    - removes all other control characters (C0, DEL, C1) and Unicode format
      characters (category Cf, e.g. U+202E bidi override, zero-width space)

    None is returned unchanged; other non-string values are converted to str.
    """
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    if not text:
        return text
    text = _ESCAPE_SEQUENCE_RE.sub('', text)
    cleaned = []
    for c in text:
        if c in _LINE_BREAK_CHARS:
            cleaned.append(' ')
        elif unicodedata.category(c) in ('Cc', 'Cf'):
            continue
        else:
            cleaned.append(c)
    return ''.join(cleaned)


# Leading characters that make spreadsheet apps (Excel, LibreOffice, Google Sheets) treat a
# CSV cell as a formula (OWASP "CSV Injection"). OWASP also lists TAB and CR; sanitize_output
# has already turned those into spaces, which is why the check ignores leading whitespace.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")


def csv_safe_cell(value) -> str:
    """Sanitize a value for a CSV cell and neutralise spreadsheet formula injection.

    A cell such as '=HYPERLINK("http://evil/?"&A1,"Click")' would run as a formula when
    the export is opened in Excel; quoting does not prevent this. Prefixing a single
    quote makes spreadsheet apps show the value as literal text.
    """
    text = sanitize_output(value)
    if text is None:
        return ""
    if text.lstrip().startswith(_CSV_FORMULA_PREFIXES):
        return "'" + text
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

        # Print without newline (stderr so redirected stdout stays clean)
        sys.stderr.write(line)
        sys.stderr.flush()

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
        print(file=sys.stderr)  # Move to next line


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
            sys.stderr.write("\r⠋\r ")
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

        sys.stderr.write(line)
        sys.stderr.flush()

    def finish(self, message: str = ""):
        """Complete the spinner."""
        elapsed = time.time() - self.start_time
        final_msg = message or f"{self.message} completed"
        line = f"\r✓ {final_msg} ({elapsed:.1f}s)"
        padding = max(0, self._last_line_length - len(line))
        line += " " * padding
        print(line, file=sys.stderr)


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

    def matches_exclude(self, exclude_term: str) -> bool:
        """Check if the software matches an exclusion term (literal, case-insensitive)."""
        term_lower = exclude_term.lower()
        return (
            term_lower in self.name.lower()
            or term_lower in self.publisher.lower()
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

    # Permissions considered sensitive for security analysis
    SENSITIVE_PERMISSIONS = [
        "<all_urls>",
        "http://*/*",
        "https://*/*",
        "*://*/*",
        "file:///*",
        "webRequest",
        "webRequestBlocking",
        "declarativeNetRequest",
        "nativeMessaging",
        "debugger",
        "cookies",
        "history",
        "tabs",
        "activeTab",
        "management",
        "privacy",
        "proxy",
        "downloads",
        "clipboardRead",
        "clipboardWrite",
        "storage",
        "notifications",
        "alarms",
        "webNavigation",
        "bookmarks",
        "geolocation",
        "contentSettings",
    ]

    def has_sensitive_permissions(self) -> bool:
        """Check if extension has potentially dangerous permissions."""
        return any(
            any(s in p for s in self.SENSITIVE_PERMISSIONS)
            for p in self.permissions
        )

    def get_sensitive_permission_details(self) -> list[str]:
        """Return list of matched sensitive permissions."""
        matched = []
        for p in self.permissions:
            for s in self.SENSITIVE_PERMISSIONS:
                if s in p:
                    matched.append(p)
                    break
        return matched


@dataclass
class CVEInfo:
    """Represents a CVE (Common Vulnerabilities and Exposures) entry."""
    cve_id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    cvss_score: float
    published_date: str
    references: list = field(default_factory=list)
    cvss_version: str = ""   # "4.0", "3.1", "3.0", "2.0"; "" if not scored yet
    score_source: str = ""   # "NVD" (NVD's own assessment) or "CNA" (assigner / other provider)
    known_exploited: bool = False  # in CISA's Known Exploited Vulnerabilities (KEV) catalog
    kev_added: str = ""            # date CISA added it to KEV
    status: str = ""               # NVD's vulnStatus, e.g. "Analyzed", "Awaiting Analysis", "Deferred"

    @property
    def score_label(self) -> str:
        """e.g. "CVSS 9.8, NVD v3.1", or "not scored yet"."""
        if not self.cvss_version:
            return "not scored yet"
        return f"CVSS {self.cvss_score}, {self.score_source} v{self.cvss_version}"

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
    not_checked: str = ""    # reason the program wasn't looked up, e.g. "no CPE mapping"
    cpe: str = ""            # CPE name that was looked up
    total_available: int = 0  # CVEs NVD reported (can exceed len(cves) if the page cap was hit)
    # Recent CVEs that mention the product but that NVD hasn't analysed yet (no product data),
    # so NVD can't say whether this version is affected. Never counted in the totals above.
    unconfirmed: list[CVEInfo] = field(default_factory=list)
    # CVEs NVD lists for every version of the product (no version range or version given),
    # e.g. a 2012 CVE recorded as "all Chrome versions". Matched, but not version-specific,
    # so kept apart from `cves` and never counted in the totals above.
    all_versions: list[CVEInfo] = field(default_factory=list)

    @property
    def kev_count(self) -> int:
        return sum(1 for c in self.cves if c.known_exploited)

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

    def __init__(self):
        # Anomaly counters, reset by get_all_registry_software() and reported once per scan.
        # Real installers store these fields as REG_SZ, so non-zero counts are worth a warning.
        self.converted_values = 0    # text values stored with another type, converted to text
        self.unreadable_entries = 0  # entries that could not be parsed at all and were skipped

    def scan_registry_key(self, hive: int, path: str) -> list[SoftwareInfo]:
        """Scan a specific registry key for installed software.

        Entries are untrusted: any process can write under HKCU. Values are converted to
        text rather than rejected, so a malformed entry is still reported instead of
        silently disappearing (or aborting the whole scan).
        """
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
                subkey_path = f"{path}\\[{i}]"
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey_path = f"{path}\\{subkey_name}"
                    subkey = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)

                    try:
                        name = self._get_registry_str(subkey, "DisplayName")
                        if not name:
                            continue

                        # Skip system components (Windows' own app list hides these too)
                        system_component = self._get_registry_str(subkey, "SystemComponent", expect_text=False)
                        if system_component.strip() == "1":
                            continue

                        software = SoftwareInfo(
                            name=name,
                            version=self._get_registry_str(subkey, "DisplayVersion"),
                            publisher=self._get_registry_str(subkey, "Publisher"),
                            install_date=self._format_install_date(
                                self._get_registry_str(subkey, "InstallDate")
                            ),
                            source="Registry",
                            install_location=self._get_registry_str(subkey, "InstallLocation"),
                        )
                        software_list.append(software)

                    finally:
                        winreg.CloseKey(subkey)

                except (FileNotFoundError, PermissionError, OSError):
                    continue
                except (TypeError, ValueError, AttributeError) as e:
                    # Backstop: one unparseable entry must not abort the rest of the scan
                    self.unreadable_entries += 1
                    logger.debug(f"Skipped unreadable registry entry {subkey_path}: {e}")
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

    @staticmethod
    def _registry_value_to_str(value) -> str:
        """Convert a value returned by winreg to text, whatever registry type it had."""
        if value is None:
            return ""
        if isinstance(value, str):            # REG_SZ, REG_EXPAND_SZ
            return value
        if isinstance(value, bytes):          # REG_BINARY, REG_NONE: REG_SZ data is UTF-16LE,
            return value.decode("utf-16-le", errors="replace").rstrip("\x00")  # so decode it the same way
        if isinstance(value, (list, tuple)):  # REG_MULTI_SZ
            return " ".join(str(v) for v in value)
        return str(value)                     # REG_DWORD, REG_QWORD

    def _get_registry_str(self, key, value_name: str, expect_text: bool = True) -> str:
        """Read a registry value as text ("" if missing).

        Args:
            expect_text: True for fields real installers store as REG_SZ. A value of any
                other type is still converted, but counted as an anomaly.
        """
        value = self._get_registry_value(key, value_name)
        if expect_text and value is not None and not isinstance(value, str):
            self.converted_values += 1
            logger.debug(f"Registry value {value_name} has type {type(value).__name__}; converted to text")
        return self._registry_value_to_str(value)

    def _format_install_date(self, date_str: Optional[str]) -> str:
        """Format install date from YYYYMMDD to readable format."""
        date_str = self._registry_value_to_str(date_str).strip()
        if len(date_str) != 8:
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
        self.converted_values = 0
        self.unreadable_entries = 0

        for hive, path in self.REGISTRY_PATHS:
            software_list = self.scan_registry_key(hive, path)
            for software in software_list:
                # Deduplicate by name (same app might appear in multiple registry locations)
                if software.name not in seen_names:
                    seen_names.add(software.name)
                    all_software.append(software)

        if self.converted_values:
            logger.warning(
                f"{self.converted_values} registry value(s) had an unexpected type and were "
                f"converted to text. Real installers don't do this; the entries are still listed."
            )
        if self.unreadable_entries:
            logger.warning(f"{self.unreadable_entries} registry entry(ies) could not be parsed and were skipped.")

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
                str(_powershell_path()),  # absolute path, never a PATH/CWD lookup
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
                encoding='utf-8',
                errors='replace',
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode != 0:
                return software_list

            reader = csv.reader(io.StringIO(result.stdout))
            rows = list(reader)
            if len(rows) <= 1:
                return software_list

            for row in rows[1:]:  # skip header
                try:
                    if len(row) >= 4:
                        name = row[0]
                        version = row[1]
                        publisher = row[2]
                        install_location = row[3]

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
            logger.warning("PowerShell command timed out while enumerating Store apps")
        except FileNotFoundError:
            logger.warning(
                "Windows PowerShell not found. Store app enumeration requires PowerShell."
            )
        except OSError as e:
            logger.debug(f"OS error during Store app enumeration: {e}")

        return software_list

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

                    version, publisher = self._get_file_info(str(exe_path))

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

    def _find_executables(self, directory: Path, max_depth: int, max_files: int = 500) -> list[Path]:
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
            if depth > max_depth or len(executables) >= max_files:
                return

            try:
                # Use os.scandir() instead of Path.iterdir() for performance.
                # DirEntry objects cache file type info from the directory
                # listing itself, avoiding extra stat() calls per file.
                with os.scandir(path) as entries:
                    for entry in entries:
                        if len(executables) >= max_files:
                            return

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
        if len(executables) >= max_files:
            logger.warning(f"File limit ({max_files}) reached scanning {directory}")
        return executables

    def _should_skip_exe(self, exe_path: Path) -> bool:
        """Check if the executable should be skipped."""
        skip_names = [
            "uninstall", "uninst", "setup", "install", "update",
            "updater", "helper", "crash", "reporter", "launcher"
        ]
        exe_name = exe_path.stem.lower()
        return any(skip in exe_name for skip in skip_names)

    def _get_file_info(self, file_path: str) -> tuple[str, str]:
        """Get version and publisher from an executable's PE header in a single read."""
        version = ""
        publisher = ""
        try:
            size = ctypes.windll.version.GetFileVersionInfoSizeW(file_path, None)
            if size == 0:
                return version, publisher

            buffer = ctypes.create_string_buffer(size)
            if not ctypes.windll.version.GetFileVersionInfoW(file_path, 0, size, buffer):
                return version, publisher

            # Extract version from VS_FIXEDFILEINFO
            val_ptr = ctypes.c_void_p()
            val_size = ctypes.c_uint()

            if ctypes.windll.version.VerQueryValueW(
                buffer, "\\", ctypes.byref(val_ptr), ctypes.byref(val_size)
            ):
                if val_size.value:
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

            # Extract publisher from StringFileInfo
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
                        publisher = ctypes.wstring_at(val_ptr, val_size.value - 1)
                        break

        except (OSError, ValueError, OverflowError) as e:
            logger.debug(f"Could not get file info for {file_path}: {e}")

        return version, publisher

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

        winget = _winget_path()
        if winget is None:
            print("Warning: winget not found. Please ensure Windows Package Manager is installed.", file=sys.stderr)
            return updates

        try:
            # Run winget upgrade to get list of available updates
            cmd = [
                str(winget), "upgrade",  # absolute path, never a PATH/CWD lookup
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
            print("Warning: winget command timed out.", file=sys.stderr)
        except FileNotFoundError:
            print("Warning: winget not found. Please ensure Windows Package Manager is installed.", file=sys.stderr)
        except OSError as e:
            logger.debug(f"Failed to check for updates: {e}")
            print("Warning: Failed to check for updates.", file=sys.stderr)

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

    @staticmethod
    def _discover_profiles(user_data_dir: Path) -> list[str]:
        """Dynamically discover browser profile directories."""
        profiles = []
        if (user_data_dir / "Default").is_dir():
            profiles.append("Default")
        try:
            for entry in user_data_dir.iterdir():
                if entry.is_dir() and entry.name.startswith("Profile "):
                    profiles.append(entry.name)
        except (PermissionError, OSError):
            pass
        return profiles

    def _scan_chrome_extensions(self) -> list[BrowserExtensionInfo]:
        """Scan Chrome extensions."""
        extensions = []
        chrome_base = Path(self.local_app_data) / "Google" / "Chrome" / "User Data"

        if not chrome_base.exists():
            return extensions

        profiles = self._discover_profiles(chrome_base)

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

        profiles = self._discover_profiles(edge_base)

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
        """Parse a Chromium extension's manifest.json file.

        The file is untrusted: fields are type-checked and converted so a malformed
        manifest can't crash the scan. Returns None if the file is missing, isn't valid
        JSON, or isn't a JSON object (Chromium won't load such an extension either).
        """
        try:
            with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
                manifest = json.load(f)
        except (OSError, ValueError, RecursionError):
            # Missing file, invalid JSON, or nesting deep enough to overflow the parser
            return None
        if not isinstance(manifest, dict):
            return None

        try:
            name = self._as_text(manifest.get("name")) or "Unknown"
            # Handle localized names (they start with __MSG_)
            if name.startswith("__MSG_"):
                name = self._get_localized_name(manifest_path.parent, name) or name

            version = self._as_text(manifest.get("version"))
            description = self._as_text(manifest.get("description"))
            if description.startswith("__MSG_"):
                description = ""  # Skip localized descriptions for simplicity

            # Gather permissions from multiple sources
            permissions = []
            for field_name in ("permissions", "host_permissions", "optional_permissions"):
                permissions.extend(self._permission_strings(manifest.get(field_name)))

            # Get content script matches as well (these are effectively permissions)
            content_scripts = manifest.get("content_scripts")
            if isinstance(content_scripts, list):
                for content_script in content_scripts:
                    if isinstance(content_script, dict):
                        permissions.extend(self._permission_strings(content_script.get("matches")))
        except (TypeError, ValueError, AttributeError) as e:
            # Backstop: still report the extension rather than dropping it
            logger.debug(f"Could not fully parse {manifest_path}: {e}")
            return BrowserExtensionInfo(name=ext_id, version="", browser=browser, extension_id=ext_id,
                                        description="(manifest could not be parsed)")

        return BrowserExtensionInfo(
            name=name,
            version=version,
            browser=browser,
            extension_id=ext_id,
            description=description[:100],
            permissions=permissions,
        )

    @staticmethod
    def _as_text(value) -> str:
        """Return a manifest field as text ("" for None); untrusted fields may not be strings."""
        if value is None:
            return ""
        return value if isinstance(value, str) else str(value)

    @staticmethod
    def _permission_strings(value) -> list[str]:
        """Return a permission list as strings. Dict entries (e.g. Chrome app
        {"fileSystem": [...]}) contribute their keys; anything that isn't a list gives []."""
        if not isinstance(value, list):
            return []
        result = []
        for item in value:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                result.extend(str(k) for k in item)
            elif item is not None:
                result.append(str(item))
        return result

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
            except (OSError, ValueError, RecursionError):
                # Missing, invalid UTF-8 / JSON (UnicodeDecodeError is a ValueError), or too deep
                continue
            if not isinstance(messages, dict):
                continue
            # Try both lowercase and original case
            for k in (key, key.lower()):
                entry = messages.get(k)
                if isinstance(entry, dict) and isinstance(entry.get("message"), str):
                    return entry["message"]

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
        """Parse Firefox's extensions.json file.

        The file is untrusted: each add-on entry is type-checked and parsed separately,
        so one malformed entry can't drop the rest of the profile's add-ons.
        """
        extensions = []

        try:
            with open(extensions_json, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (OSError, ValueError, RecursionError):
            return extensions

        addons = data.get("addons") if isinstance(data, dict) else None
        if not isinstance(addons, list):
            return extensions

        for addon in addons:
            try:
                ext = self._parse_firefox_addon(addon)
            except (TypeError, ValueError, AttributeError) as e:
                logger.debug(f"Skipped unreadable add-on entry in {extensions_json}: {e}")
                continue
            if ext:
                extensions.append(ext)

        return extensions

    def _parse_firefox_addon(self, addon) -> Optional[BrowserExtensionInfo]:
        """Parse one entry of extensions.json["addons"]; None if it isn't a user extension."""
        if not isinstance(addon, dict):
            return None

        # Skip system/built-in addons
        if addon.get("location") in ("app-system-defaults", "app-builtin"):
            return None
        if addon.get("type") != "extension":
            return None

        locale = addon.get("defaultLocale")
        if not isinstance(locale, dict):
            locale = {}
        user_permissions = addon.get("userPermissions")   # can be null in real files
        if not isinstance(user_permissions, dict):
            user_permissions = {}

        ext_id = self._as_text(addon.get("id"))
        name = self._as_text(locale.get("name")) or ext_id or "Unknown"
        description = self._as_text(locale.get("description"))
        active = addon.get("active", True)

        # Firefox stores permissions differently; also check top-level permissions (legacy/MV3)
        permissions = (self._permission_strings(user_permissions.get("permissions"))
                       + self._permission_strings(user_permissions.get("origins"))
                       + self._permission_strings(addon.get("permissions")))

        return BrowserExtensionInfo(
            name=name,
            version=self._as_text(addon.get("version")),
            browser="Firefox",
            extension_id=ext_id,
            description=description[:100],
            permissions=permissions,
            enabled=active if isinstance(active, bool) else True,
        )

    def display_extensions_table(
        self, extensions: list[BrowserExtensionInfo]
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


@dataclass
class VulnScanPlan:
    """Which programs the CVE check looks up, and what it leaves out (reported in the summary)."""
    targets: list[SoftwareInfo] = field(default_factory=list)
    unmapped: list[SoftwareInfo] = field(default_factory=list)  # no CPE mapping: not checked
    skipped: int = 0       # frameworks, runtimes, update packages (SKIP_PATTERNS)
    no_version: int = 0    # version missing or not usable in a CPE name
    duplicates: int = 0    # same product and version as a program already in targets
    over_limit: int = 0    # mapped programs left out by --cve-limit
    limit: int = 20


class NvdApiError(Exception):
    """An NVD request failed. `status` is the HTTP status code, or None for network errors."""

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class VulnerabilityScanner:
    """Scans for known CVEs using the NIST NVD API."""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # NVD returns at most 2,000 CVEs per page. Very old browser versions can be affected by
    # thousands of CVEs, so cap the pages per program and report "showing N of M".
    MAX_PAGES = 5

    # Display-name keys -> CPE (vendor, product) as NVD names them. Every pair must exist in
    # NVD's CPE dictionary: a pair NVD doesn't know makes the check find nothing, silently.
    # Deliberately absent because NVD has no CPE product for them (checked 2026-11):
    # OBS Studio, HandBrake, ShareX, Atom, AdoptOpenJDK, Slack desktop, Vivaldi (installer only),
    # Sublime Text 4 (only sublime_text_3 exists). They are reported as "not checked".
    SOFTWARE_MAPPINGS = {
        # Browsers
        "google chrome": ("google", "chrome"),
        "mozilla firefox": ("mozilla", "firefox"),
        "firefox": ("mozilla", "firefox"),
        "microsoft edge": ("microsoft", "edge_chromium"),  # "edge" is the retired EdgeHTML browser
        "microsoft edge update": ("microsoft", "edge_update"),
        "opera": ("opera", "opera_browser"),
        "brave": ("brave", "brave"),
        "tor browser": ("torproject", "tor"),
        # Dev tools - Editors & IDEs
        "notepad++": ("notepad-plus-plus", "notepad\\+\\+"),
        "vscode": ("microsoft", "visual_studio_code"),
        "visual studio code": ("microsoft", "visual_studio_code"),
        # NVD names each Visual Studio release separately; a bare "visual studio" key would
        # also catch the Visual Studio Installer and Office tools runtimes (other versions).
        "visual studio community 2019": ("microsoft", "visual_studio_2019"),
        "visual studio professional 2019": ("microsoft", "visual_studio_2019"),
        "visual studio enterprise 2019": ("microsoft", "visual_studio_2019"),
        "visual studio community 2022": ("microsoft", "visual_studio_2022"),
        "visual studio professional 2022": ("microsoft", "visual_studio_2022"),
        "visual studio enterprise 2022": ("microsoft", "visual_studio_2022"),
        "visual studio community 2026": ("microsoft", "visual_studio_2026"),
        "visual studio professional 2026": ("microsoft", "visual_studio_2026"),
        "visual studio enterprise 2026": ("microsoft", "visual_studio_2026"),
        "intellij idea": ("jetbrains", "intellij_idea"),
        "pycharm": ("jetbrains", "pycharm"),
        "webstorm": ("jetbrains", "webstorm"),
        "rider": ("jetbrains", "rider"),
        "goland": ("jetbrains", "goland"),
        "clion": ("jetbrains", "clion"),
        "phpstorm": ("jetbrains", "phpstorm"),
        "datagrip": ("jetbrains", "datagrip"),
        "eclipse": ("eclipse", "eclipse_ide"),
        # Dev tools - Languages & Runtimes
        "python": ("python", "python"),
        "nodejs": ("nodejs", "node.js"),
        "node.js": ("nodejs", "node.js"),
        "java": ("oracle", "jre"),
        "openjdk": ("oracle", "openjdk"),
        "go programming language": ("golang", "go"),
        "rust": ("rust-lang", "rust"),
        "ruby": ("ruby-lang", "ruby"),
        "php": ("php", "php"),
        "perl": ("perl", "perl"),
        ".net sdk": ("microsoft", ".net"),
        # Dev tools - Utilities
        "git": ("git-scm", "git"),
        "docker desktop": ("docker", "docker"),
        "wsl": ("microsoft", "windows_subsystem_for_linux"),
        # Productivity
        "libreoffice": ("libreoffice", "libreoffice"),
        "thunderbird": ("mozilla", "thunderbird"),
        "microsoft teams": ("microsoft", "teams"),
        "notion": ("notion", "notion"),
        # Media
        "vlc media player": ("videolan", "vlc_media_player"),
        "vlc": ("videolan", "vlc_media_player"),
        "audacity": ("audacityteam", "audacity"),
        "gimp": ("gimp", "gimp"),
        "inkscape": ("inkscape", "inkscape"),
        "blender": ("blender", "blender"),
        "ffmpeg": ("ffmpeg", "ffmpeg"),
        "kodi": ("kodi", "kodi"),
        "itunes": ("apple", "itunes"),
        "spotify": ("spotify", "spotify"),
        # Security
        "keepass": ("keepass", "keepass"),
        "bitwarden": ("bitwarden", "bitwarden"),
        "openssh": ("openbsd", "openssh"),
        "winscp": ("winscp", "winscp"),
        "nmap": ("nmap", "nmap"),
        "burp suite": ("portswigger", "burp_suite"),
        "openvpn": ("openvpn", "openvpn"),
        "openvpn connect": ("openvpn", "connect"),    # a different client from OpenVPN (community)
        "putty": ("putty", "putty"),
        "wireshark": ("wireshark", "wireshark"),
        # Compression & Utilities
        "7-zip": ("7-zip", "7-zip"),
        "winrar": ("rarlab", "winrar"),
        "peazip": ("peazip", "peazip"),
        "everything": ("voidtools", "everything"),
        "autohotkey": ("autohotkey", "autohotkey"),
        "ccleaner": ("piriform", "ccleaner"),
        "powershell": ("microsoft", "powershell"),
        # Communication & Collaboration
        "discord": ("discord", "discord"),
        "zoom": ("zoom", "zoom"),
        "zoom workplace": ("zoom", "workplace_desktop"),
        "filezilla": ("filezilla-project", "filezilla_client"),
        # System & Virtualization
        "vmware workstation": ("vmware", "workstation"),
        "vmware player": ("vmware", "workstation_player"),
        "virtualbox": ("oracle", "virtualbox"),
        "citrix workspace": ("citrix", "workspace"),
        "teamviewer": ("teamviewer", "teamviewer"),
        "anydesk": ("anydesk", "anydesk"),
        # Databases
        "mysql": ("oracle", "mysql"),
        "postgresql": ("postgresql", "postgresql"),
        "mongodb": ("mongodb", "mongodb"),
        "redis": ("redis", "redis"),
        "sqlite": ("sqlite", "sqlite"),
        # Network & Web
        "nginx": ("f5", "nginx"),
        "apache http server": ("apache", "http_server"),  # not bare "apache": OpenOffice, NetBeans, ...
        "postman": ("postman", "postman"),
        "curl": ("haxx", "curl"),
        "wget": ("gnu", "wget"),
        # Gaming (not Steam: NVD versions the Steam client by date, e.g. "2021-04-10", while
        # Windows reports "2.10.91.91", so NVD can't compare them and matches every install)
        "epic games launcher": ("epicgames", "launcher"),
        "gog galaxy": ("gog", "galaxy"),
    }

    # Phrases that name a product in CVE descriptions, used only to find recent CVEs NVD hasn't
    # analysed yet (they have no product data, so the CPE query can't see them). Left out on
    # purpose: names too generic to search for (Git, Everything, Steam, ...) and platforms that
    # other products' CVEs name, e.g. Node.js ("... package for Node.js": hundreds of npm CVEs).
    SEARCH_PHRASES = {
        ("google", "chrome"): "Google Chrome",
        ("mozilla", "firefox"): "Firefox",
        ("mozilla", "thunderbird"): "Thunderbird",
        ("microsoft", "edge_chromium"): "Microsoft Edge",
        ("microsoft", "visual_studio_code"): "Visual Studio Code",
        ("notepad-plus-plus", "notepad\\+\\+"): "Notepad++",
        ("python", "python"): "CPython",
        ("libreoffice", "libreoffice"): "LibreOffice",
        ("videolan", "vlc_media_player"): "VLC",
        ("audacityteam", "audacity"): "Audacity",
        ("gimp", "gimp"): "GIMP",
        ("inkscape", "inkscape"): "Inkscape",
        ("keepass", "keepass"): "KeePass",
        ("bitwarden", "bitwarden"): "Bitwarden",
        ("winscp", "winscp"): "WinSCP",
        ("openvpn", "openvpn"): "OpenVPN",
        ("putty", "putty"): "PuTTY",
        ("wireshark", "wireshark"): "Wireshark",
        ("7-zip", "7-zip"): "7-Zip",
        ("rarlab", "winrar"): "WinRAR",
        ("zoom", "workplace_desktop"): "Zoom Workplace",
        ("filezilla-project", "filezilla_client"): "FileZilla",
        ("oracle", "virtualbox"): "VirtualBox",
        ("vmware", "workstation"): "VMware Workstation",
        ("teamviewer", "teamviewer"): "TeamViewer",
        ("anydesk", "anydesk"): "AnyDesk",
    }
    UNCONFIRMED_DAYS = 119        # NVD allows date ranges of at most 120 days
    UNCONFIRMED_MAX_PAGES = 2

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
        r"python launcher",    # the py launcher's version is not a CPython version
    ]

    def __init__(self, api_key: str = None):
        """Initialize scanner with optional NVD API key for higher rate limits.

        API key can be provided directly or via NVD_API_KEY environment variable.
        Direct parameter takes precedence over environment variable.
        """
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self._request_timestamps = collections.deque()
        self._rate_window = 30.0  # seconds
        self._rate_max = 50 if self.api_key else 5
        self._compiled_skip_patterns = [re.compile(p) for p in self.SKIP_PATTERNS]

    def _rate_limit(self):
        """Implement sliding-window rate limiting for NVD API."""
        now = time.time()
        # Remove timestamps outside the window
        while self._request_timestamps and now - self._request_timestamps[0] > self._rate_window:
            self._request_timestamps.popleft()
        # If at capacity, sleep until oldest exits the window
        if len(self._request_timestamps) >= self._rate_max:
            sleep_time = self._rate_window - (now - self._request_timestamps[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
            self._request_timestamps.popleft()
        self._request_timestamps.append(time.time())

    def _should_skip_software(self, name: str) -> bool:
        """Check if software should be skipped from vulnerability scanning."""
        name_lower = name.lower()
        return any(pattern.search(name_lower) for pattern in self._compiled_skip_patterns)

    # Architecture words in display names, e.g. "(x64)", "(64-bit x64)", "Wireshark 4.0.0 64-bit"
    _ARCH_WORD = r"(?:x64|x86|arm64|64-bit|32-bit)"

    def _normalize_software_name(self, name: str) -> str:
        """Normalize a display name for mapping lookup: lower case, no versions or architecture.

        "7-Zip 23.01 (x64)" -> "7-zip", "Python 3.12.1 (64-bit)" -> "python",
        "Mozilla Firefox (x64 en-US)" -> "mozilla firefox". Digits that are part of a name
        ("7-Zip", "1Password") are kept: only whole tokens that look like versions are removed.
        """
        name = name.lower()
        # Parenthesised groups that mention an architecture, e.g. "(x64 en-us)", "(64-bit x64)"
        name = re.sub(r"\([^)]*\b" + self._ARCH_WORD + r"\b[^)]*\)", " ", name)
        # Stand-alone architecture words
        name = re.sub(r"(?<!\S)" + self._ARCH_WORD + r"(?!\S)", " ", name)
        # Stand-alone version tokens: "23.01", "v1.2.3", "3.11.4150.0", "2.53.1-beta"
        name = re.sub(r"(?<!\S)v?\d+(?:\.\d+)+\S*", " ", name)
        return " ".join(name.split())

    def _find_mapping(self, name: str) -> Optional[tuple[str, str]]:
        """CPE (vendor, product) for a display name, or None if no mapping applies.

        Keys match whole words of the normalised name, so "git" matches "Git" but not
        "Logitech G HUB" or "GitHub Desktop", and "rust" doesn't match "RustDesk". When
        several keys match, the longest wins ("vlc media player" over "vlc").
        """
        normalised = self._normalize_software_name(name)
        for key in sorted(self.SOFTWARE_MAPPINGS, key=len, reverse=True):
            # Word boundaries that also work for keys ending in "+" (notepad++) or starting with "."
            if re.search(r"(?<![\w+])" + re.escape(key) + r"(?![\w+])", normalised):
                return self.SOFTWARE_MAPPINGS[key]
        return None

    @staticmethod
    def _python_installer_version(version: str) -> str:
        """Python's Windows installer reports 3.11.4 as "3.11.4150.0" (micro * 1000 + build).

        Read literally, NVD treats 3.11.4150 as newer than 3.11.5 and misses CVEs fixed since.
        """
        m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:\.\d+)?", version)
        if m and int(m.group(3)) >= 100:
            return f"{m.group(1)}.{m.group(2)}.{int(m.group(3)) // 1000}"
        return version

    @staticmethod
    def _java_installer_version(version: str) -> str:
        """Java 8's installer reports 8u401 as "8.0.4010.10"; NVD names it "1.8.0:update401".

        Java 9 and later report e.g. "17.0.9.0", which NVD names "17.0.9".
        """
        m = re.fullmatch(r"8\.0\.(\d+)(?:\.\d+)?", version)
        if m:
            return f"1.8.0:update{int(m.group(1)) // 10}"
        m = re.fullmatch(r"(\d+\.\d+\.\d+)\.0", version)
        if m:
            return m.group(1)
        return version

    @staticmethod
    def _without_package_build(version: str) -> str:
        """Drop an installer package build suffix: PostgreSQL's installer reports 17.11 as "17.11-5"."""
        m = re.fullmatch(r"(\d+(?:\.\d+)*)-\d+", version)
        return m.group(1) if m else version

    # Products whose installers report versions in a form NVD reads differently
    VERSION_TRANSLATORS = {
        ("python", "python"): "_python_installer_version",
        ("oracle", "jre"): "_java_installer_version",
        ("postgresql", "postgresql"): "_without_package_build",
    }

    @classmethod
    def _cpe_version(cls, vendor: str, product: str, version: str) -> Optional[str]:
        """The installed version as it goes into a CPE name, or None if it can't be used.

        Only plain version strings are accepted: anything with spaces or CPE special
        characters (":", "*", "?", "\\", ...) would change the meaning of the CPE name.
        Then products in VERSION_TRANSLATORS get their installer's format translated.
        """
        version = (version or "").strip()
        if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", version):
            return None
        translator = cls.VERSION_TRANSLATORS.get((vendor, product))
        if translator:
            version = getattr(cls, translator)(version)
        return version

    @staticmethod
    def _cpe_name(vendor: str, product: str, cpe_version: str) -> str:
        """CPE 2.3 name for an application at one version (NVD accepts the short form)."""
        return f"cpe:2.3:a:{vendor}:{product}:{cpe_version}"

    def _nvd_request(self, params: list) -> dict:
        """Make one NVD CVE API request and return the decoded JSON page.

        Args:
            params: (name, value) pairs; a value of None sends a flag without a value
                    (NVD's isVulnerable / noRejected parameters work that way).

        Raises:
            NvdApiError: with a generic message (never the server's text) and the HTTP status.
        """
        self._rate_limit()
        query = "&".join(name if value is None else f"{name}={urllib.parse.quote(str(value), safe=':')}"
                         for name, value in params)
        url = f"{self.NVD_API_URL}?{query}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        for attempt in (1, 2):
            try:
                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request, timeout=30) as response:
                    data = json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt == 1:
                    time.sleep(self._rate_window)  # Too Many Requests: wait out the window, retry once
                    continue
                if e.code in (403, 429):
                    raise NvdApiError("NVD API rate limit exceeded. Try again later or use an API key.", e.code)
                raise NvdApiError(f"NVD API request failed (HTTP {e.code}).", e.code)
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                raise NvdApiError("Network error: Unable to reach NVD API.")
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise NvdApiError("NVD API returned an unreadable response.")
            if not isinstance(data, dict):
                raise NvdApiError("NVD API returned an unreadable response.")
            return data
        raise NvdApiError("NVD API rate limit exceeded. Try again later or use an API key.", 429)

    def _fetch_all_pages(self, params: list, max_pages: int) -> tuple[list[dict], int]:
        """Fetch up to max_pages pages of a CVE query. Returns (vulnerabilities, NVD's total count)."""
        vulnerabilities, start, total = [], 0, 0
        for _ in range(max_pages):
            page = self._nvd_request(params + [("startIndex", start)])
            batch = page.get("vulnerabilities")
            total = page.get("totalResults")
            if not isinstance(batch, list) or not isinstance(total, int):
                raise NvdApiError("NVD API returned an unreadable response.")
            vulnerabilities.extend(v for v in batch if isinstance(v, dict))
            start += len(batch)
            if not batch or start >= total:
                break
        return vulnerabilities, total

    def _query_affecting_cves(self, vendor: str, product: str, cpe_version: str) -> tuple[list[dict], int]:
        """CVEs that NVD says affect this product at this version (rejected CVEs left out).

        NVD compares the CPE name with each CVE's version ranges itself; checked against a
        local reading of NVD's data for 12 products, it matched exactly (nothing missed or added).
        """
        params = [("cpeName", self._cpe_name(vendor, product, cpe_version)),
                  ("isVulnerable", None), ("noRejected", None)]
        return self._fetch_all_pages(params, self.MAX_PAGES)

    @staticmethod
    def _listed_for_every_version(vuln: dict, vendor: str, product: str) -> bool:
        """True if NVD's data for this product in this CVE includes an "every version" entry.

        Looks only at whether NVD gave a version range or a specific version for the product
        (it does not re-check whether the installed version is in a range: NVD did that).
        Criteria with version "*" or "-" and no range mean "every version". NVD records some
        old CVEs that way, sometimes next to proper ranges (CVE-2009-2469 lists Firefox up to
        3.0.11 *and* every Firefox version), and such an entry alone makes NVD match any
        version, so the match says nothing about the installed one. If the product's criteria
        can't be found, the CVE is not set aside.
        """
        def items(obj, key):  # obj[key] if it is a list, else [] (network data: don't trust shapes)
            value = obj.get(key) if isinstance(obj, dict) else None
            return value if isinstance(value, list) else []

        for config in items(vuln.get("cve") if isinstance(vuln, dict) else None, "configurations"):
            for node in items(config, "nodes"):
                for match in items(node, "cpeMatch"):
                    if not isinstance(match, dict) or not match.get("vulnerable"):
                        continue
                    parts = str(match.get("criteria", "")).split(":")
                    if len(parts) < 6 or parts[3] != vendor or parts[4] != product:
                        continue
                    has_range = any(match.get(k) for k in ("versionStartIncluding", "versionStartExcluding",
                                                           "versionEndIncluding", "versionEndExcluding"))
                    if not has_range and parts[5] in ("*", "-", ""):
                        return True
        return False

    def _query_unanalysed_cves(self, phrase: str) -> list[dict]:
        """CVEs published in the last UNCONFIRMED_DAYS that mention `phrase` and have no product data.

        Without product (CPE) data NVD can't say which versions a CVE affects, so these are only
        candidates: the user has to check whether their version is affected.
        """
        now = datetime.now(timezone.utc).replace(microsecond=0)
        start = now - timedelta(days=self.UNCONFIRMED_DAYS)
        fmt = "%Y-%m-%dT%H:%M:%S.000Z"
        params = [("keywordSearch", phrase)]
        if " " in phrase:
            params.append(("keywordExactMatch", None))   # the phrase, not each word anywhere
        params += [("pubStartDate", start.strftime(fmt)), ("pubEndDate", now.strftime(fmt)),
                   ("noRejected", None)]
        vulnerabilities, _ = self._fetch_all_pages(params, self.UNCONFIRMED_MAX_PAGES)
        return [v for v in vulnerabilities
                if isinstance(v.get("cve"), dict) and not v["cve"].get("configurations")]

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
            cvss_score, severity, cvss_version, score_source = 0.0, "UNKNOWN", "", ""
            chosen = self._choose_metric(cve.get("metrics"))
            if chosen:
                cvss_version, entry = chosen
                score = entry["cvssData"].get("baseScore")
                cvss_score = float(score) if isinstance(score, (int, float)) else 0.0
                if cvss_version == "2.0":
                    severity = self._cvss2_to_severity(cvss_score)  # v2 has no CRITICAL label
                else:
                    severity = str(entry["cvssData"].get("baseSeverity") or "UNKNOWN")
                score_source = "NVD" if entry.get("type") == "Primary" else "CNA"

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
                cvss_version=cvss_version,
                score_source=score_source,
                # NVD includes CISA's KEV fields on CVEs that are known to be exploited
                known_exploited=isinstance(cve.get("cisaExploitAdd"), str),
                kev_added=str(cve.get("cisaExploitAdd") or "")[:10],
                status=str(cve.get("vulnStatus") or ""),
            )
        except (KeyError, TypeError, AttributeError):
            return None

    # Newest CVSS version first
    _METRIC_KEYS = [("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                    ("cvssMetricV2", "2.0")]

    @classmethod
    def _choose_metric(cls, metrics) -> Optional[tuple[str, dict]]:
        """Pick the CVSS entry to show: (version label, metric entry), or None if unscored.

        NVD's own assessment ("Primary") wins over scores from the CVE's assigner or other
        providers ("Secondary"), which NVD often lists first; within each, the newest CVSS
        version wins.
        """
        if not isinstance(metrics, dict):
            return None
        for wanted in ("Primary", None):
            for key, label in cls._METRIC_KEYS:
                entries = metrics.get(key)
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if (isinstance(entry, dict) and isinstance(entry.get("cvssData"), dict)
                            and (wanted is None or entry.get("type") == wanted)):
                        return label, entry
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

    def scan_software(self, software: SoftwareInfo) -> VulnerabilityResult:
        """Ask NVD which CVEs affect this program at its installed version.

        NVD decides whether a CVE applies (it compares the CPE name with each CVE's version
        ranges), so results are not filtered again here. Programs without a CPE mapping, or
        with a version that can't go into a CPE name, are marked as not checked.
        """
        result = VulnerabilityResult(
            software_name=software.name,
            software_version=software.version,
        )

        if self._should_skip_software(software.name):
            result.not_checked = "framework or update package"
            return result

        mapping = self._find_mapping(software.name)
        if not mapping:
            result.not_checked = "no CPE mapping"
            return result
        vendor, product = mapping
        cpe_version = self._cpe_version(vendor, product, software.version)
        if not cpe_version:
            result.not_checked = "version can't be used in a CPE name"
            return result
        result.cpe = self._cpe_name(vendor, product, cpe_version)

        try:
            vulnerabilities, result.total_available = self._query_affecting_cves(vendor, product, cpe_version)
        except NvdApiError as e:
            result.error = str(e)
            return result

        for vuln in vulnerabilities:
            cve = self._parse_cve(vuln)
            if not cve:
                continue
            # Every severity, including LOW and not yet scored. NVD decided the CVE matches;
            # only set aside the ones where NVD gives no version information at all.
            if self._listed_for_every_version(vuln, vendor, product):
                result.all_versions.append(cve)
            else:
                result.cves.append(cve)

        phrase = self.SEARCH_PHRASES.get((vendor, product))
        if phrase:
            try:
                confirmed = {c.cve_id for c in result.cves + result.all_versions}
                for vuln in self._query_unanalysed_cves(phrase):
                    cve = self._parse_cve(vuln)
                    if cve and cve.cve_id not in confirmed:
                        result.unconfirmed.append(cve)
            except NvdApiError as e:
                result.error = str(e)   # the confirmed list above is still valid

        # Known-exploited first, then by severity (CRITICAL first) and score
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        result.cves.sort(key=lambda c: (not c.known_exploited, severity_order.get(c.severity, 4), -c.cvss_score))
        return result

    def plan_scan(self, software_list: list[SoftwareInfo], limit: int = 20) -> VulnScanPlan:
        """Choose which programs to look up: mapped ones, in name order, once per product+version.

        The order doesn't depend on registry order, so --cve-limit always keeps the same
        programs. Everything left out is counted so the summary can say what wasn't checked.
        """
        plan = VulnScanPlan(limit=max(1, min(limit, 100)))   # cap to prevent API abuse
        candidates, seen = [], set()
        for software in sorted(software_list, key=lambda s: (s.name.lower(), s.version)):
            if self._should_skip_software(software.name):
                plan.skipped += 1
                continue
            mapping = self._find_mapping(software.name)
            if not mapping:
                plan.unmapped.append(software)
                continue
            cpe_version = self._cpe_version(*mapping, software.version)
            if not cpe_version:
                plan.no_version += 1
                continue
            key = (*mapping, cpe_version)
            if key in seen:            # e.g. Python's installer adds ~10 entries with one version
                plan.duplicates += 1
                continue
            seen.add(key)
            candidates.append(software)
        plan.targets = candidates[:plan.limit]
        plan.over_limit = len(candidates) - len(plan.targets)
        return plan

    def scan_plan(self, plan: VulnScanPlan, progress_callback=None) -> list[VulnerabilityResult]:
        """Look up every program in the plan. Returns one result per program, clean ones included."""
        results = []
        for done, software in enumerate(plan.targets):
            if progress_callback:
                # How many are finished, and which one is being looked up now
                progress_callback(done, len(plan.targets), software.name)
            results.append(self.scan_software(software))
        return results

    def scan_software_list(
        self, software_list: list[SoftwareInfo], progress_callback=None,
        limit: int = 20,
    ) -> list[VulnerabilityResult]:
        """plan_scan() then scan_plan(): one result per program checked."""
        return self.scan_plan(self.plan_scan(software_list, limit), progress_callback)

    @staticmethod
    def _print_cve_ids(cves: list[CVEInfo], label, shown: int = 9) -> None:
        """Compact list: up to `shown` CVE IDs, three per line, each with label(cve)."""
        labels = [f"{sanitize_output(c.cve_id)} ({sanitize_output(label(c))})" for c in cves[:shown]]
        for i in range(0, len(labels), 3):
            print("    " + ", ".join(labels[i:i + 3]))
        if len(cves) > shown:
            print(f"    ... and {len(cves) - shown} more")

    @classmethod
    def _print_unconfirmed(cls, result: VulnerabilityResult) -> None:
        """List recent CVEs that mention the product but have no NVD product data yet."""
        print(f"\n  Unconfirmed: {len(result.unconfirmed)} recent CVE(s) mention this product, but NVD hasn't")
        print("  analysed them yet, so it can't say which versions they affect. Check whether")
        print("  your version is affected (not counted above):")
        cls._print_cve_ids(result.unconfirmed, lambda c: c.status or "status unknown")

    @classmethod
    def _print_all_versions(cls, result: VulnerabilityResult) -> None:
        """List CVEs NVD records for every version of the product (no version information)."""
        print(f"\n  Listed for every version: NVD records {len(result.all_versions)} CVE(s) for all versions of")
        print("  this product, without a version range, so they may not apply to yours")
        print("  (often old, or about the product in general; not counted above):")
        cls._print_cve_ids(result.all_versions, lambda c: f"published {c.published_date}" if c.published_date
                           else "no date")

    @staticmethod
    def _print_coverage(results: list[VulnerabilityResult], plan: Optional[VulnScanPlan]) -> None:
        """What was and wasn't checked: the summary must never read as an all-clear it can't give."""
        checked = [r for r in results if not r.not_checked and not r.error]
        failed = [r for r in results if r.error]
        print(f"Checked {len(checked)} program(s) against NVD (CVEs for each program's exact version).")
        if plan:
            left_out = []
            if plan.unmapped:
                left_out.append(f"{len(plan.unmapped)} without a CPE mapping")
            if plan.skipped:
                left_out.append(f"{plan.skipped} framework/update package(s)")
            if plan.no_version:
                left_out.append(f"{plan.no_version} without a usable version")
            if plan.duplicates:
                left_out.append(f"{plan.duplicates} duplicate(s) of a checked program")
            if plan.over_limit:
                left_out.append(f"{plan.over_limit} over --cve-limit {plan.limit}")
            if left_out:
                print("Not checked: " + ", ".join(left_out) + ".")
            if plan.unmapped:
                names = sorted({sanitize_output(s.name) for s in plan.unmapped}, key=str.lower)
                more = f", ... (+{len(names) - 8} more)" if len(names) > 8 else ""
                print("  Without a mapping, e.g.: " + ", ".join(names[:8]) + more)
        if failed:
            print(f"Failed: {len(failed)} program(s): NVD could not be queried (results incomplete).")

    def display_results(self, results: list[VulnerabilityResult], plan: Optional[VulnScanPlan] = None) -> None:
        """Display vulnerability scan results, starting with what was and wasn't checked."""
        affected = [r for r in results if r.cves]
        total_cves = sum(r.total_count for r in results)
        critical_count = sum(r.critical_count for r in results)
        high_count = sum(r.high_count for r in results)
        kev_count = sum(r.kev_count for r in results)
        unconfirmed_count = sum(len(r.unconfirmed) for r in results)

        print(f"{'='*80}")
        print(f"VULNERABILITY SCAN RESULTS")
        print(f"{'='*80}")
        self._print_coverage(results, plan)
        print()
        checked = sum(1 for r in results if not r.not_checked and not r.error)
        if affected:
            print(f"Affected: {len(affected)} program(s), {total_cves} CVE(s)")
            print(f"  Known exploited (KEV): {kev_count}")
            print(f"  CRITICAL: {critical_count}")
            print(f"  HIGH: {high_count}")
        elif checked:
            print(f"No known CVEs affect the {checked} program(s) checked.")
        else:
            print("No programs were checked, so nothing can be said about CVEs.")
        all_versions_count = sum(len(r.all_versions) for r in results)
        if all_versions_count:
            print(f"Listed by NVD for every version (no version range, not counted): {all_versions_count}")
        if unconfirmed_count:
            print(f"Unconfirmed (not yet analysed by NVD, not counted): {unconfirmed_count}")
        print(f"{'='*80}\n")

        for result in results:
            has_lists = result.cves or result.unconfirmed or result.all_versions
            if result.error:
                print(f"[ERROR] {sanitize_output(result.software_name)}: Query failed")
            if not has_lists:
                continue

            print(f"\n{sanitize_output(result.software_name)} (v{sanitize_output(result.software_version)})")
            fetched = len(result.cves) + len(result.all_versions)
            if result.total_available > fetched:
                print(f"  {result.total_available} CVE(s) affect this version "
                      f"(first {fetched} fetched; page limit reached):")
            elif result.cves:
                print(f"  {result.total_count} CVE(s) affect this version:")

            for cve in result.cves[:5]:  # Show top 5 per software
                kev = " [KEV: known exploited]" if cve.known_exploited else ""
                print(f"\n  {cve.severity_color} {sanitize_output(cve.cve_id)} ({sanitize_output(cve.score_label)}){kev}")
                print(f"      Severity: {sanitize_output(cve.severity)}")
                print(f"      Published: {sanitize_output(cve.published_date)}")
                # Wrap description
                safe_desc = sanitize_output(cve.description)
                desc_lines = [safe_desc[i:i+60] for i in range(0, len(safe_desc), 60)]
                for line in desc_lines:
                    print(f"      {line}")

            if len(result.cves) > 5:
                print(f"\n  ... and {len(result.cves) - 5} more CVE(s)")
            if result.all_versions:
                self._print_all_versions(result)
            if result.unconfirmed:
                self._print_unconfirmed(result)

        print(f"\n{'='*80}")
        print("RECOMMENDATIONS:")
        print("  1. Update software to the latest versions")
        print("  2. Review critical/high severity CVEs for your specific versions")
        print("  3. Check vendor advisories for patches and mitigations")
        print("  4. Consider removing software that is no longer maintained")
        print(f"{'='*80}")
        print("\nNote: Results come from NVD's product (CPE) data for each program's exact")
        print("version. Programs without a CPE mapping are not checked. Always verify")
        print("against official vendor advisories.")


class SoftwareEnumerator:
    """Main orchestrator for software enumeration."""

    def __init__(self):
        self.registry_scanner = RegistryScanner()
        self.store_scanner = StoreAppScanner()
        self.portable_scanner = PortableAppScanner()

    def scan_all(self, sources: list[str] = None, show_progress: bool = True) -> list[SoftwareInfo]:
        """Scan all or specified sources for installed software.

        Sources are scanned concurrently using a thread pool for faster results.
        """
        if sources is None:
            sources = ["registry", "store", "portable"]

        source_callables = {
            "registry": self.registry_scanner.get_all_registry_software,
            "store": self.store_scanner.get_store_apps,
            "portable": self.portable_scanner.get_all_portable_apps,
        }

        all_software = []
        total_sources = len(sources)

        if show_progress:
            progress = ProgressBar(total=total_sources, prefix="Scanning")

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_source = {
                executor.submit(source_callables[src]): src
                for src in sources if src in source_callables
            }
            completed = 0
            for future in concurrent.futures.as_completed(future_to_source):
                src_name = future_to_source[future]
                completed += 1
                try:
                    result = future.result()
                    all_software.extend(result)
                    if show_progress:
                        progress.update(completed, f"{src_name}: {len(result)} found")
                except Exception as e:
                    logger.error(f"Error scanning {src_name}: {e}")
                    if show_progress:
                        progress.update(completed, f"{src_name}: error")

        if show_progress:
            progress.finish(f"Complete: {len(all_software)} total")

        return all_software

    def filter_results(
        self, software_list: list[SoftwareInfo], search_term: str = None,
        exclude_terms: list[str] = None
    ) -> list[SoftwareInfo]:
        """Filter software list by search term and exclusion patterns."""
        if search_term:
            software_list = [s for s in software_list if s.matches_search(search_term)]
        if exclude_terms:
            software_list = [
                s for s in software_list
                if not any(s.matches_exclude(term) for term in exclude_terms)
            ]
        return software_list

    def sort_results(
        self, software_list: list[SoftwareInfo], sort_by: str = "name"
    ) -> list[SoftwareInfo]:
        """Sort software list by specified field."""
        sort_keys = {
            "name": lambda s: s.name.lower(),
            "version": lambda s: VulnerabilityScanner._parse_version(s.version) or (0,),
            "publisher": lambda s: s.publisher.lower(),
            "source": lambda s: s.source.lower(),
        }

        key_func = sort_keys.get(sort_by, sort_keys["name"])
        return sorted(software_list, key=key_func)

    def display_table(self, software_list: list[SoftwareInfo], quiet: bool = False) -> None:
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

        if not quiet:
            print(f"\nTotal: {len(software_list)} software items found.")


class SoftwareExporter:
    """Handles exporting software lists to various formats."""

    @staticmethod
    def _sanitize_software_dict(software: SoftwareInfo) -> dict:
        """Convert SoftwareInfo to dict with sanitized string fields.

        Every field is sanitized: entries can come from a baseline file on disk,
        where even install_date and source are untrusted.
        """
        return {
            "name": sanitize_output(software.name),
            "version": sanitize_output(software.version),
            "publisher": sanitize_output(software.publisher),
            "install_date": sanitize_output(software.install_date),
            "source": sanitize_output(software.source),
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
        # "\n", not csv's default "\r\n": the text is written through a text-mode stream
        # (stdout or a file), which already turns "\n" into "\r\n" on Windows. With "\r\n"
        # here every line would end "\r\r\n" and Excel shows a blank row between records.
        writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_ALL,
                                lineterminator="\n")
        writer.writeheader()

        for software in software_list:
            row = SoftwareExporter._sanitize_software_dict(software)
            writer.writerow({k: csv_safe_cell(v) for k, v in row.items()})

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
            # CSV text already ends with a line ending; JSON doesn't, so print() adds one.
            print(content, end="" if format == "csv" else "\n")


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

        Raises:
            IsADirectoryError: If the path is a folder
            OSError: If the file can't be written (PermissionError when access is denied)
        """
        if os.path.isdir(filepath):
            raise IsADirectoryError(filepath)

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
            IsADirectoryError: If the path is a folder
            OSError: If the file can't be read (PermissionError when access is denied)
            ValueError: If baseline format is invalid or incompatible version
        """
        if os.path.isdir(filepath):
            raise IsADirectoryError(filepath)

        # Guard against excessively large baseline files (max 50 MB)
        file_size = os.path.getsize(filepath)
        max_baseline_size = 50 * 1024 * 1024
        if file_size > max_baseline_size:
            raise ValueError(
                f"Baseline file too large ({file_size / 1024 / 1024:.1f} MB). "
                f"Maximum allowed size is {max_baseline_size // 1024 // 1024} MB."
            )

        with open(filepath, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except RecursionError:
                raise ValueError("Invalid baseline format: nested too deeply") from None

        # The file is untrusted input: check its shape before using it, so a malformed
        # file gives a clear error instead of a crash
        if not isinstance(data, dict) or "version" not in data or "software" not in data:
            raise ValueError("Invalid baseline format: missing required fields")

        # Validate baseline version compatibility
        baseline_version = data["version"]
        if not isinstance(baseline_version, str):
            raise ValueError("Invalid baseline format: the version must be text")
        if not baseline_version.startswith("1."):
            raise ValueError(
                f"Incompatible baseline version: {baseline_version}. "
                f"Expected version 1.x, got {baseline_version}. "
                f"Please create a new baseline with the current tool version."
            )

        entries = data["software"]
        if not isinstance(entries, list):
            raise ValueError("Invalid baseline format: 'software' must be a list")

        # Guard against excessively large baselines
        max_baseline_entries = 50_000
        entry_count = len(entries)
        if entry_count > max_baseline_entries:
            raise ValueError(
                f"Baseline contains {entry_count} entries, exceeding the "
                f"maximum of {max_baseline_entries}."
            )

        sources = data.get("sources", [])
        if not isinstance(sources, list) or not all(isinstance(s, str) for s in sources):
            raise ValueError("Invalid baseline format: 'sources' must be a list of text")

        # A malformed entry rejects the whole file: skipping it would make that program
        # show up as added or removed, which is worse than no comparison
        software_list = []
        for number, item in enumerate(entries, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"Invalid baseline format: entry {number} is not an object")
            software_list.append(SoftwareInfo(**{
                key: BaselineManager._entry_text(item.get(key), number, key)
                for key in ("name", "version", "publisher", "install_date", "source", "install_location")
            }))

        metadata = {
            "version": data.get("version"),
            "created_at": data.get("created_at"),
            "hostname": data.get("hostname"),
            "user": data.get("user"),
            "sources": sources,
            "software_count": data.get("software_count"),
        }

        return software_list, metadata

    @staticmethod
    def _entry_text(value, number: int, key: str) -> str:
        """A text field of a baseline entry: text as is, numbers as text, missing or null empty.

        Numbers are accepted because baselines saved by older versions can hold them (registry
        DWORD values used to be stored unconverted). Anything else rejects the file.
        """
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
        raise ValueError(f"Invalid baseline format: entry {number} has a {key} that isn't text")

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
    def diff_to_json(diff: BaselineDiff, baseline_metadata: dict, baseline_file: str) -> str:
        """Render a baseline diff as JSON, with every string field sanitized."""
        sanitize = SoftwareExporter._sanitize_software_dict
        diff_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "baseline_file": sanitize_output(baseline_file),
                "baseline_created": sanitize_output(baseline_metadata.get("created_at")),
                "baseline_hostname": sanitize_output(baseline_metadata.get("hostname")),
            },
            "summary": {
                "added_count": len(diff.added),
                "removed_count": len(diff.removed),
                "changed_count": len(diff.changed),
                "total_changes": diff.total_changes,
            },
            "added": [sanitize(s) for s in diff.added],
            "removed": [sanitize(s) for s in diff.removed],
            "changed": [
                {"baseline": sanitize(b), "current": sanitize(c)}
                for b, c in diff.changed
            ],
        }
        return json.dumps(diff_data, indent=2, ensure_ascii=False)

    @staticmethod
    def diff_to_csv(diff: BaselineDiff) -> str:
        """Render a baseline diff as CSV, with every field sanitized and formula-safe.

        Columns: change_type, name, baseline_version, current_version, publisher, source
        """
        output = io.StringIO()
        # "\n" for the same reason as SoftwareExporter.to_csv: the text-mode stream adds the "\r".
        writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\n")
        writer.writerow(["change_type", "name", "baseline_version", "current_version", "publisher", "source"])

        def row(change_type, name, baseline_version, current_version, publisher, source):
            writer.writerow([change_type] + [csv_safe_cell(v) for v in
                            (name, baseline_version, current_version, publisher, source)])

        for s in diff.added:
            row("added", s.name, "", s.version, s.publisher, s.source)
        for s in diff.removed:
            row("removed", s.name, s.version, "", s.publisher, s.source)
        for b, c in diff.changed:
            row("changed", c.name, b.version, c.version, c.publisher, c.source)

        return output.getvalue()

    @staticmethod
    def display_diff(diff: BaselineDiff, baseline_metadata: dict) -> None:
        """Display baseline comparison results.

        Args:
            diff: BaselineDiff object
            baseline_metadata: Metadata from the baseline file (untrusted; sanitized on display)
        """
        def meta(key: str) -> str:
            value = baseline_metadata.get(key)
            return "unknown" if value is None else sanitize_output(value)

        print("=" * 70)
        print("BASELINE COMPARISON RESULTS")
        print("=" * 70)
        print(f"Baseline created: {meta('created_at')}")
        print(f"Baseline host: {meta('hostname')}")
        print(f"Baseline software count: {meta('software_count')}")
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
                print(f"      Source: {sanitize_output(software.source)}")

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


def _cve_limit_arg(value: str) -> int:
    """argparse type for --cve-limit: a whole number from 1 to 100 (NVD rate limits)."""
    try:
        limit = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number from 1 to 100")
    if not 1 <= limit <= 100:
        raise argparse.ArgumentTypeError(f"must be from 1 to 100, not {limit}")
    return limit


def _parse_exclude_terms(value: Optional[str]) -> Optional[list[str]]:
    """Split a comma-separated --exclude value into terms, ignoring empty ones.

    An empty term would match every name ("" is in every string), so "chrome," must mean
    just "chrome", not "everything". Returns None when no terms are left.
    """
    if not value:
        return None
    terms = [t.strip() for t in value.split(",") if t.strip()]
    return terms or None


def main():
    """Main entry point for the CLI."""
    _harden_process_environment()
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
  %(prog)s --exclude "redistributable,.NET"  Exclude matching software
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
        default=None,
        help="Source to scan (default: all; registry for --check-vulns)",
    )

    parser.add_argument(
        "--search",
        type=str,
        help="Search/filter results by name, publisher, or version",
    )

    parser.add_argument(
        "--exclude",
        type=str,
        help="Exclude software matching patterns (comma-separated, e.g. 'redistributable,.NET Runtime')",
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
        help="NVD API key for faster vulnerability scanning. "
             "Prefer setting the NVD_API_KEY environment variable instead, "
             "as CLI arguments are visible in process listings",
    )

    parser.add_argument(
        "--cve-limit",
        type=_cve_limit_arg,
        default=20,
        metavar="N",
        help="Maximum number of programs to check for CVEs, 1-100 (default: 20)",
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

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress bars and informational output. Data output is still printed.",
    )

    args = parser.parse_args()

    # Setup logging before any operations
    try:
        setup_logging(log_file=args.log_file, verbose=args.verbose)
    except LogFileOwnershipError as e:
        print(f"Error: {sanitize_output(str(e))}", file=sys.stderr)
        sys.exit(EXIT_PERMISSION_DENIED)
    except PermissionError:
        print(f"Error: cannot create or write the log file: {sanitize_output(args.log_file)}", file=sys.stderr)
        sys.exit(EXIT_PERMISSION_DENIED)

    # Load API keys from .env files (won't overwrite existing env vars)
    _load_env_file()

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
        if not args.quiet:
            spinner = Spinner("Checking for updates via winget")
            spinner.spin()

        update_checker = WingetUpdateChecker()
        updates = update_checker.check_for_updates()

        if not args.quiet:
            spinner.finish(f"Found {len(updates)} available updates")
        log_audit_event("SCAN_END", "Update check completed", updates_found=len(updates))
        if not args.quiet:
            print(file=sys.stderr)
        update_checker.display_updates_table(updates)
        return

    # Handle browser extensions mode
    if args.extensions:
        log_audit_event("SCAN_START", "Browser extension scan", mode="extensions")
        if not args.quiet:
            spinner = Spinner("Scanning browser extensions")
            spinner.spin("Chrome, Edge, Firefox...")

        extension_scanner = BrowserExtensionScanner()
        extensions = extension_scanner.get_all_extensions()

        if not args.quiet:
            spinner.finish(f"Found {len(extensions)} extensions")
        sensitive_count = sum(1 for e in extensions if e.has_sensitive_permissions())
        log_audit_event(
            "SCAN_END",
            "Browser extension scan completed",
            extensions_found=len(extensions),
            sensitive_permissions=sensitive_count,
        )
        if not args.quiet:
            print(file=sys.stderr)
        extension_scanner.display_extensions_table(extensions)
        return

    # Handle vulnerability scanning mode
    if args.check_vulns:
        log_audit_event("SCAN_START", "Vulnerability scan via NVD", mode="check-vulns")
        if not args.quiet:
            print("Scanning for known vulnerabilities (CVEs)...", file=sys.stderr)
            print("This may take a while due to API rate limits.\n", file=sys.stderr)

        # Registry by default (the most reliable versions); --source chooses others
        vuln_sources = (["registry", "store", "portable"] if args.source == "all"
                        else [args.source or "registry"])
        enumerator = SoftwareEnumerator()
        software_list = enumerator.scan_all(vuln_sources, show_progress=not args.quiet)
        software_list = enumerator.filter_results(software_list, args.search, _parse_exclude_terms(args.exclude))
        if not args.quiet:
            print(file=sys.stderr)

        vuln_scanner = VulnerabilityScanner(api_key=args.nvd_api_key)
        plan = vuln_scanner.plan_scan(software_list, limit=args.cve_limit)

        progress_callback = None
        if not args.quiet:
            progress = ProgressBar(total=len(plan.targets), prefix="CVE Check")

            def progress_callback(current, total, name):
                progress.update(current, name)
                logger.debug(f"Scanning for CVEs: {name}")

        results = vuln_scanner.scan_plan(plan, progress_callback=progress_callback)
        if not args.quiet:
            progress.finish("Complete")

        total_cves = sum(r.total_count for r in results)
        critical_count = sum(r.critical_count for r in results)
        log_audit_event(
            "SCAN_END",
            "Vulnerability scan completed",
            software_scanned=len(plan.targets),
            not_checked=len(plan.unmapped) + plan.no_version + plan.over_limit,
            cves_found=total_cves,
            critical_cves=critical_count,
            failed=sum(1 for r in results if r.error),
        )

        if not args.quiet:
            print(file=sys.stderr)
        vuln_scanner.display_results(results, plan)
        if any(r.error for r in results):
            # Results are incomplete; scripts must not read this as "no CVEs"
            sys.exit(EXIT_API_FAILURE)
        return

    # Determine sources to scan
    if args.source in (None, "all"):
        sources = ["registry", "store", "portable"]
    else:
        sources = [args.source]

    # Read the baseline before scanning, so a wrong path or a bad file fails at once
    # instead of after a full scan
    if args.diff:
        shown_path = sanitize_output(args.diff)
        try:
            baseline_list, baseline_metadata = BaselineManager.load_baseline(args.diff)
        except FileNotFoundError:
            print(f"Error: Baseline file not found: {shown_path}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        except IsADirectoryError:
            print(f"Error: {shown_path} is a folder, not a baseline file", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        except PermissionError:
            print(f"Error: cannot read the baseline file (access denied): {shown_path}", file=sys.stderr)
            sys.exit(EXIT_PERMISSION_DENIED)
        except OSError:
            print(f"Error: cannot read the baseline file: {shown_path}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        except ValueError as e:   # also invalid JSON and invalid UTF-8
            print(f"Error: Invalid baseline file: {sanitize_output(str(e))}", file=sys.stderr)
            sys.exit(EXIT_ERROR)

    # Run enumeration
    log_audit_event(
        "SCAN_START",
        "Software enumeration",
        mode="enumerate",
        sources=",".join(sources),
        search_filter=args.search or "none",
    )

    enumerator = SoftwareEnumerator()
    # Suppress progress output if outputting to JSON/CSV (for clean piping) or quiet mode
    show_progress = args.output == "table" and not args.diff and not args.quiet
    software_list = enumerator.scan_all(sources, show_progress=show_progress)
    exclude_terms = _parse_exclude_terms(args.exclude)
    software_list = enumerator.filter_results(software_list, args.search, exclude_terms)
    software_list = enumerator.sort_results(software_list, args.sort)

    log_audit_event(
        "SCAN_END",
        "Software enumeration completed",
        total_software=len(software_list),
    )

    # Handle baseline diff mode
    if args.diff:
        # Warn if sources don't match
        baseline_sources = set(baseline_metadata.get("sources", []))
        current_sources = set(sources)
        if baseline_sources and baseline_sources != current_sources:
            print("WARNING: Source mismatch detected!", file=sys.stderr)
            # The names come from the baseline file (untrusted), so sanitize them
            print(f"  Baseline sources: {sanitize_output(', '.join(sorted(baseline_sources))) or 'unknown'}",
                  file=sys.stderr)
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
            print(BaselineManager.diff_to_json(diff, baseline_metadata, args.diff))
        elif args.output == "csv":
            print(BaselineManager.diff_to_csv(diff), end="")   # CSV text ends with its own line ending
        else:
            BaselineManager.display_diff(diff, baseline_metadata)

        return

    # Handle save baseline
    if args.save_baseline:
        if not software_list:
            print("ERROR: No software found to save in baseline!", file=sys.stderr)
            print("The baseline would be empty. Check your --source, --search, and --exclude options.", file=sys.stderr)
            sys.exit(EXIT_NO_SOFTWARE)

        shown_path = sanitize_output(args.save_baseline)
        try:
            BaselineManager.save_baseline(software_list, args.save_baseline, sources=sources)
        except IsADirectoryError:
            print(f"Error: {shown_path} is a folder; give a file name for the baseline", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        except FileNotFoundError:
            print(f"Error: cannot write the baseline file (its folder doesn't exist): {shown_path}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        except PermissionError:
            print(f"Error: cannot write the baseline file (access denied): {shown_path}", file=sys.stderr)
            sys.exit(EXIT_PERMISSION_DENIED)
        except OSError:
            print(f"Error: cannot write the baseline file: {shown_path}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        if not args.quiet:
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
        enumerator.display_table(software_list, quiet=args.quiet)

    if not software_list:
        sys.exit(EXIT_NO_SOFTWARE)


def _running_as_frozen_exe() -> bool:
    """Check if running as a PyInstaller-bundled executable."""
    return getattr(sys, 'frozen', False)


if __name__ == "__main__":
    try:
        main()
    finally:
        if _running_as_frozen_exe():
            input("\nPress Enter to exit...")
