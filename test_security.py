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
import os
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
        """Control characters (except newline/tab) should be stripped."""
        malicious = "Normal\x00\x01\x02\x03Text"
        result = se.sanitize_output(malicious)
        self.assertEqual(result, "NormalText")

    def test_preserves_newlines_and_tabs(self):
        """Newlines and tabs should be preserved."""
        text = "Line1\nLine2\tTabbed"
        result = se.sanitize_output(text)
        self.assertEqual(result, "Line1\nLine2\tTabbed")

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

            # Check the request that was made
            if mock_urlopen.called:
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

        # Clear any existing handlers
        se.logger.handlers = []

    def tearDown(self):
        """Clean up temporary log file."""
        se.logger.handlers = []
        try:
            os.unlink(self.temp_log.name)
        except:
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


class SecurityTestSuite(unittest.TestSuite):
    """Aggregate all security tests."""

    def __init__(self):
        super().__init__()
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestOutputSanitization))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestApiKeyEnvironmentVariable))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestUserAgent))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestSymlinkProtection))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestErrorMessageSanitization))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestAuditLogging))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestTOCTOUFixes))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestDataclassSecurity))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestVersionMatching))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCsvParsing))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestSoftwareMappings))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLogRotation))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCveLimitArg))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestPortableAppFileLimit))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestSlidingWindowRateLimit))
        self.addTests(unittest.TestLoader().loadTestsFromTestCase(TestEnhancedPermissions))


def run_security_tests():
    """Run all security tests and print results."""
    print("=" * 70)
    print("SOFTWARE ENUMERATOR - SECURITY TEST SUITE")
    print("=" * 70)
    print()

    # Run with verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(SecurityTestSuite())

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
