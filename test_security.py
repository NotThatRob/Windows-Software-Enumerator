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

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import json

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
