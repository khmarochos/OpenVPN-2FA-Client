#!/usr/bin/env python3

import unittest
import tempfile
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

# Import the module to test
import openvpn


class TestTOTPFunctionality(unittest.TestCase):
    """Test TOTP code generation functionality."""
    
    def test_totp_now_valid_secret(self):
        """Test TOTP generation with valid secret."""
        # Known test vectors
        secret = "JBSWY3DPEHPK3PXP"  # "Hello!" in Base32
        
        # Mock time to get predictable results
        with patch('time.time', return_value=1234567890):
            code = openvpn.totp_now(secret)
            self.assertEqual(len(code), 6)
            self.assertTrue(code.isdigit())
    
    def test_totp_now_different_times(self):
        """Test that TOTP codes change over time."""
        secret = "JBSWY3DPEHPK3PXP"
        
        with patch('time.time', return_value=1234567890):
            code1 = openvpn.totp_now(secret)
        
        with patch('time.time', return_value=1234567890 + 30):
            code2 = openvpn.totp_now(secret)
        
        # Codes should be different after 30 seconds
        self.assertNotEqual(code1, code2)
    
    def test_totp_now_case_insensitive(self):
        """Test that TOTP works with lowercase secrets."""
        secret_upper = "JBSWY3DPEHPK3PXP"
        secret_lower = "jbswy3dpehpk3pxp"
        
        with patch('time.time', return_value=1234567890):
            code_upper = openvpn.totp_now(secret_upper)
            code_lower = openvpn.totp_now(secret_lower)
        
        self.assertEqual(code_upper, code_lower)
    
    def test_totp_now_with_spaces(self):
        """Test that TOTP works with spaces in secret."""
        secret_no_spaces = "JBSWY3DPEHPK3PXP"
        secret_with_spaces = "JBSW Y3DP EHPK 3PXP"
        
        with patch('time.time', return_value=1234567890):
            code_no_spaces = openvpn.totp_now(secret_no_spaces)
            code_with_spaces = openvpn.totp_now(secret_with_spaces)
        
        self.assertEqual(code_no_spaces, code_with_spaces)


class TestValidationFunctions(unittest.TestCase):
    """Test input validation functions."""
    
    def test_validate_totp_secret_valid(self):
        """Test valid TOTP secrets."""
        valid_secrets = [
            "JBSWY3DPEHPK3PXP",
            "ABCDEFGHIJKLMNOP",
            "234567ABCDEFGHIJ",  # valid Base32 chars only
            "jbswy3dpehpk3pxp",  # lowercase
            "JBSW Y3DP EHPK 3PXP",  # with spaces
        ]
        
        for secret in valid_secrets:
            with self.subTest(secret=secret):
                normalized = openvpn.validate_totp_secret(secret)
                self.assertTrue(normalized.isupper())
                self.assertNotIn(" ", normalized)
    
    def test_validate_totp_secret_invalid(self):
        """Test invalid TOTP secrets."""
        invalid_secrets = [
            "",  # empty
            "SHORT",  # too short
            "INVALID_CHARACTERS!",  # invalid chars
            "0189",  # invalid Base32 chars (0, 1, 8, 9)
            "A" * 65,  # too long
        ]
        
        for secret in invalid_secrets:
            with self.subTest(secret=secret):
                with self.assertRaises(ValueError):
                    openvpn.validate_totp_secret(secret)
    
    def test_validate_credentials_valid(self):
        """Test valid username and PIN combinations."""
        valid_creds = [
            ("username", "pin123"),
            ("user@domain.com", "complex_pin_456"),
            ("test_user", "789"),
        ]
        
        for name, pin in valid_creds:
            with self.subTest(name=name, pin=pin):
                validated_name, validated_pin = openvpn.validate_credentials(name, pin)
                self.assertEqual(validated_name, name.strip())
                self.assertEqual(validated_pin, pin.strip())
    
    def test_validate_credentials_invalid(self):
        """Test invalid username and PIN combinations."""
        invalid_creds = [
            ("", "pin"),  # empty username
            ("user", ""),  # empty PIN
            ("  ", "pin"),  # whitespace-only username
            ("user", "  "),  # whitespace-only PIN
            ("user<script>", "pin"),  # invalid characters
            ("A" * 257, "pin"),  # username too long
            ("user", "A" * 257),  # PIN too long
        ]
        
        for name, pin in invalid_creds:
            with self.subTest(name=name, pin=pin):
                with self.assertRaises(ValueError):
                    openvpn.validate_credentials(name, pin)


class TestFileOperations(unittest.TestCase):
    """Test file operations and security."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = Path(self.temp_dir) / "test_credentials.txt"
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_update_credentials_file_creates_file(self):
        """Test that credentials file is created correctly."""
        secret = "JBSWY3DPEHPK3PXP"
        name = "testuser"
        pin = "1234"
        
        with patch('time.time', return_value=1234567890):
            result_file = openvpn.update_credentials_file(secret, name, pin, self.test_file)
        
        self.assertEqual(result_file, self.test_file)
        self.assertTrue(self.test_file.exists())
        
        # Check file permissions (should be 600)
        stat_info = self.test_file.stat()
        permissions = oct(stat_info.st_mode)[-3:]
        self.assertEqual(permissions, "600")
        
        # Check file content
        content = self.test_file.read_text()
        lines = content.strip().split('\n')
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], name)
        self.assertTrue(lines[1].startswith(pin))
        self.assertEqual(len(lines[1]), len(pin) + 6)  # PIN + 6-digit TOTP
    
    def test_update_credentials_file_creates_parent_dir(self):
        """Test that parent directories are created."""
        nested_file = Path(self.temp_dir) / "nested" / "dir" / "credentials.txt"
        secret = "JBSWY3DPEHPK3PXP"
        name = "testuser"
        pin = "1234"
        
        openvpn.update_credentials_file(secret, name, pin, nested_file)
        
        self.assertTrue(nested_file.exists())
        self.assertTrue(nested_file.parent.exists())
    
    def test_update_credentials_file_invalid_secret(self):
        """Test handling of invalid TOTP secret."""
        invalid_secret = "INVALID_SECRET!"
        name = "testuser"
        pin = "1234"
        
        with self.assertRaises(SystemExit):
            openvpn.update_credentials_file(invalid_secret, name, pin, self.test_file)


class TestDefaultPaths(unittest.TestCase):
    """Test default path generation."""
    
    def test_get_default_paths_with_defaults(self):
        """Test default path generation with default values."""
        creds_file, config_paths = openvpn.get_default_paths()
        
        expected_creds = f"{openvpn.DEFAULT_CREDENTIALS_DIR}/user@openvpn.example.org_credentials.txt"
        self.assertEqual(creds_file, expected_creds)
        
        self.assertIsInstance(config_paths, list)
        self.assertTrue(len(config_paths) > 0)
        
        # Check that all expected patterns are present
        expected_patterns = [
            "user@openvpn.example.org.ovpn",
            "openvpn.example.org/user.ovpn",
            "openvpn.example.org.ovpn"
        ]
        
        for pattern in expected_patterns:
            found = any(pattern in path for path in config_paths)
            self.assertTrue(found, f"Pattern '{pattern}' not found in config paths")
    
    def test_get_default_paths_with_custom_values(self):
        """Test default path generation with custom server and username."""
        server = "company.vpn"
        username = "johndoe"
        
        creds_file, config_paths = openvpn.get_default_paths(server, username)
        
        expected_creds = f"{openvpn.DEFAULT_CREDENTIALS_DIR}/johndoe@company.vpn_credentials.txt"
        self.assertEqual(creds_file, expected_creds)
        
        # Check that custom values appear in config paths
        found_custom = any("johndoe@company.vpn" in path for path in config_paths)
        self.assertTrue(found_custom)


class TestSensitiveDataHandling(unittest.TestCase):
    """Test sensitive data clearing functionality."""
    
    def test_clear_sensitive_data_strings(self):
        """Test clearing string variables."""
        # Note: Python strings are immutable, so this is mainly for intent
        secret = "SENSITIVE_SECRET"
        pin = "1234"
        
        # This function primarily serves as a security indicator
        openvpn.clear_sensitive_data(secret, pin)
        
        # The function should complete without error
        self.assertTrue(True)
    
    def test_clear_sensitive_data_bytearray(self):
        """Test clearing bytearray variables."""
        data = bytearray(b"sensitive_data")
        original_length = len(data)
        
        openvpn.clear_sensitive_data(data)
        
        # Bytearray should be zeroed
        self.assertEqual(len(data), original_length)
        self.assertEqual(data, bytearray(original_length))


class TestCredentialsInput(unittest.TestCase):
    """Test credential input functionality."""
    
    @patch.dict(os.environ, {
        'TOTP_KEY': 'JBSWY3DPEHPK3PXP',
        'AUTH_NAME': 'testuser',
        'AUTH_PIN': '1234'
    })
    def test_get_credentials_from_env(self):
        """Test getting credentials from environment variables."""
        secret, name, pin = openvpn.get_credentials()
        
        self.assertEqual(secret, 'JBSWY3DPEHPK3PXP')
        self.assertEqual(name, 'testuser')
        self.assertEqual(pin, '1234')
    
    @patch.dict(os.environ, {}, clear=True)
    @patch('getpass.getpass')
    def test_get_credentials_from_prompt(self, mock_getpass):
        """Test getting credentials from user prompts."""
        mock_getpass.side_effect = ['JBSWY3DPEHPK3PXP', 'testuser', '1234']
        
        secret, name, pin = openvpn.get_credentials()
        
        self.assertEqual(secret, 'JBSWY3DPEHPK3PXP')
        self.assertEqual(name, 'testuser')
        self.assertEqual(pin, '1234')
        
        # Check that getpass was called 3 times
        self.assertEqual(mock_getpass.call_count, 3)
    
    @patch.dict(os.environ, {}, clear=True)
    @patch('getpass.getpass')
    def test_get_credentials_invalid_input(self, mock_getpass):
        """Test handling of invalid credential input."""
        mock_getpass.side_effect = ['INVALID!', 'testuser', '1234']
        
        with self.assertRaises(SystemExit):
            openvpn.get_credentials()


class TestMainFunctions(unittest.TestCase):
    """Test main application functions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_config = Path(self.temp_dir) / "test.ovpn"
        self.test_config.write_text("[client]\nremote example.com 1194\n")
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('subprocess.run')
    @patch('os.geteuid')
    def test_run_openvpn_loop_as_root(self, mock_geteuid, mock_subprocess):
        """Test OpenVPN loop when running as root."""
        mock_geteuid.return_value = 0  # root
        mock_subprocess.return_value.returncode = 0
        
        secret = "JBSWY3DPEHPK3PXP"
        name = "testuser"
        pin = "1234"
        
        # Mock KeyboardInterrupt to exit loop
        mock_subprocess.side_effect = KeyboardInterrupt()
        
        # Should exit gracefully without error
        openvpn.run_openvpn_loop(
            secret, name, pin,
            config_file=str(self.test_config),
            credentials_file=str(Path(self.temp_dir) / "creds.txt")
        )
        
        # Verify subprocess was called
        mock_subprocess.assert_called()
    
    @patch('subprocess.run')
    @patch('os.geteuid')
    def test_run_openvpn_loop_as_user(self, mock_geteuid, mock_subprocess):
        """Test OpenVPN loop when running as regular user."""
        mock_geteuid.return_value = 1000  # regular user
        mock_subprocess.return_value.returncode = 0
        
        secret = "JBSWY3DPEHPK3PXP"
        name = "testuser"
        pin = "1234"
        
        # Mock KeyboardInterrupt to exit loop
        mock_subprocess.side_effect = KeyboardInterrupt()
        
        openvpn.run_openvpn_loop(
            secret, name, pin,
            config_file=str(self.test_config),
            credentials_file=str(Path(self.temp_dir) / "creds.txt")
        )
        
        # Verify sudo was used
        call_args = mock_subprocess.call_args[0][0]  # First positional arg
        self.assertEqual(call_args[0], 'sudo')
        self.assertIn('openvpn', call_args)
    
    @patch('subprocess.run')
    @patch('os.geteuid')
    @patch('time.sleep')
    def test_run_openvpn_loop_retry_logic(self, mock_sleep, mock_geteuid, mock_subprocess):
        """Test retry logic when OpenVPN fails."""
        mock_geteuid.return_value = 0
        
        # First 2 calls fail, 3rd succeeds, then KeyboardInterrupt
        mock_subprocess.side_effect = [
            MagicMock(returncode=1),  # First failure
            MagicMock(returncode=1),  # Second failure  
            MagicMock(returncode=1),  # Third failure (should exit)
        ]
        
        secret = "JBSWY3DPEHPK3PXP"
        name = "testuser"
        pin = "1234"
        
        with self.assertRaises(SystemExit):
            openvpn.run_openvpn_loop(
                secret, name, pin,
                config_file=str(self.test_config),
                credentials_file=str(Path(self.temp_dir) / "creds.txt")
            )
        
        # Should have called subprocess 3 times (max retries)
        self.assertEqual(mock_subprocess.call_count, 3)
    
    @patch('argparse.ArgumentParser.parse_args')
    @patch('openvpn.get_credentials')
    @patch('openvpn.update_credentials_file')
    def test_main_once_mode(self, mock_update_file, mock_get_creds, mock_parse_args):
        """Test main function in 'once' mode."""
        # Mock command line arguments
        mock_args = MagicMock()
        mock_args.once = True
        mock_args.credentials_file = None
        mock_args.server = "test.server"
        mock_args.username = "testuser"
        mock_parse_args.return_value = mock_args
        
        # Mock credentials
        mock_get_creds.return_value = ("JBSWY3DPEHPK3PXP", "testuser", "1234")
        
        # Mock file update
        mock_update_file.return_value = Path("/tmp/test_creds.txt")
        
        # Call main function
        openvpn.main()
        
        # Verify credentials were obtained and file was updated
        mock_get_creds.assert_called_once()
        mock_update_file.assert_called_once()
    
    @patch('argparse.ArgumentParser.parse_args')
    @patch('openvpn.get_credentials')
    @patch('openvpn.run_openvpn_loop')
    def test_main_normal_mode(self, mock_run_loop, mock_get_creds, mock_parse_args):
        """Test main function in normal mode."""
        # Mock command line arguments
        mock_args = MagicMock()
        mock_args.once = False
        mock_args.config = str(self.test_config)
        mock_args.credentials_file = None
        mock_args.server = "test.server"
        mock_args.username = "testuser"
        mock_parse_args.return_value = mock_args
        
        # Mock credentials
        mock_get_creds.return_value = ("JBSWY3DPEHPK3PXP", "testuser", "1234")
        
        # Call main function
        openvpn.main()
        
        # Verify credentials were obtained and OpenVPN loop was started
        mock_get_creds.assert_called_once()
        mock_run_loop.assert_called_once()


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)