# OpenVPN 2FA

A Python utility that automatically generates TOTP (Time-based One-Time Password) codes for OpenVPN connections requiring two-factor authentication.

## Features

- Generates TOTP codes using a Base32 secret key
- Automatically updates OpenVPN credentials file with fresh codes
- Runs OpenVPN in a loop with automatic reconnection
- Supports both environment variables and interactive prompts for credentials
- Secure credential file handling with proper permissions (600)
- Automatic retry logic with configurable limits

## Requirements

- Python 3.6+
- OpenVPN client
- TOTP secret key from your 2FA provider

## Installation

1. Clone or download the script
2. Make it executable: `chmod +x openvpn.py`
3. Ensure OpenVPN is installed on your system

## Usage

### Interactive Mode
```bash
./openvpn.py
```

### With Configuration File
```bash
./openvpn.py --config /path/to/your/config.ovpn
```

### With Custom Server/Username
```bash
./openvpn.py --server company.vpn --username john
```

### With Custom Credentials File
```bash
./openvpn.py --credentials-file /path/to/credentials.txt
```

### Generate Credentials Only
```bash
./openvpn.py --once
```

## Environment Variables

You can set these environment variables to avoid interactive prompts:

### Authentication Variables
- `TOTP_KEY`: Your Base32 TOTP secret key
- `AUTH_NAME`: Your username
- `AUTH_PIN`: Your PIN/password

### Configuration Variables
- `OPENVPN_SERVER`: VPN server hostname (default: openvpn.example.org)
- `OPENVPN_USERNAME`: VPN username (default: user)
- `OPENVPN_CREDENTIALS_FILE`: Path to credentials file (overrides auto-generated path)

Example:
```bash
export TOTP_KEY="JBSWY3DPEHPK3PXP"
export AUTH_NAME="myusername"
export AUTH_PIN="mypin"
export OPENVPN_SERVER="company.vpn"
export OPENVPN_USERNAME="john"
./openvpn.py
```

## Configuration

The script automatically generates file paths based on the server and username:

### Default Paths
- Server: `openvpn.example.org` (configurable with `--server` or `OPENVPN_SERVER`)
- Username: `user` (configurable with `--username` or `OPENVPN_USERNAME`)

### Configuration File Search Order
The script searches for OpenVPN config files in this order:
1. `~/.openvpn/{username}@{server}.ovpn`
2. `~/.openvpn/{server}/{username}.ovpn`
3. `~/.openvpn/{server}.ovpn`
4. `/etc/openvpn/client/{username}@{server}.ovpn`
5. `/etc/openvpn/client/{server}/{username}.ovpn`
6. `/etc/openvpn/client/{server}.ovpn`

### Credentials File Location
Default: `~/.openvpn/{username}@{server}_credentials.txt`

### Examples
- With defaults: `~/.openvpn/user@openvpn.example.org_credentials.txt`
- With custom settings: `~/.openvpn/john@company.vpn_credentials.txt`

## Security

- Credential files are created with 600 permissions (owner read/write only)
- TOTP secrets are not stored persistently unless set as environment variables
- Use environment variables or secure input methods for production use

## Command Line Options

- `--config`, `-c`: Specify OpenVPN configuration file path
- `--credentials-file`, `-f`: Specify credentials file path (overrides auto-generated path)
- `--server`, `-s`: VPN server hostname (default: openvpn.example.org)
- `--username`, `-u`: VPN username (default: user)
- `--once`, `-1`: Generate credentials file once and exit (don't run OpenVPN)
- `--help`: Show help message

## Testing

The project includes comprehensive tests to ensure reliability and security.

### Running Tests

```bash
# Run all tests
python3 test_openvpn.py

# Or use the test runner for better output
./run_tests.py
```

### Test Coverage

The test suite covers:

- **TOTP Functionality**: Validates TOTP code generation, time-based changes, case insensitivity, and space handling
- **Input Validation**: Tests validation of TOTP secrets, usernames, and PINs with both valid and invalid inputs  
- **File Operations**: Verifies secure file creation, permissions (600), parent directory creation, and error handling
- **Path Generation**: Tests default path generation with various server/username combinations
- **Security Features**: Tests sensitive data clearing functionality
- **Main Functions**: Integration tests for command-line modes, retry logic, and OpenVPN execution
- **Error Handling**: Validates proper handling of invalid inputs and system errors

### Test Requirements

Tests use Python's built-in `unittest` framework and require no additional dependencies. All tests use mocking to avoid external dependencies and ensure consistent, fast execution.

## How It Works

1. Prompts for or reads TOTP secret, username, and PIN
2. Generates current TOTP code based on current time
3. Creates/updates OpenVPN credentials file with username and PIN+TOTP
4. Runs OpenVPN with the credentials file
5. On disconnection, waits and repeats the process with a fresh TOTP code