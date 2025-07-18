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

### Generate Credentials Only
```bash
./openvpn.py --once
```

## Environment Variables

You can set these environment variables to avoid interactive prompts:

- `TOTP_KEY`: Your Base32 TOTP secret key
- `AUTH_NAME`: Your username
- `AUTH_PIN`: Your PIN/password

Example:
```bash
export TOTP_KEY="JBSWY3DPEHPK3PXP"
export AUTH_NAME="myusername"
export AUTH_PIN="mypin"
./openvpn.py
```

## Configuration

The script will automatically look for OpenVPN configuration files in these locations:
- `~/.openvpn/user@openvpn.example.org.ovpn`
- `/etc/openvpn/client/openvpn.example.org/user.ovpn`

Credentials are written to: `~/.openvpn/user@openvpn.example.org_credentials.txt`

## Security

- Credential files are created with 600 permissions (owner read/write only)
- TOTP secrets are not stored persistently unless set as environment variables
- Use environment variables or secure input methods for production use

## Command Line Options

- `--config`, `-c`: Specify OpenVPN configuration file path
- `--once`, `-1`: Generate credentials file once and exit (don't run OpenVPN)
- `--help`: Show help message

## How It Works

1. Prompts for or reads TOTP secret, username, and PIN
2. Generates current TOTP code based on current time
3. Creates/updates OpenVPN credentials file with username and PIN+TOTP
4. Runs OpenVPN with the credentials file
5. On disconnection, waits and repeats the process with a fresh TOTP code