#!/usr/bin/env python3

import base64
import hmac
import hashlib
import os
import struct
import sys
import time
import subprocess
import getpass
import tempfile
import re
from pathlib import Path


# Configuration defaults
DEFAULT_VPN_SERVER = "openvpn.example.org"
DEFAULT_VPN_USER = "user"
DEFAULT_CREDENTIALS_DIR = "~/.openvpn"
DEFAULT_CONFIG_DIRS = [
    "~/.openvpn",
    "/etc/openvpn/client"
]


def validate_totp_secret(secret: str) -> str:
    """Validate and normalize TOTP secret."""
    if not secret:
        raise ValueError("TOTP secret cannot be empty")
    
    # Remove whitespace and convert to uppercase
    normalized = secret.upper().replace(" ", "")
    
    # Check if it's valid Base32
    if not re.match(r'^[A-Z2-7]+=*$', normalized):
        raise ValueError("TOTP secret must be valid Base32 (A-Z, 2-7)")
    
    # Check minimum length (typically 16 characters for 80-bit key)
    if len(normalized) < 16:
        raise ValueError("TOTP secret is too short (minimum 16 characters)")
    
    # Check maximum reasonable length (typically 32 characters for 160-bit key)
    if len(normalized) > 64:
        raise ValueError("TOTP secret is too long (maximum 64 characters)")
    
    # Validate by attempting to decode
    try:
        base64.b32decode(normalized, casefold=True)
    except Exception:
        raise ValueError("Invalid Base32 TOTP secret")
    
    return normalized


def validate_credentials(name: str, pin: str) -> tuple[str, str]:
    """Validate username and PIN."""
    if not name or not name.strip():
        raise ValueError("Username cannot be empty")
    
    if not pin or not pin.strip():
        raise ValueError("PIN cannot be empty")
    
    # Check for reasonable length limits
    if len(name) > 256:
        raise ValueError("Username is too long (maximum 256 characters)")
    
    if len(pin) > 256:
        raise ValueError("PIN is too long (maximum 256 characters)")
    
    # Check for invalid characters in username
    if re.search(r'[<>:"/\\|?*\x00-\x1f]', name):
        raise ValueError("Username contains invalid characters")
    
    return name.strip(), pin.strip()


def clear_sensitive_data(*variables):
    """Clear sensitive data from memory by overwriting variables.
    
    Note: Python strings are immutable, so this function primarily serves as
    a security indicator and will clear mutable data types. For complete
    memory security, consider using libraries like SecureString or running
    in a more controlled environment.
    """
    import gc
    
    for var in variables:
        if isinstance(var, str):
            # Overwrite string data (Python strings are immutable, but this helps indicate intent)
            var = "0" * len(var)
        elif isinstance(var, bytearray):
            # Clear bytearray data
            for i in range(len(var)):
                var[i] = 0
        elif isinstance(var, bytes):
            # Can't clear bytes directly, but we can indicate intent
            var = b"0" * len(var)
    
    # Force garbage collection to try to clear unreferenced objects
    gc.collect()


def get_default_paths(server=None, username=None):
    """Generate default file paths based on server and username."""
    server = server or DEFAULT_VPN_SERVER
    username = username or DEFAULT_VPN_USER
    
    # Default credentials file path
    credentials_file = f"{DEFAULT_CREDENTIALS_DIR}/{username}@{server}_credentials.txt"
    
    # Default config file paths to search
    config_paths = []
    for config_dir in DEFAULT_CONFIG_DIRS:
        config_paths.extend([
            f"{config_dir}/{username}@{server}.ovpn",
            f"{config_dir}/{server}/{username}.ovpn",
            f"{config_dir}/{server}.ovpn"
        ])
    
    return credentials_file, config_paths


def totp_now(secret_b32: str, digits: int = 6, step: int = 30) -> str:
    """Return the current TOTP code for *secret_b32* (Base-32)."""
    # Decode (ignore case and whitespace per RFC 3548 §6).
    key = base64.b32decode(secret_b32.upper().replace(" ", ""), casefold=True)

    counter = int(time.time()) // step
    msg = struct.pack(">Q", counter)

    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF) % 10**digits
    return f"{code_int:0{digits}d}"


def get_credentials():
    """Get credentials from environment or prompt user."""
    secret = os.getenv("TOTP_KEY")
    if not secret:
        secret = getpass.getpass("Enter TOTP secret key: ")
    
    name = os.getenv("AUTH_NAME")
    if not name:
        name = getpass.getpass("Enter username: ")
    
    pin = os.getenv("AUTH_PIN")
    if not pin:
        pin = getpass.getpass("Enter PIN: ")
    
    # Validate all inputs
    try:
        secret = validate_totp_secret(secret)
        name, pin = validate_credentials(name, pin)
    except ValueError as e:
        sys.exit(f"✖  {e}")
    
    return secret, name, pin


def update_credentials_file(secret, name, pin, target):
    """Generate TOTP code and update credentials file using secure methods."""
    try:
        code = totp_now(secret)
    except (base64.binascii.Error, ValueError) as exc:
        sys.exit(f"✖  Invalid TOTP secret: {exc}")

    target.parent.mkdir(parents=True, exist_ok=True)  # ensure ~/.openvpn exists

    # Create credentials content
    credentials_content = f"{name}\n{pin}{code}\n"
    
    try:
        # Use secure temporary file creation and atomic move
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            dir=target.parent,
            delete=False,
            prefix=f'.{target.name}.',
            suffix='.tmp'
        ) as tmp_file:
            # Set secure permissions before writing
            os.chmod(tmp_file.name, 0o600)
            tmp_file.write(credentials_content)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())  # Ensure data is written to disk
            tmp_path = tmp_file.name
        
        # Atomic move to final location
        os.replace(tmp_path, target)
        
        # Clear sensitive data from memory
        clear_sensitive_data(credentials_content, code)
        
    except OSError as exc:
        # Clean up temporary file if it exists
        try:
            if 'tmp_path' in locals():
                os.unlink(tmp_path)
        except OSError:
            pass
        sys.exit(f"✖  Cannot write {target}: {exc}")
    
    return target


def run_openvpn_loop(secret, name, pin, config_file=None, credentials_file=None, server=None, username=None):
    """Run OpenVPN in a loop, regenerating TOTP codes as needed."""
    default_credentials_file, default_config_paths = get_default_paths(server, username)
    
    if credentials_file is None:
        credentials_file = Path(default_credentials_file).expanduser()
    else:
        credentials_file = Path(credentials_file).expanduser()
    
    # Determine OpenVPN config file
    if config_file is None:
        # Try to find a config file
        possible_configs = [Path(path).expanduser() for path in default_config_paths]
        
        for config in possible_configs:
            if config.exists():
                config_file = str(config)
                break
        
        if config_file is None:
            print("⚠  No OpenVPN config file specified. Please provide one with --config")
            config_file = input("Enter OpenVPN config file path: ").strip()
            if not config_file or not Path(config_file).exists():
                sys.exit("✖  Valid OpenVPN config file required")
    
    print(f"ℹ  Using OpenVPN config: {config_file}")
    print(f"ℹ  Credentials file: {credentials_file}")
    
    retry_count = 0
    max_retries = 3
    
    while True:
        # Update credentials file with fresh TOTP code
        print("\n→ Generating new TOTP code...")
        update_credentials_file(secret, name, pin, credentials_file)
        
        # Build OpenVPN command
        cmd = [
            "openvpn",
            "--config", config_file,
            "--auth-user-pass", str(credentials_file)
        ]
        
        # Check if we need sudo
        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd
        
        print(f"→ Starting OpenVPN (attempt {retry_count + 1})...")
        print(f"  Command: {' '.join(cmd)}")
        
        try:
            # Run OpenVPN
            process = subprocess.run(cmd)
            
            if process.returncode == 0:
                print("\n✓ OpenVPN exited successfully")
                retry_count = 0
            else:
                print(f"\n✖ OpenVPN exited with code {process.returncode}")
                retry_count += 1
                
                if retry_count >= max_retries:
                    print(f"\n✖ Maximum retries ({max_retries}) reached. Exiting.")
                    clear_sensitive_data(secret, pin)
                    sys.exit(1)
            
            # Wait a bit before restarting
            print("\n⏳ Waiting 5 seconds before reconnecting...")
            time.sleep(5)
            
        except KeyboardInterrupt:
            print("\n\n✓ Interrupted by user. Exiting.")
            # Clear sensitive data before exiting
            clear_sensitive_data(secret, pin)
            break
        except Exception as e:
            print(f"\n✖ Error running OpenVPN: {e}")
            retry_count += 1
            
            if retry_count >= max_retries:
                print(f"\n✖ Maximum retries ({max_retries}) reached. Exiting.")
                clear_sensitive_data(secret, pin)
                sys.exit(1)
            
            print("\n⏳ Waiting 10 seconds before retry...")
            time.sleep(10)


def main() -> None:
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate TOTP credentials and run OpenVPN in a loop"
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to OpenVPN configuration file",
        default=None
    )
    parser.add_argument(
        "--credentials-file", "-f",
        help="Path to credentials file (default: auto-generated based on server/username)",
        default=os.getenv("OPENVPN_CREDENTIALS_FILE")
    )
    parser.add_argument(
        "--server", "-s",
        help="VPN server hostname (default: openvpn.example.org)",
        default=os.getenv("OPENVPN_SERVER", DEFAULT_VPN_SERVER)
    )
    parser.add_argument(
        "--username", "-u",
        help="VPN username (default: user)",
        default=os.getenv("OPENVPN_USERNAME", DEFAULT_VPN_USER)
    )
    parser.add_argument(
        "--once", "-1",
        action="store_true",
        help="Only generate credentials file once and exit (don't run OpenVPN)"
    )
    
    args = parser.parse_args()
    
    # Get credentials
    secret, name, pin = get_credentials()
    
    try:
        if args.once:
            # Just generate the credentials file and exit
            if args.credentials_file:
                target = Path(args.credentials_file).expanduser()
            else:
                default_credentials_file, _ = get_default_paths(args.server, args.username)
                target = Path(default_credentials_file).expanduser()
            update_credentials_file(secret, name, pin, target)
            print(f"✓ Credentials written to {target}")
        else:
            # Run OpenVPN in a loop
            run_openvpn_loop(secret, name, pin, args.config, args.credentials_file, args.server, args.username)
    finally:
        # Clear sensitive data from memory
        clear_sensitive_data(secret, pin)


if __name__ == "__main__":
    main()
