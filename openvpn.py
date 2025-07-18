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
from pathlib import Path


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
        if not secret:
            sys.exit("✖  TOTP secret key cannot be empty")
    
    name = os.getenv("AUTH_NAME")
    if not name:
        name = getpass.getpass("Enter username: ")
        if not name:
            sys.exit("✖  Username cannot be empty")
    
    pin = os.getenv("AUTH_PIN")
    if not pin:
        pin = getpass.getpass("Enter PIN: ")
        if not pin:
            sys.exit("✖  PIN cannot be empty")
    
    return secret, name, pin


def update_credentials_file(secret, name, pin, target):
    """Generate TOTP code and update credentials file."""
    try:
        code = totp_now(secret)
    except (base64.binascii.Error, ValueError) as exc:
        sys.exit(f"✖  Invalid TOTP secret: {exc}")

    target.parent.mkdir(parents=True, exist_ok=True)  # ensure ~/.openvpn exists

    try:
        target.write_text(name + "\n" + pin + code + "\n", encoding="utf-8")
        os.chmod(target, 0o600)  # owner-read/write only
    except OSError as exc:
        sys.exit(f"✖  Cannot write {target}: {exc}")
    
    return target


def run_openvpn_loop(secret, name, pin, config_file=None):
    """Run OpenVPN in a loop, regenerating TOTP codes as needed."""
    credentials_file = Path("~/.openvpn/user@openvpn.example.org_credentials.txt").expanduser()
    
    # Determine OpenVPN config file
    if config_file is None:
        # Try to find a config file
        possible_configs = [
            Path("~/.openvpn/user@openvpn.example.org.ovpn").expanduser(),
            Path("/etc/openvpn/client/openvpn.example.org/user.ovpn"),
        ]
        
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
                    sys.exit(1)
            
            # Wait a bit before restarting
            print("\n⏳ Waiting 5 seconds before reconnecting...")
            time.sleep(5)
            
        except KeyboardInterrupt:
            print("\n\n✓ Interrupted by user. Exiting.")
            break
        except Exception as e:
            print(f"\n✖ Error running OpenVPN: {e}")
            retry_count += 1
            
            if retry_count >= max_retries:
                print(f"\n✖ Maximum retries ({max_retries}) reached. Exiting.")
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
        "--once", "-1",
        action="store_true",
        help="Only generate credentials file once and exit (don't run OpenVPN)"
    )
    
    args = parser.parse_args()
    
    # Get credentials
    secret, name, pin = get_credentials()
    
    if args.once:
        # Just generate the credentials file and exit
        target = update_credentials_file(secret, name, pin)
        print(f"✓ Credentials written to {target}")
    else:
        # Run OpenVPN in a loop
        run_openvpn_loop(secret, name, pin, args.config)


if __name__ == "__main__":
    main()
