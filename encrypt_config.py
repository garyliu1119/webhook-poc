import argparse
import base64
import hashlib
import getpass
import json
import os
from pathlib import Path
from typing import Dict, Any

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a passphrase and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def encrypt_value(value: str, fernet: Fernet) -> str:
    return fernet.encrypt(value.encode()).decode()


def decrypt_value(value: str, fernet: Fernet) -> str:
    return fernet.decrypt(value.encode()).decode()


def encrypt_config(in_path: Path, out_path: Path, passphrase: str, deterministic_salt: bool = True) -> None:
    with in_path.open("r", encoding="utf-8") as f:
        config = json.load(f)
    if deterministic_salt:
        # Derive a deterministic salt from the passphrase.
        # WARNING: this is less secure than a random salt and makes
        # the encryption vulnerable to precomputation/rainbow-table attacks.
        # Use only if you fully understand the trade-offs.
        salt = hashlib.sha256(passphrase.encode()).digest()[:16]
        # Inform the user that we're not storing salt and are deriving it.
        print("⚠️  Deterministic salt derived from passphrase; salt will NOT be stored in the output file")
    else:
        salt = os.urandom(16)
    key = derive_key_from_passphrase(passphrase, salt)
    fernet = Fernet(key)

    cfg = dict(config)  # shallow copy
    for k in ("client_id", "client_secret"):
        if k in cfg and cfg[k] is not None:
            cfg[k] = encrypt_value(str(cfg[k]), fernet)

    # Write a flat config file. If storing salt, include it as a top-level key.
    if deterministic_salt:
        out = cfg
    else:
        out = {"salt": base64.b64encode(salt).decode(), **cfg}
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print(f"✅ Encrypted config written to {out_path}")


def decrypt_config(in_path: Path, out_path: Path | None, passphrase: str, show: bool = False) -> None:
    with in_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    # Accept multiple formats:
    # - legacy: {"salt":..., "config": { ... }}
    # - new stored-salt flat: {"salt":..., "client_id":..., "client_secret":...}
    # - new deterministic (no salt): {"client_id":..., "client_secret":...}

    salt_b64 = data.get("salt")
    if salt_b64:
        salt = base64.b64decode(salt_b64)
    else:
        # No salt stored: assume deterministic salt derived from passphrase
        salt = hashlib.sha256(passphrase.encode()).digest()[:16]

    # Extract config fields. If "config" key exists (legacy), use it. Otherwise,
    # treat top-level keys (excluding 'salt') as the config.
    if isinstance(data.get("config"), dict):
        cfg_enc = data.get("config") or {}
    else:
        # copy data but remove 'salt' if present
        cfg_enc = {k: v for k, v in data.items() if k != "salt"}
    key = derive_key_from_passphrase(passphrase, salt)
    fernet = Fernet(key)

    cfg = dict(cfg_enc)
    for k in ("client_id", "client_secret"):
        if k in cfg and cfg[k] is not None:
            try:
                cfg[k] = decrypt_value(cfg[k], fernet)
            except Exception as e:
                raise ValueError(f"Failed to decrypt field '{k}': {e}") from e

    if out_path:
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        print(f"✅ Decrypted config written to {out_path}")

    if show:
        print(json.dumps(cfg, indent=2))


def _prompt_passphrase(confirm: bool = False) -> str:
    pw = getpass.getpass("Passphrase: ")
    if confirm:
        pw2 = getpass.getpass("Confirm passphrase: ")
        if pw != pw2:
            raise SystemExit("Passphrases do not match")
    return pw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Encrypt/decrypt client_id and client_secret in a JSON config")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Encrypt client_id/client_secret in a plain config.json")
    p_enc.add_argument("-i", "--input", type=Path, default=Path("config.json"), help="Input plain config file")
    p_enc.add_argument("-o", "--output", type=Path, default=Path("config.dev.json"), help="Output encrypted file")
    p_enc.add_argument("-p", "--passphrase", type=str, help="Passphrase (will prompt if omitted)")
    p_enc.add_argument("--store-salt", action="store_true", help="Store a random salt in the output file (default: omit salt and derive it from passphrase)")

    p_dec = sub.add_parser("decrypt", help="Decrypt an encrypted config file")
    p_dec.add_argument("-i", "--input", type=Path, default=Path("config.dev.json"), help="Input encrypted file")
    p_dec.add_argument("-o", "--output", type=Path, help="Output decrypted config file (if omitted will print to stdout)")
    p_dec.add_argument("-p", "--passphrase", type=str, help="Passphrase (will prompt if omitted)")
    p_dec.add_argument("--show", action="store_true", help="Also print decrypted config to stdout")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "encrypt":
            passphrase = args.passphrase or _prompt_passphrase(confirm=True)
            # Default behavior: deterministic salt (no salt stored). If user requests --store-salt,
            # generate a random salt and save it in the output file.
            encrypt_config(args.input, args.output, passphrase, deterministic_salt=(not args.store_salt))
        elif args.cmd == "decrypt":
            passphrase = args.passphrase or _prompt_passphrase(confirm=False)
            out = args.output if args.output else None
            decrypt_config(args.input, out, passphrase, show=args.show or (out is None))
        else:
            parser.print_help()
            return 2
    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

