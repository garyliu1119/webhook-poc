"""Fetch an OAuth2 client_credentials token for SmartRecruiters.

Usage:
  - Set environment variables SR_CLIENT_ID and SR_CLIENT_SECRET
  - Or create a `config.json` (or use `config.example.json`) in the repo root with keys
    {"client_id": ..., "client_secret": ..., "token_url": ...}

Run:
  python get_token.py

This script prefers environment variables, then falls back to `config.json`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict


REPO_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = REPO_ROOT / "config.json"
EXAMPLE_CONFIG = REPO_ROOT / "config.example.json"


def _load_config() -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    # environment first
    cfg["token_url"] = os.getenv("SR_TOKEN_URL")
    cfg["client_id"] = os.getenv("SR_CLIENT_ID")
    cfg["client_secret"] = os.getenv("SR_CLIENT_SECRET")
    cfg["grant_type"] = os.getenv("SR_GRANT_TYPE") or "client_credentials"

    # fallback to config.json, then example
    for path in (CONFIG_PATH, EXAMPLE_CONFIG):
        if not (cfg.get("client_id") and cfg.get("client_secret") and cfg.get("token_url")):
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        file_cfg = json.load(f)
                    cfg["client_id"] = cfg.get("client_id") or file_cfg.get("client_id")
                    cfg["client_secret"] = cfg.get("client_secret") or file_cfg.get("client_secret")
                    cfg["grant_type"] = cfg.get("grant_type") or file_cfg.get("grant_type")
                    cfg["token_url"] = cfg.get("token_url") or file_cfg.get("token_url")
                except Exception:
                    # ignore parse errors
                    pass

    # final defaults
    cfg["token_url"] = cfg.get("token_url") or "https://www.smartrecruiters.com/identity/oauth/token"
    return cfg


def get_client_credentials_token() -> Dict[str, Any]:
    try:
        import requests
    except Exception as e:  # pragma: no cover - dependency check
        raise RuntimeError("The 'requests' library is required. Install with: pip install requests") from e

    cfg = _load_config()
    client_id = cfg.get("client_id")
    client_secret = cfg.get("client_secret")
    grant_type = cfg.get("grant_type") or "client_credentials"
    token_url = cfg.get("token_url")

    if not client_id or not client_secret:
        raise RuntimeError(
            "Missing client_id or client_secret. Set SR_CLIENT_ID/SR_CLIENT_SECRET or create config.json from config.example.json"
        )

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"grant_type": grant_type, "client_id": client_id, "client_secret": client_secret}

    resp = requests.post(token_url, headers=headers, data=data, timeout=10)
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    token = get_client_credentials_token()
    print(json.dumps(token, indent=2))


if __name__ == "__main__":