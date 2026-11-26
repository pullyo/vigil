"""Pro entitlement gate.

Free features (manifest scan + license audit + report) always work, no key needed.
Pro features (CVE scan, policy engine, exports) need a license key:

    VIGIL2-<base64url payload>.<base64url Ed25519 signature>

The payload is compact JSON, e.g. ``{"v":1,"ent":"pro","sub":"<customer>","iat":"2026-11-26"}``
with an optional ``"exp":"YYYY-MM-DD"``. Keys are signed offline by the seller
with a private key that never ships (see tools/issue_key.py); vigil only holds
the public key below, so reading this source does not let anyone mint keys,
and each customer gets a distinct key that can be traced if it leaks.

vigil is open source, so a determined user can still patch this check out.
That is accepted: the gate is there to make paying the easy path, not to be DRM.
"""
from __future__ import annotations

import base64
import binascii
import datetime as _dt
import json
import os
from typing import Optional

from . import ed25519

KEY_PREFIX = "VIGIL2-"
# Seller's Ed25519 public key (hex). The matching private key is kept offline.
PUBLIC_KEY = "5f8993b449c5aeff8fb71df202ee0fd342a094e7f8f942349f4c6b1ecceeebf6"
_MAX_KEY_LEN = 1024


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def encode_key(payload: dict, signature: bytes) -> str:
    """Assemble a key string (used by the issuing tool and tests)."""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return KEY_PREFIX + _b64e(body) + "." + _b64e(signature)


def signed_bytes(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


def decode_key(key, today: Optional[_dt.date] = None) -> Optional[dict]:
    """Return the payload of a valid Pro key, else None."""
    if not isinstance(key, str):
        return None
    key = key.strip()
    if not key.startswith(KEY_PREFIX) or len(key) > _MAX_KEY_LEN or key.count(".") != 1:
        return None
    body_b64, sig_b64 = key[len(KEY_PREFIX):].split(".")
    try:
        body, sig = _b64d(body_b64), _b64d(sig_b64)
        public = bytes.fromhex(PUBLIC_KEY)
    except (ValueError, binascii.Error):
        return None
    if not ed25519.verify(public, body, sig):
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("v") != 1 or payload.get("ent") != "pro":
        return None
    exp = payload.get("exp")
    if exp is not None:
        try:
            if (today or _dt.date.today()) > _dt.date.fromisoformat(str(exp)):
                return None
        except ValueError:
            return None
    return payload


def is_valid(key) -> bool:
    return decode_key(key) is not None


def _key_from_env() -> Optional[str]:
    return os.environ.get("VIGIL_PRO_KEY") or None


def _key_from_file() -> Optional[str]:
    for p in (os.path.expanduser("~/.vigil/key"), os.path.join(os.getcwd(), ".vigil_key")):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return None


def resolve_key(key: Optional[str] = None) -> Optional[str]:
    return key or _key_from_env() or _key_from_file()


def pro_enabled(key: Optional[str] = None) -> bool:
    return is_valid(resolve_key(key))
