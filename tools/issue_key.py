#!/usr/bin/env python3
"""Seller-side tool: create the signing key and issue vigil Pro license keys.

Run from the vigil checkout. The private key file must stay off the repo and
off customer machines; back it up — losing it means existing keys still work
but no new ones can be issued without shipping a new public key.

    # once: create the signing key, then paste the printed public key into
    # vigil/prokey.py PUBLIC_KEY
    python3 tools/issue_key.py genkey ~/.config/vigil/signing.key

    # per sale (customer id = Gumroad sale id or an email hash, not a secret)
    python3 tools/issue_key.py issue --keyfile ~/.config/vigil/signing.key --customer SALE123
    python3 tools/issue_key.py issue ... --expires 2027-12-31     # optional expiry
"""
import argparse
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vigil import ed25519, prokey  # noqa: E402


def _load_secret(path: str) -> bytes:
    with open(os.path.expanduser(path), "r", encoding="ascii") as f:
        secret = bytes.fromhex(f.read().strip())
    if len(secret) != 32:
        sys.exit("signing key must be 32 bytes of hex")
    return secret


def genkey(path: str) -> int:
    path = os.path.expanduser(path)
    if os.path.exists(path):
        sys.exit("refusing to overwrite existing key: %s" % path)
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    secret = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(secret.hex() + "\n")
    print("signing key written to %s (mode 600) - back it up, never commit it" % path,
          file=sys.stderr)
    print("public key (put in vigil/prokey.py PUBLIC_KEY):")
    print(ed25519.public_key(secret).hex())
    return 0


def issue(keyfile: str, customer: str, expires) -> int:
    secret = _load_secret(keyfile)
    if ed25519.public_key(secret).hex() != prokey.PUBLIC_KEY:
        sys.exit("this signing key does not match vigil/prokey.py PUBLIC_KEY")
    payload = {"v": 1, "ent": "pro", "sub": customer,
               "iat": datetime.date.today().isoformat()}
    if expires:
        datetime.date.fromisoformat(expires)
        payload["exp"] = expires
    key = prokey.encode_key(payload, ed25519.sign(secret, prokey.signed_bytes(payload)))
    assert prokey.is_valid(key)
    print(key)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("genkey")
    g.add_argument("path")
    i = sub.add_parser("issue")
    i.add_argument("--keyfile", required=True)
    i.add_argument("--customer", required=True)
    i.add_argument("--expires")
    a = ap.parse_args()
    return genkey(a.path) if a.cmd == "genkey" else issue(a.keyfile, a.customer, a.expires)


if __name__ == "__main__":
    sys.exit(main())
