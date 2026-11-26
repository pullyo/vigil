"""Pro key: Ed25519 implementation and signed-key verification."""
import datetime
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vigil import ed25519, prokey  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# RFC 8032 section 7.1, TEST 1 and TEST 2.
RFC_VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]

SECRET = bytes(range(32))
OTHER = bytes(range(1, 33))


def make_key(payload, secret=SECRET):
    return prokey.encode_key(payload, ed25519.sign(secret, prokey.signed_bytes(payload)))


PAYLOAD = {"v": 1, "ent": "pro", "sub": "cust-1", "iat": "2026-11-26"}


class Ed25519Test(unittest.TestCase):
    def test_rfc8032_vectors(self):
        for sk, pk, msg, sig in RFC_VECTORS:
            sk, pk, msg, sig = map(bytes.fromhex, (sk, pk, msg, sig))
            self.assertEqual(ed25519.public_key(sk), pk)
            self.assertEqual(ed25519.sign(sk, msg), sig)
            self.assertTrue(ed25519.verify(pk, msg, sig))
            self.assertFalse(ed25519.verify(pk, msg + b"x", sig))
            bad = bytearray(sig)
            bad[10] ^= 1
            self.assertFalse(ed25519.verify(pk, msg, bytes(bad)))

    def test_malformed_inputs_are_rejected(self):
        pk = ed25519.public_key(SECRET)
        sig = ed25519.sign(SECRET, b"m")
        self.assertFalse(ed25519.verify(pk[:31], b"m", sig))
        self.assertFalse(ed25519.verify(pk, b"m", sig[:63]))
        # s >= L must be rejected (signature malleability)
        s = int.from_bytes(sig[32:], "little") + ed25519.L
        self.assertFalse(ed25519.verify(pk, b"m", sig[:32] + s.to_bytes(32, "little")))


class ProKeyTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(prokey, "PUBLIC_KEY", ed25519.public_key(SECRET).hex())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_signed_key_is_valid_and_payload_returned(self):
        key = make_key(PAYLOAD)
        self.assertTrue(key.startswith("VIGIL2-"))
        self.assertEqual(prokey.decode_key(key), PAYLOAD)
        self.assertTrue(prokey.pro_enabled(key))

    def test_key_signed_by_someone_else_is_rejected(self):
        self.assertFalse(prokey.is_valid(make_key(PAYLOAD, OTHER)))

    def test_edited_payload_is_rejected(self):
        key = make_key(PAYLOAD)
        forged = make_key(dict(PAYLOAD, sub="cust-2"))
        body_forged = forged[len("VIGIL2-"):].split(".")[0]
        sig_orig = key.split(".")[1]
        self.assertFalse(prokey.is_valid("VIGIL2-%s.%s" % (body_forged, sig_orig)))

    def test_wrong_entitlement_or_version_is_rejected(self):
        self.assertFalse(prokey.is_valid(make_key(dict(PAYLOAD, ent="free"))))
        self.assertFalse(prokey.is_valid(make_key(dict(PAYLOAD, v=2))))

    def test_expiry(self):
        key = make_key(dict(PAYLOAD, exp="2027-01-31"))
        self.assertIsNotNone(prokey.decode_key(key, today=datetime.date(2027, 1, 31)))
        self.assertIsNone(prokey.decode_key(key, today=datetime.date(2027, 2, 1)))
        self.assertFalse(prokey.is_valid(make_key(dict(PAYLOAD, exp="not-a-date"))))

    def test_garbage_and_old_format_rejected(self):
        for k in (None, 42, "", "VIGIL-0123456789ABCDEF", "VIGIL2-", "VIGIL2-a.b.c",
                  "VIGIL2-!!!.???", "VIGIL2-" + "A" * 2000 + ".x"):
            self.assertFalse(prokey.is_valid(k), k)

    def test_env_key_is_used(self):
        with mock.patch.dict(os.environ, {"VIGIL_PRO_KEY": make_key(PAYLOAD)}):
            self.assertTrue(prokey.pro_enabled())


class ShippedKeyTest(unittest.TestCase):
    def test_shipped_public_key_is_a_valid_point(self):
        pk = bytes.fromhex(prokey.PUBLIC_KEY)
        self.assertEqual(len(pk), 32)
        self.assertIsNotNone(ed25519._decompress(pk))

    def test_no_signing_secret_in_package(self):
        src = open(os.path.join(ROOT, "vigil", "prokey.py"), encoding="utf-8").read()
        self.assertNotIn("_SECRET", src)
        self.assertNotIn("def issue_key", src)
        self.assertNotIn("vigil-open-core-2026", src)


if __name__ == "__main__":
    unittest.main()
