"""Fix-version guidance, free CVE output, the Pro CI gate and Pro deliverables."""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vigil import cli, ed25519, prokey, vuln  # noqa: E402

DJANGO_ADV = {  # trimmed real record shape (several release lines fixed separately)
    "id": "GHSA-x",
    "affected": [
        {"package": {"ecosystem": "PyPI", "name": "Django"},
         "ranges": [{"type": "ECOSYSTEM", "events": [
             {"introduced": "0"}, {"fixed": "3.2.25"},
             {"introduced": "4.0"}, {"fixed": "4.2.11"},
             {"introduced": "5.0a1"}, {"fixed": "5.0.3"}]}]},
        {"package": {"ecosystem": "PyPI", "name": "other"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.1"}]}]},
    ],
}


class VersionOrderTest(unittest.TestCase):
    def test_ordering(self):
        for a, b in [("1.2.9", "1.2.10"), ("4.2rc1", "4.2"), ("1.0.0-beta.2", "1.0.0"),
                     ("1.0", "1.0.post1"), ("v0.17.0", "v0.23.0"), ("5.0a1", "5.0b1"),
                     ("2.9.1", "2.10"), ("1.0.dev0", "1.0a1")]:
            self.assertTrue(vuln._vlt(a, b), (a, b))
            self.assertFalse(vuln._vlt(b, a), (b, a))
        self.assertFalse(vuln._vlt("1.0", "1.0.0"))
        self.assertFalse(vuln._vlt("1.0.0", "1.0"))


class FixVersionTest(unittest.TestCase):
    def test_fix_from_the_matching_release_line(self):
        self.assertEqual(vuln.fix_version(DJANGO_ADV, "PyPI", "django", "3.2.4"), "3.2.25")
        self.assertEqual(vuln.fix_version(DJANGO_ADV, "PyPI", "django", "4.2"), "4.2.11")
        self.assertEqual(vuln.fix_version(DJANGO_ADV, "PyPI", "django", "5.0rc1"), "5.0.3")

    def test_other_package_and_no_fix(self):
        self.assertIsNone(vuln.fix_version(DJANGO_ADV, "PyPI", "django", "5.0.3"))
        self.assertIsNone(vuln.fix_version(DJANGO_ADV, "npm", "django", "4.2"))
        no_fix = {"affected": [{"package": {"ecosystem": "npm", "name": "x"},
                                "ranges": [{"type": "SEMVER", "events": [
                                    {"introduced": "0"}, {"last_affected": "1.2.3"}]}]}]}
        self.assertIsNone(vuln.fix_version(no_fix, "npm", "x", "1.0.0"))

    def test_git_ranges_ignored(self):
        adv = {"affected": [{"package": {"ecosystem": "npm", "name": "x"},
                             "ranges": [{"type": "GIT", "events": [
                                 {"introduced": "0"}, {"fixed": "abc123"}]}]}]}
        self.assertIsNone(vuln.fix_version(adv, "npm", "x", "1.0.0"))


def _adv(i, cvss):
    return {"id": "GHSA-%d" % i, "aliases": ["CVE-2024-%d" % i], "summary": "bug %d" % i,
            "cvss": cvss, "versions": ["1.0.0"], "approximate": False, "fixed": {"1.0.0": "1.0.1"}}


FULL = {"npm:a": [_adv(1, 5.0), _adv(2, 9.8)],
        "npm:b": [_adv(3, None), _adv(4, 7.5)],
        "npm:c": [_adv(5, 8.1)]}


SECRET = bytes(range(32))
PAYLOAD = {"v": 1, "ent": "pro", "sub": "t", "iat": "2026-11-26"}


class CliGateTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        with open(os.path.join(self.dir.name, "package.json"), "w") as f:
            f.write('{"name":"t","license":"MIT","dependencies":'
                    '{"a":"1.0.0","b":"1.0.0","c":"1.0.0"}}')
        for p in (mock.patch.object(vuln, "query_osv", return_value=FULL),
                  mock.patch.object(prokey, "PUBLIC_KEY", ed25519.public_key(SECRET).hex()),
                  mock.patch.dict(os.environ, {"HOME": self.dir.name}, clear=False)):
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop("VIGIL_PRO_KEY", None)
        self.addCleanup(self.dir.cleanup)

    def run_cli(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.main([self.dir.name, "--vuln", "--fail-on", "high"] + list(extra))
        return rc, out.getvalue(), err.getvalue()

    def test_free_shows_every_cve_with_fix_but_does_not_gate(self):
        rc, out, err = self.run_cli()
        self.assertEqual(out.count("-> upgrade to 1.0.1"), 5)
        self.assertIn("GHSA-2 / CVE-2024-2", out)
        self.assertIn("do not fail the build in the free edition", err)
        self.assertEqual(rc, 0)

    def test_free_json_includes_cves(self):
        rc, out, err = self.run_cli("-f", "json")
        self.assertIn('"GHSA-5"', out)
        self.assertEqual(rc, 0)

    def test_pro_gates_on_cves(self):
        key = prokey.encode_key(PAYLOAD, ed25519.sign(SECRET, prokey.signed_bytes(PAYLOAD)))
        rc, out, err = self.run_cli("--key", key)
        self.assertEqual(out.count("-> upgrade to 1.0.1"), 5)
        self.assertNotIn("free edition", err)
        self.assertEqual(rc, 1)

    def test_sbom_and_notice_need_pro(self):
        sbom = os.path.join(self.dir.name, "bom.json")
        rc, out, err = self.run_cli("--sbom", sbom)
        self.assertFalse(os.path.exists(sbom))
        self.assertIn("--sbom is a Pro feature", err)
        key = prokey.encode_key(PAYLOAD, ed25519.sign(SECRET, prokey.signed_bytes(PAYLOAD)))
        notice = os.path.join(self.dir.name, "NOTICES.md")
        self.run_cli("--key", key, "--sbom", sbom, "--notice", notice)
        self.assertTrue(os.path.exists(sbom) and os.path.exists(notice))

    def test_markdown_lists_fixes(self):
        rc, out, _ = self.run_cli("-f", "md")
        self.assertIn("## Known vulnerabilities", out)
        self.assertIn("| upgrade to 1.0.1 |", out)


if __name__ == "__main__":
    unittest.main()
