"""Deterministic tests for the SARIF 2.1.0 export and machine-readable stdout (no network).

Run: python3 -m unittest discover -s tests
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from vigil import cli, prokey, sarif, vuln  # noqa: E402

DEMO = os.path.join("examples", "demo")

# Advisories the mocked OSV boundary returns, keyed by (OSV ecosystem, name).
CANNED = {
    ("PyPI", "django"): [{
        "id": "CVE-2026-9999", "aliases": ["GHSA-0000-0000-aaaa"],
        "summary": "Remote code execution.\nSecond line.",
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]}],
    ("PyPI", "requests"): [{
        "id": "CVE-2023-32681", "summary": "Header leak.",
        "severity": [{"type": "CVSS_V3", "score": "7.5"}]}],
    ("npm", "lodash"): [{
        "id": "CVE-2026-8888", "summary": "Prototype pollution.",
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}]}],
    ("npm", "axios"): [{"id": "GHSA-xxxx-yyyy-zzzz", "summary": "No score given."}],
}


_BY_ID = {a["id"]: a for advs in CANNED.values() for a in advs}


def fake_post_json(url, obj, timeout=30.0):
    """Real OSV querybatch shape: IDs only, index-aligned with obj["queries"]."""
    out = []
    for q in obj["queries"]:
        advs = CANNED.get((q["package"]["ecosystem"], q["package"]["name"]), [])
        out.append({"vulns": [{"id": a["id"]} for a in advs]} if advs else {})
    return {"results": out}


def fake_get_json(url, timeout=30.0):
    return _BY_ID[url.rsplit("/", 1)[1]]


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


def results_by(log, key=lambda r: r["properties"]["package"]):
    return {key(r): r for r in log["runs"][0]["results"]}


class Base(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(vuln, "_get_json", fake_get_json)
        p.start()
        self.addCleanup(p.stop)
        self._cwd = os.getcwd()
        os.chdir(ROOT)  # locations are relative to cwd (the checkout root in CI)

    def tearDown(self):
        os.chdir(self._cwd)


class SarifFormatTests(Base):
    def test_document_shape_and_stable_rules(self):
        rc, out, err = run([DEMO, "-f", "sarif"])
        log = json.loads(out)  # stdout is exactly one JSON document
        self.assertEqual(log["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", log["$schema"])
        self.assertEqual(len(log["runs"]), 1)
        driver = log["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "vigil")
        self.assertEqual([r["id"] for r in driver["rules"]], [
            "vigil/license-incompatible", "vigil/license-policy-blocked",
            "vigil/license-review", "vigil/license-unknown",
            "vigil/vuln-critical", "vigil/vuln-high", "vigil/vuln-medium",
            "vigil/vuln-low", "vigil/vuln-unscored"])
        for r in driver["rules"]:
            self.assertIn(r["defaultConfiguration"]["level"], ("error", "warning", "note"))
            self.assertTrue(r["shortDescription"]["text"] and r["fullDescription"]["text"])
        for res in log["runs"][0]["results"]:
            self.assertEqual(driver["rules"][res["ruleIndex"]]["id"], res["ruleId"])
            self.assertTrue(res["message"]["text"])
            self.assertTrue(res["partialFingerprints"]["vigilFindingId/v1"])
            self.assertEqual(len(res["locations"]), 1)
        self.assertEqual(log["runs"][0]["properties"]["advisoryLookupAttempted"], False)

    def test_license_findings_severity_and_locations(self):
        _, out, _ = run([DEMO, "-f", "sarif"])
        res = results_by(json.loads(out))
        # Only non-ok verdicts become results.
        self.assertEqual(set(res), {"gitpython", "moment", "rails", "nokogiri"})
        expect = {
            "gitpython": ("vigil/license-incompatible", "error", "requirements.txt", 3),
            "moment": ("vigil/license-review", "warning", "package.json", 7),
            "rails": ("vigil/license-unknown", "warning", "Gemfile", 3),
            "nokogiri": ("vigil/license-unknown", "warning", "Gemfile", 4),
        }
        for name, (rule, level, fname, line) in expect.items():
            r = res[name]
            loc = r["locations"][0]["physicalLocation"]
            self.assertEqual(r["ruleId"], rule, name)
            self.assertEqual(r["level"], level, name)
            self.assertEqual(loc["artifactLocation"]["uri"], "examples/demo/" + fname)
            self.assertEqual(loc["artifactLocation"]["uriBaseId"], "%SRCROOT%")
            self.assertEqual(loc["region"]["startLine"], line, name)
        self.assertIn("gpl-3.0", res["gitpython"]["message"]["text"])
        self.assertIn("Replace it", res["gitpython"]["message"]["text"])
        # Registry hint only where --registry can actually help (npm/PyPI).
        self.assertNotIn("--registry", res["rails"]["message"]["text"])

    def test_scan_from_inside_root_gives_root_relative_uris(self):
        os.chdir(os.path.join(ROOT, DEMO))
        _, out, _ = run([".", "-f", "sarif"])
        res = results_by(json.loads(out))
        uri = res["gitpython"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "requirements.txt")

    def test_locations_never_absolute_or_escaping(self):
        with tempfile.TemporaryDirectory() as td:
            proj = os.path.join(td, "out of tree", "proj")
            os.makedirs(os.path.join(proj, "sub dir"))
            with open(os.path.join(proj, "sub dir", "requirements.txt"), "w") as f:
                f.write("gitpython==3.1.40\n")
            # cwd (ROOT) does not contain the scanned tree -> fall back to scan-root paths.
            _, out, _ = run([proj, "-f", "sarif"])
            self.assertNotIn(td, out)
            self.assertNotIn(os.path.realpath(td), out)
            for r in json.loads(out)["runs"][0]["results"]:
                uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                self.assertEqual(uri, "sub%20dir/requirements.txt")
        for bad in ("/abs/x", "../x", "a/../../x", "C:/x", ""):
            self.assertIsNone(sarif._safe_rel(bad), bad)

    def test_policy_blocked_rule(self):
        with tempfile.TemporaryDirectory() as td:
            pol = os.path.join(td, "vigil.toml")
            with open(pol, "w") as f:
                f.write('[policy]\nlicense = "proprietary"\n[[allowed]]\nclass = "permissive"\n')
            rc, out, _ = run([DEMO, "-f", "sarif", "--policy", pol])
        res = results_by(json.loads(out))
        self.assertEqual(res["gitpython"]["ruleId"], "vigil/license-policy-blocked")
        self.assertEqual(res["moment"]["ruleId"], "vigil/license-policy-blocked")
        self.assertEqual(res["moment"]["level"], "error")
        self.assertEqual(rc, 1)

    def test_output_file_matches_stdout(self):
        with tempfile.TemporaryDirectory() as td:
            dest = os.path.join(td, "vigil.sarif")
            rc, out, err = run([DEMO, "-f", "sarif", "-o", dest])
            with open(dest, encoding="utf-8") as f:
                written = f.read()
        self.assertEqual(json.loads(written), json.loads(out))
        self.assertIn("report written to", err)
        self.assertNotIn("report written to", out)

    def test_deterministic(self):
        self.assertEqual(run([DEMO, "-f", "sarif"])[1], run([DEMO, "-f", "sarif"])[1])


class AdvisoryTests(Base):
    def test_advisory_results_from_returned_data_only(self):
        with mock.patch.object(prokey, "pro_enabled", return_value=True), \
                mock.patch.object(vuln, "_post_json", fake_post_json):
            rc, out, _ = run([DEMO, "-f", "sarif", "--vuln"])
        log = json.loads(out)
        self.assertTrue(log["runs"][0]["properties"]["advisoryLookupAttempted"])
        adv = {r["properties"]["advisory"]: r for r in log["runs"][0]["results"]
               if r["ruleId"].startswith("vigil/vuln-")}
        self.assertEqual(set(adv), {"CVE-2026-9999", "CVE-2023-32681", "CVE-2026-8888",
                                    "GHSA-xxxx-yyyy-zzzz"})
        expect = {"CVE-2026-9999": ("vigil/vuln-critical", "error", 10.0, "requirements.txt", 5),
                  "CVE-2023-32681": ("vigil/vuln-high", "error", 7.5, "requirements.txt", 4),
                  "CVE-2026-8888": ("vigil/vuln-medium", "warning", 6.5, "package.json", 6),
                  "GHSA-xxxx-yyyy-zzzz": ("vigil/vuln-unscored", "warning", None,
                                          "package.json", 8)}
        rules = log["runs"][0]["tool"]["driver"]["rules"]
        for aid, (rule, level, cvss, fname, line) in expect.items():
            r = adv[aid]
            loc = r["locations"][0]["physicalLocation"]
            self.assertEqual((r["ruleId"], r["level"]), (rule, level), aid)
            self.assertEqual(r["properties"].get("cvss"), cvss, aid)
            self.assertEqual(loc["artifactLocation"]["uri"], "examples/demo/" + fname)
            self.assertEqual(loc["region"]["startLine"], line, aid)
            self.assertIn(aid, r["message"]["text"])
            self.assertIn("https://osv.dev/vulnerability/" + aid, r["message"]["text"])
            self.assertNotIn("\n", r["message"]["text"])
        sev = {r["id"]: r["properties"].get("security-severity") for r in rules}
        self.assertEqual(sev["vigil/vuln-critical"], "9.5")
        self.assertEqual(sev["vigil/vuln-high"], "8.0")
        self.assertIsNone(sev["vigil/license-incompatible"])
        self.assertEqual(rc, 1)

    def test_free_reports_advisories_without_gating_and_lookup_failure(self):
        def boom(url, obj, timeout=30.0):
            raise OSError("network down")

        with mock.patch.object(prokey, "pro_enabled", return_value=False), \
                mock.patch.object(vuln, "_post_json", fake_post_json):
            rc, out, err = run([DEMO, "-f", "sarif", "--vuln", "--license", "copyleft"])
        log = json.loads(out)
        self.assertIn("do not fail the build in the free edition", err)
        self.assertTrue(log["runs"][0]["properties"]["advisoryLookupAttempted"])
        self.assertTrue(any(r["ruleId"].startswith("vigil/vuln-")
                            for r in log["runs"][0]["results"]))

        for fmt in ("sarif", "json"):
            with mock.patch.object(prokey, "pro_enabled", return_value=True), \
                    mock.patch.object(vuln, "_post_json", boom):
                _, out, err = run([DEMO, "-f", fmt, "--vuln"])
            data = json.loads(out)  # diagnostics must not leak into stdout
            self.assertIn("vuln lookup failed", err)
            if fmt == "sarif":
                self.assertFalse(any(r["ruleId"].startswith("vigil/vuln-")
                                     for r in data["runs"][0]["results"]))
            else:
                self.assertEqual(data["vulnerabilities"], {})


class ExitCodeAndStdoutTests(Base):
    def test_sarif_exit_codes_match_json(self):
        for fail_on, expected in (("high", 1), ("warn", 1), ("any", 1), ("never", 0)):
            rc_s = run([DEMO, "-f", "sarif", "--fail-on", fail_on])[0]
            rc_j = run([DEMO, "-f", "json", "--fail-on", fail_on])[0]
            rc_t = run([DEMO, "--fail-on", fail_on])[0]
            self.assertEqual((rc_s, rc_j, rc_t), (expected,) * 3, fail_on)
        # A copyleft project has only warn-level findings in the demo.
        self.assertEqual(run([DEMO, "-f", "sarif", "--license", "copyleft"])[0], 0)
        self.assertEqual(run([DEMO, "-f", "sarif", "--license", "copyleft",
                              "--fail-on", "warn"])[0], 1)

    def test_no_manifests(self):
        with tempfile.TemporaryDirectory() as td:
            rc, out, err = run([td, "-f", "sarif"])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out)["runs"][0]["results"], [])
            self.assertIn("no dependency manifests", err)
            rc, out, _ = run([td, "-f", "json"])
            self.assertEqual((rc, json.loads(out)["dependencies"]), (0, []))
            rc, out, _ = run([td])  # human format unchanged
            self.assertEqual(rc, 0)
            self.assertIn("no dependency manifests", out)

    def test_existing_formats_unchanged(self):
        _, out, _ = run([DEMO, "-f", "json"])
        data = json.loads(out)
        self.assertEqual(set(data), {"tool", "project_license", "summary",
                                     "dependencies", "vulnerabilities"})
        self.assertEqual(data["summary"], {"ok": 9, "warn": 3, "high": 1})
        _, out, _ = run([DEMO, "-f", "md"])
        self.assertTrue(out.startswith("# vigil"))
        _, out, _ = run([DEMO])
        self.assertIn("9 ok / 3 warn / 1 high", out)


if __name__ == "__main__":
    unittest.main()
