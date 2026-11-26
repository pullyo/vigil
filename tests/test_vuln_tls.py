"""OSV transport must only accept verified TLS and never follow redirects."""
import os
import ssl
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vigil import vuln  # noqa: E402


class _Dep:
    def __init__(self, name, version, eco="npm"):
        self.name, self.version, self.ecosystem = name, version, eco


class VulnTLSTest(unittest.TestCase):
    def test_all_contexts_verify_certificates(self):
        ctxs = vuln._ssl_contexts()
        self.assertTrue(ctxs)
        for ctx in ctxs:
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(ctx.check_hostname)

    def test_no_unverified_fallback_in_source(self):
        with open(vuln.__file__, encoding="utf-8") as f:
            self.assertNotIn("_create_unverified_context", f.read())

    def test_cert_failure_raises_instead_of_downgrading(self):
        err = urllib.error.URLError(ssl.SSLCertVerificationError("bad cert"))
        opener = mock.Mock()
        opener.open.side_effect = err
        with mock.patch("urllib.request.build_opener", return_value=opener) as bo:
            with self.assertRaises(RuntimeError) as cm:
                vuln._post_json("https://api.osv.dev/v1/querybatch", {})
        self.assertIn("certificate", str(cm.exception))
        # one attempt per verified trust store, nothing more
        self.assertEqual(opener.open.call_count, len(vuln._ssl_contexts()))
        for call in bo.call_args_list:
            handler = call.args[0]
            self.assertEqual(handler._context.verify_mode, ssl.CERT_REQUIRED)

    def test_network_error_is_not_retried(self):
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.URLError(TimeoutError("timed out"))
        with mock.patch("urllib.request.build_opener", return_value=opener):
            with self.assertRaises(urllib.error.URLError):
                vuln._post_json("https://api.osv.dev/v1/querybatch", {})
        self.assertEqual(opener.open.call_count, 1)

    def test_redirect_refused(self):
        h = vuln._NoRedirect()
        with self.assertRaises(urllib.error.HTTPError):
            h.redirect_request(mock.Mock(), None, 302, "Found", {}, "https://evil.example/")

    def test_query_osv_failure_yields_no_advisories(self):
        def boom(*a, **k):
            raise RuntimeError("could not verify the TLS certificate")
        with mock.patch.object(vuln, "_post_json", boom), \
                mock.patch("sys.stdout") as out:
            self.assertEqual(vuln.query_osv([_Dep("lodash", "4.17.20")]), {})
        out.write.assert_not_called()  # diagnostics never pollute stdout


class OSVProtocolTest(unittest.TestCase):
    """query_osv speaks the real OSV API: batch IDs, paging, then per-ID details."""

    DETAILS = {
        "GHSA-aaaa-bbbb-cccc": {"id": "GHSA-aaaa-bbbb-cccc", "summary": "Bad thing.",
                                "aliases": ["CVE-2026-1"],
                                "severity": [{"type": "CVSS_V3", "score":
                                              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
        "GHSA-dddd-eeee-ffff": {"id": "GHSA-dddd-eeee-ffff", "summary": "Page two."},
    }

    def setUp(self):
        self.posts = []

    def _post(self, url, obj, timeout=30.0):
        self.posts.append(obj)
        self.assertIn("queries", obj)
        q = obj["queries"][0]
        if "page_token" not in q:
            return {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"},
                                           {"id": "../../etc/passwd"}],
                                 "next_page_token": "T1"}, {}]}
        self.assertEqual(q["page_token"], "T1")
        return {"results": [{"vulns": [{"id": "GHSA-dddd-eeee-ffff"}]}]}

    def _get(self, url, timeout=30.0):
        vid = url.rsplit("/", 1)[1]
        if vid == "GHSA-dddd-eeee-ffff":
            raise OSError("detail endpoint down")
        return self.DETAILS[vid]

    def test_paging_details_and_id_filtering(self):
        with mock.patch.object(vuln, "_post_json", self._post), \
                mock.patch.object(vuln, "_get_json", self._get):
            out = vuln.query_osv([_Dep("lodash", "4.17.20"), _Dep("left-pad", "1.3.0")])
        self.assertEqual(set(out), {"npm:lodash"})  # clean package has no entry
        advs = {a["id"]: a for a in out["npm:lodash"]}
        self.assertEqual(set(advs), {"GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"})
        self.assertEqual(advs["GHSA-aaaa-bbbb-cccc"]["cvss"], 9.8)
        self.assertEqual(advs["GHSA-aaaa-bbbb-cccc"]["aliases"], ["CVE-2026-1"])
        self.assertIsNone(advs["GHSA-dddd-eeee-ffff"]["cvss"])  # detail failed -> unscored
        self.assertEqual(len(self.posts), 2)
        self.assertEqual(len(self.posts[1]["queries"]), 1)  # only the paged query

    def test_detail_record_must_match_requested_id(self):
        def post(url, obj, timeout=30.0):
            return {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}]}

        def get(url, timeout=30.0):
            return {"id": "GHSA-zzzz-zzzz-zzzz", "summary": "spoofed",
                    "severity": [{"type": "CVSS_V3", "score": "10.0"}]}
        with mock.patch.object(vuln, "_post_json", post), \
                mock.patch.object(vuln, "_get_json", get):
            out = vuln.query_osv([_Dep("lodash", "4.17.20")])
        adv = out["npm:lodash"][0]
        self.assertEqual(adv["id"], "GHSA-aaaa-bbbb-cccc")
        self.assertIsNone(adv["cvss"])

    def test_malformed_batch_response_is_a_lookup_failure(self):
        with mock.patch.object(vuln, "_post_json", lambda *a, **k: {"vulnerabilities": []}):
            self.assertEqual(vuln.query_osv([_Dep("lodash", "4.17.20")]), {})

    def test_cross_database_duplicates_are_merged(self):
        recs = {
            "GHSA-1111-2222-3333": {"id": "GHSA-1111-2222-3333", "aliases": ["CVE-2026-7"],
                                    "summary": "Same bug.",
                                    "severity": [{"type": "CVSS_V3", "score": "7.5"}]},
            "PYSEC-2026-9": {"id": "PYSEC-2026-9",
                             "aliases": ["CVE-2026-7", "GHSA-1111-2222-3333"]},
            "GHSA-4444-5555-6666": {"id": "GHSA-4444-5555-6666", "summary": "Other bug."},
        }

        def post(url, obj, timeout=30.0):
            return {"results": [{"vulns": [{"id": k} for k in recs]}]}
        with mock.patch.object(vuln, "_post_json", post), \
                mock.patch.object(vuln, "_get_json",
                                  lambda url, timeout=30.0: recs[url.rsplit("/", 1)[1]]):
            out = vuln.query_osv([_Dep("requests", "2.19.0", "pypi")])
        advs = {a["id"]: a for a in out["pypi:requests"]}
        self.assertEqual(set(advs), {"GHSA-1111-2222-3333", "GHSA-4444-5555-6666"})
        self.assertEqual(advs["GHSA-1111-2222-3333"]["cvss"], 7.5)
        self.assertEqual(advs["GHSA-1111-2222-3333"]["aliases"], ["CVE-2026-7", "PYSEC-2026-9"])

    def test_one_invalid_query_does_not_sink_the_batch(self):
        calls = []

        def post(url, obj, timeout=30.0):
            calls.append(len(obj["queries"]))
            if any(q["version"] == "1.0" for q in obj["queries"]):
                raise urllib.error.HTTPError(url, 400, "Bad Request", {}, None)
            return {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}
                                for _ in obj["queries"]]}
        with mock.patch.object(vuln, "_post_json", post), \
                mock.patch.object(vuln, "_get_json", self._get), \
                mock.patch("sys.stderr") as err:
            out = vuln.query_osv([_Dep("serde", "1.0", "crates"), _Dep("lodash", "4.17.20")])
        self.assertEqual(set(out), {"npm:lodash"})
        self.assertEqual(calls, [2, 1, 1])
        self.assertIn("serde@1.0", "".join(c.args[0] for c in err.write.call_args_list))


if __name__ == "__main__":
    unittest.main()
