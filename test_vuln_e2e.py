"""E2E: exercise the full CVE pipeline with a mocked OSV batch boundary.

Mocks the OSV boundary (vuln._post_json batch IDs + vuln._get_json details) in
the real API shape, then runs the real CLI so query_osv -> _annotate -> _best_score
-> report rendering -> exit code all execute for real.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from vigil import vuln, cli, prokey, ed25519

# Throwaway signing key for this test run; the real seller key never ships.
_TEST_SECRET = bytes(range(32))
prokey.PUBLIC_KEY = ed25519.public_key(_TEST_SECRET).hex()
_PAYLOAD = {"v": 1, "ent": "pro", "sub": "e2e-test", "iat": "2026-11-26"}
KEY = prokey.encode_key(_PAYLOAD, ed25519.sign(_TEST_SECRET, prokey.signed_bytes(_PAYLOAD)))

# Canned advisories keyed by (ecosystem, name). Mix of scope-changed (10.0),
# scope-unchanged (6.5) and a numeric-score path.
CANNED = {
    ("PyPI", "django"): [
        {"id": "CVE-2026-9999", "database": "GITHUB_ADVISORIES",
         "aliases": ["GHSA-0000-0000-aaaa"],
         "summary": "Remote code execution via template autoescape bypass.\nSecond line.",
         "severity": [{"type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]},
    ],
    ("npm", "lodash"): [
        {"id": "CVE-2026-8888", "database": "NVD",
         "aliases": [],
         "summary": "Prototype pollution in _.template.",
         "severity": [{"type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}]},
    ],
    # numeric-score path (already a float, not a vector). Note: code normalizes
    # the OSV ecosystem name to "PyPI", so key by that, not the raw "pypi".
    ("PyPI", "requests"): [
        {"id": "CVE-2023-32681", "database": "GITHUB_ADVISORIES",
         "aliases": ["GHSA-39ph-fvjr-hcwh"],
         "summary": "Proxy-Authorization header leak on redirects.",
         "severity": [{"type": "CVSS_V3", "score": "7.5"}]},
    ],
}
# Map demo ecosystems to OSV ecosystem names the way vuln.ECO_TO_OSV does.
ECO = {"pypi": "PyPI", "npm": "npm"}

BY_ID = {a["id"]: a for advs in CANNED.values() for a in advs}

def fake_post_json(url, obj, timeout=30.0):
    # Real OSV querybatch shape: {"queries": [...]} -> {"results": [{"vulns": [{"id"}]}]}
    assert url == vuln.OSV_BATCH and "queries" in obj, obj
    out = []
    for q in obj["queries"]:
        advs = CANNED.get((q["package"]["ecosystem"], q["package"]["name"]), [])
        out.append({"vulns": [{"id": a["id"], "modified": "2026-01-01T00:00:00Z"}
                              for a in advs]} if advs else {})
    return {"results": out}

def fake_get_json(url, timeout=30.0):
    return BY_ID[url.rsplit("/", 1)[1]]

vuln._post_json = fake_post_json
vuln._get_json = fake_get_json

args = ["examples/demo", "--vuln", "--key", KEY, "--fail-on", "any", "--format", "json"]
rc = cli.main(args)

import json
# Re-run to capture JSON stdout for assertions
import io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc2 = cli.main(["examples/demo", "--vuln", "--key", KEY, "--fail-on", "any", "--format", "json"])
data = json.loads(buf.getvalue())

checks = []
vmap = data["vulnerabilities"]
checks.append(("vuln_map has pypi:django", "pypi:django" in vmap))
checks.append(("vuln_map has npm:lodash", "npm:lodash" in vmap))
checks.append(("vuln_map has pypi:requests", "pypi:requests" in vmap))
checks.append(("no vuln for six", "pypi:six" not in vmap))

dj = vmap.get("pypi:django", [{}])[0]
lo = vmap.get("npm:lodash", [{}])[0]
rq = vmap.get("pypi:requests", [{}])[0]
checks.append(("django CVSS computed 10.0 (scope changed)", dj.get("cvss") == 10.0))
checks.append(("lodash CVSS computed 6.5 (scope unchanged)", abs(lo.get("cvss", 0) - 6.5) < 0.05))
checks.append(("requests CVSS numeric 7.5 passed through", rq.get("cvss") == 7.5))
checks.append(("django alias carried", "GHSA-0000-0000-aaaa" in dj.get("aliases", [])) )
checks.append(("summary first-line only", dj.get("summary", "").count("\n") == 0))
checks.append(("exit code 1 (vulns present, fail-on any)", rc2 == 1))

ok = all(c[1] for c in checks)
for name, passed in checks:
    print("  %s  %s" % ("OK " if passed else "FAIL", name))
print("\nE2E:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
