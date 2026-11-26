"""CycloneDX SBOM and third-party notices."""
import datetime
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vigil import compliance, licenses, parsers  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _scan(path):
    deps = parsers.scan(path)
    licenses.resolve_all(deps, path, None)
    return deps, [licenses.evaluate(d, "proprietary") for d in deps]


class PurlTest(unittest.TestCase):
    def test_purls(self):
        D = parsers.Dependency
        cases = [
            (D("@babel/core", "7.0.0", "npm", "x"), "7.0.0", "pkg:npm/%40babel/core@7.0.0"),
            (D("Django_REST", "1", "pypi", "x"), "3.1", "pkg:pypi/django-rest@3.1"),
            (D("golang.org/x/net", "0.17.0", "go", "x"), "0.17.0", "pkg:golang/golang.org/x/net@v0.17.0"),
            (D("monolog/monolog", "2.9.1", "packagist", "x"), "2.9.1", "pkg:composer/monolog/monolog@2.9.1"),
            (D("serde", "1", "crates", "x"), "1.0.1", "pkg:cargo/serde@1.0.1"),
            (D("rails", "7", "rubygems", "x"), None, "pkg:gem/rails"),
        ]
        for dep, ver, want in cases:
            self.assertEqual(compliance.purl(dep, ver), want)

    def test_spdx_canonical(self):
        self.assertEqual(compliance.spdx_id("apache-2.0"), "Apache-2.0")
        self.assertEqual(compliance.spdx_id("bsd-3-clause"), "BSD-3-Clause")
        self.assertIsNone(compliance.spdx_id("unknown"))


class SbomTest(unittest.TestCase):
    def test_demo_sbom(self):
        demo = os.path.join(ROOT, "examples", "demo")
        deps, verdicts = _scan(demo)
        bom = json.loads(compliance.cyclonedx(
            deps, verdicts, "demo", now=datetime.datetime(2026, 11, 26, tzinfo=datetime.timezone.utc),
            serial="urn:uuid:00000000-0000-4000-8000-000000000000"))
        self.assertEqual((bom["bomFormat"], bom["specVersion"]), ("CycloneDX", "1.5"))
        self.assertEqual(bom["metadata"]["timestamp"], "2026-11-26T00:00:00Z")
        names = {c["name"] for c in bom["components"]}
        self.assertEqual(names, {d.name for d in deps})
        refs = [c["bom-ref"] for c in bom["components"]]
        self.assertEqual(len(refs), len(set(refs)))
        self.assertEqual(bom["dependencies"][0]["dependsOn"], refs)
        gp = [c for c in bom["components"] if c["name"] == "gitpython"][0]
        self.assertEqual(gp["licenses"], [{"license": {"id": "GPL-3.0"}}])

    def test_one_component_per_installed_version(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "uv.lock"), "w") as f:
                f.write('version = 1\n\n[[package]]\nname = "asgiref"\nversion = "3.11.1"\n'
                        'source = { registry = "https://pypi.org/simple" }\n\n[[package]]\n'
                        'name = "asgiref"\nversion = "3.12.1"\n'
                        'source = { registry = "https://pypi.org/simple" }\n')
            deps, verdicts = _scan(d)
        bom = json.loads(compliance.cyclonedx(deps, verdicts))
        self.assertEqual([c["purl"] for c in bom["components"]],
                         ["pkg:pypi/asgiref@3.11.1", "pkg:pypi/asgiref@3.12.1"])


class NoticesTest(unittest.TestCase):
    def test_demo_notices(self):
        deps, verdicts = _scan(os.path.join(ROOT, "examples", "demo"))
        text = compliance.notices(deps, verdicts, "demo")
        self.assertTrue(text.startswith("# Third-party notices"))
        self.assertLess(text.index("License not identified"), text.index("## MIT"))
        self.assertIn("https://spdx.org/licenses/GPL-3.0.html", text)
        for d in deps:
            self.assertIn("- %s" % d.name, text)


if __name__ == "__main__":
    unittest.main()
