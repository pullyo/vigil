"""Deterministic tests for the opt-in registry license resolver (no network).

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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vigil import cli, licenses, parsers, registry  # noqa: E402


def npm_doc(name, version, lic):
    return {"name": name, "version": version, "license": lic}


def pypi_doc(name, version, **info):
    d = {"name": name, "version": version}
    d.update(info)
    return {"info": d}


class FakeFetch:
    """Maps URL -> doc (or Exception instance); records every call."""

    def __init__(self, table=None):
        self.table = table or {}
        self.calls = []

    def __call__(self, url, timeout, max_bytes):
        self.calls.append(url)
        res = self.table.get(url, registry.RegistryError("HTTP 404"))
        if isinstance(res, Exception):
            raise res
        return res


NPM = registry.NPM_REGISTRY
PYPI = registry.PYPI_REGISTRY


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text if isinstance(text, str) else json.dumps(text))


class TmpCase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = os.path.join(self._td.name, "proj")
        self.cache = os.path.join(self._td.name, "cache")
        os.makedirs(self.root)

    def tearDown(self):
        self._td.cleanup()

    def resolver(self, fetch, **kw):
        kw.setdefault("workers", 1)
        return registry.RegistryResolver(cache_dir=self.cache, fetch=fetch, **kw)

    def deps(self):
        return {d.name: d for d in parsers.scan(self.root)}


class ExactnessTests(TmpCase):
    def test_npm_ranges_are_not_exact_and_version_field_unchanged(self):
        write(self.root, "package.json", {"license": "GPL-3.0", "dependencies": {
            "a": "^4.17.21", "b": "4.17.21", "c": "=v1.2.3", "d": "latest",
            "e": "1.x", "f": ">=1.0.0 <2.0.0", "g": "npm:other@1.0.0"}})
        d = self.deps()
        self.assertEqual(d["a"].version, "4.17.21")          # unchanged normalization
        self.assertIsNone(d["a"].exact_version)              # ...but a range minimum
        self.assertEqual(d["b"].exact_version, "4.17.21")
        self.assertEqual(d["c"].exact_version, "1.2.3")
        for n in "defg":
            self.assertIsNone(d[n].exact_version, n)
        # root package.json license never leaks into dependencies
        self.assertTrue(all(x.license is None for x in d.values()))

    def test_pip_only_double_equals_is_exact(self):
        write(self.root, "requirements.txt", "\n".join([
            "django==4.2", "flask>=2.0", "six~=1.16", "numpy==1.*",
            "requests==2.31.0 ; python_version > '3' # pinned", "pandas==2.0,<3",
            "torch==2.1.0+cpu", "attrs===23.1.0"]))
        d = self.deps()
        self.assertEqual(d["django"].exact_version, "4.2")
        self.assertEqual(d["requests"].exact_version, "2.31.0")
        for n in ("flask", "six", "numpy", "pandas", "torch", "attrs"):
            self.assertIsNone(d[n].exact_version, n)
        self.assertEqual(d["flask"].version, "2.0")

    def test_lockfile_exact_version_and_license_provenance(self):
        write(self.root, "package.json", {"dependencies": {"lodash": "^4.17.0"}})
        write(self.root, "package-lock.json", {"packages": {
            "": {"name": "me", "version": "1.0.0", "license": "AGPL-3.0"},
            "node_modules/lodash": {"version": "4.17.21", "license": "MIT",
                                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
            "node_modules/aliased": {"name": "real", "version": "1.0.0", "license": "ISC"},
            "node_modules/gitdep": {"version": "2.0.0", "resolved": "git+ssh://x/y.git"},
            "packages/ws": {"version": "1.0.0", "license": "AGPL-3.0"}}})
        d = self.deps()
        self.assertEqual(d["lodash"].version, "4.17.21")
        self.assertEqual(d["lodash"].exact_version, "4.17.21")     # concrete, from lock
        self.assertEqual((d["lodash"].license, d["lodash"].license_src), ("MIT", "manifest"))
        self.assertIsNone(d["aliased"].exact_version)              # alias: wrong registry name
        self.assertEqual(d["aliased"].license, "ISC")              # declaration still trusted
        self.assertIsNone(d["gitdep"].exact_version)               # non-registry source
        self.assertIsNone(d["packages/ws"].exact_version)          # project's own workspace
        self.assertIsNone(d["packages/ws"].license)
        self.assertNotIn("me", d)
        self.assertFalse(any(x.license == "AGPL-3.0" for x in d.values()))

    def test_conflicting_exact_versions_are_not_trusted(self):
        write(self.root, "requirements.txt", "django>=3.0\n")
        write(self.root, "a/requirements.txt", "django==4.2\n")
        write(self.root, "b/requirements.txt", "django==4.1\n")
        self.assertIsNone(self.deps()["django"].exact_version)

    def test_conflicting_npm_locks_do_not_trust_the_first_version(self):
        write(self.root, "package-lock.json", {"packages": {
            "node_modules/pkg": {"version": "1.0.0", "license": "MIT"},
            "node_modules/a/node_modules/pkg": {"version": "2.0.0", "license": "GPL-3.0"},
        }})
        dep = self.deps()["pkg"]
        self.assertIsNone(dep.exact_version)
        self.assertIsNone(dep.license)


class PrecedenceTests(TmpCase):
    def test_registry_outranks_name_db_and_is_version_specific(self):
        fetch = FakeFetch({NPM + "/moment/2.29.4": npm_doc("moment", "2.29.4", "MIT"),
                           PYPI + "/pypi/gitpython/3.1.40/json":
                               pypi_doc("GitPython", "3.1.40", license="BSD-3-Clause")})
        write(self.root, "package.json", {"dependencies": {"moment": "2.29.4", "lodash": "^4.0.0"}})
        write(self.root, "requirements.txt", "gitpython==3.1.40\n")
        deps = parsers.scan(self.root)
        counts = licenses.resolve_all(deps, self.root, self.resolver(fetch))
        d = {x.name: x for x in deps}
        self.assertEqual((d["moment"].license, d["moment"].license_src), ("MIT", "registry"))
        self.assertEqual(d["gitpython"].license, "BSD-3-Clause")
        self.assertEqual((d["lodash"].license, d["lodash"].license_src), ("mit", "db"))
        self.assertFalse(any("lodash" in u for u in fetch.calls))  # range never looked up
        self.assertFalse(any("latest" in u for u in fetch.calls))
        self.assertEqual(counts, {"eligible": 3, "local": 0, "registry": 2,
                                  "no_exact": 1, "fallback": 0})

    def test_lockfile_and_installed_outrank_registry(self):
        write(self.root, "package-lock.json", {"packages": {
            "node_modules/a": {"version": "1.0.0", "license": "Apache-2.0"},
            "node_modules/b": {"version": "1.0.0"}}})
        write(self.root, "node_modules/b/package.json", {
            "name": "b", "version": "1.0.0", "license": "BSD-2-Clause"})
        fetch = FakeFetch()
        deps = parsers.scan(self.root)
        licenses.resolve_all(deps, self.root, self.resolver(fetch))
        d = {x.name: x for x in deps}
        self.assertEqual((d["a"].license, d["a"].license_src), ("Apache-2.0", "manifest"))
        self.assertEqual((d["b"].license, d["b"].license_src), ("BSD-2-Clause", "installed"))
        self.assertEqual(fetch.calls, [])

    def test_stale_installed_metadata_does_not_override_pinned_metadata(self):
        write(self.root, "package.json", {"dependencies": {"a": "1.0.0"}})
        write(self.root, "node_modules/a/package.json", {
            "name": "a", "version": "0.9.0", "license": "GPL-3.0"})
        write(self.root, "requirements.txt", "b==1.0.0\n")
        write(self.root, "site-packages/b-0.9.0.dist-info/METADATA",
              "Name: b\nVersion: 0.9.0\nLicense: GPL-3.0\n")
        fetch = FakeFetch({NPM + "/a/1.0.0": npm_doc("a", "1.0.0", "MIT"),
                           PYPI + "/pypi/b/1.0.0/json": pypi_doc("B", "1.0", license="ISC")})
        deps = self.deps()
        licenses.resolve_all(list(deps.values()), self.root, self.resolver(fetch))
        self.assertEqual((deps["a"].license, deps["a"].license_src), ("MIT", "registry"))
        self.assertEqual((deps["b"].license, deps["b"].license_src), ("ISC", "registry"))

    def test_compound_license_requires_review(self):
        self.assertEqual(licenses.classify("MIT AND GPL-3.0"), "unknown")

    def test_mismatched_metadata_is_rejected(self):
        fetch = FakeFetch({NPM + "/moment/2.29.4": npm_doc("moment", "2.30.1", "MIT")})
        dep = parsers.Dependency("moment", "2.29.4", "npm", "package.json", exact_version="2.29.4")
        licenses.resolve_license(dep, self.root, self.resolver(fetch))
        self.assertEqual((dep.license, dep.license_src), ("mpl-2.0", "db"))

    def test_pypi_license_field_selection(self):
        p = registry.parse_license
        self.assertEqual(p("pypi", pypi_doc("x", "1.0", license_expression="MIT OR Apache-2.0",
                                            license="BSD"), "x", "1.0.0"), "MIT OR Apache-2.0")
        long_text = "Copyright (c) ...\n" + "Permission is hereby granted " * 20
        self.assertEqual(p("pypi", pypi_doc("x", "1.0", license=long_text, classifiers=[
            "License :: OSI Approved :: Apache Software License"]), "x", "1.0"), "Apache-2.0")
        self.assertIsNone(p("pypi", pypi_doc("x", "1.0", license="UNKNOWN"), "x", "1.0"))
        self.assertEqual(p("npm", {"name": "@s/p", "version": "1.0.0",
                                   "licenses": [{"type": "MIT"}, {"type": "GPL-2.0"}]},
                           "@s/p", "1.0.0"), "MIT OR GPL-2.0")

    def test_name_and_version_validation(self):
        ok = registry.lookup_url
        self.assertEqual(ok("npm", "@scope/pkg", "1.0.0-rc.1"),
                         NPM + "/@scope/pkg/1.0.0-rc.1")
        self.assertEqual(ok("pypi", "zope.interface", "6.0"), PYPI + "/pypi/zope.interface/6.0/json")
        for eco, name, ver in [("npm", "../etc", "1.0.0"), ("npm", "a/b", "1.0.0"),
                               ("npm", "a", "^1.0.0"), ("npm", "a", "latest"),
                               ("npm", "a?x=1", "1.0.0"), ("pypi", "a b", "1.0"),
                               ("pypi", "x", "1.*"), ("pypi", "x/../y", "1.0"),
                               ("go", "x", "1.0.0")]:
            with self.assertRaises(ValueError, msg=(eco, name, ver)):
                ok(eco, name, ver)


class OfflineAndCacheTests(TmpCase):
    def test_network_failure_falls_back_and_circuit_breaks(self):
        err = registry.RegistryError("network error: offline", network=True)
        fetch = FakeFetch()
        fetch.table = type("All", (dict,), {"get": lambda self, k, d=None: err})()
        r = self.resolver(fetch, max_failures=2)
        deps = [parsers.Dependency(n, "1.0.0", "npm", "package.json", exact_version="1.0.0")
                for n in ("react", "axios", "x1", "x2", "x3")]
        counts = licenses.resolve_all(deps, self.root, r)
        self.assertEqual(len(fetch.calls), 2)                     # stopped early
        self.assertEqual(r.stats["failed"], 2)
        self.assertEqual(r.stats["skipped"], 3)
        self.assertEqual([d.license for d in deps], ["mit", "mit", "unknown", "unknown", "unknown"])
        self.assertEqual(counts["fallback"], 5)
        self.assertFalse(os.path.exists(self.cache) and os.listdir(self.cache))  # nothing cached

    def test_max_lookups_bound(self):
        fetch = FakeFetch()
        r = self.resolver(fetch, max_lookups=2)
        r.prefetch(("npm", "p%d" % i, "1.0.0") for i in range(5))
        self.assertEqual(len(fetch.calls), 2)
        self.assertEqual(r.stats["skipped"], 3)

    def test_cache_reuse_dedupe_and_expiry(self):
        url = PYPI + "/pypi/requests/2.31.0/json"
        fetch = FakeFetch({url: pypi_doc("requests", "2.31.0", license="Apache 2.0")})
        now = [1000.0]
        r1 = self.resolver(fetch, workers=4, clock=lambda: now[0])
        r1.prefetch([("pypi", "requests", "2.31.0"), ("pypi", "Requests", "2.31.0"),
                     ("pypi", "requests", "2.31.0")])
        self.assertEqual(fetch.calls, [url])                      # deduplicated
        self.assertEqual(r1.lookup("pypi", "requests", "2.31.0"), (True, "Apache 2.0"))
        self.assertEqual(len(fetch.calls), 1)

        offline = FakeFetch()                                     # everything fails
        r2 = self.resolver(offline, clock=lambda: now[0] + 3600)
        self.assertEqual(r2.lookup("pypi", "requests", "2.31.0"), (True, "Apache 2.0"))
        self.assertEqual((offline.calls, r2.stats["cached"]), ([], 1))

        r3 = self.resolver(offline, ttl=60, clock=lambda: now[0] + 3600)  # expired
        self.assertEqual(r3.lookup("pypi", "requests", "2.31.0"), (False, None))
        self.assertEqual(offline.calls, [url])

    def test_http_response_size_is_bounded(self):
        class Resp(io.BytesIO):
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        opener = mock.Mock()
        opener.open.return_value = Resp(b'{"x": "' + b"a" * 100 + b'"}')
        with mock.patch("urllib.request.build_opener", return_value=opener):
            with self.assertRaises(registry.RegistryError):
                registry.http_get_json(NPM + "/a/1.0.0", 1.0, 50)
            opener.open.return_value = Resp(b'{"ok": 1}')
            self.assertEqual(registry.http_get_json(NPM + "/a/1.0.0", 1.0, 50), {"ok": 1})
            self.assertEqual(opener.open.call_args[1]["timeout"], 1.0)


class CliTests(TmpCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def setUp(self):
        super().setUp()
        write(self.root, "package.json", {"dependencies": {"moment": "2.29.4", "axios": "^1.6.0"}})
        write(self.root, "requirements.txt", "gitpython==3.1.40\n")
        self.fetch = FakeFetch({
            NPM + "/moment/2.29.4": npm_doc("moment", "2.29.4", "MIT"),
            PYPI + "/pypi/gitpython/3.1.40/json": pypi_doc("GitPython", "3.1.40",
                                                           license="BSD-3-Clause")})
        p = mock.patch.object(registry, "http_get_json", self.fetch)
        p.start()
        self.addCleanup(p.stop)

    def test_default_is_offline(self):
        rc, out, err = self.run_cli(self.root, "-f", "json")
        self.assertEqual(self.fetch.calls, [])
        data = json.loads(out)
        lic = {d["dep_name"]: d["license"] for d in data["dependencies"]}
        self.assertEqual(lic, {"moment": "mpl-2.0", "axios": "mit", "gitpython": "gpl-3.0"})
        self.assertEqual((rc, err), (1, ""))                      # gpl-3.0 -> high

    def test_registry_json_stays_clean_and_counts_are_honest(self):
        args = (self.root, "-f", "json", "--registry", "--registry-cache", self.cache)
        rc, out, err = self.run_cli(*args)
        data = json.loads(out)                                    # stdout is pure JSON
        by = {d["dep_name"]: d for d in data["dependencies"]}
        self.assertEqual(by["moment"]["license"], "MIT")
        self.assertEqual(by["gitpython"]["license"], "BSD-3-Clause")
        self.assertEqual(by["axios"]["license"], "mit")           # range -> offline DB
        self.assertEqual(by["axios"]["version"], "1.6.0")         # reported field unchanged
        self.assertEqual(set(data), {"tool", "project_license", "summary",
                                     "dependencies", "vulnerabilities"})
        self.assertEqual(rc, 0)                                   # no more high findings
        self.assertIn("resolved 2/3", err)
        self.assertIn("0 cached, 2 fetched, 0 failed", err)
        self.assertIn("1 without an exact version", err)

        self.fetch.table = {}                                     # registry now "down"
        rc2, out2, err2 = self.run_cli(*args)
        self.assertEqual(json.loads(out2), data)
        self.assertIn("2 cached, 0 fetched", err2)
        self.assertEqual(len(self.fetch.calls), 2)

    def test_registry_offline_matches_default_output(self):
        self.fetch.table = type("All", (dict,), {"get": lambda s, k, d=None: registry.RegistryError(
            "network error", network=True)})()
        _, base, _ = self.run_cli(self.root)
        rc, out, err = self.run_cli(self.root, "--registry", "--registry-cache", self.cache)
        self.assertEqual((rc, out), (1, base))
        self.assertIn("resolved 0/3", err)
        self.assertIn("2 failed", err)


if __name__ == "__main__":
    unittest.main()
