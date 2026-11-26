"""Opt-in public registry license lookups (npm + PyPI), with a local disk cache.

Only used when the CLI is run with ``--registry``; the default scan never
touches the network. Lookups are per *exact* version only:

    npm:  GET https://registry.npmjs.org/<name>/<version>
    PyPI: GET https://pypi.org/pypi/<name>/<version>/json

Nothing about the scanned project is sent beyond the package name and version
in the URL. Guard rails:

* package names and versions are validated before any URL is built;
* HTTPS only, redirects restricted to the same registry host, TLS verified;
* per-request timeout, bounded response size, bounded worker pool, a total
  lookup cap and wall-clock budget, and a circuit breaker that stops after
  repeated network failures (so an offline run degrades quickly);
* the returned document must name the same package and version, otherwise it
  is ignored;
* successful responses are cached on disk with an expiry; in-run duplicates are
  looked up once.

Failures never raise out of this module: callers fall back to the offline DB.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from typing import Callable, Dict, Iterable, Optional, Tuple

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org"
_ALLOWED_HOSTS = {"registry.npmjs.org", "pypi.org"}

DEFAULT_TTL = 7 * 24 * 3600        # cache expiry (seconds)
DEFAULT_TIMEOUT = 10.0             # per request (seconds)
DEFAULT_MAX_BYTES = 2 * 1024 * 1024  # per response
DEFAULT_MAX_LOOKUPS = 300          # network requests per run
DEFAULT_BUDGET = 60.0              # wall-clock seconds for all network work
DEFAULT_WORKERS = 8
DEFAULT_MAX_FAILURES = 5           # network errors before giving up for the run
SUPPORTED = ("npm", "pypi")

_NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$")
_NPM_VER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_PYPI_VER_RE = re.compile(r"^[0-9][0-9A-Za-z.!-]*$")

# Trove classifier suffix -> SPDX-ish id understood by licenses.classify().
_CLASSIFIERS = {
    "mit license": "MIT", "isc license (iscl)": "ISC",
    "apache software license": "Apache-2.0", "bsd license": "BSD",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "gnu general public license v2 (gplv2)": "GPL-2.0",
    "gnu general public license v3 (gplv3)": "GPL-3.0",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "gnu affero general public license v3": "AGPL-3.0",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.1",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0",
    "the unlicense (unlicense)": "Unlicense",
    "python software foundation license": "PSF-2.0",
}


class RegistryError(Exception):
    """A lookup failed (network, HTTP, size, parse or identity mismatch)."""

    def __init__(self, msg: str, network: bool = False):
        super().__init__(msg)
        self.network = network


def default_cache_dir() -> str:
    env = os.environ.get("VIGIL_CACHE_DIR")
    if env:
        return os.path.join(env, "registry")
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "vigil", "registry")


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _norm_pyver(v: str) -> str:
    v = v.strip().lower()
    parts = re.split(r"(?=[a-z!+-])", v, maxsplit=1)
    rel = parts[0].split(".")
    while len(rel) > 1 and rel[-1] == "0":
        rel.pop()
    return ".".join(rel) + (parts[1] if len(parts) > 1 else "")


def lookup_url(ecosystem: str, name: str, version: str) -> str:
    """Build the per-version metadata URL, or raise ValueError if invalid."""
    if ecosystem == "npm":
        if (len(name) > 214 or len(version) > 256 or
                not _NPM_NAME_RE.fullmatch(name) or not _NPM_VER_RE.fullmatch(version)):
            raise ValueError("invalid npm package/version")
        return "%s/%s/%s" % (NPM_REGISTRY, name, urllib.parse.quote(version, safe=".-+"))
    if ecosystem == "pypi":
        if (len(name) > 200 or len(version) > 64 or
                not _PYPI_NAME_RE.fullmatch(name) or not _PYPI_VER_RE.fullmatch(version)):
            raise ValueError("invalid PyPI package/version")
        return "%s/pypi/%s/%s/json" % (PYPI_REGISTRY, name, urllib.parse.quote(version, safe=".-"))
    raise ValueError("unsupported ecosystem %r" % ecosystem)


def _npm_license(doc: dict, name: str, version: str) -> Optional[str]:
    if doc.get("name") != name or doc.get("version") != version:
        raise RegistryError("npm metadata does not match %s@%s" % (name, version))
    lic = doc.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    if not lic and isinstance(doc.get("licenses"), list):
        types = [l.get("type") if isinstance(l, dict) else l for l in doc["licenses"]]
        types = [str(t) for t in types if t]
        lic = " OR ".join(types) if types else None
    return str(lic).strip() if lic and str(lic).strip() else None


def _pypi_license(doc: dict, name: str, version: str) -> Optional[str]:
    info = doc.get("info") if isinstance(doc, dict) else None
    if not isinstance(info, dict):
        raise RegistryError("PyPI metadata has no info")
    if _pep503(str(info.get("name", ""))) != _pep503(name) or \
            _norm_pyver(str(info.get("version", ""))) != _norm_pyver(version):
        raise RegistryError("PyPI metadata does not match %s==%s" % (name, version))
    expr = info.get("license_expression")
    if isinstance(expr, str) and expr.strip():
        return expr.strip()
    text = info.get("license")
    if isinstance(text, str):
        text = text.strip()
        # Short one-line declarations only; full license texts are ambiguous.
        if text and "\n" not in text and len(text) <= 80 and text.upper() != "UNKNOWN":
            return text
    for c in info.get("classifiers") or []:
        if isinstance(c, str) and c.startswith("License ::"):
            hit = _CLASSIFIERS.get(c.split("::")[-1].strip().lower())
            if hit:
                return hit
    return None


def parse_license(ecosystem: str, doc, name: str, version: str) -> Optional[str]:
    if not isinstance(doc, dict):
        raise RegistryError("unexpected metadata shape")
    lic = (_npm_license if ecosystem == "npm" else _pypi_license)(doc, name, version)
    if lic and len(lic) <= 300 and lic.isprintable():
        return lic
    return None


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlparse(newurl)
        if u.scheme != "https" or u.hostname not in _ALLOWED_HOSTS or \
                u.hostname != urllib.parse.urlparse(req.full_url).hostname:
            raise RegistryError("refusing redirect to %s" % newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@lru_cache(maxsize=1)
def _ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    # macOS framework Python may lack its own OpenSSL bundle. Use the system
    # bundle when Python has no configured CA path, while preserving TLS checks.
    if (sys.platform == "darwin" and not os.getenv("SSL_CERT_FILE") and
            not os.getenv("SSL_CERT_DIR") and not context.get_ca_certs() and
            not ssl.get_default_verify_paths().capath and os.path.isfile("/etc/ssl/cert.pem")):
        context.load_verify_locations(cafile="/etc/ssl/cert.pem")
    return context


def http_get_json(url: str, timeout: float, max_bytes: int):
    """GET a JSON document with a timeout and a hard response-size cap."""
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "vigil-license-audit"})
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_ssl_context()), _SameHostRedirect())
    try:
        with opener.open(req, timeout=timeout) as r:
            length = r.headers.get("Content-Length")
            if length and length.isdigit() and int(length) > max_bytes:
                raise RegistryError("response too large")
            body = r.read(max_bytes + 1)
    except urllib.error.HTTPError as e:
        # 404 & co. are definitive answers from a reachable registry.
        raise RegistryError("HTTP %s" % e.code, network=e.code >= 500 or e.code == 429)
    except RegistryError:
        raise
    except Exception as e:  # URLError, timeouts, TLS, connection resets
        raise RegistryError("network error: %s" % e, network=True)
    if len(body) > max_bytes:
        raise RegistryError("response too large")
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        raise RegistryError("invalid JSON")


Key = Tuple[str, str, str]


class RegistryResolver:
    """Resolve licenses for exact (ecosystem, name, version) triples.

    ``fetch(url, timeout, max_bytes) -> parsed JSON`` is injectable for tests.
    """

    def __init__(self, cache_dir: Optional[str] = None, ttl: float = DEFAULT_TTL,
                 timeout: float = DEFAULT_TIMEOUT, max_bytes: int = DEFAULT_MAX_BYTES,
                 max_lookups: int = DEFAULT_MAX_LOOKUPS, budget: float = DEFAULT_BUDGET,
                 workers: int = DEFAULT_WORKERS, max_failures: int = DEFAULT_MAX_FAILURES,
                 fetch: Optional[Callable] = None, clock: Callable[[], float] = time.time):
        self.cache_dir = cache_dir or default_cache_dir()
        self.ttl, self.timeout, self.max_bytes = ttl, timeout, max_bytes
        self.max_lookups, self.budget, self.workers = max_lookups, budget, max(1, workers)
        self.max_failures = max_failures
        self.fetch = fetch or http_get_json
        self.clock = clock
        self._memo: Dict[Key, Tuple[bool, Optional[str]]] = {}  # key -> (ok, license)
        self._lock = threading.Lock()
        self._deadline: Optional[float] = None
        self._net_failures = 0
        self.stats = {"cached": 0, "fetched": 0, "failed": 0, "skipped": 0, "invalid": 0}

    # -- cache -------------------------------------------------------------
    @staticmethod
    def _key(ecosystem: str, name: str, version: str) -> Key:
        return (ecosystem, _pep503(name) if ecosystem == "pypi" else name, version)

    def _cache_path(self, key: Key) -> str:
        h = hashlib.sha256("\0".join(key).encode("utf-8")).hexdigest()
        return os.path.join(self.cache_dir, h + ".json")

    def _cache_get(self, key: Key):
        try:
            with open(self._cache_path(key), "r", encoding="utf-8") as f:
                entry = json.load(f)
            if entry.get("key") != list(key):
                return None
            age = self.clock() - float(entry.get("fetched_at", 0))
            if age < 0 or age > self.ttl:
                return None
            lic = entry.get("license")
            return (lic if isinstance(lic, str) else None,)
        except Exception:
            return None

    def _cache_put(self, key: Key, lic: Optional[str]) -> None:
        try:
            os.makedirs(self.cache_dir, mode=0o700, exist_ok=True)
            path = self._cache_path(key)
            tmp = "%s.%d.%d.tmp" % (path, os.getpid(), threading.get_ident())
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"key": list(key), "license": lic, "fetched_at": self.clock()}, f)
            os.replace(tmp, path)
        except Exception:
            pass  # cache is best-effort

    # -- lookups -----------------------------------------------------------
    def _resolve(self, key: Key, name: str) -> None:
        eco, _, version = key
        hit = self._cache_get(key)
        if hit is not None:
            with self._lock:
                self._memo[key] = (True, hit[0])
                self.stats["cached"] += 1
            return
        try:
            url = lookup_url(eco, name, version)
        except ValueError:
            with self._lock:
                self._memo[key] = (False, None)
                self.stats["invalid"] += 1
            return
        with self._lock:
            out_of_budget = (self._net_failures >= self.max_failures or
                             self.stats["fetched"] + self.stats["failed"] >= self.max_lookups or
                             (self._deadline is not None and self.clock() > self._deadline))
            if out_of_budget:
                self._memo[key] = (False, None)
                self.stats["skipped"] += 1
                return
            self.stats["failed"] += 1  # provisional: reserves a lookup slot
        try:
            remaining = self.timeout
            if self._deadline is not None:
                remaining = max(0.5, min(self.timeout, self._deadline - self.clock()))
            lic = parse_license(eco, self.fetch(url, remaining, self.max_bytes), name, version)
        except Exception as e:
            with self._lock:
                self._memo[key] = (False, None)
                if getattr(e, "network", False):
                    self._net_failures += 1
            return
        with self._lock:
            self.stats["failed"] -= 1
            self.stats["fetched"] += 1
            self._memo[key] = (True, lic)
        self._cache_put(key, lic)

    def prefetch(self, items: Iterable[Tuple[str, str, str]]) -> None:
        """Resolve many (ecosystem, name, version) triples, deduplicated."""
        todo = {}
        for eco, name, version in items:
            if eco not in SUPPORTED or not version:
                continue
            key = self._key(eco, name, version)
            if key not in self._memo and key not in todo:
                todo[key] = name
        if not todo:
            return
        if self._deadline is None:
            self._deadline = self.clock() + self.budget
        if self.workers == 1 or len(todo) == 1:
            for key, name in todo.items():
                self._resolve(key, name)
            return
        with ThreadPoolExecutor(max_workers=min(self.workers, len(todo))) as pool:
            list(pool.map(lambda kv: self._resolve(*kv), list(todo.items())))

    def lookup(self, ecosystem: str, name: str, version: Optional[str]) -> Tuple[bool, Optional[str]]:
        """Return (found, license). ``found`` means a matching metadata document
        was obtained (license may still be None if it declares none)."""
        if ecosystem not in SUPPORTED or not version:
            return (False, None)
        key = self._key(ecosystem, name, version)
        if key not in self._memo:
            self.prefetch([(ecosystem, name, version)])
        return self._memo.get(key, (False, None))
