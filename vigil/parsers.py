
"""Manifest parsers: turn dependency files into a flat list of Dependency objects.

Supported ecosystems and files:
  npm       package.json, package-lock.json, yarn.lock (v1 + berry), pnpm-lock.yaml
  pip       requirements.txt, pyproject.toml, poetry.lock, Pipfile.lock, uv.lock
  go        go.mod (versions there are the exact selected versions)
  cargo     Cargo.toml, Cargo.lock
  composer  composer.json, composer.lock
  ruby      Gemfile, Gemfile.lock

Versions are normalized to the best exact-ish value we can find (lockfiles win
over ranges) because the vuln engine wants concrete versions.

Normalization strips range operators, so ``version`` alone cannot tell a pin
from a range minimum. Exactness is tracked separately: ``exact_version`` is set
only when a manifest pins a concrete version (npm ``"1.2.3"``, pip ``==1.2.3``)
or a lockfile records the installed one, and only that value may be used to
fetch per-version registry metadata. The reported version uses that concrete
version when all observations agree on it.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class Dependency:
    name: str
    version: str          # exact or range; "*" when unknown
    ecosystem: str        # npm | pypi | go | crates | packagist | rubygems
    manifest: str         # relative path of the manifest this came from
    license: Optional[str] = None
    license_src: str = "none"
    direct: bool = True
    # Concrete version safe for a public-registry per-version lookup (None when
    # only a range / unknown / non-registry source is known). Never a range min.
    exact_version: Optional[str] = None
    # (concrete version, public-registry lookup ok, lockfile-declared license)
    # observations; resolved into exact_version/license by _dedupe().
    _exact: List[Tuple[str, bool, Optional[str]]] = field(default_factory=list, repr=False)
    # Every concrete version observed for this package (lockfiles, pins, go.mod),
    # sorted. More than one means several versions are installed side by side.
    # Empty when only a range is known. Used for CVE lookups.
    resolved: List[str] = field(default_factory=list)


_NPM_EXACT_RE = re.compile(r"^=?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$")
_PIP_EXACT_RE = re.compile(r"^==\s*([0-9][0-9A-Za-z.!-]*)$")
_NPM_PUBLIC_RESOLVED = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")


def _npm_exact(spec) -> Optional[str]:
    """Concrete version when an npm spec is a bare pin (no range/tag/url)."""
    if not isinstance(spec, str):
        return None
    m = _NPM_EXACT_RE.match(spec.strip())
    return m.group(1) if m else None


def _pip_exact(rest: str) -> Optional[str]:
    """Concrete version when a requirement's specifier is exactly ``==X``.

    ``rest`` is the text after the project name. Markers, comments and line
    continuations are ignored; wildcards, local versions, extras and
    multi-clause specifiers are not treated as exact.
    """
    rest = rest.split(";", 1)[0].split("#", 1)[0].strip().rstrip("\\").strip()
    m = _PIP_EXACT_RE.match(rest)
    return m.group(1) if m else None


def _mark_exact(dep: Dependency, version: Optional[str], public: bool = True,
                license: Optional[str] = None) -> Dependency:
    if version:
        dep._exact.append((version, public, license))
    return dep


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _read_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _clean_ver(v: Optional[str]) -> str:
    """Strip caret/tilde/compare prefixes and a leading v; keep the core version."""
    if not isinstance(v, str) or not v:
        return "*"
    v = v.strip()
    v = re.sub(r"^[~^>=<\s]+", "", v)
    v = re.sub(r"^v(?=\d)", "", v)
    v = v.split()[0]
    return v or "*"


def _npm_deps(path: str) -> List[Dependency]:
    data = _read_json(path)
    out = []
    # Only dependency sections are read; the root "license" field is the
    # project's own and is deliberately never attached to a dependency.
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver in (data.get(section) or {}).items():
            out.append(_mark_exact(Dependency(name, _clean_ver(ver), "npm", "package.json"),
                                   _npm_exact(ver)))
    return out


def _lock_license(meta: dict) -> Optional[str]:
    lic = meta.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    return lic.strip() if isinstance(lic, str) and lic.strip() else None


def _npm_lock_deps(path: str) -> List[Dependency]:
    data = _read_json(path)
    out = []
    packages = data.get("packages") or {}
    for key, meta in packages.items():
        if not key:
            continue  # "" is the root project itself
        name = key.split("node_modules/")[-1]
        ver = meta.get("version")
        if name and ver:
            dep = Dependency(name, _clean_ver(ver), "npm", "package-lock.json", direct=False)
            exact = _npm_exact(ver)
            # Workspace/linked entries (no node_modules/ segment) are the
            # project's own packages: no exactness, no license provenance.
            if exact and "node_modules/" in key and not meta.get("link"):
                resolved = meta.get("resolved")
                public = (meta.get("name") in (None, name)) and (
                    not resolved or str(resolved).startswith(_NPM_PUBLIC_RESOLVED))
                _mark_exact(dep, exact, public, _lock_license(meta))
            out.append(dep)
    return out


_REQ_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:[<>=!~]=\s*([A-Za-z0-9.*+-]+))?")


def _pip_reqs(path: str) -> List[Dependency]:
    out = []
    for line in _read(path).splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "--")):
            continue
        m = _REQ_RE.match(line)
        if m:
            name, ver = m.group(1), m.group(2)
            dep = Dependency(name, _clean_ver(ver) if ver else "*", "pypi", "requirements.txt")
            out.append(_mark_exact(dep, _pip_exact(line[len(name):].lstrip()) if ver else None))
    return out


def _pip_pyproject(path: str) -> List[Dependency]:
    text = _read(path)
    out = []
    m = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.S)
    if m:
        for raw in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
            mm = re.match(r"([A-Za-z0-9._-]+)\s*(?:[<>=!~]=\s*([A-Za-z0-9.*+-]+))?", raw)
            if mm:
                dep = Dependency(mm.group(1), _clean_ver(mm.group(2)) if mm.group(2) else "*",
                                 "pypi", "pyproject.toml")
                out.append(_mark_exact(dep, _pip_exact(raw[len(mm.group(1)):].lstrip())
                                       if mm.group(2) else None))
    return out


def _go_mod(path: str) -> List[Dependency]:
    # go.mod records the exact selected version of every requirement (MVS), so
    # these count as concrete for CVE lookups. No registry license lookup for go.
    out = []
    in_replace = False
    for line in _read(path).splitlines():
        stripped = line.strip()
        if stripped.startswith("replace") or stripped.startswith("exclude") or stripped.startswith("retract"):
            in_replace = stripped.endswith("(")
            continue
        if in_replace:
            if stripped == ")":
                in_replace = False
            continue
        m = re.match(r"^\s*(?:require\s+)?([a-z0-9][\w./-]+)\s+v([A-Za-z0-9.+-]+)", line)
        if m:
            ver = _clean_ver(m.group(2))
            out.append(_mark_exact(Dependency(m.group(1), ver, "go", "go.mod"), ver, public=False))
    return out


def _cargo(path: str) -> List[Dependency]:
    text = _read(path)
    out = []
    if re.search(r"^\s*\[dependencies\]", text, re.M):
        block = re.search(r"^\[dependencies\](.*?)(?=^\[|\Z)", text, re.S | re.M)
        if block:
            for line in block.group(1).splitlines():
                m = re.match(r"^\s*([A-Za-z0-9_]+)\s*=\s*(?:\"([^\"]*)\"|\{[^}]*version\s*=\s*\"([^\"]*)\")", line)
                if m:
                    ver = m.group(2) or m.group(3)
                    out.append(Dependency(m.group(1), _clean_ver(ver) if ver else "*", "crates", "Cargo.toml"))
    return out


def _composer(path: str) -> List[Dependency]:
    data = _read_json(path)
    out = []
    for section in ("require", "require-dev"):
        for name, ver in (data.get(section) or {}).items():
            if name == "php":
                continue
            out.append(Dependency(name, _clean_ver(str(ver)), "packagist", "composer.json"))
    return out


def _gem(path: str) -> List[Dependency]:
    out = []
    for line in _read(path).splitlines():
        m = re.match(r"^\s*gem\s+['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]", line)
        if m:
            out.append(Dependency(m.group(1), _clean_ver(m.group(2)), "rubygems", "Gemfile"))
        else:
            m2 = re.match(r"^\s*gem\s+['\"]([^'\"]+)['\"]", line)
            if m2:
                out.append(Dependency(m2.group(1), "*", "rubygems", "Gemfile"))
    return out


# --------------------------------------------------------------------------
# Lockfiles. Each entry is a transitive-or-direct install with a concrete
# version; direct=False because lockfiles do not say which ones are direct.
# ``public`` is True only for packages fetched from the ecosystem's public
# registry (it gates per-version registry license lookups, npm/PyPI only).
# --------------------------------------------------------------------------

_LOCK_VER_RE = re.compile(r"^v?(\d[0-9A-Za-z.+!_~-]*)$")


def _lock_ver(v) -> Optional[str]:
    if not isinstance(v, str):
        return None
    m = _LOCK_VER_RE.match(v.strip())
    return m.group(1) if m else None


def _lock_dep(name: str, ver: str, eco: str, manifest: str, public: bool,
              license: Optional[str] = None) -> Dependency:
    return _mark_exact(Dependency(name, ver, eco, manifest, direct=False), ver, public, license)


def _toml_tables(text: str, header: str = "package"):
    """Yield {key: str} for each ``[[header]]`` table in a lockfile.

    Lockfiles (Cargo.lock, poetry.lock, uv.lock) are machine-written and keep
    ``key = "value"`` / ``key = { ... }`` on one line, so a line parser is
    enough and keeps vigil dependency-free on Python 3.9/3.10 (no tomllib).
    Sub-tables such as ``[package.source]`` are folded in as ``source.<key>``.
    """
    cur = None
    prefix = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[["):
            if cur is not None:
                yield cur
            cur = {} if line == "[[%s]]" % header else None
            prefix = ""
            continue
        if line.startswith("["):
            name = line.strip("[]").strip()
            if cur is not None and name.startswith(header + "."):
                prefix = name[len(header) + 1:] + "."
            else:
                if cur is not None:
                    yield cur
                cur, prefix = None, ""
            continue
        if cur is None:
            continue
        m = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*(.*)$', line)
        if not m:
            continue
        key, val = prefix + m.group(1), m.group(2).strip()
        sm = re.match(r'^"((?:[^"\\]|\\.)*)"', val)
        cur[key] = sm.group(1) if sm else val
    if cur is not None:
        yield cur


def _cargo_lock(path: str) -> List[Dependency]:
    out = []
    for pkg in _toml_tables(_read(path)):
        name, ver, src = pkg.get("name"), _lock_ver(pkg.get("version")), pkg.get("source", "")
        # No source = a crate from this workspace (incl. the root package).
        if name and ver and src:
            out.append(_lock_dep(name, ver, "crates", "Cargo.lock",
                                 public=src.startswith("registry+")))
    return out


def _poetry_lock(path: str) -> List[Dependency]:
    out = []
    for pkg in _toml_tables(_read(path)):
        name, ver = pkg.get("name"), _lock_ver(pkg.get("version"))
        stype = pkg.get("source.type", "")
        if not name or not ver or stype in ("directory", "file"):
            continue
        public = stype == "" or (stype == "legacy" and "pypi.org" in pkg.get("source.url", ""))
        out.append(_lock_dep(name, ver, "pypi", "poetry.lock", public))
    return out


def _uv_lock(path: str) -> List[Dependency]:
    out = []
    for pkg in _toml_tables(_read(path)):
        name, ver, src = pkg.get("name"), _lock_ver(pkg.get("version")), pkg.get("source", "")
        if not name or not ver:
            continue
        if any(k in src for k in ("editable", "virtual", "path", "directory")):
            continue  # the project itself / local packages
        public = "registry" in src and "pypi.org" in src
        out.append(_lock_dep(name, ver, "pypi", "uv.lock", public))
    return out


def _pipfile_lock(path: str) -> List[Dependency]:
    data = _read_json(path)
    out = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            if not isinstance(meta, dict):
                continue
            ver = _pip_exact(str(meta.get("version", "")))
            if ver and not any(k in meta for k in ("git", "path", "file", "editable")):
                out.append(_lock_dep(name, ver, "pypi", "Pipfile.lock", True))
    return out


def _composer_lock(path: str) -> List[Dependency]:
    data = _read_json(path)
    out = []
    for section in ("packages", "packages-dev"):
        for meta in data.get(section) or []:
            if not isinstance(meta, dict):
                continue
            name, ver = meta.get("name"), _lock_ver(meta.get("version"))
            if not name or not ver or meta.get("dist", {}).get("type") == "path":
                continue
            lic = meta.get("license")
            lic = lic[0] if isinstance(lic, list) and len(lic) == 1 and isinstance(lic[0], str) else None
            out.append(_lock_dep(name, ver, "packagist", "composer.lock", True, lic))
    return out


_GEM_PLATFORM_RE = re.compile(r"-(?:x86|x64|arm|aarch64|java|universal|mingw|mswin|darwin|linux)\S*$")


def _gemfile_lock(path: str) -> List[Dependency]:
    out = []
    section = None
    in_specs = False
    for raw in _read(path).splitlines():
        if raw and not raw.startswith(" "):
            section, in_specs = raw.strip(), False
            continue
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if section != "GEM" or not in_specs:
            continue  # GIT / PATH gems are not on rubygems.org
        m = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)]+)\)$", raw)
        if m:
            # Platform gems: "1.15.4-x86_64-linux" -> "1.15.4"
            ver = _lock_ver(_GEM_PLATFORM_RE.sub("", m.group(2)))
            if ver:
                out.append(_lock_dep(m.group(1), ver, "rubygems", "Gemfile.lock", True))
    return out


def _yarn_lock(path: str) -> List[Dependency]:
    """yarn v1 (``version "1.2.3"``) and berry (``version: 1.2.3``) lockfiles."""
    out = []
    names: List[Tuple[str, str]] = []
    for raw in _read(path).splitlines():
        if not raw or raw.startswith("#"):
            continue
        if not raw.startswith(" "):
            names = []
            header = raw.rstrip(":").strip()
            if header == "__metadata":
                continue
            for spec in header.split(","):
                spec = spec.strip().strip('"')
                at = spec.rfind("@")
                if at <= 0:
                    continue
                name, rng = spec[:at], spec[at + 1:]
                names.append((name, rng))
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', raw)
        if m and names:
            ver = _lock_ver(m.group(1))
            name, rng = names[0]
            local = any(rng.startswith(p) for p in ("workspace:", "file:", "link:", "portal:", "patch:", "git", "github:", "http"))
            if rng.startswith("npm:"):
                rng = rng[4:]
                local = False
            if ver and not rng.startswith(("workspace:", "link:", "portal:")):
                out.append(_lock_dep(name, ver, "npm", "yarn.lock", public=not local))
            names = []
    return out


def _pnpm_lock(path: str) -> List[Dependency]:
    """pnpm-lock.yaml v5-v9: keys under ``packages:`` encode name@version."""
    out = []
    in_pkgs = False
    for raw in _read(path).splitlines():
        if raw and not raw.startswith(" "):
            in_pkgs = raw.strip() == "packages:"
            continue
        if not in_pkgs:
            continue
        m = re.match(r"^  ['\"]?/?((?:@[^/@\s]+/)?[^@/\s'\"(]+)[@/]([^('\"\s:]+)", raw)
        if not m or raw.startswith("   "):
            continue
        name, ver = m.group(1), _lock_ver(m.group(2))
        if ver:
            out.append(_lock_dep(name, ver, "npm", "pnpm-lock.yaml", True))
    return out


PARSERS = {
    "npm": {"package.json": _npm_deps, "package-lock.json": _npm_lock_deps,
            "yarn.lock": _yarn_lock, "pnpm-lock.yaml": _pnpm_lock},
    "pip": {"requirements.txt": _pip_reqs, "pyproject.toml": _pip_pyproject,
            "poetry.lock": _poetry_lock, "Pipfile.lock": _pipfile_lock, "uv.lock": _uv_lock},
    "go": {"go.mod": _go_mod},
    "cargo": {"Cargo.toml": _cargo, "Cargo.lock": _cargo_lock},
    "composer": {"composer.json": _composer, "composer.lock": _composer_lock},
    "gem": {"Gemfile": _gem, "Gemfile.lock": _gemfile_lock},
}

MANIFEST_MAP = {fn: eco for eco, files in PARSERS.items() for fn in files}

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "dist", "build", ".tox",
              "site-packages", ".idea", ".vscode", "coverage", "node_modules"}


def find_manifests(root: str = "."):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            eco = MANIFEST_MAP.get(fn)
            if eco:
                found.append((os.path.join(dirpath, fn), fn, eco))
    return found


def parse_manifest(abs_path: str, filename: str, ecosystem: str) -> List[Dependency]:
    parsers = PARSERS.get(ecosystem, {})
    fn = parsers.get(filename)
    if fn is None:
        return []
    try:
        return fn(abs_path)
    except Exception:
        return []


def _norm_name(dep: Dependency) -> str:
    if dep.ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", dep.name).lower()
    if dep.ecosystem == "npm":
        return dep.name.lower()
    return dep.name.lower().replace("_", "-")


def _settle_exact(dep: Dependency, obs: List[Tuple[str, bool, Optional[str]]]) -> None:
    """Attach version-specific metadata only if the merged row is unambiguous."""
    versions = {v for v, _, _ in obs}
    dep.resolved = sorted(versions)
    if len(versions) != 1:
        return
    chosen = next(iter(versions))
    dep.version = chosen
    if all(public for _, public, _ in obs):
        dep.exact_version = chosen
    declared = {license for _, _, license in obs if license}
    if len(declared) == 1 and not dep.license:
        dep.license, dep.license_src = next(iter(declared)), "manifest"


def _dedupe(deps: List[Dependency]) -> List[Dependency]:
    best = {}
    obs = {}
    for d in deps:
        key = (d.ecosystem, _norm_name(d))
        cur = best.get(key)
        if cur is None:
            best[key] = Dependency(d.name, d.version, d.ecosystem, d.manifest,
                                   license=d.license, license_src=d.license_src,
                                   direct=(d.version != "*"))
            obs[key] = list(d._exact)
        else:
            obs[key].extend(d._exact)
            if d.version != "*" and cur.version == "*":
                cur.version = d.version
                cur.direct = True
    for key, dep in best.items():
        _settle_exact(dep, obs[key])
    return list(best.values())


def scan(root: str = ".") -> List[Dependency]:
    deps: List[Dependency] = []
    for abs_path, filename, eco in find_manifests(root):
        for d in parse_manifest(abs_path, filename, eco):
            d.manifest = os.path.relpath(abs_path, root)
            deps.append(d)
    return _dedupe(deps)
