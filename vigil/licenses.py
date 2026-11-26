
"""License classification + compatibility engine."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from email.parser import Parser
from typing import Optional

from .registry import SUPPORTED, _norm_pyver, _pep503

LICENSE_CLASS = {
    "mit": "permissive", "isc": "permissive", "zlib": "permissive",
    "bsd-2-clause": "permissive", "bsd-3-clause": "permissive",
    "apache-2.0": "permissive", "unlicense": "permissive", "cc0-1.0": "permissive",
    "0bsd": "permissive", "numpy-1.0": "permissive",
    "lgpl-2.1": "weak-copyleft", "lgpl-3.0": "weak-copyleft",
    "mpl-2.0": "weak-copyleft", "epl-2.0": "weak-copyleft", "cddl-1.0": "weak-copyleft",
    "gpl-2.0": "strong-copyleft", "gpl-3.0": "strong-copyleft",
    "agpl-3.0": "strong-copyleft",
    "gpl-2.0-only": "strong-copyleft", "gpl-3.0-only": "strong-copyleft",
    "agpl-3.0-only": "strong-copyleft",
    "gpl-2.0-or-later": "strong-copyleft", "gpl-3.0-or-later": "strong-copyleft",
    "agpl-3.0-or-later": "strong-copyleft",
    "gpl-2.0+": "strong-copyleft", "gpl-3.0+": "strong-copyleft",
    "agpl-3.0+": "strong-copyleft",
    "sspl-1.0": "source-available", "busl-1.1": "source-available",
    "bsl-1.0": "source-available", "cc-by-nc-4.0": "source-available",
    "commons-clause-1.0": "source-available", "elast-2.0": "source-available",
}

PKG_LICENSE_DB = {
    ("pypi", "six"): "mit", ("pypi", "requests"): "apache-2.0",
    ("pypi", "urllib3"): "numpy-1.0", ("pypi", "django"): "bsd-3-clause",
    ("pypi", "flask"): "bsd-3-clause", ("pypi", "numpy"): "bsd-3-clause",
    ("pypi", "pandas"): "bsd-3-clause", ("pypi", "cryptography"): "apache-2.0",
    ("pypi", "gitpython"): "gpl-3.0", ("pypi", "scrapy"): "bsd-3-clause",
    ("pypi", "ipython"): "bsd-3-clause", ("pypi", "sqlalchemy"): "mit",
    ("npm", "webpack"): "mit", ("npm", "react"): "mit", ("npm", "lodash"): "mit",
    ("npm", "axios"): "mit", ("npm", "express"): "mit", ("npm", "moment"): "mpl-2.0",
    ("npm", "jquery"): "mit", ("npm", "rxjs"): "apache-2.0",
    ("npm", "eslint"): "mit", ("npm", "typescript"): "apache-2.0",
    ("go", "github.com/stretchr/testify"): "mit",
    ("crates", "serde"): "mit", ("crates", "tokio"): "mit",
    ("packagist", "laravel/framework"): "mit",
}


@dataclass
class Verdict:
    dep_name: str
    ecosystem: str
    version: str
    license: str
    license_class: str
    compatible: bool
    risk: str
    note: str


def classify(license_id: Optional[str]) -> str:
    if not license_id:
        return "unknown"
    lid = license_id.strip().lower()
    if re.search(r"\b(?:and|or|with)\b|[&|]", lid):
        return "unknown"  # A single license token cannot classify a compound expression.
    token = re.split(r"[ ;()&|]", lid)[0].strip()
    if token in LICENSE_CLASS:
        return LICENSE_CLASS[token]
    if token.startswith("gpl") or token.startswith("agpl"):
        return "strong-copyleft"
    if token.startswith("lgpl"):
        return "weak-copyleft"
    if token in ("mit", "apache", "bsd"):
        return "permissive"
    if token in ("mozilla", "eclipse", "mpl", "epl", "cddl"):
        return "weak-copyleft"
    if "nc" in token or "noncommercial" in token:
        return "source-available"
    return "unknown"


def _norm(name: str) -> str:
    return name.lower().replace("_", "-")


def _installed_license(dep, root: str) -> Optional[str]:
    from . import parsers
    eco = dep.ecosystem
    exact = getattr(dep, "exact_version", None)
    if eco == "npm":
        if not re.fullmatch(r"(?:@[a-zA-Z0-9][a-zA-Z0-9._~-]*/)?[a-zA-Z0-9][a-zA-Z0-9._~-]*", dep.name):
            return None
        data = parsers._read_json(os.path.join(root, "node_modules", dep.name, "package.json"))
        if not isinstance(data, dict) or data.get("name") not in (None, dep.name):
            return None
        if exact and (data.get("name") != dep.name or data.get("version") != exact):
            return None
        lic = data.get("license") or data.get("licenses")
        if isinstance(lic, list):
            lic = lic[0]
        if isinstance(lic, dict):
            lic = lic.get("type")
        return lic if isinstance(lic, str) and lic.strip() else None
    elif eco == "pypi":
        for base in ("site-packages",):
            rootdir = os.path.join(root, base)
            if not os.path.isdir(rootdir):
                continue
            for dirpath, dirnames, _ in os.walk(rootdir):
                for d in dirnames:
                    if _pep503(d).startswith(_pep503(dep.name)[:14]):
                        for cand in (os.path.join(dirpath, d, "METADATA"),
                                     os.path.join(dirpath, d + ".dist-info", "METADATA")):
                            if os.path.exists(cand):
                                meta = Parser().parsestr(parsers._read(cand), headersonly=True)
                                name = meta.get("Name")
                                if name and _pep503(name) != _pep503(dep.name):
                                    continue
                                version = meta.get("Version")
                                if exact and (not name or not version or
                                              _norm_pyver(version) != _norm_pyver(exact)):
                                    continue
                                lic = meta.get("License-Expression") or meta.get("License")
                                if lic and lic.strip():
                                    return lic.strip()
    return None


def _resolve_one(dep, installed: Optional[str], resolver=None) -> str:
    # 1) verified installed metadata, 2) license a lockfile recorded for the
    # exact installed version, 3) opt-in registry metadata for the exact
    # version, 4) the name-only offline DB, 5) unknown.
    if installed:
        dep.license = installed
        dep.license_src = "installed"
        return installed
    if dep.license and dep.license_src == "manifest":
        return dep.license
    if resolver is not None and getattr(dep, "exact_version", None):
        found, lic = resolver.lookup(dep.ecosystem, dep.name, dep.exact_version)
        if found and lic:
            dep.license = lic
            dep.license_src = "registry"
            return lic
    db = PKG_LICENSE_DB.get((dep.ecosystem, _norm(dep.name)))
    if db:
        dep.license = db
        dep.license_src = "db"
        return db
    if not dep.license:
        dep.license = "unknown"
        dep.license_src = "none"
    return dep.license


def resolve_license(dep, root: str = ".", resolver=None) -> str:
    return _resolve_one(dep, _installed_license(dep, root), resolver)


def resolve_all(deps, root: str = ".", resolver=None) -> dict:
    """Resolve every dependency's license; registry lookups are batched.

    Returns per-dependency counts for the npm/PyPI deps the registry covers
    (all zero-cost bookkeeping; nothing is printed here).
    """
    installed = [_installed_license(d, root) for d in deps]
    if resolver is not None:
        resolver.prefetch((d.ecosystem, d.name, d.exact_version)
                          for d, inst in zip(deps, installed)
                          if d.ecosystem in SUPPORTED and d.exact_version and not inst
                          and not (d.license and d.license_src == "manifest"))
    counts = {"eligible": 0, "local": 0, "registry": 0, "no_exact": 0, "fallback": 0}
    for d, inst in zip(deps, installed):
        _resolve_one(d, inst, resolver)
        if d.ecosystem not in SUPPORTED:
            continue
        counts["eligible"] += 1
        if d.license_src in ("installed", "manifest"):
            counts["local"] += 1
        elif d.license_src == "registry":
            counts["registry"] += 1
        elif not d.exact_version:
            counts["no_exact"] += 1
        else:
            counts["fallback"] += 1
    return counts


POLICY_DEFAULT = {
    "proprietary": {"ok": {"permissive"}, "warn": {"weak-copyleft"},
                    "risk": {"strong-copyleft", "source-available"}},
    "permissive":  {"ok": {"permissive", "weak-copyleft"},
                    "risk": {"strong-copyleft", "source-available"}},
    "copyleft":    {"ok": {"permissive", "weak-copyleft", "strong-copyleft"},
                    "risk": {"source-available"}},
    "unknown":     {"ok": {"permissive"}, "warn": {"weak-copyleft", "unknown"},
                    "risk": {"strong-copyleft", "source-available"}},
}


def evaluate(dep, project_lic: str = "proprietary", policy=None) -> Verdict:
    policy = policy or POLICY_DEFAULT.get(project_lic, POLICY_DEFAULT["proprietary"])
    lic = dep.license or "unknown"
    lclass = classify(lic)
    if lclass in policy.get("risk", set()):
        risk, compat = "high", False
    elif lclass in policy.get("warn", set()) or lclass == "unknown":
        risk, compat = "warn", True
    else:
        risk, compat = "ok", True
    notes = {
        "high": "incompatible with a %s project - review or replace" % project_lic,
        "warn": "review: %s license class" % lclass,
        "ok": "compatible",
    }
    return Verdict(dep.name, dep.ecosystem, dep.version, lic, lclass, compat, risk, notes[risk])
