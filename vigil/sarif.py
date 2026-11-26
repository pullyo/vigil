"""SARIF 2.1.0 export for GitHub Code Scanning and other SARIF consumers.

Built only from data the scan already produced: the license verdicts (paired
index-for-index with the scanned dependencies, which carry the manifest path)
and the advisory map the CVE path returned (empty unless ``--vuln`` ran and
OSV answered). Nothing is looked up or inferred here.

Rule IDs are a fixed, ordered set so ``ruleIndex`` and alert identity stay
stable across runs and versions. Locations are repository-relative URIs
(relative to ``base_dir``, default: the current working directory, i.e. the
checkout root in CI); absolute paths and ``..`` segments are never emitted.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

from . import __version__
from .registry import SUPPORTED as REGISTRY_ECOSYSTEMS

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

_LICENSE_TAGS = ["license", "compliance", "dependency"]
_VULN_TAGS = ["security", "vulnerability", "dependency"]

# (id, name, short description, full description, default level, security-severity)
# Order is part of the contract: ruleIndex values must not change. Append only.
RULES: List[Tuple[str, str, str, str, str, Optional[str]]] = [
    ("vigil/license-incompatible", "LicenseIncompatible",
     "Dependency license is incompatible with the project's license intent",
     "The dependency's license class (strong-copyleft or source-available) conflicts "
     "with the declared project license intent. Replace the dependency, obtain a "
     "different license from its authors, or change the declared intent if it is wrong.",
     "error", None),
    ("vigil/license-policy-blocked", "LicensePolicyBlocked",
     "Dependency license class is not allowed by the vigil policy",
     "The dependency's license class is not listed under [[allowed]] in the policy "
     "file. Replace the dependency or, after review, allow the class in the policy.",
     "error", None),
    ("vigil/license-review", "LicenseReview",
     "Dependency license needs review",
     "The dependency uses a license class (e.g. weak-copyleft) that is usually usable "
     "but carries obligations. Review how the dependency is linked and distributed.",
     "warning", None),
    ("vigil/license-unknown", "LicenseUnknown",
     "Dependency license could not be determined",
     "vigil could not determine the dependency's license from installed metadata, "
     "lockfiles, opt-in registry metadata or its built-in table. Install dependencies, "
     "pin an exact version and use --registry, or review the license manually.",
     "warning", None),
    ("vigil/vuln-critical", "KnownVulnerabilityCritical",
     "Dependency version has a known critical-severity advisory (CVSS >= 9.0)",
     "OSV.dev reports an advisory affecting this exact dependency version. Upgrade to a "
     "release the advisory lists as fixed, or remove the dependency.",
     "error", "9.5"),
    ("vigil/vuln-high", "KnownVulnerabilityHigh",
     "Dependency version has a known high-severity advisory (CVSS 7.0-8.9)",
     "OSV.dev reports an advisory affecting this exact dependency version. Upgrade to a "
     "release the advisory lists as fixed, or remove the dependency.",
     "error", "8.0"),
    ("vigil/vuln-medium", "KnownVulnerabilityMedium",
     "Dependency version has a known medium-severity advisory (CVSS 4.0-6.9)",
     "OSV.dev reports an advisory affecting this exact dependency version. Upgrade to a "
     "release the advisory lists as fixed, or remove the dependency.",
     "warning", "5.5"),
    ("vigil/vuln-low", "KnownVulnerabilityLow",
     "Dependency version has a known low-severity advisory (CVSS < 4.0)",
     "OSV.dev reports an advisory affecting this exact dependency version. Upgrade to a "
     "release the advisory lists as fixed, or remove the dependency.",
     "note", "2.0"),
    ("vigil/vuln-unscored", "KnownVulnerabilityUnscored",
     "Dependency version has a known advisory without a CVSS score",
     "OSV.dev reports an advisory affecting this exact dependency version but no CVSS "
     "v3 score was available. Read the advisory and upgrade to a fixed release.",
     "warning", None),
]
RULE_IDS = [r[0] for r in RULES]
_RULE_INDEX = {rid: i for i, rid in enumerate(RULE_IDS)}
_RULE_LEVEL = {r[0]: r[4] for r in RULES}

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024


def _rule(r) -> dict:
    rid, name, short, full, level, sev = r
    props = {"tags": list(_VULN_TAGS if rid.startswith("vigil/vuln-") else _LICENSE_TAGS)}
    if sev is not None:
        props["security-severity"] = sev
    return {
        "id": rid,
        "name": name,
        "shortDescription": {"text": short},
        "fullDescription": {"text": full},
        "help": {"text": full},
        "defaultConfiguration": {"level": level},
        "properties": props,
    }


def _vuln_rule(cvss: Optional[float]) -> str:
    if cvss is None:
        return "vigil/vuln-unscored"
    if cvss >= 9.0:
        return "vigil/vuln-critical"
    if cvss >= 7.0:
        return "vigil/vuln-high"
    if cvss >= 4.0:
        return "vigil/vuln-medium"
    return "vigil/vuln-low"


def _license_rule(verdict) -> Optional[str]:
    if verdict.risk == "high":
        if str(verdict.note).startswith("blocked by policy"):
            return "vigil/license-policy-blocked"
        return "vigil/license-incompatible"
    if verdict.risk == "warn":
        if verdict.license_class == "unknown":
            return "vigil/license-unknown"
        return "vigil/license-review"
    return None


def _clean(text, limit: int = 300) -> str:
    """Single-line, bounded text for messages built from untrusted metadata."""
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _safe_rel(path: str) -> Optional[str]:
    p = path.replace(os.sep, "/")
    if not p or os.path.isabs(path) or p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        return None
    parts = [x for x in p.split("/") if x not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def artifact_uri(scan_root: str, manifest: str, base_dir: Optional[str] = None) -> str:
    """Repository-relative, URI-encoded manifest path; never absolute or escaping.

    Preferred: relative to ``base_dir`` (cwd by default - the checkout root in
    CI). If the manifest lies outside it, fall back to the path relative to the
    scanned root, then to the bare file name.
    """
    base = os.path.abspath(base_dir or os.getcwd())
    target = os.path.abspath(os.path.join(scan_root, manifest))
    rel = None
    try:
        rel = _safe_rel(os.path.relpath(target, base))
    except ValueError:  # different drive on Windows
        rel = None
    if rel is None:
        rel = _safe_rel(manifest) or _safe_rel(os.path.basename(manifest)) or "unknown"
    return quote(rel, safe="/")


def _find_line(path: str, name: str, cache: Dict[str, List[str]]) -> int:
    """1-based line where the dependency name first appears; 1 if not found."""
    if path not in cache:
        lines: List[str] = []
        try:
            if os.path.getsize(path) <= _MAX_MANIFEST_BYTES:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
        except OSError:
            pass
        cache[path] = lines
    pat = re.compile(r"(?<![A-Za-z0-9_.@/-])" + re.escape(name) + r"(?![A-Za-z0-9_.-])",
                     re.IGNORECASE)
    for i, line in enumerate(cache[path], 1):
        if pat.search(line):
            return i
    return 1


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:32]


def _location(uri: str, line: int) -> dict:
    return {"physicalLocation": {
        "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
        "region": {"startLine": line},
    }}


def _result(rule_id: str, level: str, text: str, uri: str, line: int,
            fp: str, props: dict) -> dict:
    return {
        "ruleId": rule_id,
        "ruleIndex": _RULE_INDEX[rule_id],
        "level": level,
        "message": {"text": text},
        "locations": [_location(uri, line)],
        "partialFingerprints": {"vigilFindingId/v1": fp},
        "properties": props,
    }


def render(deps, verdicts, vuln_map: Optional[dict] = None,
           project_lic: str = "proprietary", scan_root: str = ".",
           base_dir: Optional[str] = None, advisory_check: bool = False) -> str:
    """Return a SARIF 2.1.0 log (JSON text) for the scan.

    ``deps`` and ``verdicts`` must be index-aligned (as built by the CLI).
    ``advisory_check`` records whether the CVE lookup was attempted (a failed
    lookup yields no advisory results, never guessed ones).
    """
    vuln_map = vuln_map or {}
    lines_cache: Dict[str, List[str]] = {}
    keyed = []
    for dep, v in zip(deps, verdicts):
        uri = artifact_uri(scan_root, dep.manifest, base_dir)
        line = _find_line(os.path.join(scan_root, dep.manifest), dep.name, lines_cache)
        ident = "%s@%s (%s)" % (_clean(v.dep_name, 200), _clean(v.version, 60), v.ecosystem)
        base_props = {"ecosystem": v.ecosystem, "package": v.dep_name, "version": v.version}

        rid = _license_rule(v)
        if rid:
            if rid == "vigil/license-incompatible":
                text = ("%s is licensed %s (%s), incompatible with a %s project. Replace it, "
                        "obtain a different license from its authors, or correct the declared "
                        "project license intent." % (ident, _clean(v.license, 80),
                                                     v.license_class, project_lic))
            elif rid == "vigil/license-policy-blocked":
                text = ("%s is licensed %s (%s), a class not allowed by the vigil policy. "
                        "Replace it or, after review, add the class under [[allowed]]."
                        % (ident, _clean(v.license, 80), v.license_class))
            elif rid == "vigil/license-unknown":
                if v.ecosystem in REGISTRY_ECOSYSTEMS:
                    hint = ("Install dependencies, pin an exact version and run with "
                            "--registry, or review its license manually.")
                else:
                    hint = "Review its license manually (or install dependencies and rescan)."
                text = "%s has no determinable license. %s" % (ident, hint)
            else:
                text = ("%s is licensed %s (%s). Review its obligations for a %s project."
                        % (ident, _clean(v.license, 80), v.license_class, project_lic))
            props = dict(base_props, license=v.license, licenseClass=v.license_class,
                         risk=v.risk)
            fp = _fingerprint(rid, v.ecosystem, v.dep_name.lower())
            keyed.append(((_RULE_INDEX[rid], v.ecosystem, v.dep_name.lower(), ""),
                          _result(rid, _RULE_LEVEL[rid], text, uri, line, fp, props)))

        seen = set()
        for adv in vuln_map.get("%s:%s" % (v.ecosystem, v.dep_name)) or []:
            if not isinstance(adv, dict):
                continue
            adv_id = _clean(adv.get("id"), 100)
            if not adv_id or adv_id in seen:
                continue
            seen.add(adv_id)
            cvss = adv.get("cvss")
            cvss = float(cvss) if isinstance(cvss, (int, float)) else None
            rid = _vuln_rule(cvss)
            aliases = [_clean(a, 100) for a in (adv.get("aliases") or []) if a][:5]
            text = "%s is affected by %s%s%s%s Upgrade to a version the advisory lists as fixed." % (
                ident, adv_id,
                " (%s)" % ", ".join(aliases) if aliases else "",
                ", CVSS %.1f" % cvss if cvss is not None else ", no CVSS score",
                ": %s." % _clean(adv.get("summary"), 200).rstrip(".") if adv.get("summary")
                else ".")
            affected = [_clean(x, 60) for x in (adv.get("versions") or []) if isinstance(x, str)][:10]
            if adv.get("approximate"):
                text += (" Checked against the lowest version the declared range allows; "
                         "commit a lockfile for an exact result.")
            elif len(affected) > 1:
                text += " Installed affected versions: %s." % ", ".join(affected)
            if _SAFE_ID.match(adv_id):
                text += " Details: https://osv.dev/vulnerability/%s" % adv_id
            props = dict(base_props, advisory=adv_id, aliases=aliases)
            if affected:
                props["affectedVersions"] = affected
            if adv.get("approximate"):
                props["approximate"] = True
            if cvss is not None:
                props["cvss"] = cvss
            fp = _fingerprint(rid, v.ecosystem, v.dep_name.lower(), adv_id)
            keyed.append(((_RULE_INDEX[rid], v.ecosystem, v.dep_name.lower(), adv_id),
                          _result(rid, _RULE_LEVEL[rid], text, uri, line, fp, props)))

    keyed.sort(key=lambda kr: kr[0])
    counts = {"ok": 0, "warn": 0, "high": 0}
    for v in verdicts:
        counts[v.risk] = counts.get(v.risk, 0) + 1
    log = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "vigil",
                "version": __version__,
                "semanticVersion": __version__,
                "rules": [_rule(r) for r in RULES],
            }},
            "invocations": [{"executionSuccessful": True}],
            "columnKind": "utf16CodeUnits",
            "results": [r for _, r in keyed],
            "properties": {"projectLicense": project_lic, "summary": counts,
                           "advisoryLookupAttempted": bool(advisory_check)},
        }],
    }
    return json.dumps(log, indent=2)
