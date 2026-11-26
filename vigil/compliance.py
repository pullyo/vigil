"""Compliance deliverables (Pro): CycloneDX SBOM and third-party notices.

These are the files a team has to hand over when shipping software to a
customer, passing due diligence or meeting SBOM requirements (e.g. the EU
Cyber Resilience Act): what is inside, at which version, under which license.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import urllib.parse
import uuid
from typing import Dict, List, Optional

from . import __version__

# vigil keeps licenses lower-cased; SBOM/notices want canonical SPDX ids.
_SPDX = {s.lower(): s for s in (
    "0BSD", "AFL-3.0", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "Apache-1.1",
    "Apache-2.0", "Artistic-2.0", "BlueOak-1.0.0", "BSD-2-Clause", "BSD-3-Clause",
    "BSD-3-Clause-Clear", "BSL-1.0", "BUSL-1.1", "CC-BY-3.0", "CC-BY-4.0", "CC-BY-SA-4.0",
    "CC0-1.0", "CDDL-1.0", "CDDL-1.1", "ECL-2.0", "EPL-1.0", "EPL-2.0", "EUPL-1.2",
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only",
    "GPL-3.0-or-later", "ISC", "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0",
    "LGPL-3.0-only", "LGPL-3.0-or-later", "MIT", "MIT-0", "MPL-1.1", "MPL-2.0", "MS-PL",
    "NCSA", "ODbL-1.0", "OFL-1.1", "OpenSSL", "PHP-3.01", "PostgreSQL", "Python-2.0",
    "PSF-2.0", "Ruby", "SSPL-1.0", "Unicode-DFS-2016", "Unlicense", "UPL-1.0", "W3C",
    "WTFPL", "X11", "Zlib", "ZPL-2.1")}

_PURL_TYPE = {"npm": "npm", "pypi": "pypi", "go": "golang", "crates": "cargo",
              "packagist": "composer", "rubygems": "gem"}


def spdx_id(lic: Optional[str]) -> Optional[str]:
    """Canonical SPDX id for a single known license, else None."""
    if not lic:
        return None
    return _SPDX.get(lic.strip().lower())


def _versions(dep) -> List[Optional[str]]:
    """Concrete versions of a dependency; [None] when only a range is known."""
    vs = list(getattr(dep, "resolved", None) or [])
    if vs:
        return vs
    if dep.exact_version:
        return [dep.exact_version]
    return [None]


def purl(dep, version: Optional[str]) -> str:
    """Package URL (https://github.com/package-url/purl-spec)."""
    typ = _PURL_TYPE.get(dep.ecosystem, dep.ecosystem)
    name = dep.name
    if typ == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    q = lambda s: urllib.parse.quote(s, safe="")  # noqa: E731
    if typ == "npm" and name.startswith("@") and "/" in name:
        ns, base = name.split("/", 1)
        path = "%s/%s" % (q(ns), q(base))
    elif typ in ("golang", "composer"):
        path = "/".join(q(p) for p in name.split("/"))
    else:
        path = q(name)
    out = "pkg:%s/%s" % (typ, path)
    if version:
        if typ == "golang" and not version.startswith("v"):
            version = "v" + version
        out += "@" + q(version)
    return out


def _license_entry(lic: Optional[str]) -> List[dict]:
    if not lic or lic.lower() in ("unknown", "none", "noassertion"):
        return []
    sid = spdx_id(lic)
    if sid:
        return [{"license": {"id": sid}}]
    if re.search(r"\b(?:AND|OR|WITH)\b", lic, re.I):
        return [{"expression": lic}]
    return [{"license": {"name": lic}}]


def cyclonedx(deps, verdicts, project_name: str = "project",
              now: Optional[_dt.datetime] = None, serial: Optional[str] = None) -> str:
    """CycloneDX 1.5 JSON SBOM; one component per installed version."""
    by_key = {(v.ecosystem, v.dep_name): v for v in verdicts}
    comps, seen = [], set()
    for d in deps:
        v = by_key.get((d.ecosystem, d.name))
        lic = v.license if v else d.license
        for ver in _versions(d):
            ref = purl(d, ver)
            if ref in seen:
                continue
            seen.add(ref)
            c = {"type": "library", "bom-ref": ref, "name": d.name, "purl": ref,
                 "scope": "required" if d.direct else "optional"}
            if ver:
                c["version"] = ver
            else:
                c["version"] = d.version
                c["properties"] = [{"name": "vigil:version-is-range-minimum", "value": "true"}]
            lic_entry = _license_entry(lic)
            if lic_entry:
                c["licenses"] = lic_entry
            comps.append(c)
    comps.sort(key=lambda c: c["bom-ref"])
    ts = (now or _dt.datetime.now(_dt.timezone.utc)).replace(microsecond=0)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial or "urn:uuid:%s" % uuid.uuid4(),
        "version": 1,
        "metadata": {
            "timestamp": ts.isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "vigil",
                                      "version": __version__}]},
            "component": {"type": "application", "name": project_name,
                          "bom-ref": "project"},
        },
        "components": comps,
        "dependencies": [{"ref": "project", "dependsOn": [c["bom-ref"] for c in comps]}],
    }
    return json.dumps(bom, indent=2)


def notices(deps, verdicts, project_name: str = "project") -> str:
    """THIRD_PARTY_NOTICES.md: every dependency grouped by license.

    Dependencies whose license could not be identified are listed first so they
    get reviewed before the file ships.
    """
    by_key = {(v.ecosystem, v.dep_name): v for v in verdicts}
    groups: Dict[str, List[str]] = {}
    for d in deps:
        v = by_key.get((d.ecosystem, d.name))
        lic = (v.license if v else d.license) or "unknown"
        label = spdx_id(lic) or ("UNKNOWN" if lic.lower() in ("unknown", "none") else lic)
        vers = [x for x in _versions(d) if x] or ([d.version] if d.version not in ("", "*") else [])
        groups.setdefault(label, []).append(
            "- %s%s (%s)" % (d.name, " " + ", ".join(vers) if vers else "", d.ecosystem))
    out = ["# Third-party notices", "",
           "%s includes the following third-party software. Each component is "
           "distributed under its own license, listed below." % project_name, ""]
    unknown = groups.pop("UNKNOWN", None)
    if unknown:
        out += ["## License not identified - review before shipping", "",
                "vigil could not determine a license for these components. Check each "
                "project's repository before distributing.", ""]
        out += sorted(set(unknown)) + [""]
    for label in sorted(groups, key=str.lower):
        out.append("## %s" % label)
        out.append("")
        if spdx_id(label):
            out.append("License text: https://spdx.org/licenses/%s.html" % label)
            out.append("")
        out += sorted(set(groups[label])) + [""]
    out += ["---", "Generated by vigil %s. Copyright notices of each component are found "
            "in its source distribution and must be kept when redistributing." % __version__]
    return "\n".join(out) + "\n"
