
"""Render findings to terminal / markdown / JSON and compute the CI exit code."""
from __future__ import annotations

import json
from typing import List, Optional

RISK_ORDER = {"ok": 0, "warn": 1, "high": 2}
RISK_ICON = {"ok": "+", "warn": "~", "high": "X"}


def summarize(verdicts) -> dict:
    counts = {"ok": 0, "warn": 0, "high": 0}
    for v in verdicts:
        counts[v.risk] = counts.get(v.risk, 0) + 1
    return counts


def _adv_rows(verdicts, vuln_map: Optional[dict]):
    """(package, versions, id, cvss, summary, fix text, approximate) per advisory, worst first."""
    rows = []
    if not vuln_map:
        return rows
    seen = set()
    for v in verdicts:
        key = "%s:%s" % (v.ecosystem, v.dep_name)
        if key in seen:
            continue
        seen.add(key)
        for a in vuln_map.get(key, []):
            ids = [a.get("id")] + [x for x in (a.get("aliases") or []) if str(x).startswith("CVE-")][:1]
            fixed = a.get("fixed") or {}
            vers = a.get("versions") or [v.version]
            if fixed:
                fix = "upgrade to " + ", ".join(
                    "%s (from %s)" % (fixed[x], x) if len(fixed) > 1 else fixed[x]
                    for x in vers if x in fixed)
            else:
                fix = "no fixed version published"
            rows.append((v.dep_name, ", ".join(vers), " / ".join(str(i) for i in ids if i),
                         a.get("cvss"), (a.get("summary") or "").strip(), fix,
                         bool(a.get("approximate"))))
    rows.sort(key=lambda r: (r[3] is None, -(r[3] or 0.0), r[0], r[2]))
    return rows


def _cvss(x) -> str:
    return ("%.1f" % x) if x is not None else "?"


def terminal(verdicts, vuln_map: Optional[dict] = None, title: str = "vigil") -> str:
    lines = ["", "== %s — dependency supply-chain audit ==" % title, ""]
    if not verdicts:
        lines.append("  (no dependencies found)")
        return "\n".join(lines)
    w = max(len(v.dep_name) for v in verdicts)
    w = max(w, 8)
    for v in sorted(verdicts, key=lambda x: (-RISK_ORDER[x.risk], x.ecosystem, x.dep_name)):
        extra = ""
        if vuln_map:
            vv = vuln_map.get("%s:%s" % (v.ecosystem, v.dep_name), [])
            if vv:
                worst = max((a.get("cvss") for a in vv if a.get("cvss") is not None), default=None)
                approx = any(a.get("approximate") for a in vv)
                extra = "   [%d known CVE%s, max CVSS %s%s]" % (
                    len(vv), "s" if len(vv) > 1 else "",
                    ("%.1f" % worst) if worst is not None else "?",
                    ", range minimum - add a lockfile" if approx else "")
        lines.append("  %s  %-*s  %-16s %-5s %s%s" % (
            RISK_ICON[v.risk], w, v.dep_name, v.license, v.risk.upper(), v.note, extra))
    c = summarize(verdicts)
    lines.append("")
    lines.append("  %d ok / %d warn / %d high" % (c["ok"], c["warn"], c["high"]))
    rows = _adv_rows(verdicts, vuln_map)
    if rows:
        lines += ["", "  Known vulnerabilities:"]
        for name, vers, ids, cvss, summary, fix, approx in rows:
            lines.append("  - %s %s  %s  CVSS %s%s" % (name, vers, ids, _cvss(cvss),
                                                    "  (approximate)" if approx else ""))
            if summary:
                lines.append("      %s" % (summary if len(summary) <= 100 else summary[:97] + "..."))
            lines.append("      -> %s" % fix)
    return "\n".join(lines)


def markdown(verdicts, vuln_map: Optional[dict] = None, project_lic: str = "proprietary") -> str:
    c = summarize(verdicts)
    out = [
        "# vigil — dependency audit",
        "",
        "Project license intent: `%s`" % project_lic,
        "",
        "**Summary:** %d ok · %d warn · %d high-risk" % (c["ok"], c["warn"], c["high"]),
        "",
        "| Dependency | Ecosystem | Version | License | Class | Risk | Notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for v in sorted(verdicts, key=lambda x: (-RISK_ORDER[x.risk], x.ecosystem, x.dep_name)):
        out.append("| %s | %s | %s | %s | %s | **%s** | %s |" % (
            v.dep_name, v.ecosystem, v.version, v.license, v.license_class, v.risk, v.note))
    rows = _adv_rows(verdicts, vuln_map)
    if rows:
        out += ["", "## Known vulnerabilities", "",
                "| Package | Version | Advisory | CVSS | Fix | Summary |", "|---|---|---|---|---|---|"]
        for name, vers, ids, cvss, summary, fix, approx in rows:
            cell = lambda t: str(t).replace("|", "\\|").replace("\n", " ")
            out.append("| %s | %s%s | %s | %s | %s | %s |" % (
                cell(name), cell(vers), " (approx.)" if approx else "", cell(ids), _cvss(cvss),
                cell(fix), cell(summary)))
    return "\n".join(out) + "\n"


def json_out(verdicts, vuln_map: Optional[dict] = None, project_lic: str = "proprietary") -> str:
    return json.dumps({
        "tool": "vigil",
        "project_license": project_lic,
        "summary": summarize(verdicts),
        "dependencies": [v.__dict__ for v in verdicts],
        "vulnerabilities": vuln_map or {},
    }, indent=2)


def exit_code(verdicts, fail_on: str = "high", vuln_map: Optional[dict] = None) -> int:
    if fail_on == "never":
        return 0
    has_high = any(v.risk == "high" for v in verdicts)
    has_warn = any(v.risk == "warn" for v in verdicts)
    has_vuln = False
    if vuln_map:
        for v in verdicts:
            if vuln_map.get("%s:%s" % (v.ecosystem, v.dep_name)):
                has_vuln = True
                break
    if fail_on in ("any", "warn"):
        return 1 if (has_high or has_warn or has_vuln) else 0
    # fail_on == "high"
    return 1 if (has_high or has_vuln) else 0
