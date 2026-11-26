
"""vigil command-line interface."""
from __future__ import annotations

import argparse
import os
import sys
from typing import Optional, Tuple

from . import __version__, compliance, parsers, licenses, registry, report, sarif, vuln, prokey

PRO_URL = "https://github.com/pullyo/vigil#pro"  # TODO: point at the Gumroad page once it exists


def _starter_policy() -> str:
    return (
        "# vigil policy - gate which license classes your dependencies may use.\n"
        "# `license` is your project's license intent (proprietary|permissive|copyleft|unknown).\n"
        "# List the license classes you allow under [[allowed]].\n"
        "[policy]\n"
        "license = \"proprietary\"\n"
        "\n"
        "[[allowed]]\n"
        "class = \"permissive\"\n"
        "\n"
        "[[allowed]]\n"
        "class = \"weak-copyleft\"\n"
    )


def _load_policy(path: Optional[str]) -> Tuple[Optional[str], Optional[set]]:
    if not path:
        return None, None
    try:
        import tomllib
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except ImportError:
        print("vigil: --policy needs Python 3.11+ (tomllib); ignoring policy file.",
              file=sys.stderr)
        return None, None
    except Exception as e:
        print("vigil: could not read policy %s: %s" % (path, e), file=sys.stderr)
        return None, None
    lic = (data.get("policy") or {}).get("license")
    allowed = {a.get("class") for a in data.get("allowed", []) if a.get("class")}
    return lic, (allowed or None)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vigil",
        description="Audit your dependencies for license taint and known CVEs.")
    p.add_argument("path", nargs="?", default=".", help="project root to scan (default: .)")
    p.add_argument("--license", dest="project_license", default=None,
                   choices=["proprietary", "permissive", "copyleft", "unknown"],
                   help="your project's license intent (default: proprietary, or from --policy)")
    p.add_argument("--vuln", action="store_true", help="cross-check known CVEs via OSV.dev, with the version that fixes each "
                        "(Pro: also fail CI on CVEs)")
    p.add_argument("--sbom", default=None, metavar="FILE",
                   help="[Pro] write a CycloneDX 1.5 JSON SBOM")
    p.add_argument("--notice", default=None, metavar="FILE",
                   help="[Pro] write THIRD_PARTY_NOTICES.md (dependencies grouped by license)")
    p.add_argument("--policy", default=None, help="path to a vigil.toml policy file")
    p.add_argument("--key", default=None, help="[Pro] license key (or set VIGIL_PRO_KEY)")
    p.add_argument("-f", "--format", choices=["table", "md", "json", "sarif"], default="table",
                   help="report format; sarif = SARIF 2.1.0 for GitHub Code Scanning "
                        "(locations are relative to the current directory)")
    p.add_argument("-o", "--output", default=None, help="also write the report to this file")
    p.add_argument("--fail-on", choices=["any", "high", "warn", "never"], default="high",
                   help="exit 1 when a finding at/above this level exists (default: high)")
    p.add_argument("--init", action="store_true", help="write a starter vigil.toml and exit")
    p.add_argument("--registry", action="store_true",
                   help="opt in to license lookups on the public npm/PyPI registries for "
                        "exactly pinned/locked versions (sends package names + versions; "
                        "results cached locally). Default: fully offline")
    p.add_argument("--registry-cache", default=None, metavar="DIR",
                   help="cache directory for --registry (default: $VIGIL_CACHE_DIR/registry "
                        "or ~/.cache/vigil/registry)")
    p.add_argument("--registry-max-lookups", type=int, default=registry.DEFAULT_MAX_LOOKUPS,
                   metavar="N", help="cap on network requests per run for --registry "
                                     "(default: %d)" % registry.DEFAULT_MAX_LOOKUPS)
    p.add_argument("--version", action="version", version="vigil " + __version__)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.init:
        dest = os.path.join(args.path, "vigil.toml")
        with open(dest, "w", encoding="utf-8") as f:
            f.write(_starter_policy())
        print("wrote %s" % dest)
        return 0

    policy_lic, allowed = _load_policy(args.policy)
    project_lic = args.project_license or policy_lic or "proprietary"

    machine = args.format in ("json", "sarif")
    deps = parsers.scan(args.path)
    if not deps:
        if not machine:
            print("vigil: no dependency manifests found under %s" % args.path)
            return 0
        # Machine formats still emit a valid, empty report (e.g. for SARIF upload).
        print("vigil: no dependency manifests found under %s" % args.path, file=sys.stderr)

    resolver = None
    if args.registry:
        resolver = registry.RegistryResolver(cache_dir=args.registry_cache,
                                             max_lookups=max(0, args.registry_max_lookups))
    counts = licenses.resolve_all(deps, args.path, resolver)
    if resolver is not None:
        # stderr keeps -f json / md on stdout machine-readable.
        s = resolver.stats
        print("vigil: registry: resolved %d/%d npm/PyPI deps from exact-version registry "
              "metadata (lookups: %d cached, %d fetched, %d failed, %d skipped by limits); "
              "%d from installed/lockfile metadata, %d without an exact version, "
              "%d fell back to offline data"
              % (counts["registry"], counts["eligible"], s["cached"], s["fetched"],
                 s["failed"] + s["invalid"], s["skipped"], counts["local"],
                 counts["no_exact"], counts["fallback"]), file=sys.stderr)

    verdicts = [licenses.evaluate(d, project_lic) for d in deps]

    if allowed is not None:
        for v in verdicts:
            ok = (v.license_class in allowed) or (v.license_class == "permissive")
            v.risk = "ok" if ok else "high"
            v.compatible = ok
            v.note = "allowed by policy" if ok else "blocked by policy (class=%s)" % v.license_class

    # Diagnostics go to stderr so json / sarif stdout stays parseable.
    pro = prokey.pro_enabled(args.key)
    vuln_map = {}
    vuln_attempted = False
    if args.vuln:
        vuln_attempted = True
        try:
            vuln_map = vuln.query_osv(deps)
        except Exception as e:
            print("vigil: vuln lookup failed: %s" % e, file=sys.stderr)
            vuln_map = {}
        if vuln_map and not pro and args.fail_on != "never":
            print("vigil: CVEs are reported but do not fail the build in the free edition "
                  "(Pro: CI gate on CVEs) -> " + PRO_URL, file=sys.stderr)

    wants_pro = [flag for flag, val in (("--sbom", args.sbom), ("--notice", args.notice)) if val]
    if wants_pro and not pro:
        print("vigil: %s %s a Pro feature (compliance deliverables); skipped. -> %s"
              % (" and ".join(wants_pro), "are" if len(wants_pro) > 1 else "is", PRO_URL),
              file=sys.stderr)
    elif wants_pro:
        project_name = os.path.basename(os.path.abspath(args.path)) or "project"
        for path, render in ((args.sbom, compliance.cyclonedx), (args.notice, compliance.notices)):
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(render(deps, verdicts, project_name))
                print("vigil: wrote %s" % path, file=sys.stderr)

    if args.format == "table":
        out = report.terminal(verdicts, vuln_map)
    elif args.format == "md":
        out = report.markdown(verdicts, vuln_map, project_lic)
    elif args.format == "sarif":
        out = sarif.render(deps, verdicts, vuln_map, project_lic, scan_root=args.path,
                           advisory_check=vuln_attempted)
    else:
        out = report.json_out(verdicts, vuln_map, project_lic)

    print(out)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
            if not out.endswith("\n"):
                f.write("\n")
        print("report written to %s" % args.output, file=sys.stderr)

    return report.exit_code(verdicts, args.fail_on, vuln_map if pro else None)
