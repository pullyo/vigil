"""Known-vulnerability lookup (Pro) via the free OSV.dev API.

OSV.dev needs no API key. Two steps:
    POST https://api.osv.dev/v1/querybatch
         {"queries": [{"package": {"name","ecosystem"}, "version"}, ...]}
    -> {"results": [{"vulns": [{"id", "modified"}, ...], "next_page_token"?}, ...]}
       # index-aligned with the input; only IDs, no details
    GET  https://api.osv.dev/v1/vulns/<id>   -> full advisory (summary, aliases, severity)

For each dependency with a concrete version we return the published advisories
with a CVSS v3.1 base score (computed from the vector per the FIRST spec).
"""
from __future__ import annotations

import json
import math
import re
from concurrent.futures import ThreadPoolExecutor
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/%s"
MAX_DETAIL_LOOKUPS = 300
MAX_PAGES = 5
_DETAIL_WORKERS = 8
_SAFE_OSV_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")

ECO_TO_OSV = {
    "npm": "npm", "pypi": "PyPI", "go": "Go",
    "crates": "crates.io", "packagist": "Packagist", "rubygems": "RubyGems",
}

# --- CVSS v3.1 metric weights (FIRST spec 7.1) ---
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_IMP = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(x: float) -> float:
    """CVSS 'Roundup': smallest 1-decimal value >= x (floating-point safe)."""
    if x <= 0:
        return 0.0
    return math.ceil(x * 10.0 - 1e-9) / 10.0


def cvss_base_score(vector: str) -> Optional[float]:
    """Compute a CVSS v3.x base score from a vector string, per the FIRST spec.

    BaseScore:
        Impact <= 0 -> 0
        Scope Unchanged -> Roundup(Min(Impact + Exploitability, 10))
        Scope Changed   -> Roundup(Min(1.08 * (Impact + Exploitability), 10))
        Impact(U) = 6.42 * ISS
        Impact(C) = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02) ** 15
        ISS = 1 - (1-C)(1-I)(1-A)
        Exploitability = 8.22 * AV * AC * PR * UI
    """
    if not vector or "CVSS:3" not in vector:
        return None
    m = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            m[k.strip()] = v.strip()
    try:
        av = _AV[m.get("AV", "")]
        ac = _AC[m.get("AC", "")]
        pr = (_PR_C if m.get("S") == "C" else _PR_U)[m.get("PR", "")]
        ui = _UI[m.get("UI", "")]
        c = _IMP[m.get("C", "")]
        i = _IMP[m.get("I", "")]
        a = _IMP[m.get("A", "")]
    except KeyError:
        return None
    iss = 1.0 - ((1 - c) * (1 - i) * (1 - a))
    if iss <= 0:
        return 0.0
    exploit = 8.22 * av * ac * pr * ui
    if m.get("S") == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    base = 1.08 * (impact + exploit) if m.get("S") == "C" else (impact + exploit)
    return _roundup(min(base, 10.0))


def _best_score(vuln: dict) -> Optional[float]:
    """Best CVSS base score for an advisory: a direct number if given, else computed."""
    scores = []
    for sev in vuln.get("severity") or []:
        if "CVSS" not in str(sev.get("type", "")).upper():
            continue
        raw = sev.get("score", "")
        s = None
        try:
            s = float(raw)
        except (TypeError, ValueError):
            s = cvss_base_score(str(raw))
        if s is not None:
            scores.append(s)
    return max(scores) if scores else None


def _annotate(vulns: List[dict]) -> List[dict]:
    out = []
    for v in vulns:
        text = (v.get("summary") or v.get("details") or "").strip()
        first = text.splitlines()[0][:160] if text else ""
        out.append({
            "id": v.get("id"),
            "database": v.get("database"),
            "aliases": v.get("aliases", []),
            "summary": first,
            "cvss": _best_score(v),
        })
    return out


_MAX_RESPONSE_BYTES = 32 * 1024 * 1024


def _ssl_contexts() -> List["ssl.SSLContext"]:
    """Verified TLS contexts only: system trust store, then certifi if installed.

    There is deliberately no unverified fallback: a security tool must not
    accept advisory data from an endpoint it could not authenticate.
    """
    from .registry import _ssl_context  # same trust setup as --registry
    ctxs = [_ssl_context()]
    try:
        import certifi  # type: ignore
        ctxs.append(ssl.create_default_context(cafile=certifi.where()))
    except Exception:
        pass
    return ctxs


def _is_cert_error(e: Exception) -> bool:
    reason = getattr(e, "reason", e)
    return isinstance(reason, ssl.SSLCertVerificationError) or isinstance(
        e, ssl.SSLCertVerificationError)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, "redirect refused", headers, fp)


def _request_json(url: str, obj: Optional[dict], timeout: float) -> dict:
    """GET (obj=None) or POST JSON over verified HTTPS and parse the response.

    Tries the system trust store, then certifi (both verified). Certificate
    failures surface as an error with a hint; the caller treats any error as
    "lookup failed" and reports no advisories rather than guessed ones.
    Redirects are refused and the response size is capped.
    """
    data = json.dumps(obj).encode() if obj is not None else None
    headers = {"Accept": "application/json", "User-Agent": "vigil-osv"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    last_err: Optional[Exception] = None
    for ctx in _ssl_contexts():
        req = urllib.request.Request(url, data=data, headers=headers)
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx), _NoRedirect())
        try:
            with opener.open(req, timeout=timeout) as r:
                body = r.read(_MAX_RESPONSE_BYTES + 1)
            if len(body) > _MAX_RESPONSE_BYTES:
                raise ValueError("OSV response too large")
            return json.loads(body.decode("utf-8", errors="replace"))
        except Exception as e:  # noqa: BLE001
            last_err = e
            if _is_cert_error(e):
                continue  # try the next *verified* trust store
            raise
    raise RuntimeError("could not verify the TLS certificate of %s (%s); fix the "
                       "host CA store, set SSL_CERT_FILE, or `pip install certifi`"
                       % (urllib.parse.urlparse(url).hostname, last_err))


def _post_json(url: str, obj: dict, timeout: float = 30.0) -> dict:
    """OSV batch boundary (mocked in tests)."""
    return _request_json(url, obj, timeout)


def _get_json(url: str, timeout: float = 30.0) -> dict:
    """OSV advisory-detail boundary (mocked in tests)."""
    return _request_json(url, None, timeout)


def _post_batch(batch: List[dict], timeout: float) -> List[Optional[dict]]:
    """One querybatch call; results index-aligned with ``batch``.

    OSV rejects the whole batch (HTTP 400) if any single query is invalid,
    e.g. a non-semver Cargo version like "1.0". In that case re-ask one query
    at a time so one bad entry does not hide advisories for the rest; queries
    OSV rejects on their own come back as None.
    """
    try:
        data = _post_json(OSV_BATCH, {"queries": batch}, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code != 400:
            raise
        if len(batch) == 1:
            return [None]
        out: List[Optional[dict]] = []
        for q in batch:
            out.extend(_post_batch([q], timeout))
        return out
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list) or len(results) != len(batch):
        raise ValueError("unexpected OSV batch response")
    return results


def _batch_ids(queries: List[dict], timeout: float) -> List[List[str]]:
    """Advisory IDs per query (index-aligned), following next_page_token."""
    ids: List[List[str]] = [[] for _ in queries]
    pending = list(range(len(queries)))
    tokens: Dict[int, str] = {}
    rejected: List[int] = []
    for _ in range(MAX_PAGES):
        if not pending:
            break
        batch = []
        for i in pending:
            q = dict(queries[i])
            if i in tokens:
                q["page_token"] = tokens[i]
            batch.append(q)
        results = _post_batch(batch, timeout)
        nxt = []
        for i, res in zip(pending, results):
            if res is None:
                rejected.append(i)
                continue
            if not isinstance(res, dict):
                continue
            for v in res.get("vulns") or []:
                vid = v.get("id") if isinstance(v, dict) else None
                if isinstance(vid, str) and _SAFE_OSV_ID.match(vid) and vid not in ids[i]:
                    ids[i].append(vid)
            tok = res.get("next_page_token")
            if isinstance(tok, str) and tok:
                tokens[i] = tok
                nxt.append(i)
        pending = nxt
    if rejected:
        names = ", ".join("%s@%s" % (queries[i]["package"]["name"], queries[i]["version"])
                          for i in rejected[:5])
        print("vigil: OSV rejected %d quer%s as invalid (not checked): %s%s"
              % (len(rejected), "y" if len(rejected) == 1 else "ies", names,
                 ", ..." if len(rejected) > 5 else ""), file=sys.stderr)
    if pending:
        print("vigil: OSV returned more pages than vigil fetches; some advisories "
              "may be missing", file=sys.stderr)
    return ids


def _fetch_details(ids: List[str], timeout: float) -> Dict[str, dict]:
    """Full advisory records by ID. Failed lookups map to a bare {"id": ...}."""
    todo = ids[:MAX_DETAIL_LOOKUPS]
    if len(ids) > len(todo):
        print("vigil: %d advisories found; details fetched for the first %d"
              % (len(ids), len(todo)), file=sys.stderr)

    def one(vid: str):
        try:
            rec = _get_json(OSV_VULN % vid, timeout=timeout)
            if isinstance(rec, dict) and rec.get("id") == vid:
                return vid, rec
        except Exception:  # noqa: BLE001 - detail failure degrades to "unscored"
            pass
        return vid, None

    out: Dict[str, dict] = {}
    failed = 0
    with ThreadPoolExecutor(max_workers=_DETAIL_WORKERS) as ex:
        for vid, rec in ex.map(one, todo):
            if rec is None:
                failed += 1
                rec = {"id": vid}
            out[vid] = rec
    for vid in ids[len(todo):]:
        out[vid] = {"id": vid}
    if failed:
        print("vigil: could not fetch details for %d advisories (listed without "
              "score)" % failed, file=sys.stderr)
    return out


def _merge_aliases(advs: List[dict]) -> List[dict]:
    """Collapse records that describe the same issue (e.g. GHSA-x and PYSEC-y
    listing each other as aliases) into one, keeping the scored record.

    OSV returns every database's copy of an advisory; counting each copy would
    inflate "N known CVEs" several-fold.
    """
    groups: List[Tuple[set, List[dict]]] = []
    for a in advs:
        names = {a.get("id")} | set(a.get("aliases") or [])
        names.discard(None)
        hit = [g for g in groups if g[0] & names]
        merged_names, merged = set(names), [a]
        for g in hit:
            merged_names |= g[0]
            merged = g[1] + merged
            groups.remove(g)
        groups.append((merged_names, merged))
    out = []
    for names, members in groups:
        # Prefer a scored record, then a GHSA record (best-maintained summaries).
        best = sorted(members, key=lambda m: (m.get("cvss") is None,
                                              not str(m.get("id")).startswith("GHSA-")))[0]
        rec = dict(best)
        rec["aliases"] = sorted(n for n in names if n != best.get("id"))
        out.append(rec)
    return out


_VTOK = re.compile(r"\d+|[A-Za-z]+")
_PRE = {"dev": -4, "a": -3, "alpha": -3, "b": -2, "beta": -2, "pre": -1, "c": -1, "rc": -1,
        "preview": -1}


def _vkey(v: str) -> list:
    """Rough cross-ecosystem version order (semver, PEP 440, gem, cargo).

    Numbers compare numerically and missing parts count as 0 (1.0 == 1.0.0);
    pre-release words (rc, beta, dev...) sort before the release they precede,
    ``post`` after it; build metadata after ``+`` is ignored.
    """
    v = str(v).strip().lstrip("vV").split("+", 1)[0]
    out = []
    for t in _VTOK.findall(v):
        if t.isdigit():
            out.append((1, int(t), ""))
        elif t.lower() == "post":
            out.append((1, 0, "post"))
        else:
            out.append((0, _PRE.get(t.lower(), 0), t.lower()))
    return out


def _vlt(a: str, b: str) -> bool:
    ka, kb = _vkey(a), _vkey(b)
    n = max(len(ka), len(kb))
    zero = (1, 0, "")
    return ka + [zero] * (n - len(ka)) < kb + [zero] * (n - len(kb))


def _norm_pkg(eco: str, name: str) -> str:
    n = (name or "").strip()
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", n).lower()
    if eco in ("npm", "crates.io", "Packagist", "RubyGems"):
        return n.lower()
    return n


def fix_version(advisory: dict, eco: str, name: str, version: str) -> Optional[str]:
    """Lowest version that fixes ``advisory`` for ``name@version``, if OSV lists one.

    Uses the ECOSYSTEM/SEMVER range that contains ``version``; falls back to the
    lowest listed fix above it. Returns None when no fix is published.
    """
    want = _norm_pkg(eco, name)
    contained, above = [], []
    for aff in advisory.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem", "").split(":")[0] != eco or _norm_pkg(eco, pkg.get("name", "")) != want:
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            intro = None
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    intro = ev["introduced"]
                elif "fixed" in ev:
                    fixed = ev["fixed"]
                    if _vlt(version, fixed):
                        above.append(fixed)
                        if intro is not None and (intro == "0" or not _vlt(version, intro)):
                            contained.append(fixed)
                    intro = None
                elif "last_affected" in ev or "limit" in ev:
                    intro = None
    pool = contained or above
    if not pool:
        return None
    best = pool[0]
    for f in pool[1:]:
        if _vlt(f, best):
            best = f
    return best


def query_osv(deps, timeout: float = 30.0) -> Dict[str, List[dict]]:
    """Return {"<eco>:<name>": [advisory,...]} for every dep with a known version.

    Concrete versions (lockfiles, exact pins, go.mod) are preferred; when several
    versions of one package are installed, each is checked and every advisory
    lists the affected ones in ``versions``. Without a concrete version the
    lowest version a range allows is used and the advisory is marked
    ``"approximate": True`` — a lockfile gives exact results.
    """
    queries, owners = [], []          # owners[i] = (key, version, approximate)
    approx_pkgs = 0
    for d in deps:
        eco = ECO_TO_OSV.get(d.ecosystem)
        if not eco:
            continue
        versions = list(getattr(d, "resolved", None) or [])
        approximate = not versions
        if approximate:
            if d.version in ("", "*"):
                continue
            versions = [d.version]
            approx_pkgs += 1
        key = "%s:%s" % (d.ecosystem, d.name)
        for ver in versions:
            queries.append({"package": {"name": d.name, "ecosystem": eco}, "version": ver})
            owners.append((key, ver, approximate))
    if not queries:
        return {}
    if approx_pkgs:
        print("vigil: %d package(s) have no lockfile or exact pin; their CVE results use the "
              "lowest version the range allows (marked approximate). Commit a lockfile for "
              "exact results." % approx_pkgs, file=sys.stderr)
    try:
        per_query = _batch_ids(queries, timeout)
        unique = list(dict.fromkeys(v for ids in per_query for v in ids))
        details = _fetch_details(unique, timeout) if unique else {}
    except Exception as e:
        print("vigil: vuln lookup failed: %s" % e, file=sys.stderr)
        return {}
    by_key: Dict[str, List[Tuple[str, bool, List[str]]]] = {}
    for (key, ver, approximate), ids in zip(owners, per_query):
        by_key.setdefault(key, []).append((ver, approximate, [i for i in ids if i in details]))
    result: Dict[str, List[dict]] = {}
    for key, rows in by_key.items():
        all_ids = list(dict.fromkeys(i for _, _, ids in rows for i in ids))
        if not all_ids:
            continue
        merged = _merge_aliases(_annotate([details[i] for i in all_ids]))
        eco, name = key.split(":", 1)
        osv_eco = ECO_TO_OSV.get(eco, eco)
        for rec in merged:
            names = {rec.get("id")} | set(rec.get("aliases") or [])
            rec["versions"] = [ver for ver, _, ids in rows if names & set(ids)]
            rec["approximate"] = any(a for _, a, _ in rows)
            raws = [details[i] for i in all_ids if i in names]
            fixes = {}
            for ver in rec["versions"]:
                for raw in raws:
                    f = fix_version(raw, osv_eco, name, ver)
                    if f:
                        fixes[ver] = f
                        break
            rec["fixed"] = fixes
        result[key] = merged
    return result
