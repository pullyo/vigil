
# vigil

A **dependency supply-chain sentinel**. Point it at your repo and it tells you,
before you ship (or before you get acquired, audited, or pwned):

1. **License taint** — what each dependency's license is, its license class
   (permissive / weak-copyleft / strong-copyleft / source-available), and whether
   it's compatible with *your* project's license intent.
2. **Known CVEs** — cross-checks every dependency against the free **OSV.dev**
   database, reports severity (parsed CVSS v3.1 base scores) and the version to
   upgrade to.
   Sends package names + versions to `api.osv.dev` over verified HTTPS only
   (no unverified fallback, redirects refused); copies of one advisory from
   several databases (GHSA / PYSEC / CVE) are counted once.
   Versions come from your lockfile when there is one (see below), so results
   match what is actually installed. If several versions of a package are
   installed, each is checked and the affected ones are listed. Without a
   lockfile or exact pin, the lowest version the range allows is checked and
   the result is marked *approximate*.
3. **Policy engine** — a `vigil.toml` gates which license classes your
   dependency graph is allowed to use.
4. **CI-ready** — `--fail-on high` exits non-zero so you can wire it into a pipeline.

Works across **npm, pip, Go, Cargo, Composer, and Ruby** in one command.

## Install

```bash
pipx install git+https://github.com/pullyo/vigil   # or: pip install git+https://github.com/pullyo/vigil
vigil --version
```

## Usage

```bash
vigil .                     # scan the current repo (license audit, free)
vigil /path/to/repo         # scan a specific path
vigil . --license copyleft  # "my project is copyleft" — relaxes the matrix
vigil . --vuln              # add known-CVE checking via OSV.dev (network)
vigil . --policy vigil.toml # enforce a license-class policy
vigil . --sbom bom.json --notice THIRD_PARTY_NOTICES.md   # [Pro] compliance files
vigil . -f json -o report.json   # machine-readable export
vigil . -f sarif -o vigil.sarif  # SARIF 2.1.0 for GitHub Code Scanning
vigil . --registry          # opt-in: resolve licenses from npm/PyPI (network)
vigil --init                # write a starter vigil.toml
```

## CI: GitHub Actions + SARIF

`.github/workflows/vigil.yml` is a ready-made workflow:

- **`vigil gate`** scans the repo, fails the check on findings at/above
  `VIGIL_FAIL_ON` (default `high`), writes a Markdown summary to the job page and
  uploads `vigil.sarif` as an artifact. Make this a required status check.
- **`code-scanning` (optional)** uploads the same SARIF to GitHub Code Scanning
  so findings show up in the **Security** tab and on PR diffs. It only runs where
  a write token exists (default-branch pushes, manual runs, same-repo PRs), never
  blocks the gate, and can be turned off with the repository variable
  `VIGIL_CODE_SCANNING=false`.
- No secrets are used; fork PRs run with a read-only token.

SARIF details: stable rule IDs (`vigil/license-*`, `vigil/vuln-*`),
repository-relative locations pointing at the manifest line that declares the
dependency, `security-severity` on vulnerability rules, and stable fingerprints
so alerts don't churn between runs. Paths are relative to the current
directory — run vigil from the checkout root. With no manifests, a valid empty
SARIF log is still written.

## Supported files

| Ecosystem | Manifests | Lockfiles (exact installed versions) |
|---|---|---|
| npm | `package.json` | `package-lock.json`, `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` |
| PyPI | `requirements.txt`, `pyproject.toml` | `poetry.lock`, `Pipfile.lock`, `uv.lock` |
| Go | `go.mod` (versions there are already exact) | — |
| Cargo | `Cargo.toml` | `Cargo.lock` |
| Composer | `composer.json` | `composer.lock` |
| RubyGems | `Gemfile` | `Gemfile.lock` |

Lockfile entries for the project's own workspace/path packages are skipped.
Git, path and other non-registry sources are still checked for CVEs but never
used for registry license lookups.

## Registry license lookups (opt-in)

By default vigil is fully offline: licenses come from installed metadata
(`node_modules/`, `site-packages/`), lockfile declarations, and a small built-in
name → license table. `--registry` adds lookups against the public
`https://registry.npmjs.org/<name>/<version>` and
`https://pypi.org/pypi/<name>/<version>/json` endpoints.

- **What is sent:** only package names and versions, in the request URL. No
  manifest contents or project data. HTTPS with certificate verification;
  redirects to other hosts are refused.
- **Exact versions only:** lookups happen only for versions known exactly — a
  bare npm pin (`"1.2.3"`), a pip `==1.2.3` pin, or an entry from
  a lockfile listed under *Supported files* (npm and PyPI only). Ranges (`^1.2.0`, `>=2.0`, `~=1.4`, `1.*`), tags
  (`latest`), aliases and git/file/tarball sources are never looked up, and
  "latest" is never substituted. When a lockfile settles a range on one
  concrete version, that concrete version is reported. Dependencies with
  conflicting exact versions are skipped for registry lookup.
  The response must name the same package and version or it is ignored.
- **Precedence:** installed metadata (matched by name and pinned version) → license recorded in the
  lockfile for that exact version → registry metadata → built-in table →
  `unknown`. The root project's own `license` field is never applied to a
  dependency.
- **Compound licenses:** SPDX expressions involving multiple licenses or
  exceptions are reported for review.
- **Limits:** 10 s per request, 2 MiB per response, 8 parallel requests, at
  most 300 requests per run (`--registry-max-lookups N`), 60 s to start requests; after 5
  network errors the remaining lookups are skipped. Failures fall back to the
  offline result — the scan never aborts because the registry is unreachable.
- **Cache:** successful responses are cached for 7 days in
  `$VIGIL_CACHE_DIR/registry` (default `~/.cache/vigil/registry`, override with
  `--registry-cache DIR`); duplicate packages are looked up once per run.
- **Counts:** a one-line summary (resolved X/Y, cached / fetched / failed /
  skipped) goes to **stderr**, so `-f json` / `-f md` stdout stays clean. Exit
  codes and report formats are unchanged.

## The license matrix (free)

| Your project is… | permissive | weak-copyleft | strong-copyleft | source-available |
|---|---|---|---|---|
| **proprietary** | ok | warn | **high** | **high** |
| **permissive** | ok | ok | **high** | **high** |
| **copyleft** | ok | ok | ok | **high** |

`high` = your lawyer / a customer / a CI gate will care. `warn` = review.

Example output:

```
== vigil — dependency supply-chain audit ==

  X  gitpython       gpl-3.0          HIGH  incompatible with a proprietary project
  ~  moment          mpl-2.0          WARN  review: weak-copyleft
  +  lodash          mit              OK    compatible
  ...
  12 ok / 3 warn / 1 high
```

## Pro

Free: the full license audit and the full CVE list (with the version that
fixes each one), in every output format.

**vigil Pro** is for shipping software to customers and passing audits:

- `--sbom bom.json` — CycloneDX 1.5 SBOM (validated against the official schema),
  one component per installed version, with package URLs and SPDX license ids.
- `--notice THIRD_PARTY_NOTICES.md` — every dependency grouped by license,
  unidentified licenses listed first for review.
- CI gate on CVEs: `--fail-on` also fails the build on known vulnerabilities.

Every CVE finding says what to upgrade to, picked from the fix in the same
release line as the installed version (e.g. Django 4.2 → 4.2.11, not 5.0.3).

```bash
export VIGIL_PRO_KEY=***
vigil . --vuln --sbom bom.json --notice THIRD_PARTY_NOTICES.md
```

Get a key: Pro keys are not on sale yet — open an issue at
https://github.com/pullyo/vigil/issues to get a free early-access key.

The key can also live in `~/.vigil/key` or `./.vigil_key`, or be passed with
`--key`. Keys are checked offline (an Ed25519 signature; vigil only ships the
public key), so no network call or account is involved.

### Issuing keys (maintainer)

```bash
python3 tools/issue_key.py genkey ~/.config/vigil/signing.key   # once; paste the printed
                                                                # public key into vigil/prokey.py
python3 tools/issue_key.py issue --keyfile ~/.config/vigil/signing.key --customer SALE_ID
python3 tools/issue_key.py issue ... --expires 2027-01-31       # trial / time-limited key
```

Keep the signing key out of the repository and back it up.

## Why this exists

License compliance and CVE triage live in a million different SaaS dashboards
and enterprise CLM suites. `vigil` is the small, open, single-binary answer:
run it locally, in CI, on a laptop, in a shell. No daemon, no account.

## License

MIT. *(Pro gating is a soft gate for a small paid product — see `vigil/prokey.py`
and the `launchkit/` notes on how the open-core line is drawn.)*
