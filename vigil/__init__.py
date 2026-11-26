"""vigil — a dependency supply-chain & license sentinel.

Scans your repo's dependency manifests (npm / pip / go / cargo / composer / gem),
classifies each dependency's license, flags copyleft / source-available risk
against your project's license, and (Pro) cross-checks known CVEs via OSV.dev.

Free features are MIT. Pro features (vuln scan + policy engine + exports)
require a license key.
"""

__version__ = "0.1.0"

PRO = "pro"
FREE = "free"
