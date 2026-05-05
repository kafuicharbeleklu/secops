"""CVE lookup — query NVD for known vulnerabilities.

Uses only stdlib (urllib) to avoid adding external dependencies.
"""

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT = 15
USER_AGENT = "SECOPS-Agent/1.0"


@dataclass(frozen=True)
class CVEEntry:
    """A single CVE record with score and description."""

    cve_id: str
    score: float
    severity: str
    description: str


def search_cve(service: str, version: str = "", limit: int = 5) -> list[CVEEntry]:
    """Search NVD for CVEs matching a service and optional version.

    Returns a list of CVEEntry sorted by CVSS score (highest first).
    On network errors or timeouts, returns an empty list silently.
    """
    keyword = f"{service} {version}".strip()
    if not keyword:
        return []

    params = urllib.parse.urlencode(
        {
            "keywordSearch": keyword,
            "resultsPerPage": min(limit, 20),
        }
    )
    url = f"{NVD_API_URL}?{params}"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []

    entries = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        # Extract CVSS score — try v3.1, then v3.0, then v2
        score = 0.0
        severity = "unknown"
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(metric_key, [])
            if metrics:
                cvss_data = metrics[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN").lower()
                break

        # Extract description — prefer English
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc:
            descriptions = cve.get("descriptions", [])
            desc = descriptions[0].get("value", "") if descriptions else ""

        entries.append(
            CVEEntry(
                cve_id=cve_id,
                score=score,
                severity=severity,
                description=desc[:200],
            )
        )

    entries.sort(key=lambda e: e.score, reverse=True)
    return entries[:limit]


def format_cve_results(entries: list[CVEEntry]) -> str:
    """Format CVE entries as a human-readable summary."""
    if not entries:
        return "Aucune CVE trouvee."
    lines = []
    for e in entries:
        lines.append(f"{e.cve_id} (CVSS {e.score:.1f}, {e.severity}): {e.description}")
    return "\n".join(lines)
