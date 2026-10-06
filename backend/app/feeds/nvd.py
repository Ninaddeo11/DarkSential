"""NVD CVE API 2.0 -> Vulnerability SDOs with CVSS and CPE match rules.

Format verified 2026-10-02 against
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228
(top-level: resultsPerPage, startIndex, totalResults, vulnerabilities[].cve with
id, published, lastModified, descriptions, metrics.cvssMetricV31/V40/V2,
configurations[].nodes[].cpeMatch[], cisaExploitAdd...).

Fetching is incremental: records modified in the last ``lookback_days``
(NVD caps lastMod ranges at 120 days), paginated by ``startIndex``. The
optional API key is sent as the ``apiKey`` header and raises the rate limit.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from app.feeds.base import Candidate, FeedAdapter, Rejection
from app.intel.sanitize import excerpt
from app.intel.stix import build_vulnerability, parse_timestamp

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_CPE_MATCHES = 2000
_CVSS_ORDER = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _nvd_time(dt: Any) -> str:
    return str(dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"))


def _cvss(metrics: dict[str, Any]) -> dict[str, Any] | None:
    for key in _CVSS_ORDER:
        entries = metrics.get(key) or []
        primary = next((e for e in entries if e.get("type") == "Primary"), None)
        entry = primary or (entries[0] if entries else None)
        if entry:
            data = entry.get("cvssData", {})
            return {
                "version": data.get("version"),
                "base_score": data.get("baseScore"),
                "base_severity": data.get("baseSeverity") or entry.get("baseSeverity"),
                "vector": data.get("vectorString"),
            }
    return None


def _cpe_matches(cve: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten vulnerable cpeMatch entries.

    Approximation: AND-configurations (e.g. firmware AND specific hardware) are
    flattened to their vulnerable components. Documented in docs/architecture.md.
    """
    out: list[dict[str, Any]] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable") or not match.get("criteria"):
                    continue
                out.append(
                    {
                        "criteria": match["criteria"],
                        "version_start_including": match.get("versionStartIncluding"),
                        "version_start_excluding": match.get("versionStartExcluding"),
                        "version_end_including": match.get("versionEndIncluding"),
                        "version_end_excluding": match.get("versionEndExcluding"),
                    }
                )
                if len(out) >= MAX_CPE_MATCHES:
                    return out
    return out


class NvdCveAdapter(FeedAdapter):
    name = "nvd_cve"

    def fetch(self) -> Any:
        opts = self.ctx.config.options
        lookback = min(int(opts.get("lookback_days", 2)), 120)
        per_page = min(int(opts.get("results_per_page", 2000)), 2000)
        max_pages = int(opts.get("max_pages", 20))
        end = self.ctx.clock()
        start = end - timedelta(days=lookback)
        headers = {}
        if self.ctx.settings.nvd_api_key:
            headers["apiKey"] = self.ctx.settings.nvd_api_key.get_secret_value()

        vulns: list[Any] = []
        index = 0
        total = 0
        for _ in range(max_pages):
            page = self._fetcher().fetch_json(
                NVD_URL,
                params={
                    "lastModStartDate": _nvd_time(start),
                    "lastModEndDate": _nvd_time(end),
                    "resultsPerPage": per_page,
                    "startIndex": index,
                },
                headers=headers,
            )
            batch = page.get("vulnerabilities") or []
            vulns.extend(batch)
            total = int(page.get("totalResults", 0))
            index += len(batch)
            if not batch or index >= total:
                break
        return {"totalResults": total, "vulnerabilities": vulns}

    def candidates(self, raw: Any) -> Iterable[Candidate | Rejection]:
        for wrapper in raw.get("vulnerabilities", []):
            cve = wrapper.get("cve") or {}
            cve_id = str(cve.get("id", ""))
            if cve.get("vulnStatus") == "Rejected":
                yield Rejection(cve_id, "rejected by NVD")
                continue
            published = parse_timestamp(cve.get("published"))
            if published is None:
                yield Rejection(cve_id or "?", "missing published date")
                continue
            description = next(
                (d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                None,
            )
            kev = None
            if cve.get("cisaExploitAdd"):
                kev = {
                    "date_added": cve.get("cisaExploitAdd"),
                    "due_date": cve.get("cisaActionDue"),
                    "name": cve.get("cisaVulnerabilityName"),
                }
            try:
                yield build_vulnerability(
                    cve_id,
                    source=self.name,
                    confidence=self.confidence,
                    created=published,
                    modified=parse_timestamp(cve.get("lastModified")),
                    description=excerpt(description, 4000) if description else None,
                    cvss=_cvss(cve.get("metrics") or {}),
                    cpe_matches=_cpe_matches(cve),
                    kev=kev,
                )
            except ValueError as exc:
                yield Rejection(cve_id or "?", str(exc))
