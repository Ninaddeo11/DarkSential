"""CISA Known Exploited Vulnerabilities catalog -> Vulnerability SDOs.

Format verified 2026-10-02 against
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
(fields: cveID, vendorProject, product, vulnerabilityName, dateAdded,
shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.feeds.base import Candidate, FeedAdapter, Rejection
from app.intel.sanitize import excerpt
from app.intel.stix import build_vulnerability, parse_timestamp

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevAdapter(FeedAdapter):
    name = "cisa_kev"

    def fetch(self) -> Any:
        return self._fetcher().fetch_json(KEV_URL)

    def candidates(self, raw: Any) -> Iterable[Candidate | Rejection]:
        for item in raw.get("vulnerabilities", []):
            cve = str(item.get("cveID", ""))
            added = parse_timestamp(item.get("dateAdded"))
            if added is None:
                yield Rejection(cve or "?", "missing dateAdded")
                continue
            try:
                yield build_vulnerability(
                    cve,
                    source=self.name,
                    confidence=self.confidence,
                    created=added,
                    description=excerpt(str(item.get("shortDescription", "")), 2000) or None,
                    kev={
                        "date_added": item.get("dateAdded"),
                        "due_date": item.get("dueDate"),
                        "ransomware": item.get("knownRansomwareCampaignUse"),
                        "vendor": item.get("vendorProject"),
                        "product": item.get("product"),
                        "name": item.get("vulnerabilityName"),
                        "required_action": excerpt(str(item.get("requiredAction", "")), 1000),
                        "cwes": list(item.get("cwes") or []),
                    },
                )
            except ValueError as exc:
                yield Rejection(cve or "?", str(exc))
