"""Registry of the automated (machine-readable) sources used by the pipeline."""

from __future__ import annotations

AUTOMATED_SOURCES: list[dict[str, str]] = [
    {
        "id": "nvd",
        "name": "NIST National Vulnerability Database (via fkie-cad/nvd-json-data-feeds)",
        "url": "https://github.com/fkie-cad/nvd-json-data-feeds",
        "used_for": "CVEs published per year and month, CVSS severity, NVD analysis status",
    },
    {
        "id": "cvelist",
        "name": "CVE Program, cvelistV5 (CVE JSON 5 records)",
        "url": "https://github.com/CVEProject/cvelistV5",
        "used_for": "Credits naming AI systems and AI security teams",
    },
    {
        "id": "kev",
        "name": "CISA Known Exploited Vulnerabilities catalog",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "used_for": "Exploited vulnerabilities per year, publication-to-listing lag, ransomware use",
    },
    {
        "id": "epss",
        "name": "FIRST Exploit Prediction Scoring System (EPSS)",
        "url": "https://www.first.org/epss/",
        "used_for": "Distribution of predicted exploitation probability",
    },
    {
        "id": "exploitdb",
        "name": "Exploit-DB (OffSec)",
        "url": "https://gitlab.com/exploit-database/exploitdb",
        "used_for": "Public exploits published per year",
    },
    {
        "id": "metasploit",
        "name": "Metasploit Framework module metadata (Rapid7)",
        "url": "https://github.com/rapid7/metasploit-framework",
        "used_for": "Exploit modules by disclosure year",
    },
    {
        "id": "nuclei",
        "name": "ProjectDiscovery nuclei-templates",
        "url": "https://github.com/projectdiscovery/nuclei-templates",
        "used_for": "CVE detection templates by CVE year",
    },
    {
        "id": "p0",
        "name": "Google Project Zero, 0day In the Wild tracking sheet",
        "url": "https://googleprojectzero.blogspot.com/p/0day.html",
        "used_for": "Zero-days exploited in the wild per year and vendor",
    },
    {
        "id": "hibp",
        "name": "Have I Been Pwned breach catalog",
        "url": "https://haveibeenpwned.com/PwnedWebsites",
        "used_for": "Breaches and exposed accounts per year",
    },
    {
        "id": "ransomwarelive",
        "name": "ransomware.live public API",
        "url": "https://www.ransomware.live/",
        "used_for": "Ransomware leak-site victim posts per month and active groups",
    },
]
