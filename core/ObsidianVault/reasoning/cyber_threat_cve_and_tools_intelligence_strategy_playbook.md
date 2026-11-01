---
title: cyber_threat_cve_and_tools_intelligence_strategy_playbook
category: reasoning
engine: team_strategy_arbiter
team_role: cyber_threat_intel
os_platform: cross-platform
domain_hub: "[[knowledge/10_digital_forensics_pe_reversing_and_threat_intel]]"
primary_tactic: Passive_Enum
summary: "Authoritative Cybersecurity, NIST NVD API 2.0, Local ~/Projects/CVEs/ Data Feeds (417,614 CVEs across 2002–2026), CISA KEV/EPSS, Vendor PSIRT Advisories, and Living-Off-The-Land (LOLBINS/GTFOBins/LOLDrivers) Intelligence Playbook with verified fetch_webpage, web_search, query_cve.py, curl+python3, and PowerShell Invoke-RestMethod access patterns."
when_to_apply: "Apply whenever the operator, LLM, or 15 reasoning engines need to pull down complete CVE data for a CVE being researched via the NIST NVD 2.0 REST API (services.nvd.nist.gov/rest/json/cves/2.0), query the local offline NVD 2.0 CVE repository (~/Projects/CVEs/ — 2002–2026 feeds from https://nvd.nist.gov/vuln/data-feeds), or look up CISA KEV, EPSS, vendor PSIRT advisories, Exploit-DB PoCs, GTFOBins, LOLBINS (https://github.com/CROWInnovations/LOLBAS), or LOLDrivers."
tags: [reasoning, cyber_threat_intel, cve, nvd, nvd-api-2.0, data-feeds, cisa, kev, epss, mitre, osv, exploit-db, nuclei, gtfobins, lolbins, lolbas, loldrivers, kali, sysinternals, shodan, abuse-ch, psirt, threat-intelligence, cybersecurity-tools, web_search, fetch_webpage, curl, python3, windows, linux]
updated: 2026-11-01 01:31:00
---
# Cybersecurity, NIST NVD 2.0 CVE & Tools Intelligence Strategy Playbook (`cyber_threat_cve_and_tools_intelligence_strategy_playbook`)

> **Team Role:** `CYBER_THREAT_INTEL` (Cross-Team CVE, NVD 2.0 API/Feeds, Exploit & Tooling Intelligence)  
> **Primary H-MDP Tactics:** `Passive_Enum` $\to$ `Enumeration` $\to$ `Initial_Access_Exploit` / `Defense_Evasion_Firewall`  
> **Local NVD 2.0 Repository (`417,614` CVEs, `2002`–`2026`):** `~/Projects/CVEs/` (`query_cve.py`, `sync_nvd_feeds.py`, `nvd_cves.sqlite`, `nvdcve-2.0-<YEAR>.json`)  
> **CORA Native Web Tools:** `fetch_webpage(url, query_filter, max_chars)` & `web_search(query, site, max_results)` (`core/Reasoning/engines/web_intel.py`)  
> **Backlinks:** [[00_MEMORY_INDEX]] | [[reasoning/LOLBINS]] | [[commands/curl_playbook]] | [[reasoning/red_team_strategy_playbook]] | [[reasoning/blue_team_strategy_playbook]] | [[reasoning/hunt_team_strategy_playbook]] | [[reasoning/windows_digital_forensics_strategy_playbook]] | [[reasoning/linux_digital_forensics_strategy_playbook]] | [[reasoning/reverse_engineering_strategy_playbook]] | [[knowledge/10_digital_forensics_pe_reversing_and_threat_intel]]

---

## 1. Critical Architecture Note: Why NVD Web Pages Fail & How to Pull Complete CVE Data

1. **Why `https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNN` & `https://nvd.nist.gov/vuln/data-feeds` Cannot Be Scraped as Static HTML:**
   - The NIST NVD website (`nvd.nist.gov`) is a client-side Angular Single-Page Application (`<app-root></app-root>`) behind Cloudflare. Fetching the HTML page directly with `curl` returns only the empty `NVD - Home` shell.
   - **Solution Implemented in CORA:**
     - Always query either the **Local Offline NVD 2.0 Repository (`~/Projects/CVEs/`)** or the **Official NIST NVD 2.0 JSON REST API (`https://services.nvd.nist.gov/rest/json/cves/2.0`)**.
     - CORA's `fetch_webpage` (`core/Reasoning/engines/web_intel.py`) now **automatically rewrites** any `https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNN` request to `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNN`, falls back to `~/Projects/CVEs/` if offline/rate-limited, and parses **100% of all NVD 2.0 fields** (CISA KEV status, English descriptions, CVSS v4.0/v3.1/v3.0/v2.0 metrics, CWEs, vulnerable CPE 2.3 version bounds, and tagged exploit/patch/vendor references).
2. **Never Pipe to `jq` Unless Verified Installed — Use `query_cve.py` or `python3 -m json.tool`:**
   - Many minimal Linux hosts do not have `jq` installed (`jq: command not found`). Always use `python3 ~/Projects/CVEs/query_cve.py` or `python3 -c "import sys,json; ..."` for 100% portable JSON parsing.

---

## 2. NIST NVD 2.0 Data Feeds (`https://nvd.nist.gov/vuln/data-feeds`) & Local `~/Projects/CVEs/` Mirror

NIST publishes bulk NVD 2.0 feeds at `https://nvd.nist.gov/vuln/data-feeds` under `https://nvd.nist.gov/feeds/json/cve/2.0/`.

### 2.1 Why **NVD JSON 2.0 (`.json.gz` $\to$ `.json` + SQLite)** Is the Best Format for the System
| Available NVD Feed Format | Assessment for CORA & Linux/Python Analysis |
| :--- | :--- |
| **1. `nvdcve-2.0-<YEAR>.json.gz` + `.meta` $\to$ Extracted `.json` & `nvd_cves.sqlite` (SELECTED BEST FORMAT)** | - **Identical Schema to NVD 2.0 REST API:** Uses `"format": "NVD_CVE", "version": "2.0"`, preserving CVSS v4.0/v3.1/v3.0/v2.0, embedded CISA KEV fields (`cisaExploitAdd`), CWEs, CPE 2.3 version ranges, and tagged references.<br>- **Zero External Dependencies:** Decompressed natively by Python (`gzip` / `json` / `sqlite3`), `zcat`, and `grep`.<br>- **Cryptographic Integrity:** Verified against NIST's `.meta` `sha256` hash (`261 MB` compressed / `3.08 GB` uncompressed across all years `2002`–`2026` + `recent` + `modified`, totaling **`417,614` unique CVEs**). |
| **2. `nvdcve-2.0-<YEAR>.json.zip`** | Used automatically by `sync_nvd_feeds.py` as a fallback if a `.json.gz` file is mid-rotation on NIST's CDN. |
| **3. Legacy NVD 1.1 JSON / XML Feeds** | **Deprecated / Obsolete:** Lacks CVSS v4.0, embedded CISA KEV fields, and NVD 2.0 CPE match structures. Do not use. |

### 2.2 Local `~/Projects/CVEs/` Directory Layout & Instant Lookup Commands (`< 2 ms` Offline)
All yearly NVD 2.0 feeds (`2002` through `2026`, plus `recent` and `modified`) are stored locally in `~/Projects/CVEs/`:
- `~/Projects/CVEs/nvdcve-2.0-<YEAR>.json` — Uncompressed NVD 2.0 JSON for each year (`2002`–`2026`, `recent`, `modified`). Note: `nvdcve-2.0-2002.json` also contains all `CVE-1999-*`, `CVE-2000-*`, and `CVE-2001-*` records.
- `~/Projects/CVEs/feeds_gz/nvdcve-2.0-<YEAR>.json.gz` & `.meta` — Original compressed archives and SHA-256 metadata.
- `~/Projects/CVEs/nvd_cves.sqlite` — Indexed SQLite database of all `417,614` unique CVEs for `< 2 ms` queries.
- `~/Projects/CVEs/query_cve.py` — Full-featured CLI & Python lookup utility.
- `~/Projects/CVEs/sync_nvd_feeds.py` — Incremental downloader & SHA-256 verifier.

```bash
# 1. Pull ALL NVD 2.0 data (Description, CVSS v4.0/v3.1/v2.0, CWE, CISA KEV, CPEs, References) for a CVE:
python3 ~/Projects/CVEs/query_cve.py CVE-2024-21762

# 2. Output the complete unabridged raw NVD 2.0 JSON object for a CVE:
python3 ~/Projects/CVEs/query_cve.py CVE-2024-21762 --json

# 3. Force a live query directly against NIST's NVD 2.0 REST API (services.nvd.nist.gov):
python3 ~/Projects/CVEs/query_cve.py CVE-2024-21762 --live

# 4. Search all 417,614 local CVEs by product/keyword, year, minimum CVSS, CWE, or CISA KEV status:
python3 ~/Projects/CVEs/query_cve.py --search "FortiOS" --min-cvss 9.0 --kev-only --limit 15
python3 ~/Projects/CVEs/query_cve.py --year 2026 --cwe CWE-787 --min-cvss 9.0 --limit 20

# 5. Incrementally sync/update ~/Projects/CVEs/ from https://nvd.nist.gov/vuln/data-feeds:
python3 ~/Projects/CVEs/sync_nvd_feeds.py
```

---

## 3. How to Use the Live NIST NVD 2.0 REST API (`https://services.nvd.nist.gov/rest/json/cves/2.0`)

When querying NIST's live API directly via `fetch_webpage` or `curl` + `python3`:
- **Base Endpoint:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Rate Limits:** `5 requests per 30 seconds` (public, no key) or `50 requests per 30 seconds` with header `apiKey: <NVD_API_KEY>` (set `export NVD_API_KEY="..."` and `web_intel.py` / `query_cve.py` will attach it automatically).

### 3.1 Complete NVD 2.0 REST API Parameter Matrix
| Research Objective | CORA Tier-1 `fetch_webpage` Call (Auto-Parses All Fields) | Shell CLI (`curl` + `python3` — No `jq` Required) |
| :--- | :--- | :--- |
| **1. Pull All Data for a Specific CVE (`cveId`)** | `fetch_webpage(url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-21762")` | `python3 ~/Projects/CVEs/query_cve.py CVE-2024-21762 --live` *(or)*<br>`curl -sSL --max-time 20 "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-21762" \| python3 -m json.tool` |
| **2. Search CVEs by Product / Keyword (`keywordSearch`)** | `fetch_webpage(url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenSSH&resultsPerPage=10")` | `curl -sSL --max-time 20 "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenSSH&resultsPerPage=5" \| python3 -c "import sys,json; d=json.load(sys.stdin); [print(v['cve']['id'], v['cve']['descriptions'][0]['value'][:140]) for v in d.get('vulnerabilities',[])]"` |
| **3. Exact Phrase Keyword Search (`keywordExactMatch`)** | `fetch_webpage(url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=FortiOS%20SSL%20VPN&keywordExactMatch")` | `python3 ~/Projects/CVEs/query_cve.py --search "FortiOS SSL VPN"` |
| **4. Query CVEs Affecting an Exact CPE (`cpeName`)** | `fetch_webpage(url="https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:fortinet:fortios:7.4.0:*:*:*:*:*:*:*&resultsPerPage=10")` | `curl -sSL --max-time 20 "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:fortinet:fortios:7.4.0:*:*:*:*:*:*:*&resultsPerPage=10" \| python3 -m json.tool \| head -n 60` |
| **5. Filter by CVSS v3/v4 Severity & CISA KEV (`cvssV3Severity`, `hasKev`)** | `fetch_webpage(url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Exchange&cvssV3Severity=CRITICAL&hasKev&resultsPerPage=10")` | `python3 ~/Projects/CVEs/query_cve.py --search "Exchange" --min-cvss 9.0 --kev-only` |
| **6. Filter by CWE Weakness (`cweId`)** | `fetch_webpage(url="https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-787&cvssV3Severity=CRITICAL&resultsPerPage=5")` | `python3 ~/Projects/CVEs/query_cve.py --cwe CWE-787 --min-cvss 9.0 --limit 10` |
| **7. Filter by Publication / Modification Date Window (`<= 120 days`)** | `fetch_webpage(url="https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2026-08-01T00:00:00.000&pubEndDate=2026-11-01T00:00:00.000&cvssV3Severity=CRITICAL&resultsPerPage=10")` | `python3 ~/Projects/CVEs/query_cve.py --year 2026 --min-cvss 9.0 --limit 20` |
| **8. Exact CPE Product + Point-Version Range Lookup (e.g., `FortiOS 6.2.1` or `6.0.6`)** | `web_search(query="FortiOS 6.2.1 CVE vulnerabilities", site="nvd.nist.gov")` *(automatically runs CPE 2.3 version-range matching against `~/Projects/CVEs/nvd_cves.sqlite`)* | `python3 ~/Projects/CVEs/query_cve.py --product fortios --version 6.2.1 --limit 20` |

### 3.2 Complete NVD 2.0 JSON Field Map (`vulnerabilities[i].cve`)
When pulling down a CVE from `services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNN` or `~/Projects/CVEs/nvdcve-2.0-<YEAR>.json`, the `cve` object contains:
- **`id` / `sourceIdentifier` / `published` / `lastModified` / `vulnStatus`**: Canonical CVE ID, assigning CNA, timestamps, and lifecycle state (`Analyzed`, `Modified`, `Awaiting Analysis`, `Deferred`, `Rejected`).
- **`cisaExploitAdd` / `cisaActionDue` / `cisaRequiredAction` / `cisaVulnerabilityName`**: Present whenever the CVE is in CISA's Known Exploited Vulnerabilities (KEV) catalog.
- **`descriptions[]`**: Array of `{ "lang": "en", "value": "..." }` descriptions.
- **`metrics`**:
  - `cvssMetricV40[]` (CVSS v4.0), `cvssMetricV31[]` (CVSS v3.1), `cvssMetricV30[]` (CVSS v3.0), `cvssMetricV2[]` (CVSS v2.0).
  - Each entry contains `type` (`Primary` = NIST NVD assessment, `Secondary` = CNA/Vendor assessment), `cvssData.baseScore`, `cvssData.baseSeverity`, `cvssData.vectorString`, `exploitabilityScore`, and `impactScore`.
- **`weaknesses[]`**: CWE identifiers (`weaknesses[].description[].value`, e.g., `CWE-787`).
- **`configurations[]`**: Boolean CPE 2.3 trees (`nodes[].cpeMatch[]`) with `criteria`, `vulnerable`, `versionStartIncluding`/`Excluding`, and `versionEndIncluding`/`Excluding`.
- **`references[]`**: External links with `url`, `source`, and `tags` (`Exploit`, `Patch`, `Vendor Advisory`, `Mitigation`, `Technical Description`, `US Government Resource`).

---

## 4. Other Authoritative CVE, KEV, EPSS & Exploit Databases (`fetch_webpage`, `web_search` & `python3`)

| Source & Need | Easiest CORA Tool Call (`fetch_webpage` / `web_search`) | Exact `curl` + `python3` CLI Command (`run_shell`) |
| :--- | :--- | :--- |
| **1. MITRE / CVE.org (Canonical CVE Record & CNA References)**<br>`cve.org` | `fetch_webpage(url="https://cveawg.mitre.org/api/cve/CVE-YYYY-NNNN", query_filter="descriptions")` | `curl -sSL --max-time 15 "https://cveawg.mitre.org/api/cve/CVE-YYYY-NNNN" \| python3 -m json.tool \| head -n 60` |
| **2. CISA Known Exploited Vulnerabilities (KEV Catalog)**<br>`cisa.gov` | `fetch_webpage(url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", query_filter="CVE-YYYY-NNNN")` | `curl -sSL --max-time 15 "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \| python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps([x for x in d.get('vulnerabilities',[]) if x.get('cveID')=='CVE-YYYY-NNNN'], indent=2))"` |
| **3. FIRST EPSS (30-Day Exploitation Probability `0.0–1.0`)**<br>`first.org` | `fetch_webpage(url="https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNN")` | `curl -sSL --max-time 15 "https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNN" \| python3 -m json.tool` |
| **4. CIRCL Vulnerability-Lookup (Fast CVE + CWE + CAPEC JSON)**<br>`vulnerability.circl.lu` | `fetch_webpage(url="https://vulnerability.circl.lu/api/cve/CVE-YYYY-NNNN", query_filter="summary")` | `curl -sSL --max-time 15 "https://vulnerability.circl.lu/api/cve/CVE-YYYY-NNNN" \| python3 -m json.tool \| head -n 60` |
| **5. Google OSV.dev (Open-Source Package & Linux Distro CVEs)**<br>`osv.dev` | `fetch_webpage(url="https://api.osv.dev/v1/vulns/CVE-YYYY-NNNN", query_filter="details")` | `curl -sSL --max-time 15 -X POST "https://api.osv.dev/v1/query" -H "Content-Type: application/json" -d '{"version":"2.4.49","package":{"name":"apache2","ecosystem":"Debian"}}' \| python3 -m json.tool \| head -n 60` |
| **6. Exploit-DB & GitLab Mirror (Public Exploit PoCs)**<br>`exploit-db.com` | `web_search(query="CVE-YYYY-NNNN", site="exploit-db.com")` *(or)* `fetch_webpage(url="https://www.exploit-db.com/raw/<EDB_ID>")` | `curl -sSL --max-time 15 -A "Mozilla/5.0" "https://www.exploit-db.com/raw/<EDB_ID>" -o /tmp/exploit_<EDB_ID>.py` |
| **7. ProjectDiscovery Nuclei Templates (Detection & PoC YAML)**<br>`github.com/projectdiscovery/nuclei-templates` | `web_search(query="CVE-YYYY-NNNN", site="github.com/projectdiscovery/nuclei-templates")` | `curl -sSL --max-time 15 "https://api.github.com/search/code?q=CVE-YYYY-NNNN+repo:projectdiscovery/nuclei-templates" \| python3 -m json.tool \| head -n 50` |
| **8. OpenCVE (`app.opencve.io` — NVD 2.0 + MITRE 5.0 + CISA KEV + EPSS)**<br>`app.opencve.io` | **Zero-Auth Public HTML (No Token / No JS):**<br>`fetch_webpage(url="https://app.opencve.io/cve/?vendor=fortinet&product=fortios")`<br>`fetch_webpage(url="https://app.opencve.io/cve/?search=FortiOS+6.2")`<br>`fetch_webpage(url="https://app.opencve.io/cve/CVE-2024-21762")`<br>**Authenticated REST API v2 (requires `OPENCVE_API_TOKEN`):**<br>`fetch_webpage(url="https://app.opencve.io/api/v2/cves?vendor=fortinet&product=fortios&cvss=critical")` | `curl -sSL --max-time 15 "https://app.opencve.io/cve/?vendor=fortinet&product=fortios"` *(or with token: `curl -sSL -H "Authorization: Bearer $OPENCVE_API_TOKEN" "https://app.opencve.io/api/v2/cves/CVE-2024-21762"`)* |

---

## 5. Verified Vendor Security Advisories & PSIRT Portals

| Vendor / OS | Easiest CORA Tool Call (`fetch_webpage` / `web_search`) | Exact `curl` + `python3` CLI Command (`run_shell`) |
| :--- | :--- | :--- |
| **Microsoft MSRC (Windows / Server / AD / Exchange)** | `web_search(query="CVE-YYYY-NNNN", site="msrc.microsoft.com")` *(or)* `fetch_webpage(url="https://api.msrc.microsoft.com/cvrf/v3.0/updates", query_filter="2026")` | `curl -sSL --max-time 15 -H "Accept: application/json" "https://api.msrc.microsoft.com/cvrf/v3.0/updates" \| python3 -m json.tool \| head -n 45` |
| **Fortinet PSIRT (FortiOS / FortiGate / FortiProxy)** | `fetch_webpage(url="https://www.fortiguard.com/psirt", query_filter="FG-IR")` *(or)* `web_search(query="CVE-YYYY-NNNN FG-IR", site="fortiguard.com")` | `curl -sSL --max-time 15 "https://www.fortiguard.com/rss/ir.xml" \| grep -E "<title>\|<link>\|<description>" \| head -n 30` |
| **Cisco PSIRT (IOS XE / ASA / FTD / AnyConnect)** | `web_search(query="CVE-YYYY-NNNN Cisco Security Advisory", site="sec.cloudapps.cisco.com")` | `curl -sSL --max-time 15 "https://sec.cloudapps.cisco.com/security/center/publicationListing.x" \| head -n 40` |
| **Palo Alto Networks PSIRT (PAN-OS / GlobalProtect)** | `fetch_webpage(url="https://security.paloaltonetworks.com/json/CVE-YYYY-NNNN")` | `curl -sSL --max-time 15 "https://security.paloaltonetworks.com/json/CVE-YYYY-NNNN" \| python3 -m json.tool \| head -n 50` |
| **Ubuntu / Canonical Linux Security** | `fetch_webpage(url="https://ubuntu.com/security/cves/CVE-YYYY-NNNN.json", query_filter="packages")` | `curl -sSL --max-time 15 "https://ubuntu.com/security/cves/CVE-YYYY-NNNN.json" \| python3 -m json.tool \| head -n 50` |
| **Debian Security Tracker** | `fetch_webpage(url="https://security-tracker.debian.org/tracker/CVE-YYYY-NNNN")` | `curl -sSL --max-time 15 "https://security-tracker.debian.org/tracker/CVE-YYYY-NNNN" \| grep -E "CVE-\|Fixed\|buster\|bullseye\|bookworm" \| head -n 40` |
| **Red Hat Enterprise Linux (RHEL Hydra Security API)** | `fetch_webpage(url="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-YYYY-NNNN.json")` | `curl -sSL --max-time 15 "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-YYYY-NNNN.json" \| python3 -m json.tool \| head -n 50` |

---

## 6. Reputable Cybersecurity Tools, Repositories & Living-Off-The-Land (`LOLBINS`) Indexes

| Resource & Purpose | Easiest CORA Tool Call (`fetch_webpage` / `vault_read_note`) | Exact `curl` + `python3` CLI Command (`run_shell`) |
| :--- | :--- | :--- |
| **1. GTFOBins (Linux SUID, Sudo, Capabilities)**<br>`gtfobins.github.io` | `fetch_webpage(url="https://gtfobins.github.io/gtfobins/<binary>/", query_filter="sudo suid")` | `curl -sSL --max-time 15 "https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/<binary>.md"` |
| **2. LOLBAS / LOLBINS (`CROWInnovations/LOLBAS`)**<br>`github.com/CROWInnovations/LOLBAS` & `[[reasoning/LOLBINS]]` | **Local Vault Hub (202 entries / 414 commands):**<br>`vault_read_note(note="reasoning/LOLBINS")`<br>**Live CROW Innovations YAML:**<br>`fetch_webpage(url="https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Certutil.yml")` | `curl -sSL --max-time 15 "https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Certutil.yml"` |
| **3. LOLDrivers (Vulnerable Windows Kernel Drivers / BYOVD)**<br>`loldrivers.io` | `fetch_webpage(url="https://www.loldrivers.io/api/drivers.json", query_filter="rtcore64.sys")` | `curl -sSL --max-time 15 "https://www.loldrivers.io/api/drivers.json" \| python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps([x for x in d if 'rtcore64.sys' in str(x.get('Tags',[])).lower()], indent=2)[:2000])"` |
| **4. Kali Linux Official Tools Index (600+ Tools)**<br>`kali.org/tools` | `fetch_webpage(url="https://www.kali.org/tools/<toolname>/")` | `curl -sSL --max-time 15 "https://www.kali.org/tools/<toolname>/" \| grep -E "Usage\|Options\|-" \| head -n 40` |
| **5. Microsoft Windows Sysinternals Official Docs**<br>`learn.microsoft.com/en-us/sysinternals` | `fetch_webpage(url="https://learn.microsoft.com/en-us/sysinternals/downloads/<toolname>", query_filter="Usage")` | `curl.exe -sSL --max-time 15 "https://live.sysinternals.com/<ToolName>64.exe" -o C:\Temp\<ToolName>64.exe` |

---

## 7. External Threat Intelligence, IP Recon & Malware IoC Portals

| Intelligence Need | Easiest CORA Tool Call (`fetch_webpage` / `web_search`) | Exact `curl` + `python3` CLI Command (`run_shell`) |
| :--- | :--- | :--- |
| **1. Shodan InternetDB (Zero-Packet Public IP Ports, CPEs & CVEs)** | `fetch_webpage(url="https://internetdb.shodan.io/<PUBLIC_IPV4>")` | `curl -sSL --max-time 15 "https://internetdb.shodan.io/<PUBLIC_IPV4>" \| python3 -m json.tool` |
| **2. SANS ISC IP Reputation & Attack Count API** | `fetch_webpage(url="https://isc.sans.edu/api/ip/<PUBLIC_IPV4>?json")` | `curl -sSL --max-time 15 "https://isc.sans.edu/api/ip/<PUBLIC_IPV4>?json" \| python3 -m json.tool` |
| **3. GreyNoise Community IP Lookup** | `fetch_webpage(url="https://api.greynoise.io/v3/community/<PUBLIC_IPV4>")` | `curl -sSL --max-time 15 "https://api.greynoise.io/v3/community/<PUBLIC_IPV4>" \| python3 -m json.tool` |
| **4. abuse.ch MalwareBazaar (Malware SHA256 / MD5 Hash Lookup)** | `web_search(query="<SHA256_HASH>", site="bazaar.abuse.ch")` | `curl -sSL --max-time 15 -X POST "https://mb-api.abuse.ch/api/v1/" -d "query=get_info&hash=<SHA256_HASH>" \| python3 -m json.tool \| head -n 50` |
| **5. abuse.ch ThreatFox (C2 IP:Port, Domain & IoC Search)** | `web_search(query="<IP_OR_DOMAIN>", site="threatfox.abuse.ch")` | `curl -sSL --max-time 15 -X POST "https://threatfox-api.abuse.ch/api/v1/" -H "Content-Type: application/json" -d '{"query":"search_ioc","search_term":"<IP_OR_DOMAIN>"}' \| python3 -m json.tool \| head -n 50` |
| **6. abuse.ch Feodo Tracker (Active Botnet C2 IP Blocklist)** | `fetch_webpage(url="https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json", query_filter="<IP_ADDRESS>")` | `curl -sSL --max-time 15 "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json" \| python3 -m json.tool \| head -n 50` |
