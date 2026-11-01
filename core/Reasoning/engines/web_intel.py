"""
Tier-1 Pure-Python Web Search & Website Query Engine (`web_intel.py`).
Provides fast, zero-JavaScript, zero-VRAM internet search (`web_search`) and deep URL/API
content extraction (`fetch_webpage`) for both the CORA WebUI and CLI, as well as the
15-Engine Neuro-Symbolic Reasoning Pipeline.

Security & Efficiency Guarantees:
  1. 0 MB GPU VRAM & ~5 MB CPU RAM (pure Python `urllib.request` + `html` + `ssl` + `gzip`).
  2. Zero remote JavaScript / WebAssembly / WebGL / Cookie execution (immune to browser exploits).
  3. Enforces CORA Network Isolation (`RED` = Full Access, `BLUE` = Allowed Local Subnets Only,
     `WHITE` / `Analyst` = Strictly Air-Gapped) and Engine 12 (`cegar_verifier`) address checks.
  4. Anti-Prompt-Injection HTML Sanitizer: strips `<script>`, `<style>`, `<iframe>`, comments,
     and hidden CSS elements (`display:none`, `visibility:hidden`, `opacity:0`, `aria-hidden="true"`).
  5. Converts HTML headings, tables, code blocks, forms, and JSON APIs into compact Markdown
     and archives full reports into `Projects/<active_project>/targets/`.
"""

import gzip
import html
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .cegar_verifier import is_analyst_mode, verify_target_address_cegar
from .sygus_extractor import extract_structured_facts
from .temporal_fluents import record_command_event
from .vault_bridge import get_active_project_dir, slugify, update_project_memory_index

_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
)
_LOCAL_CVE_DIR = Path(os.environ.get("CORA_CVE_DIR", str(Path.home() / "Projects" / "CVEs"))).resolve()
_LOCAL_CVE_SQLITE = _LOCAL_CVE_DIR / "nvd_cves.sqlite"


def _parse_ver_tuple(v_str: str) -> Tuple[int, ...]:
    """Parse a dotted software version string (e.g., `6.2.1` or `7.0.14`) into an integer tuple."""
    nums = [int(x) for x in re.findall(r"\d+", str(v_str or ""))]
    return tuple(nums)


def _cpe_version_matches(cm: Dict[str, Any], target_ver: str) -> bool:
    """Return True if `target_ver` falls within the CPE 2.3 match criteria or version range bounds."""
    if not target_ver:
        return True
    tv = _parse_ver_tuple(target_ver)
    if not tv:
        return True
    crit = str(cm.get("criteria") or "")
    parts = crit.split(":")
    cpe_ver = parts[5] if len(parts) > 5 else "*"

    has_range = any(
        cm.get(k)
        for k in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
    )
    if not has_range:
        if cpe_ver in ("*", "-", ""):
            return False
        cv = _parse_ver_tuple(cpe_ver)
        if not cv:
            return False
        if len(tv) < len(cv):
            return cv[: len(tv)] == tv
        return cv == tv

    # If both start and end bounds exist, enforce exact range check; if only an upper bound exists without a start bound,
    # ensure the major.minor branch matches when `target_ver` has >= 2 components (prevents `<= 6.4.2` matching `5.0.1` unless same major).
    v_start_inc = cm.get("versionStartIncluding")
    v_start_exc = cm.get("versionStartExcluding")
    v_end_inc = cm.get("versionEndIncluding")
    v_end_exc = cm.get("versionEndExcluding")

    if v_start_inc and tv < _parse_ver_tuple(v_start_inc):
        return False
    if v_start_exc and tv <= _parse_ver_tuple(v_start_exc):
        return False
    if v_end_inc:
        ev = _parse_ver_tuple(v_end_inc)
        if tv > ev:
            return False
        if not v_start_inc and not v_start_exc and len(tv) >= 2 and len(ev) >= 2 and tv[0] != ev[0]:
            return False
    if v_end_exc:
        ev = _parse_ver_tuple(v_end_exc)
        if tv >= ev:
            return False
        if not v_start_inc and not v_start_exc and len(tv) >= 2 and len(ev) >= 2 and tv[0] != ev[0]:
            return False
    return True


def _search_local_nvd_by_product_version(query_text: str, max_items: int = 8) -> List[Dict[str, Any]]:
    """
    Search `~/Projects/CVEs/nvd_cves.sqlite` (`cve_products` + CPE 2.3 version ranges) when a query asks
    about product/version CVEs (e.g., `FortiOS 6.2`, `FortiOS 6.2.1`, `OpenSSH 8.9`, `Apache 2.4.49`).
    Solves the point-version search problem where search engines miss `6.2.1` because NVD stores `6.2.0 through 6.2.15`.
    """
    import sqlite3

    if not _LOCAL_CVE_SQLITE.is_file() or not query_text:
        return []

    # Strip `site:...` and common stop/intent words to isolate product & version tokens
    cleaned_q = re.sub(r"\bsite:[^\s]+", " ", query_text, flags=re.I)
    stop_words = {
        "cve", "cves", "vuln", "vulns", "vulnerability", "vulnerabilities", "exploit", "exploits",
        "poc", "rce", "nvd", "nist", "gov", "mitre", "kev", "cisa", "known", "affected", "version",
        "versions", "advisory", "advisories", "security", "patch", "bypass", "authentication",
        "remote", "code", "execution", "privilege", "escalation", "search", "find", "list",
        "for", "the", "and", "with", "from", "in", "on", "of", "to",
    }
    ver_match = re.search(r"\b(\d+\.\d+(?:\.\d+)*)\b", cleaned_q)
    target_version = ver_match.group(1) if ver_match else ""

    raw_tokens = re.findall(r"[A-Za-z0-9_\-]+", cleaned_q.lower())
    cand_tokens = [
        t for t in raw_tokens
        if t not in stop_words and not re.match(r"^\d+(?:\.\d+)*$", t) and len(t) >= 3
    ]
    if not cand_tokens:
        return []

    # Common hardware/appliance alias normalization (e.g., fortigate -> fortios, apache -> http_server)
    expanded_products: List[str] = []
    for tok in cand_tokens:
        expanded_products.append(tok)
        if tok in ("fortigate", "fgt") or re.match(r"^fgt\d+", tok):
            if "fortios" not in expanded_products:
                expanded_products.append("fortios")
        elif tok == "apache" and "http_server" not in expanded_products:
            expanded_products.append("http_server")

    try:
        conn = sqlite3.connect(str(_LOCAL_CVE_SQLITE))
        cur = conn.cursor()
        # Check if `cve_products` index table exists
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_products';")
        has_prod_table = bool(cur.fetchone())

        matched_rows: List[Tuple[Any, ...]] = []
        if has_prod_table:
            placeholders = ",".join("?" for _ in expanded_products)
            sql = f"""
                SELECT DISTINCT c.cve_id, c.cvss_score, c.cvss_severity, c.cisa_kev, c.published, c.raw_cve_json
                FROM cve_products p
                JOIN cves c ON p.cve_id = c.cve_id
                WHERE p.product IN ({placeholders})
                ORDER BY c.cisa_kev DESC, COALESCE(c.cvss_score, 0.0) DESC, c.cve_id DESC
                LIMIT 600;
            """
            cur.execute(sql, tuple(expanded_products))
            matched_rows = cur.fetchall()

        if not matched_rows:
            # Fallback keyword search on description/CPE if product name wasn't an exact CPE token
            primary_tok = expanded_products[0]
            cur.execute(
                """
                SELECT cve_id, cvss_score, cvss_severity, cisa_kev, published, raw_cve_json
                FROM cves
                WHERE description LIKE ? OR raw_cve_json LIKE ?
                ORDER BY cisa_kev DESC, COALESCE(cvss_score, 0.0) DESC, cve_id DESC
                LIMIT 250;
                """,
                (f"%{primary_tok}%", f"%:{primary_tok}:%"),
            )
            matched_rows = cur.fetchall()
        conn.close()
    except Exception:
        return []

    verified_cves: List[Dict[str, Any]] = []
    for cve_id, score, sev, kev, pub, raw_j in matched_rows:
        try:
            c_obj = json.loads(raw_j)
        except Exception:
            continue
        if target_version:
            ver_ok = False
            matched_range_str = ""
            for cfg in c_obj.get("configurations") or []:
                for node in cfg.get("nodes") or []:
                    for cm in node.get("cpeMatch") or []:
                        if not cm.get("vulnerable", True):
                            continue
                        crit = str(cm.get("criteria") or "").lower()
                        if any(f":{p}:" in crit for p in expanded_products) and _cpe_version_matches(cm, target_version):
                            ver_ok = True
                            bounds = []
                            for bk, bl in (
                                ("versionStartIncluding", ">="),
                                ("versionStartExcluding", ">"),
                                ("versionEndIncluding", "<="),
                                ("versionEndExcluding", "<"),
                            ):
                                if cm.get(bk):
                                    bounds.append(f"{bl} {cm[bk]}")
                            matched_range_str = " and ".join(bounds) if bounds else crit.split(":")[5]
                            break
                    if ver_ok:
                        break
                if ver_ok:
                    break
            if not ver_ok:
                continue
            c_obj["_matched_version_range"] = f"{expanded_products[0]} {target_version} (matches `{matched_range_str}`)"
        verified_cves.append(c_obj)
        if len(verified_cves) >= max_items:
            break

    return verified_cves


def _lookup_local_nvd_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Look up a full NVD 2.0 CVE object in `~/Projects/CVEs/nvd_cves.sqlite` or `nvdcve-2.0-<YEAR>.json` (< 2 ms)."""
    import sqlite3

    cve_norm = (cve_id or "").strip().upper()
    if not re.match(r"^CVE-\d{4}-\d+$", cve_norm):
        return None
    if _LOCAL_CVE_SQLITE.is_file():
        try:
            conn = sqlite3.connect(str(_LOCAL_CVE_SQLITE))
            cur = conn.cursor()
            cur.execute("SELECT raw_cve_json FROM cves WHERE cve_id = ?;", (cve_norm,))
            row = cur.fetchone()
            conn.close()
            if row and row[0]:
                return json.loads(row[0])
        except Exception:
            pass
    m = re.match(r"^CVE-(\d{4})-\d+$", cve_norm)
    if m and _LOCAL_CVE_DIR.is_dir():
        yr = str(max(2002, int(m.group(1))))
        for feed in ("modified", "recent", yr):
            jf = _LOCAL_CVE_DIR / f"nvdcve-2.0-{feed}.json"
            if jf.is_file():
                try:
                    data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
                    for item in data.get("vulnerabilities") or []:
                        c_obj = (item or {}).get("cve") or {}
                        if str(c_obj.get("id", "")).upper() == cve_norm:
                            return c_obj
                except Exception:
                    pass
    return None


def _format_nvd_cve_20_record(cve_obj: Dict[str, Any], source_label: str = "NIST NVD 2.0") -> str:
    """Format 100% of NVD 2.0 CVE fields into a structured Markdown intelligence report."""
    if not isinstance(cve_obj, dict) or not cve_obj.get("id"):
        return ""
    cve_id = str(cve_obj.get("id"))
    status = str(cve_obj.get("vulnStatus") or "N/A")
    src_id = str(cve_obj.get("sourceIdentifier") or "N/A")
    pub = str(cve_obj.get("published") or "N/A")
    mod = str(cve_obj.get("lastModified") or "N/A")
    lines = [
        f"### {cve_id} — Complete NIST NVD 2.0 Vulnerability Record",
        f"- **Source:** `{source_label}` | **Status:** `{status}` | **CNA:** `{src_id}`",
        f"- **Published:** `{pub}` | **Last Modified:** `{mod}`",
        f"- **NVD 2.0 API:** `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}`",
    ]
    if cve_obj.get("cisaExploitAdd"):
        lines.append(
            f"- **CISA KEV Status:** **ACTIVE EXPLOITATION IN THE WILD** (`{cve_obj.get('cisaVulnerabilityName', '')}` | "
            f"Added: `{cve_obj.get('cisaExploitAdd')}` | Due: `{cve_obj.get('cisaActionDue', 'N/A')}` | "
            f"Action: {cve_obj.get('cisaRequiredAction', 'N/A')})"
        )
    descs = cve_obj.get("descriptions") or []
    en_descs = [str(d.get("value", "")).strip() for d in descs if d.get("lang") == "en" and d.get("value")]
    if not en_descs and descs:
        en_descs = [str(d.get("value", "")).strip() for d in descs if d.get("value")]
    if en_descs:
        lines.append("\n#### 1. Description")
        lines.extend(en_descs)

    metrics = cve_obj.get("metrics") or {}
    m_rows = []
    for m_key, ver_label in (
        ("cvssMetricV40", "CVSS v4.0"),
        ("cvssMetricV31", "CVSS v3.1"),
        ("cvssMetricV30", "CVSS v3.0"),
        ("cvssMetricV2", "CVSS v2.0"),
    ):
        for m in metrics.get(m_key) or []:
            cv = m.get("cvssData") or {}
            m_type = f"{m.get('type', 'Primary')} ({m.get('source', 'NVD')})"
            b_score = cv.get("baseScore", "N/A")
            b_sev = cv.get("baseSeverity") or m.get("baseSeverity") or "N/A"
            vec = cv.get("vectorString", "N/A")
            exp_s = m.get("exploitabilityScore", "N/A")
            imp_s = m.get("impactScore", "N/A")
            m_rows.append(f"| **{ver_label}** | `{m_type}` | **`{b_score}`** | **`{b_sev}`** | `{vec}` | `{exp_s}` | `{imp_s}` |")
    if m_rows:
        lines.append("\n#### 2. CVSS Metrics (v4.0 / v3.1 / v3.0 / v2.0)")
        lines.append("| Version | Source | Base Score | Severity | Vector String | Exploitability | Impact |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        lines.extend(m_rows)

    cwes = []
    for w in cve_obj.get("weaknesses") or []:
        w_vals = [str(d.get("value", "")) for d in (w.get("description") or []) if d.get("value")]
        if w_vals:
            cwes.append(f"`{', '.join(w_vals)}` ({w.get('type', 'Primary')} — `{w.get('source', 'NVD')}`)")
    if cwes:
        lines.append("\n#### 3. CWE Weaknesses")
        for c in cwes:
            lines.append(f"- {c}")

    cpe_lines = []
    for cfg in cve_obj.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                crit = cm.get("criteria", "")
                vflag = "VULNERABLE" if cm.get("vulnerable", True) else "RUNNING_ON"
                bounds = []
                for bk, bl in (
                    ("versionStartIncluding", ">="),
                    ("versionStartExcluding", ">"),
                    ("versionEndIncluding", "<="),
                    ("versionEndExcluding", "<"),
                ):
                    if cm.get(bk):
                        bounds.append(f"{bl} {cm[bk]}")
                b_str = f" (`{' and '.join(bounds)}`)" if bounds else ""
                cpe_lines.append(f"- [{vflag}] `{crit}`{b_str}")
    if cpe_lines:
        lines.append(f"\n#### 4. Affected CPE 2.3 Products & Version Ranges ({len(cpe_lines)} match rules)")
        lines.extend(cpe_lines[:35])
        if len(cpe_lines) > 35:
            lines.append(f"- *(... +{len(cpe_lines) - 35} more CPE rules)*")

    refs = cve_obj.get("references") or []
    if refs:
        lines.append(f"\n#### 5. Advisories, Patches & Exploit References ({len(refs)} total)")
        for r in refs[:25]:
            r_tags = ", ".join(r.get("tags") or [])
            t_s = f" [`{r_tags}`]" if r_tags else ""
            lines.append(f"- `{r.get('url', '')}` *(Source: `{r.get('source', '')}`)*{t_s}")
        if len(refs) > 25:
            lines.append(f"- *(... +{len(refs) - 25} more references)*")
    return "\n".join(lines)


def _filter_json_payload(parsed_json: Any, query_filter: str) -> Optional[Any]:
    """Filter a JSON list or dict (e.g., CISA KEV `vulnerabilities`, LOLBAS, LOLDrivers) by `query_filter`."""
    qf = (query_filter or "").strip().lower()
    if not qf:
        return None
    tokens = [t for t in re.split(r"\s+", qf) if len(t) >= 2]

    def _matches(item: Any) -> bool:
        s = json.dumps(item, ensure_ascii=False).lower()
        return (qf in s) or (bool(tokens) and all(tok in s for tok in tokens))

    if isinstance(parsed_json, list):
        matched = [x for x in parsed_json if _matches(x)]
        return matched[:15] if matched else None
    if isinstance(parsed_json, dict):
        # Check common list containers (e.g., `vulnerabilities` in NVD/CISA KEV, `data` in EPSS/abuse.ch, `items` in GitHub)
        for list_key in ("vulnerabilities", "data", "items", "results", "cves", "drivers"):
            val = parsed_json.get(list_key)
            if isinstance(val, list):
                matched = [x for x in val if _matches(x)]
                if matched:
                    return {list_key: matched[:15], "matched_count": len(matched)}
        # Or filter matching top-level keys/values
        sub = {k: v for k, v in parsed_json.items() if qf in str(k).lower() or _matches(v)}
        return sub if sub else None
    return None


def _check_network_isolation_for_host(
    host: str,
    mode_info: Optional[Dict[str, Any]] = None,
    posture: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    Verify that querying `host` is permitted under the active Personality Mode and
    RED / BLUE / WHITE Network Isolation posture. Returns None if allowed, or a
    human-readable block reason string if prohibited.
    """
    if mode_info and mode_info.get("read_only"):
        return (
            "Blocked by Mode [2] Analyst (Strictly Read-Only & WHITE Air-Gap). "
            "Switch to Mode [1] Default, [3] Berserker, or [4] Ninja with RED isolation for online web queries."
        )
    if is_analyst_mode():
        return (
            "Blocked by Analyst Mode (WHITE Network Isolation — local loopback only). "
            "Switch to RED (Full Access) mode to perform online web searches or website queries."
        )

    iso_mode = ""
    if posture and isinstance(posture, dict):
        iso_mode = str(posture.get("mode") or posture.get("isolation_level") or "").upper()
    if not iso_mode:
        iso_mode = os.environ.get("LLM_ISOLATION_MODE", "RED").upper()

    if iso_mode in ("WHITE", "AIR_GAPPED_NETNS"):
        clean_h = (host or "").strip().lower()
        if clean_h not in ("127.0.0.1", "localhost", "::1"):
            return (
                f"Blocked by WHITE Network Isolation (`AIR_GAPPED_NETNS`): external host `{host}` is not reachable "
                "in air-gapped loopback mode. Switch Network Isolation to RED (`FULL-ACCESS`)."
            )

    if iso_mode in ("BLUE", "ISOLATED_LAN_USB"):
        clean_h = (host or "").strip().lower()
        if clean_h in ("127.0.0.1", "localhost", "::1"):
            return None
        try:
            ip_obj = ipaddress.ip_address(clean_h)
            if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
                return (
                    f"Blocked by BLUE Network Isolation (`ISOLATED_LAN_USB`): `{host}` is a public internet IP. "
                    "BLUE mode restricts traffic to local LAN/USB subnets. Switch to RED (`FULL-ACCESS`) for internet queries."
                )
        except ValueError:
            # Hostname (e.g., duckduckgo.com or external website)
            if "." in clean_h and not clean_h.endswith((".local", ".lan", ".internal", ".home", ".arpa")):
                return (
                    f"Blocked by BLUE Network Isolation (`ISOLATED_LAN_USB`): external internet domain `{host}` "
                    "is blocked in isolated LAN mode. Switch to RED (`FULL-ACCESS`) for online web searches."
                )

    cegar_ver = verify_target_address_cegar(host)
    if cegar_ver.get("blocked"):
        return f"Blocked by Engine 12 CEGAR Pre-Verifier: {cegar_ver.get('reason')} ({cegar_ver.get('counterexample')})"

    return None


def _decode_http_bytes(raw_bytes: bytes, content_encoding: str = "", content_type: str = "") -> str:
    """Decompress gzip/deflate HTTP bodies if needed and decode to UTF-8 text."""
    data = raw_bytes or b""
    enc = (content_encoding or "").lower()
    try:
        if "gzip" in enc or (len(data) >= 2 and data[:2] == b"\x1f\x8b"):
            data = gzip.decompress(data)
        elif "deflate" in enc:
            try:
                data = zlib.decompress(data)
            except zlib.error:
                data = zlib.decompress(data, -zlib.MAX_WBITS)
    except Exception:
        pass

    charset = "utf-8"
    m_cs = re.search(r"charset=([A-Za-z0-9_\-]+)", content_type or "", flags=re.I)
    if m_cs:
        charset = m_cs.group(1).strip()
    try:
        return data.decode(charset, errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def _http_fetch_raw(
    url: str,
    method: str = "GET",
    post_data: Optional[bytes] = None,
    extra_headers: Optional[Dict[str, str]] = None,
    timeout: float = 15.0,
    max_bytes: int = 10_000_000,
) -> Dict[str, Any]:
    """Perform a pure-Python HTTP/HTTPS request with TLS fallback and safe byte capping (up to 10 MB for JSON feeds)."""
    headers = {
        "User-Agent": _DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }
    nvd_key = os.environ.get("NVD_API_KEY", "").strip()
    if nvd_key and "nvd.nist.gov" in (url or "").lower():
        headers["apiKey"] = nvd_key
    opencve_token = os.environ.get("OPENCVE_API_TOKEN", "").strip()
    if opencve_token and "opencve.io" in (url or "").lower():
        headers["Authorization"] = f"Bearer {opencve_token}"
    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(url, data=post_data, headers=headers, method=method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status_code = int(resp.getcode() or 200)
            final_url = str(resp.geturl() or url)
            resp_headers = {k: v for k, v in resp.info().items()}
            raw_bytes = resp.read(max_bytes)
    except urllib.error.HTTPError as he:
        status_code = int(he.code or 500)
        final_url = str(he.geturl() or url)
        resp_headers = {k: v for k, v in he.headers.items()} if he.headers else {}
        try:
            raw_bytes = he.read(max_bytes)
        except Exception:
            raw_bytes = b""
    except Exception as exc:
        return {
            "ok": False,
            "status_code": 0,
            "final_url": url,
            "headers": {},
            "text": "",
            "error": str(exc),
            "latency_ms": round((time.perf_counter() - t0) * 1000.0, 1),
        }

    c_enc = resp_headers.get("Content-Encoding") or resp_headers.get("content-encoding") or ""
    c_type = resp_headers.get("Content-Type") or resp_headers.get("content-type") or ""
    decoded_text = _decode_http_bytes(raw_bytes, content_encoding=c_enc, content_type=c_type)
    return {
        "ok": 200 <= status_code < 400 or bool(decoded_text.strip()),
        "status_code": status_code,
        "final_url": final_url,
        "headers": resp_headers,
        "content_type": c_type,
        "text": decoded_text,
        "raw_len": len(raw_bytes),
        "error": "" if status_code < 400 else f"HTTP {status_code}",
        "latency_ms": round((time.perf_counter() - t0) * 1000.0, 1),
    }


def _unwrap_ddg_url(raw_href: str) -> str:
    """Unwrap DuckDuckGo redirect links (`//duckduckgo.com/l/?uddg=...`) into clean target URLs."""
    href = html.unescape((raw_href or "").strip())
    if "uddg=" in href:
        try:
            parsed = urllib.parse.urlsplit(href)
            qs = urllib.parse.parse_qs(parsed.query)
            if qs.get("uddg"):
                return urllib.parse.unquote(qs["uddg"][0])
        except Exception:
            pass
    if href.startswith("//"):
        return "https:" + href
    return href


def _strip_tags_clean(fragment: str) -> str:
    """Remove HTML tags and normalize whitespace."""
    if not fragment:
        return ""
    no_tags = re.sub(r"<[^>]+>", " ", fragment)
    return re.sub(r"\s+", " ", html.unescape(no_tags)).strip()


def _sanitize_and_convert_html_to_markdown(raw_html: str, base_url: str = "") -> Dict[str, Any]:
    """
    Sanitize untrusted HTML (removing scripts, styles, comments, and hidden CSS prompt-injection blocks)
    and convert headings, code blocks, tables, lists, forms, and paragraphs into clean Markdown.
    """
    if not raw_html:
        return {"title": "", "meta_description": "", "markdown": "", "links": [], "forms": []}

    # Extract title and meta description before stripping head
    title_m = re.search(r"(?is)<title[^>]*>(.*?)</title>", raw_html)
    title_str = _strip_tags_clean(title_m.group(1)) if title_m else ""

    meta_desc = ""
    meta_m = re.search(
        r'(?is)<meta\b[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']',
        raw_html,
    ) or re.search(
        r'(?is)<meta\b[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']description["\']',
        raw_html,
    )
    if meta_m:
        meta_desc = _strip_tags_clean(meta_m.group(1))

    # Extract HTML forms before stripping
    forms_summary: List[str] = []
    for idx, f_match in enumerate(re.findall(r"(?is)<form\b[^>]*>.*?</form>", raw_html)[:6], 1):
        action_m = re.search(r'(?i)\baction=["\']?([^"\' >]+)', f_match)
        method_m = re.search(r'(?i)\bmethod=["\']?([^"\' >]+)', f_match)
        inputs = re.findall(r'(?i)<input\b[^>]*\bname=["\']?([^"\' >]+)', f_match)
        forms_summary.append(
            f"Form #{idx}: method={(method_m.group(1).upper() if method_m else 'GET')} "
            f"action={(action_m.group(1) if action_m else base_url)} inputs={inputs}"
        )

    # Extract useful links
    discovered_links: List[str] = []
    for href_m, anchor_m in re.findall(r'(?is)<a\b[^>]*href=["\']([^"\'#]+)["\'][^>]*>(.*?)</a>', raw_html):
        clean_href = html.unescape(href_m.strip())
        if clean_href.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        if base_url and clean_href.startswith("/"):
            clean_href = urllib.parse.urljoin(base_url, clean_href)
        anchor_txt = _strip_tags_clean(anchor_m)[:80]
        entry = f"{anchor_txt} ({clean_href})" if anchor_txt else clean_href
        if clean_href and entry not in discovered_links:
            discovered_links.append(entry)
        if len(discovered_links) >= 30:
            break

    # 1. Remove comments, scripts, styles, svg, canvas, iframe, noscript, header/footer/nav clutter
    cleaned = re.sub(r"(?is)<!--.*?-->", " ", raw_html)
    cleaned = re.sub(
        r"(?is)<(script|style|svg|noscript|iframe|object|embed|canvas|audio|video)\b.*?>.*?</\1>",
        " ",
        cleaned,
    )
    # 2. Anti-Prompt-Injection: strip elements with inline hidden styles or aria-hidden="true" or hidden attribute
    cleaned = re.sub(
        r'(?is)<([a-z0-9]+)\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\b|font-size\s*:\s*0|aria-hidden\s*=\s*["\']true["\']|\bhidden\b)[^>]*>.*?</\1>',
        " ",
        cleaned,
    )

    # 3. Convert structural HTML tags into Markdown equivalents
    for h_lvl in range(1, 5):
        cleaned = re.sub(
            rf"(?is)<h{h_lvl}\b[^>]*>(.*?)</h{h_lvl}>",
            lambda m, lvl=h_lvl: f"\n\n{'#' * lvl} {_strip_tags_clean(m.group(1))}\n\n",
            cleaned,
        )
    cleaned = re.sub(
        r"(?is)<pre\b[^>]*>(.*?)</pre>",
        lambda m: f"\n\n```text\n{_strip_tags_clean(m.group(1))}\n```\n\n",
        cleaned,
    )
    cleaned = re.sub(
        r"(?is)<code\b[^>]*>(.*?)</code>",
        lambda m: f"`{_strip_tags_clean(m.group(1))}`",
        cleaned,
    )
    cleaned = re.sub(
        r"(?is)<li\b[^>]*>(.*?)</li>",
        lambda m: f"\n- {_strip_tags_clean(m.group(1))}",
        cleaned,
    )
    cleaned = re.sub(r"(?is)</?(?:tr|p|div|section|article|blockquote|br|hr)\b[^>]*>", "\n", cleaned)
    cleaned = re.sub(r"(?is)</?(?:td|th)\b[^>]*>", " | ", cleaned)

    # Strip remaining tags
    cleaned = re.sub(r"(?s)<[^>]+>", " ", cleaned)
    cleaned = html.unescape(cleaned)

    # Normalize lines and collapse blank lines
    norm_lines: List[str] = []
    for ln in cleaned.splitlines():
        s = re.sub(r"[ \t]+", " ", ln).strip()
        if s and s != "|":
            norm_lines.append(s)

    markdown_body = "\n".join(norm_lines)
    return {
        "title": title_str,
        "meta_description": meta_desc,
        "markdown": markdown_body,
        "links": discovered_links,
        "forms": forms_summary,
    }


def _save_web_report_to_project(
    project_slug: str,
    slug_name: str,
    title: str,
    summary: str,
    report_body: str,
    tags: List[str],
    subdir: str = "notes",
) -> str:
    """Persist web search notes into `Projects/<project>/notes/` and fetched webpages/feeds into `Projects/<project>/downloads/`."""
    try:
        proj_dir = get_active_project_dir(project_slug)
        clean_sub = subdir if subdir in ("notes", "downloads", "artifacts", "assets", "targets") else "notes"
        out_dir = proj_dir / clean_sub
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_slug = slugify(slug_name)[:64] or "web_intel"
        note_path = out_dir / f"{safe_slug}.md"
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        frontmatter = (
            "---\n"
            f"title: {title}\n"
            f"category: {clean_sub}\n"
            f"project: {proj_dir.name}\n"
            f"summary: {summary}\n"
            f"tags: [{', '.join(tags)}]\n"
            f"updated: {now_str}\n"
            "---\n"
        )
        full_md = (
            frontmatter
            + f"# {title}\n\n"
            + f"> **Summary:** {summary}  \n"
            + f"> **Project Workspace:** `Projects/{proj_dir.name}/{clean_sub}/` | **Updated:** `{now_str}`\n\n"
            + report_body.strip()
            + "\n"
        )
        note_path.write_text(full_md, encoding="utf-8", errors="replace")
        update_project_memory_index(proj_dir, f"{clean_sub}/{safe_slug}", summary, tags)
        return f"Projects/{proj_dir.name}/{clean_sub}/{safe_slug}.md"
    except Exception:
        return ""


def execute_tier1_web_search(
    query: str,
    site: str = "",
    max_results: int = 8,
    mode_info: Optional[Dict[str, Any]] = None,
    posture: Optional[Dict[str, Any]] = None,
    project_slug: str = "",
    cancel_check_fn: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """
    Tier-1 Pure-Python Online Web Search (`web_search`):
      1. Enforces RED/BLUE/WHITE Network Isolation + Engine 12 CEGAR verification.
      2. Supports domain/website scoping via `site` (e.g. `site="fortinet.com"` or `site:nvd.nist.gov`).
      3. Queries DuckDuckGo HTML (`html.duckduckgo.com/html/`) + Lite fallback without JavaScript.
      4. Automatically enriches CVE queries via the official NIST NVD REST API v2.0 JSON endpoint.
      5. Archives results to `Projects/<project>/targets/` and extracts Engine 13 SyGuS facts.
    """
    if cancel_check_fn and cancel_check_fn():
        return {"executed": False, "blocked": True, "cancelled": True, "reason": "Execution cancelled by operator."}

    raw_q = (query or "").strip()
    raw_site = (site or "").strip()
    if not raw_q and not raw_site:
        return {"executed": False, "blocked": True, "exit_code": 1, "reason": "Empty search query."}

    # Normalize `site` parameter if user passed a full URL (e.g. "https://docs.fortinet.com/...")
    site_domain = ""
    if raw_site:
        clean_s = re.sub(r"^https?://", "", raw_site, flags=re.I).strip("/")
        site_domain = clean_s

    effective_query = raw_q
    if site_domain and f"site:{site_domain.lower()}" not in raw_q.lower():
        effective_query = f"site:{site_domain} {raw_q}".strip()

    block_reason = _check_network_isolation_for_host("html.duckduckgo.com", mode_info=mode_info, posture=posture)
    if block_reason:
        return {
            "executed": False,
            "blocked": True,
            "exit_code": 126,
            "command": f"web_search({effective_query})",
            "reason": block_reason,
            "output": f"BLOCKED: {block_reason}",
        }

    t0 = time.perf_counter()
    max_res = max(1, min(int(max_results or 8), 15))
    results: List[Dict[str, str]] = []

    # 1. Primary Query: DuckDuckGo HTML Endpoint (POST)
    post_body = urllib.parse.urlencode({"q": effective_query, "kl": "us-en"}).encode("utf-8")
    ddg_resp = _http_fetch_raw(
        "https://html.duckduckgo.com/html/",
        method="POST",
        post_data=post_body,
        extra_headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://html.duckduckgo.com/",
        },
        timeout=10.0,
    )

    if ddg_resp.get("text"):
        html_text = ddg_resp["text"]
        # Split on top-level `<div ... class="... result ...">` containers so nested `result__extras` divs
        # never truncate the block before `<a class="result__snippet">` is reached.
        raw_blocks = re.split(r'(?i)(?=<div\b[^>]*class="[^"]*\bresult\b(?![_a-z0-9\-]))', html_text)
        for blk in raw_blocks:
            m_a = re.search(r'(?is)<a\b[^>]*class="[^"]*\bresult__a\b[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', blk)
            if not m_a:
                continue
            url_clean = _unwrap_ddg_url(m_a.group(1))
            if not url_clean or "duckduckgo.com/y.js" in url_clean:
                continue
            title_clean = _strip_tags_clean(m_a.group(2))
            if not title_clean:
                continue
            m_s = re.search(r'(?is)<(?:a|div)\b[^>]*class="[^"]*\bresult__snippet\b[^"]*"[^>]*>(.*?)</(?:a|div)>', blk)
            snip_clean = _strip_tags_clean(m_s.group(1)) if m_s else ""
            results.append({"title": title_clean, "url": url_clean, "snippet": snip_clean})
            if len(results) >= max_res:
                break

        if not results:
            # Fallback paired regex on result__a + result__snippet
            links = re.findall(r'(?is)<a\b[^>]*class="[^"]*\bresult__a\b[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', html_text)
            snips = re.findall(r'(?is)class="[^"]*\bresult__snippet\b[^"]*"[^>]*>(.*?)</(?:a|div)>', html_text)
            for idx, (href, t_html) in enumerate(links[:max_res]):
                url_clean = _unwrap_ddg_url(href)
                title_clean = _strip_tags_clean(t_html)
                snip_clean = _strip_tags_clean(snips[idx]) if idx < len(snips) else ""
                if url_clean and title_clean and "duckduckgo.com/y.js" not in url_clean:
                    results.append({"title": title_clean, "url": url_clean, "snippet": snip_clean})

    # 2. Secondary Fallback: DuckDuckGo Instant Answer JSON API if HTML returned 0 results
    if not results:
        ia_url = "https://api.duckduckgo.com/?" + urllib.parse.urlencode(
            {"q": effective_query, "format": "json", "no_html": "1", "skip_disambig": "1"}
        )
        ia_resp = _http_fetch_raw(ia_url, method="GET", timeout=8.0)
        if ia_resp.get("text"):
            try:
                ia_json = json.loads(ia_resp["text"])
                if ia_json.get("AbstractText"):
                    results.append(
                        {
                            "title": str(ia_json.get("Heading") or effective_query),
                            "url": str(ia_json.get("AbstractURL") or "https://duckduckgo.com"),
                            "snippet": str(ia_json.get("AbstractText")),
                        }
                    )
                for topic in (ia_json.get("RelatedTopics") or [])[:max_res]:
                    if isinstance(topic, dict) and topic.get("Text") and topic.get("FirstURL"):
                        results.append(
                            {
                                "title": str(topic.get("Text"))[:90],
                                "url": str(topic.get("FirstURL")),
                                "snippet": str(topic.get("Text")),
                            }
                        )
            except Exception:
                pass

    # 3. Direct NIST NVD CVE API v2.0 + Local ~/Projects/CVEs/ Enrichment:
    #    a) Collect any explicit CVE IDs from BOTH the query string AND the top web search results (titles/URLs/snippets).
    #    b) If the query is searching for CVEs/vulnerabilities/exploits of a product/version (e.g. "FortiOS 6.2", "FortiOS 6.2.1"),
    #       also run exact CPE 2.3 version-range matching against `~/Projects/CVEs/nvd_cves.sqlite`!
    ordered_cve_ids: List[str] = []
    for cid in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", effective_query, flags=re.I):
        cu = cid.upper()
        if cu not in ordered_cve_ids:
            ordered_cve_ids.append(cu)
    for r_item in results:
        blob_r = f"{r_item.get('title', '')} {r_item.get('url', '')} {r_item.get('snippet', '')}"
        for cid in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", blob_r, flags=re.I):
            cu = cid.upper()
            if cu not in ordered_cve_ids:
                ordered_cve_ids.append(cu)

    cve_details: List[str] = []
    enriched_ids: set = set()
    for cve_upper in ordered_cve_ids[:4]:
        if cancel_check_fn and cancel_check_fn():
            break
        cve_obj = _lookup_local_nvd_cve(cve_upper)
        cve_src = f"Local NVD 2.0 Feed ({_LOCAL_CVE_DIR})"
        if not cve_obj:
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_upper}"
            nvd_resp = _http_fetch_raw(nvd_url, method="GET", timeout=10.0)
            if nvd_resp.get("ok") and nvd_resp.get("text"):
                try:
                    nvd_data = json.loads(nvd_resp["text"])
                    vulns = nvd_data.get("vulnerabilities") or []
                    if vulns:
                        cve_obj = (vulns[0] or {}).get("cve") or {}
                        cve_src = "Live NIST NVD 2.0 API"
                except Exception:
                    pass
        if cve_obj:
            enriched_ids.add(cve_upper)
            cve_details.append(_format_nvd_cve_20_record(cve_obj, source_label=cve_src))

    # 4. Product + Version-Range NVD 2.0 Lookup (solves point-version searches like `FortiOS 6.2.1` or `FortiOS 6.0.6`
    #    where search engines return 0 results because NVD advisories write `6.2.0 through 6.2.15`).
    is_vuln_intent = bool(
        re.search(
            r"\b(cve|cves|vuln|vulnerabilit\w*|exploit\w*|nvd|nist|opencve|kev|rce|advisor\w*|\d+\.\d+(?:\.\d+)*)\b",
            effective_query,
            flags=re.I,
        )
    )
    if is_vuln_intent:
        prod_ver_cves = _search_local_nvd_by_product_version(effective_query, max_items=6)
        for c_obj in prod_ver_cves:
            cid = str(c_obj.get("id") or "").upper()
            if not cid or cid in enriched_ids:
                continue
            enriched_ids.add(cid)
            match_note = c_obj.get("_matched_version_range")
            src_lbl = f"Local NVD 2.0 CPE Range Match ({match_note})" if match_note else f"Local NVD 2.0 Feed ({_LOCAL_CVE_DIR})"
            if len(cve_details) < 5:
                cve_details.append(_format_nvd_cve_20_record(c_obj, source_label=src_lbl))
            # If DuckDuckGo returned 0 web results (e.g., `site:nvd.nist.gov FortiOS 6.2.1`), populate `results` from local NVD 2.0!
            if len(results) < max_res:
                descs = c_obj.get("descriptions") or []
                en_d = next((str(d.get("value", "")) for d in descs if d.get("lang") == "en" and d.get("value")), "")
                kev_badge = "[CISA KEV] " if c_obj.get("cisaExploitAdd") else ""
                results.append(
                    {
                        "title": f"{kev_badge}{cid} — NVD 2.0 Vulnerability Record ({match_note or 'Matched Product'})",
                        "url": f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cid}",
                        "snippet": en_d[:280],
                    }
                )

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
    report_lines = [
        f"=== Tier-1 Pure-Python Web Search Results ===",
        f"- **Query:** `{effective_query}`",
        f"- **Results Returned:** `{len(results)}` (fetched in `{elapsed_ms} ms`, `0 MB` GPU VRAM, JS disabled)",
    ]

    if cve_details:
        report_lines.append("\n### Authoritative NIST NVD CVE Telemetry:")
        report_lines.extend(cve_details)

    if results:
        report_lines.append("\n### Top Web Results:")
        for idx, item in enumerate(results, 1):
            report_lines.append(
                f"{idx}. **{item['title']}**\n"
                f"   - URL: `{item['url']}`\n"
                f"   - Snippet: {item['snippet'] or '(no snippet)'}"
            )
        report_lines.append(
            "\n*(Tip: Call `fetch_webpage` on any URL above to read its full Markdown content, tables, or code blocks.)*"
        )
    else:
        report_lines.append(
            f"\nNo search results returned for `{effective_query}`. Try broadening your search terms or calling `fetch_webpage` directly on a known URL."
        )

    full_out = "\n".join(report_lines)
    saved_path = _save_web_report_to_project(
        project_slug=project_slug,
        slug_name=f"search_{slugify(effective_query)[:40]}",
        title=f"Web Search: {effective_query[:60]}",
        summary=f"Tier-1 Web Search for '{effective_query[:60]}' ({len(results)} results in {elapsed_ms} ms)",
        report_body=full_out,
        tags=["web-search", "tier1", "osint"],
    )
    if saved_path:
        full_out += f"\n\n[Saved to Project Workspace]: `{saved_path}`"

    sygus_facts = extract_structured_facts(f"web_search {effective_query}", full_out)
    try:
        record_command_event(f"web_search {effective_query}", full_out, 0 if results else 1)
    except Exception:
        pass

    return {
        "executed": True,
        "blocked": False,
        "exit_code": 0 if results or cve_details else 1,
        "command": f"web_search({effective_query})",
        "output": full_out,
        "results": results,
        "latency_ms": elapsed_ms,
        "sygus_facts": sygus_facts,
        "saved_note": saved_path,
    }


def execute_tier1_fetch_webpage(
    url: str,
    query_filter: str = "",
    max_chars: int = 7500,
    mode_info: Optional[Dict[str, Any]] = None,
    posture: Optional[Dict[str, Any]] = None,
    project_slug: str = "",
    cancel_check_fn: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """
    Tier-1 Pure-Python Webpage & API Reader (`fetch_webpage`):
      1. Preserves full URL path, query parameters (`?q=...`), and endpoints.
      2. Enforces RED/BLUE/WHITE Network Isolation + Engine 12 CEGAR verification.
      3. Strips `<script>`, `<style>`, `<iframe>`, comments, and hidden CSS prompt-injection blocks.
      4. Converts HTML headings, tables, code blocks, forms, or JSON payloads into clean Markdown.
      5. If `query_filter` is specified, highlights matching sections/lines at the top of the output.
      6. Saves the full extracted Markdown into `Projects/<project>/targets/`.
    """
    if cancel_check_fn and cancel_check_fn():
        return {"executed": False, "blocked": True, "cancelled": True, "reason": "Execution cancelled by operator."}

    raw_url = (url or "").strip()
    if not raw_url:
        return {"executed": False, "blocked": True, "exit_code": 1, "reason": "Empty URL."}

    if not re.match(r"^https?://", raw_url, flags=re.I):
        raw_url = "https://" + raw_url

    parsed = urllib.parse.urlsplit(raw_url)
    host_only = (parsed.hostname or "").strip()
    if not host_only:
        return {"executed": False, "blocked": True, "exit_code": 1, "reason": f"Invalid URL host: {raw_url}"}

    # Smart NVD 2.0 Angular SPA Interception:
    # 1. `https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNN` is an empty Angular shell (`<app-root>`);
    #    automatically rewrite to the official NVD 2.0 JSON API (`services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`)
    #    with instant fallback to the local `~/Projects/CVEs/` repository.
    m_nvd_detail = re.search(r"nvd\.nist\.gov/vuln/detail/(CVE-\d{4}-\d{4,7})", raw_url, flags=re.I)
    if m_nvd_detail:
        cve_target = m_nvd_detail.group(1).upper()
        raw_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_target}"
        parsed = urllib.parse.urlsplit(raw_url)
        host_only = parsed.hostname or host_only

    # 2. `https://nvd.nist.gov/vuln/data-feeds` is an Angular SPA whose table is built from
    #    `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<YEAR>.meta|json.gz|json.zip`.
    if "nvd.nist.gov/vuln/data-feeds" in raw_url.lower():
        manifest_path = _LOCAL_CVE_DIR / "manifest.json"
        feed_lines = [
            "=== NIST NVD 2.0 Vulnerability Data Feeds (`https://nvd.nist.gov/vuln/data-feeds`) ===",
            f"- **Official NVD 2.0 Feed Base URL:** `https://nvd.nist.gov/feeds/json/cve/2.0/`",
            f"- **Official NVD 2.0 REST API Endpoint:** `https://services.nvd.nist.gov/rest/json/cves/2.0`",
            f"- **Best System Format:** **NVD JSON 2.0 Schema** (`nvdcve-2.0-<YEAR>.json.gz` + `.meta` SHA-256 -> extracted `.json` & `nvd_cves.sqlite`)",
            f"- **Local Offline Mirror Directory:** `{_LOCAL_CVE_DIR}` (`query_cve.py` & `sync_nvd_feeds.py`)",
        ]
        if manifest_path.is_file():
            try:
                man = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
                feed_lines.append(
                    f"- **Local Repository Status:** Synced `{man.get('total_unique_cves', 0):,}` unique CVEs across `{len(man.get('feeds', []))}` feeds (`{man.get('updated_at', '')}`)"
                )
                feed_lines.append("\n### Downloaded NVD 2.0 Yearly & Incremental Feeds (`~/Projects/CVEs/`):")
                feed_lines.append("| Feed Name | Local JSON Path | Uncompressed Size | NIST `.json.gz` URL | Verified SHA-256 |")
                feed_lines.append("| :--- | :--- | :--- | :--- | :--- |")
                for f_entry in man.get("feeds") or []:
                    fn = f_entry.get("feed", "")
                    gz_u = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{fn}.json.gz"
                    feed_lines.append(
                        f"| **`nvdcve-2.0-{fn}`** | `{f_entry.get('json_path', '')}` | `{f_entry.get('size_mb', 0)} MB` | `{gz_u}` | `{str(f_entry.get('sha256', ''))[:20]}...` |"
                    )
            except Exception:
                pass
        out_txt = "\n".join(feed_lines)
        return {
            "executed": True,
            "blocked": False,
            "exit_code": 0,
            "command": f"fetch_webpage({url})",
            "output": out_txt,
            "latency_ms": 1.0,
            "sygus_facts": extract_structured_facts(f"fetch_webpage {url}", out_txt),
            "saved_note": "",
        }

    # Check if this is a single-CVE NVD 2.0 or OpenCVE request that can be served or enriched from local `~/Projects/CVEs/`
    m_nvd_api_cve = re.search(r"services\.nvd\.nist\.gov/rest/json/cves/2\.0\?[^#]*cveId=(CVE-\d{4}-\d{4,7})", raw_url, flags=re.I)
    if not m_nvd_api_cve:
        m_nvd_api_cve = re.search(r"opencve\.io/(?:api/v2/cves|cve)/(CVE-\d{4}-\d{4,7})", raw_url, flags=re.I)
    local_cve_fallback = _lookup_local_nvd_cve(m_nvd_api_cve.group(1)) if m_nvd_api_cve else None

    # 3. Smart OpenCVE (`app.opencve.io`) Interception:
    #    - `https://app.opencve.io/api/v2/docs/` is a JavaScript Swagger UI wrapper; rewrite to the OpenAPI schema or summarize endpoints.
    #    - `https://app.opencve.io/api/v2/cves...` requires `Authorization: Bearer <OPENCVE_API_TOKEN>`; if no token is set,
    #      automatically rewrite to OpenCVE's server-rendered public web endpoint (`https://app.opencve.io/cve/...`) which needs NO token and NO JS!
    if "app.opencve.io/api/v2/docs" in raw_url.lower():
        opencve_doc_lines = [
            "=== OpenCVE API v2 Documentation & Endpoint Guide (`https://app.opencve.io/api/v2/docs/`) ===",
            "- **Data Sources:** Synchronized with **NIST NVD API 2.0**, **MITRE CVE 5.0 (`cvelistV5`)**, **CISA KEV**, and **FIRST EPSS**.",
            "- **REST API v2 Authentication (`https://app.opencve.io/api/v2/*`):** Requires an Organization API Token (`Authorization: Bearer <OPENCVE_API_TOKEN>` or HTTP Basic Auth) — unauthenticated requests return `HTTP 401 Unauthorized`.",
            "- **Zero-Auth Public HTML Endpoints (`https://app.opencve.io/cve/`):** Server-side rendered HTML (NO API key and NO JavaScript required):",
            "  - Search by Keyword/Version: `https://app.opencve.io/cve/?search=FortiOS+6.2`",
            "  - Filter by Vendor & Product: `https://app.opencve.io/cve/?vendor=fortinet&product=fortios`",
            "  - Filter by CWE or Tag: `https://app.opencve.io/cve/?cwe=CWE-787`",
            "  - Single CVE Detail Page: `https://app.opencve.io/cve/CVE-2024-21762`",
            "- **Authenticated REST API v2 Endpoints (when `OPENCVE_API_TOKEN` is set in `.env`):**",
            "  - `GET https://app.opencve.io/api/v2/cves?search=<keyword>&vendor=<vendor>&product=<product>&cvss=<low|medium|high|critical>`",
            "  - `GET https://app.opencve.io/api/v2/cves/<CVE-ID>`",
            "  - `GET https://app.opencve.io/api/v2/vendors` | `GET https://app.opencve.io/api/v2/vendors/<vendor>/products`",
            "  - `GET https://app.opencve.io/api/v2/cwes` | `GET https://app.opencve.io/api/v2/kb/`",
            f"- **CORA Local Zero-Latency Alternative (`{_LOCAL_CVE_DIR}`):** All `417,614` NVD 2.0 CVEs + `958,619` CPE product/version mappings are indexed locally in `{_LOCAL_CVE_SQLITE}` (`python3 ~/Projects/CVEs/query_cve.py`).",
        ]
        out_oc = "\n".join(opencve_doc_lines)
        return {
            "executed": True,
            "blocked": False,
            "exit_code": 0,
            "command": f"fetch_webpage({url})",
            "output": out_oc,
            "latency_ms": 1.0,
            "sygus_facts": extract_structured_facts(f"fetch_webpage {url}", out_oc),
            "saved_note": "",
        }

    if "app.opencve.io/api/v2/cves" in raw_url.lower() and not os.environ.get("OPENCVE_API_TOKEN", "").strip():
        # Rewrite unauthenticated `/api/v2/cves` requests to the public server-rendered `/cve/` HTML interface
        raw_url = re.sub(r"(?i)app\.opencve\.io/api/v2/cves/?", "app.opencve.io/cve/", raw_url)
        parsed = urllib.parse.urlsplit(raw_url)
        host_only = parsed.hostname or host_only

    block_reason = _check_network_isolation_for_host(host_only, mode_info=mode_info, posture=posture)
    if block_reason:
        if local_cve_fallback:
            md_cve = _format_nvd_cve_20_record(
                local_cve_fallback,
                source_label=f"Local Offline NVD 2.0 Repository ({_LOCAL_CVE_DIR})",
            )
            return {
                "executed": True,
                "blocked": False,
                "exit_code": 0,
                "command": f"fetch_webpage({raw_url})",
                "output": f"=== Offline NVD 2.0 CVE Lookup (Served from `{_LOCAL_CVE_DIR}`) ===\n\n{md_cve}",
                "latency_ms": 1.2,
                "sygus_facts": extract_structured_facts(f"fetch_webpage {raw_url}", md_cve),
                "saved_note": "",
            }
        return {
            "executed": False,
            "blocked": True,
            "exit_code": 126,
            "command": f"fetch_webpage({raw_url})",
            "reason": block_reason,
            "output": f"BLOCKED: {block_reason}",
        }

    resp = _http_fetch_raw(raw_url, method="GET", timeout=15.0)
    # If HTTPS failed on a local/custom port or host, try HTTP fallback automatically
    if not resp.get("ok") and raw_url.startswith("https://") and resp.get("status_code") == 0:
        http_fallback_url = "http://" + raw_url[len("https://") :]
        resp_http = _http_fetch_raw(http_fallback_url, method="GET", timeout=10.0)
        if resp_http.get("ok") or resp_http.get("text"):
            resp = resp_http
            raw_url = http_fallback_url

    if (not resp.get("ok") or resp.get("status_code", 200) >= 400) and local_cve_fallback:
        md_cve = _format_nvd_cve_20_record(
            local_cve_fallback,
            source_label=f"Local NVD 2.0 Repository Fallback ({_LOCAL_CVE_DIR})",
        )
        return {
            "executed": True,
            "blocked": False,
            "exit_code": 0,
            "command": f"fetch_webpage({raw_url})",
            "output": f"=== NVD 2.0 CVE Record (Served from `{_LOCAL_CVE_DIR}`) ===\n\n{md_cve}",
            "latency_ms": resp.get("latency_ms", 1.5),
            "sygus_facts": extract_structured_facts(f"fetch_webpage {raw_url}", md_cve),
            "saved_note": "",
        }

    if not resp.get("ok") and not resp.get("text"):
        err_msg = f"Failed to fetch `{raw_url}`: {resp.get('error') or 'No response'}"
        return {
            "executed": False,
            "blocked": False,
            "exit_code": 1,
            "command": f"fetch_webpage({raw_url})",
            "output": err_msg,
            "latency_ms": resp.get("latency_ms", 0.0),
        }

    status_code = resp.get("status_code", 200)
    final_url = resp.get("final_url", raw_url)
    c_type = (resp.get("content_type") or "").lower()
    raw_text = resp.get("text") or ""
    hdrs = resp.get("headers") or {}

    key_hdrs = []
    for hk in ("Server", "Content-Type", "Last-Modified", "ETag", "X-Powered-By", "WWW-Authenticate"):
        for actual_k, actual_v in hdrs.items():
            if actual_k.lower() == hk.lower():
                key_hdrs.append(f"{hk}: {actual_v}")
                break

    report_lines = [
        f"=== Tier-1 Webpage & Endpoint Extraction ===",
        f"- **Requested URL:** `{raw_url}`",
        f"- **Final URL:** `{final_url}` (HTTP `{status_code}`, `{resp.get('latency_ms', 0.0)} ms`, `{resp.get('raw_len', 0)}` bytes)",
    ]
    if key_hdrs:
        report_lines.append(f"- **Response Headers:** `{' | '.join(key_hdrs)}`")

    # Handle JSON endpoints directly (with NVD 2.0 structured extraction & `query_filter` support)
    stripped_body = raw_text.strip()
    if "application/json" in c_type or stripped_body.startswith(("{", "[")):
        try:
            parsed_json = json.loads(stripped_body)
            # 1. If this is an NVD 2.0 CVE JSON payload (`format == "NVD_CVE"`), render full structured CVE breakdown
            if isinstance(parsed_json, dict) and parsed_json.get("format") == "NVD_CVE" and isinstance(parsed_json.get("vulnerabilities"), list):
                vulns_list = parsed_json.get("vulnerabilities") or []
                report_lines.append(
                    f"- **NVD 2.0 Query Summary:** `totalResults={parsed_json.get('totalResults', len(vulns_list))}` | "
                    f"`startIndex={parsed_json.get('startIndex', 0)}` | `resultsPerPage={parsed_json.get('resultsPerPage', len(vulns_list))}`"
                )
                for v_item in vulns_list[:8]:
                    c_obj = (v_item or {}).get("cve") or {}
                    if c_obj:
                        report_lines.append("\n" + _format_nvd_cve_20_record(c_obj, source_label="Live NIST NVD 2.0 REST API"))
                if len(vulns_list) > 8:
                    report_lines.append(f"\n*(... +{len(vulns_list) - 8} additional CVEs in response)*")
            # 2. If `query_filter` was passed to a JSON endpoint (e.g. CISA KEV, LOLBAS, LOLDrivers), filter matching records first!
            filtered_obj = _filter_json_payload(parsed_json, query_filter) if query_filter else None
            if filtered_obj is not None:
                filt_pretty = json.dumps(filtered_obj, indent=2)
                report_lines.append(
                    f"\n### Filtered JSON Matches for `{query_filter}` (`{len(filt_pretty)}` chars):\n```json\n{filt_pretty[:max_chars]}\n```"
                )
            else:
                pretty_json = json.dumps(parsed_json, indent=2)
                report_lines.append(f"\n### JSON Payload (`{len(pretty_json)}` chars):\n```json\n{pretty_json[:max_chars]}\n```")
            full_report = "\n".join(report_lines)
            page_slug = f"page_{slugify(host_only)}_{slugify(parsed.path or 'index')[:30]}"
            try:
                proj_dir_dl = get_active_project_dir(project_slug) / "downloads"
                proj_dir_dl.mkdir(parents=True, exist_ok=True)
                (proj_dir_dl / f"{page_slug}.json").write_text(
                    json.dumps(parsed_json, indent=2), encoding="utf-8", errors="replace"
                )
            except Exception:
                pass
            saved_p = _save_web_report_to_project(
                project_slug=project_slug,
                slug_name=page_slug,
                title=f"JSON Endpoint: {final_url[:65]}",
                summary=f"Fetched JSON from {final_url} (HTTP {status_code})",
                report_body=full_report,
                tags=["webpage", "json", "tier1", slugify(host_only)],
                subdir="downloads",
            )
            if saved_p:
                full_report += f"\n\n[Saved to Project Workspace]: `{saved_p}`"
            sygus_facts = extract_structured_facts(f"fetch_webpage {final_url}", full_report)
            return {
                "executed": True,
                "blocked": False,
                "exit_code": 0,
                "command": f"fetch_webpage({raw_url})",
                "output": full_report,
                "latency_ms": resp.get("latency_ms", 0.0),
                "sygus_facts": sygus_facts,
                "saved_note": saved_p,
            }
        except Exception:
            pass

    parsed_doc = _sanitize_and_convert_html_to_markdown(raw_text, base_url=final_url)
    if parsed_doc["title"]:
        report_lines.append(f"- **Page Title:** {parsed_doc['title']}")
    if parsed_doc["meta_description"]:
        report_lines.append(f"- **Meta Description:** {parsed_doc['meta_description']}")
    if parsed_doc["forms"]:
        report_lines.append("\n### Discovered HTML Forms & Query Inputs:")
        for fm in parsed_doc["forms"]:
            report_lines.append(f"- `{fm}`")

    md_body = parsed_doc["markdown"]

    # If `query_filter` was provided, extract matching lines/sections with context at the top
    q_filt = (query_filter or "").strip()
    if q_filt and md_body:
        tokens = [t.lower() for t in re.split(r"\s+", q_filt) if len(t) >= 2]
        md_lines = md_body.splitlines()
        matched_snippets: List[str] = []
        seen_idx = set()
        for i, ln in enumerate(md_lines):
            ln_low = ln.lower()
            if q_filt.lower() in ln_low or (tokens and all(tok in ln_low for tok in tokens)):
                start_i = max(0, i - 1)
                end_i = min(len(md_lines), i + 3)
                if i not in seen_idx:
                    for k in range(start_i, end_i):
                        seen_idx.add(k)
                    snippet_blk = "\n".join(md_lines[start_i:end_i]).strip()
                    if snippet_blk:
                        matched_snippets.append(snippet_blk)
                if len(matched_snippets) >= 12:
                    break
        if matched_snippets:
            report_lines.append(f"\n### Filtered Matches for `{q_filt}` ({len(matched_snippets)} sections):")
            for idx, ms in enumerate(matched_snippets, 1):
                report_lines.append(f"**[{idx}]** {ms}\n")
        else:
            report_lines.append(f"\n*(No exact matches for filter `{q_filt}` on page; showing full page content below.)*")

    if md_body:
        if len(md_body) > max_chars:
            half = max_chars // 2
            trimmed_md = (
                md_body[: half + 800]
                + f"\n\n... [{len(md_body) - max_chars} middle chars archived in project downloads note; head+tail preserved] ...\n\n"
                + md_body[-(half - 800) :]
            )
        else:
            trimmed_md = md_body
        report_lines.append(f"\n### Extracted Page Content (Clean Markdown):\n{trimmed_md}")
    else:
        report_lines.append(
            "\n*(Page returned minimal static text — it may require authentication or dynamic client parameters.)*"
        )

    if parsed_doc["links"]:
        report_lines.append("\n### Discovered Page Links (up to 15):")
        for lnk in parsed_doc["links"][:15]:
            report_lines.append(f"- {lnk}")

    # Save full un-truncated report to `Projects/<project>/downloads/`
    full_untruncated_report = "\n".join(report_lines[:6]) + f"\n\n### Full Extracted Page Content:\n{md_body}\n"
    saved_p = _save_web_report_to_project(
        project_slug=project_slug,
        slug_name=f"page_{slugify(host_only)}_{slugify(parsed.path or 'index')[:30]}",
        title=parsed_doc["title"][:70] or f"Webpage: {final_url[:65]}",
        summary=f"Fetched {final_url} (HTTP {status_code}, {len(md_body)} chars clean Markdown)",
        report_body=full_untruncated_report,
        tags=["webpage", "tier1", slugify(host_only)],
        subdir="downloads",
    )

    llm_digest = "\n".join(report_lines)
    if saved_p:
        llm_digest += f"\n\n[Full Un-Truncated Page Saved to Project Workspace]: `{saved_p}`"

    sygus_facts = extract_structured_facts(f"fetch_webpage {final_url}", llm_digest)
    try:
        record_command_event(f"fetch_webpage {final_url}", llm_digest, 0)
    except Exception:
        pass

    return {
        "executed": True,
        "blocked": False,
        "exit_code": 0,
        "command": f"fetch_webpage({raw_url})",
        "output": llm_digest,
        "latency_ms": resp.get("latency_ms", 0.0),
        "sygus_facts": sygus_facts,
        "saved_note": saved_p,
    }
