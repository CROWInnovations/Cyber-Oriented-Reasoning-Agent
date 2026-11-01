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
    timeout: float = 12.0,
    max_bytes: int = 350_000,
) -> Dict[str, Any]:
    """Perform a pure-Python HTTP/HTTPS request with TLS fallback and safe byte capping."""
    headers = {
        "User-Agent": _DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }
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
) -> str:
    """Persist web search or webpage report into `Projects/<project>/targets/` and update `memory.md`."""
    try:
        proj_dir = get_active_project_dir(project_slug)
        targets_dir = proj_dir / "targets"
        targets_dir.mkdir(parents=True, exist_ok=True)
        safe_slug = slugify(slug_name)[:64] or "web_intel"
        note_path = targets_dir / f"{safe_slug}.md"
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        frontmatter = (
            "---\n"
            f"title: {title}\n"
            "category: targets\n"
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
            + f"> **Project Workspace:** `Projects/{proj_dir.name}/` | **Updated:** `{now_str}`\n\n"
            + report_body.strip()
            + "\n"
        )
        note_path.write_text(full_md, encoding="utf-8", errors="replace")
        update_project_memory_index(proj_dir, f"targets/{safe_slug}", summary, tags)
        return f"Projects/{proj_dir.name}/targets/{safe_slug}.md"
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
        blocks = re.findall(
            r'(?is)<div\b[^>]*class="[^"]*\bresult\b[^"]*"[^>]*>(.*?)</div>\s*</div>',
            html_text,
        )
        if not blocks:
            # Fallback regex on result__a + result__snippet
            links = re.findall(r'(?is)<a\b[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', html_text)
            snips = re.findall(r'(?is)class="result__snippet"[^>]*>(.*?)</(?:a|div)>', html_text)
            for idx, (href, t_html) in enumerate(links[:max_res]):
                url_clean = _unwrap_ddg_url(href)
                title_clean = _strip_tags_clean(t_html)
                snip_clean = _strip_tags_clean(snips[idx]) if idx < len(snips) else ""
                if url_clean and title_clean and not url_clean.startswith("https://duckduckgo.com/y.js"):
                    results.append({"title": title_clean, "url": url_clean, "snippet": snip_clean})
        else:
            for blk in blocks:
                m_a = re.search(r'(?is)<a\b[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', blk)
                if not m_a:
                    continue
                url_clean = _unwrap_ddg_url(m_a.group(1))
                if not url_clean or "duckduckgo.com/y.js" in url_clean:
                    continue
                title_clean = _strip_tags_clean(m_a.group(2))
                m_s = re.search(r'(?is)class="result__snippet"[^>]*>(.*?)</(?:a|div)>', blk)
                snip_clean = _strip_tags_clean(m_s.group(1)) if m_s else ""
                results.append({"title": title_clean, "url": url_clean, "snippet": snip_clean})
                if len(results) >= max_res:
                    break

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

    # 3. Direct NIST NVD CVE API v2.0 Enrichment when a CVE ID is present in the query
    cve_matches = sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", effective_query, flags=re.I)))
    cve_details: List[str] = []
    for cve_id in cve_matches[:2]:
        if cancel_check_fn and cancel_check_fn():
            break
        cve_upper = cve_id.upper()
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_upper}"
        nvd_resp = _http_fetch_raw(nvd_url, method="GET", timeout=8.0)
        if nvd_resp.get("ok") and nvd_resp.get("text"):
            try:
                nvd_data = json.loads(nvd_resp["text"])
                vulns = nvd_data.get("vulnerabilities") or []
                if vulns:
                    cve_obj = (vulns[0] or {}).get("cve") or {}
                    descs = cve_obj.get("descriptions") or []
                    en_desc = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
                    metrics = cve_obj.get("metrics") or {}
                    cvss_str = "N/A"
                    for m_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
                        m_list = metrics.get(m_key) or []
                        if m_list:
                            cv_data = (m_list[0] or {}).get("cvssData") or {}
                            cvss_str = f"{cv_data.get('baseScore', 'N/A')} ({cv_data.get('baseSeverity', 'UNKNOWN')} | {cv_data.get('vectorString', '')})"
                            break
                    cve_details.append(
                        f"- **{cve_upper}** (CVSS: `{cvss_str}`): {en_desc[:600]} "
                        f"([NVD Detail](https://nvd.nist.gov/vuln/detail/{cve_upper}))"
                    )
            except Exception:
                pass

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

    block_reason = _check_network_isolation_for_host(host_only, mode_info=mode_info, posture=posture)
    if block_reason:
        return {
            "executed": False,
            "blocked": True,
            "exit_code": 126,
            "command": f"fetch_webpage({raw_url})",
            "reason": block_reason,
            "output": f"BLOCKED: {block_reason}",
        }

    resp = _http_fetch_raw(raw_url, method="GET", timeout=14.0)
    # If HTTPS failed on a local/custom port or host, try HTTP fallback automatically
    if not resp.get("ok") and raw_url.startswith("https://") and resp.get("status_code") == 0:
        http_fallback_url = "http://" + raw_url[len("https://") :]
        resp_http = _http_fetch_raw(http_fallback_url, method="GET", timeout=10.0)
        if resp_http.get("ok") or resp_http.get("text"):
            resp = resp_http
            raw_url = http_fallback_url

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

    # Handle JSON endpoints directly
    stripped_body = raw_text.strip()
    if "application/json" in c_type or stripped_body.startswith(("{", "[")):
        try:
            parsed_json = json.loads(stripped_body)
            pretty_json = json.dumps(parsed_json, indent=2)
            report_lines.append(f"\n### JSON Payload (`{len(pretty_json)}` chars):\n```json\n{pretty_json[:max_chars]}\n```")
            full_report = "\n".join(report_lines)
            saved_p = _save_web_report_to_project(
                project_slug=project_slug,
                slug_name=f"page_{slugify(host_only)}_{slugify(parsed.path or 'index')[:30]}",
                title=f"JSON Endpoint: {final_url[:65]}",
                summary=f"Fetched JSON from {final_url} (HTTP {status_code})",
                report_body=full_report,
                tags=["webpage", "json", "tier1", slugify(host_only)],
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
                + f"\n\n... [{len(md_body) - max_chars} middle chars archived in project targets note; head+tail preserved] ...\n\n"
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

    # Save full un-truncated report to `Projects/<project>/targets/`
    full_untruncated_report = "\n".join(report_lines[:6]) + f"\n\n### Full Extracted Page Content:\n{md_body}\n"
    saved_p = _save_web_report_to_project(
        project_slug=project_slug,
        slug_name=f"page_{slugify(host_only)}_{slugify(parsed.path or 'index')[:30]}",
        title=parsed_doc["title"][:70] or f"Webpage: {final_url[:65]}",
        summary=f"Fetched {final_url} (HTTP {status_code}, {len(md_body)} chars clean Markdown)",
        report_body=full_untruncated_report,
        tags=["webpage", "tier1", slugify(host_only)],
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
