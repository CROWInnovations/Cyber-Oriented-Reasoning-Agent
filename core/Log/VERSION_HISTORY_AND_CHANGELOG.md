# C.O.R.A. Master Version History & Architectural Changelog (`core/Log/VERSION_HISTORY_AND_CHANGELOG.md`)

**Author:** CROW Innovations  
**Current Semantic Version:** `5.22.20` ([`cora_version.json`](./cora_version.json))  

---

## 1. Semantic Versioning Specification (`MAJOR.ENGINE_REV.PATCH_REV`)

`C.O.R.A.` tracks its version deterministically in [`core/Log/cora_version.json`](./cora_version.json):
- **`major_cli` (`5`)**: Major CLI, Custom WebUI, and Two-Tier Project/Vault Architecture generation.
- **`engine_rev` (`22`)**: Reasoning & Logic Engine revision (verified via SHA-256 tree hash `engine_tree_sha256` across `core/Reasoning/engines/*.py` and `core/Reasoning/reasoning_cli.py`).
- **`patch_rev` (`20`)**: Incremental patch, documentation, launcher, and training corpus revision (`patch_tree_sha256`).

---

## 2. Release History & Root-Cause Fix Ledger

### `v5.22.20` — Workspace Subdirectory Routing (`targets/`, `notes/`, `downloads/`, `artifacts/`, `assets/`, `Files/`), Equipment Inventory Tracking & Auto-Persist Script Guard
- **Structured Project Workspace Routing (`core/webui/server.py`, `core/Reasoning/engines/web_intel.py`, `core/Reasoning/engines/vault_bridge.py`)**:
  - **`targets/` (Equipment & Host Inventory Only)**: Added `_persist_target_and_telemetry_to_workspace()` and `_lookup_host_mac_and_neigh()` to automatically maintain per-host equipment profiles (`target_<host>.md`) and a master inventory table (`equipment_inventory.md`) tracking IP Address, L2 MAC Address & Interface, Open TCP/UDP Ports, System OS/Firmware, Hardware Model/Architecture/Serial, and Discovered URLs.
  - **`notes/` (Web Search & Analytical Notes)**: Updated `execute_tier1_web_search()` to persist `search_*.md` OSINT reports into `Projects/<project>/notes/` (instead of `targets/`) and added `save_project_note` to `WEBUI_AGENT_TOOLS`.
  - **`downloads/` (Fetched Webpages, JSON Feeds & Payloads)**: Updated `execute_tier1_fetch_webpage()` and `execute_safe_shell_command()` to save fetched pages (`page_*.md`), JSON feeds, `curl` HTML/JSON bodies, and redirected `/tmp/<file>` downloads into `Projects/<project>/downloads/`.
  - **`artifacts/` & `assets/` (Raw Scan/Query Logs & Target Web/TLS Assets)**: Automatically records timestamped scan, `curl`, probe, and script execution transcripts into `Projects/<project>/artifacts/` and saves extracted static web asset paths, `Last-Modified`/`ETag` build headers, and TLS certificate metadata into `Projects/<project>/assets/assets_<host>.md`.
- **Reliable `Files/` Script Creation & Editing (`core/webui/server.py`)**:
  - Fixed `_recover_tool_args()` and `_resolve_default_project_script_filename()` to resolve target script filenames even when `llama-server` emits empty `{}` arguments, increased `read_project_file` retention to `16,000` chars, and added an Automatic Code-Block-to-`Files/` Persistence Guard when the operator requests creating or fixing a script.
- **Repository Sanitization**: Hardened `.gitignore` and sanitized all remaining legacy `172.24.X.XXX` templates in `mdp_transitions.json` and `trained_rules.json` to `{target_ip}`.

### `v5.22.19` — `AUTO-RUN` & `CONFIRM` Permission Enforcement, Short-Reply Resolution, Local Exploit Callback Abduction & Tool-Call Recovery
- **WebUI `AUTO-RUN` & `CONFIRM` Enforcement (`core/webui/server.py`)**:
  - Enforced `permission_mode` (`confirm` vs. `auto`) in `api_submit_query`: in `CONFIRM` mode, passive read tools (`read_project_file`, `list_project_files_tool`, `vault_search`, `vault_read_note`) execute while active/mutating/network tools (`run_shell_command`, `write_project_file`, `scan_target`, `web_search`, `fetch_webpage`) are queued in `pending_confirm_tools_<project>` awaiting operator approval.
  - Added an explicit `AUTO-RUN` behavioral directive and Anti-Stall `AUTO-RUN` Guard that prevents the LLM from stopping to ask for confirmation when `AUTO-RUN` is enabled.
  - Gated autonomous Wave A/B execution so background `scan_target` and `web_search`/`fetch_webpage` waves only run during active `/goal` or `/relentless` pursuit with `AUTO-RUN` enabled.
- **Conversation History Tail Preservation & Short-Reply Resolution (`core/webui/server.py`)**:
  - Preserved both head and tail (`[:1100] + ... + [-1700:]`) of assistant messages in `history_msgs` so numbered options and confirmation prompts at the end of responses are never truncated.
  - Added automatic resolution of short confirmation replies (`yes`, `yes, confirm`, `confirm`, `proceed`) and numbered choices (`1`, `2`, `3`) against the previous assistant turn before invoking the 15-Engine pipeline and LLM.
- **15-Engine Local Exploit / Callback Abduction & Target Priority (`bayesian.py`, `pipeline.py`, `vault_bridge.py`)**:
  - Added the `exploit_callback_or_script_failure` Bayesian profile and `_auto_select_profile_and_dag()` in `pipeline.py` with automatic `$PROJECT_FILES_DIR` script inspection to detect hardcoded callback `LHOST`/`LPORT` mismatches against active host interfaces.
  - Prioritized active project `memory.md` over stale cross-project `relentless_ledger.json` entries in `resolve_problem_targets()`.
- **Tool-Call Truncation Recovery & CLI Permission Sync (`core/webui/server.py` & `core/agent-cli.py`)**:
  - Increased tool-call token budget (`2800`/`3200`), added `_recover_tool_args()`, and supported both JSON and Qwen XML `<function=...><parameter=...>` tool call formats.
  - Synced `SKIP_PERMISSIONS` with `[3] Berserker` mode and gated `scan_target`, `web_search`, and `fetch_webpage` with `confirm_action()` in `core/agent-cli.py`.

### `v5.21.19` — LOLBINS Reasoning Vault (`CROWInnovations/LOLBAS`), NIST NVD 2.0 & OpenCVE Intelligence & `web_intel.py` Fixes
- **LOLBINS Living-Off-The-Land Binaries, Scripts & Libraries Reasoning Suite (`core/ObsidianVault/reasoning/LOLBINS.md` & `core/ObsidianVault/reasoning/LOLBINS/`)**:
  - Ingested the complete [`https://github.com/CROWInnovations/LOLBAS`](https://github.com/CROWInnovations/LOLBAS) repository (**202 entries** across `OSBinaries` (`117`), `OSScripts` (`10`), `OSLibraries` (`16`), `OtherMSBinaries` (`57`), and `HonorableMentions` (`2`), totaling **414 verified commands** across `15` tactical categories: `Execute`, `Download`, `Upload`, `AWL Bypass`, `UAC Bypass`, `Dump`, `Credentials`, `ADS`, `Compile`, `Copy`, `Encode`/`Decode`, `Reconnaissance`, and `Tamper`).
  - Wired `reasoning/LOLBINS` and its 5 sub-playbooks (`lolbins_os_binaries_a_to_l.md`, `lolbins_os_binaries_m_to_z.md`, `lolbins_os_scripts_and_libraries.md`, `lolbins_other_ms_binaries.md`, `lolbins_tactical_categories_and_detections.md`) into [`00_MEMORY_INDEX.md`](../ObsidianVault/00_MEMORY_INDEX.md), [`vault_bridge.py`](../Reasoning/engines/vault_bridge.py), Engine 1 (`associative.py`), and the 15-Engine Orchestrator (`pipeline.py`).
- **NIST NVD API 2.0, Local `~/Projects/CVEs/` Repository & OpenCVE Integration (`core/Reasoning/engines/web_intel.py` & [`cyber_threat_cve_and_tools_intelligence_strategy_playbook.md`](../ObsidianVault/reasoning/cyber_threat_cve_and_tools_intelligence_strategy_playbook.md))**:
  - **Fixed DuckDuckGo HTML Snippet Extraction**: Updated `execute_tier1_web_search()` to split on top-level `<div class="result ...">` boundaries so nested `result__extras` divs never truncate the block before `<a class="result__snippet">` is parsed (resolving `Snippet: (no snippet)` on web search results).
  - **Automatic Result CVE Enrichment**: Updated `execute_tier1_web_search()` to extract `CVE-YYYY-NNNN` identifiers from both the query string and the returned search result titles/URLs/snippets, automatically enriching top CVEs with complete NVD 2.0 telemetry (Descriptions, CVSS v4.0/v3.1/v3.0/v2.0, CWEs, CISA KEV status/deadlines, CPE 2.3 version ranges, and tagged references).
  - **Point-Version CPE 2.3 Range Matching (`_search_local_nvd_by_product_version` & `_cpe_version_matches`)**: Added automatic CPE 2.3 `versionStartIncluding`/`versionStartExcluding`/`versionEndIncluding`/`versionEndExcluding` range evaluation against `~/Projects/CVEs/nvd_cves.sqlite` (`417,614` CVEs, `958,619` product/vendor mappings) so point-version queries (e.g., `FortiOS 6.2.1` or `FortiOS 6.0.6`) immediately return all matching CVEs even when search engines only index range strings (`6.2.0 through 6.2.15`).
  - **Smart NVD Angular SPA & OpenCVE (`app.opencve.io`) Interception**: Updated `execute_tier1_fetch_webpage()` to rewrite `nvd.nist.gov/vuln/detail/CVE-*` Angular shells to `services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`, handle `nvd.nist.gov/vuln/data-feeds`, support `OPENCVE_API_TOKEN` bearer auth on `app.opencve.io/api/v2/*`, and automatically route unauthenticated `app.opencve.io/api/v2/cves` calls to OpenCVE's zero-auth server-rendered `app.opencve.io/cve/` endpoints.

### `v5.20.18` — End-to-End 15-Engine Mathematical & Logic Audit, LLM KV-Cache Reuse & CPU/GPU Resource Balance
- **15-Engine Neuro-Symbolic & Mathematical Fixes (`core/Reasoning/engines/`)**:
  - **Engine 1 (`associative.py`)**: Filtered 2–3 character English stopwords during node extraction, enforced word-boundary regex matching for short tokens (`<= 4` chars), added per-file `(mtime_ns, fsize)` to `_GRAPH_CACHE` key, resolved stem-only `[[WikiLinks]]`, and removed duplicate `nx.has_path` checks.
  - **Engine 2 (`geometric.py`)**: Added all-ones additivity and residual verification in `_try_fast_linear_solve` to reject bilinear cross-terms (`x * y`), passed `z3_timeout_ms` to Z3 solver instances, split chained inequalities (`0 <= x <= 255`), and capped `common_bits` at `prefixlen` in `compute_minimal_covering_supernet`.
  - **Engine 4 (`bayesian.py`)**: Rendered `remediation` templates via `_render_bayesian_text` in `ranked_hypotheses`, sanitized legacy `172.24.` IPs in-place without wiping learned priors, and accepted `list`/`tuple`/`set` evidence inputs.
  - **Engine 5 (`causal.py`)**: Fixed `_propagate_scm_probabilities` double-negation when `standard_preds` is empty, computed single-node `ACE` against the un-clamped baseline distribution, and cached default DAGs in RAM.
  - **Engine 7 (`vsa.py`)**: Eliminated 2-vector `_bundle` tie-breaking erasure (`np.where(summed >= 0, 1, -1)`), required `timeout_hits >= 2` or explicit repeated-failure cues before triggering somatic trap overrides, and bound `live_hv` roles to distinct filler hypervectors.
  - **Engine 9 (`temporal_fluents.py`)**: Unified JSON state I/O with `vault_bridge.load_json_state`/`save_json_state`, guarded state-mutating fluent invalidation with `returncode == 0`, fixed overbroad `" down"` matching, added `iptables -F`/`nft flush`, and extracted `ip addr add/replace` into `transient_ip_alias`.
  - **Engine 10 (`dempster_shafer.py`)**: Realigned compatible sensor focal elements so consistent L2/L3/L7 failures produce low conflict (`K = 0.104 < 0.25`) while contradictory sensors (`arp_l2_reachable` + `icmp_100pct_loss`) produce high conflict (`K = 0.518 >= 0.35`); prevented `"not reachable"` and bare `"https://"` from triggering false-positive evidence; added `"diagnostic_probe"` output key.
  - **Engine 11 (`cbr_fingerprints.py`)**: Enforced `pat_re.search(out_txt)` when a case defines an `error_regex`, used precompiled `bin_re`, and stopped baking `CBR-TRN-*`/`CBR-AUTO-*` cases into `cbr_library.json`.
  - **Engine 12 (`cegar_verifier.py`)**: Allowed optional whitespace (`\s*`) after command separators in `WHITE`/air-gap network-isolation regexes so chained commands (`ip addr && ping ...`) cannot bypass isolation; restricted `ping -n` count check to Windows; exempted SNMP OIDs and `grep` strings from truncated-IP false positives; added 5-second TTL and `copy.deepcopy` to `_CEGAR_CMD_CACHE`.
  - **Engine 13 (`sygus_extractor.py`)**: Added `ip -4 -br addr show` and `ifconfig` CIDR extraction, separated `closed`/`filtered` Nmap ports into `facts["closed_or_filtered_ports"]`, parsed all `Test-NetConnection` blocks via `re.finditer`, and matched `UNCONN` UDP sockets in `ss -tulpn`.
  - **Engine 15 (`mdp_tactical.py`)**: Invalidated `_MDP_SOLVED_CACHE` on live transition updates, fixed Bellman potential triple-counting and self-loop positive floors, and returned both `"decision"` and `"stopping_decision"` in `solve_in_task_optimal_stopping_mdp`.
  - **Engine 16 (`continual_learner.py`)**: Preserved Layer-5 Bayesian EIG conflict probes during Pass-2 refinement unless `stop_dec == "PIVOT_TACTIC_IMMEDIATELY"`, wildcarded concrete IPs/ports/tokens in auto-learned CBR regexes, and decayed `alpha_success` and `alpha_fail` symmetrically during forgetting decay.
  - **Engine 17 (`meta_learner.py`)**: Centered Brier loss around `0.25` and normalized Hedge weights (`mean = 1.0`), implemented binned Expected Calibration Error (ECE), and allowed `serial_oob` health to recover to `"HEALTHY"`.
  - **Engine 19 (`rl_network_policy.py`)**: Bootstrapped failed/non-advancing commands from `post_s_key` instead of `next_stage`, decayed/reset eligibility traces on goal or target change, and checked `has_route_fluent` in `sense_live_local_network_topology`.
  - **Engine 20 (`spectral_manifold_pca.py`)**: Fixed Mahalanobis distance formula (`np.sqrt(np.sum(diff_norm ** 2))`) using per-cluster feature std, tracked `total_observations_count` across sliding-window trims, and included `"silhouette_score"` inside `cluster_assignment`.
  - **Orchestrator & Context VM (`pipeline.py`, `context_vm.py`, `vault_bridge.py`, `reasoning_cli.py`, `install_reasoning.py`)**: Added evidence inference for `l2_l3_routing_blackhole` and `api_auth_rejection`; mapped valid `network_api_reachability` DAG nodes when `not has_serial_oob`; normalized `mdp_q`, `rl_q_lcb`, and `eig_score` onto `[0, 1]` in the Layer-5 arbiter; applied `apply_serial_pacing_transform` before `verify_command_cegar`; removed duplicate `mdp_tactical` calls in `context_vm.py`; sanitized `NIC:<iface>` to `NIC:<PRIMARY_NIC>` in `vault_bridge.py`; preserved `mdp_transitions.json` and `spectral_manifold_state.json` during `reasoning_cli.py test` (`369.9 ms` total self-test runtime, down from `664.8 ms`).
- **LLM KV-Cache, WebUI & Resource Balance Fixes (`core/webui/server.py`, `core/agent-cli.py`, `run_cora_NIX.sh`, `run_cora_WIN.ps1`)**:
  - Kept `messages[0]` (`sys_prompt`) 100% static across turns in both `core/webui/server.py` and `core/agent-cli.py` by moving dynamic `memory.md` and `[15-Engine L1 Guidance]` blocks into the user turn message for full `llama-server` KV-cache prefix reuse.
  - Dynamically aligned `MAX_HISTORY_TOKENS` in `core/agent-cli.py` with `CTX_SIZE` and live `/props` `n_ctx`.
  - Replaced hardcoded appliance synthesis prompts in `core/webui/server.py` with target-agnostic synthesis, enforced Linux `unshare -r -n` network namespace isolation in `WHITE` mode, and added process-group (`os.killpg`) cleanup on command timeout/cancellation.
  - Removed unsupported `--context-shift` / `--cache-reuse` flags from `run_cora_NIX.sh`, `run_cora_WIN.ps1`, and `core/webui/server.py`, and separated `"gpu_vram_mb"` (detected hardware VRAM) from `"reasoning_gpu_vram_mb": 0` in `hardware_profile.json`.

### `v5.15.12` — Custom Svelte/FastAPI WebUI, Cross-Platform Parity & 15-Engine Audit Fixes
- **Custom Local WebUI (`core/webui/`)**:
  - Replaced third-party Docker `open-webui` container with a native **Svelte + TypeScript + Tailwind CSS** dashboard and **Python + FastAPI + WebSockets + SQLite + `psutil` + NVIDIA `NVML`** local backend (`core/webui/server.py`).
  - Added CLI-equivalent dropdown selectors (`Projects/<slug>/` with Create & Rename, `Personality Mode [1-4]`, `Network Isolation [Red/Blue/White]`, `Model Selector [llama-server]`, `Thinking`, `Permissions`), with the **Results Display Window** positioned directly above the **Input Window & Select Options**.
  - Added real-time WebSocket hardware monitoring (`/ws/metrics`) for CPU, RAM, Disk, Network throughput/NICs (`psutil`), and NVIDIA GPU utilization, VRAM, temperature, and power draw (`pynvml`).
- **Log & Reasoning Engine Bug Fixes**:
  - Fixed `/train` `TypeError` in `core/agent-cli.py` where `run_training_pipeline()` was passed an unsupported `quiet=False` keyword argument.
  - Fixed `/reason -engine:<name>` in `core/agent-cli.py` so all 15 individual reasoning engines can be invoked directly instead of only 5.
  - Unified `shadow_archive` path inspection across `context_vm.py`, `agent-cli.py` (`/state`), and `Troubleshooting/troubleshoot_core.py` so project-scoped `Projects/<project>/shadow_archive/sha256_*.log` files and global `Reasoning/data/shadow_archive/` files are both counted and reported accurately.
  - Fixed `vault_bridge.load_json_state()` in-memory cache shallow reference mutation bug and removed `len(str(cached[1]))` serialization overhead.
  - Fixed `train_llm.py` version bump logic so `cora_version.json` updates `patch_tree_sha256` cleanly without causing a double patch increment on the next CLI launch.
  - Fixed Windows `ping` auto-repair in `cegar_verifier.py` (`ping -n 3 -w 2000` on Windows vs `ping -c 3 -W 2` on POSIX) and cross-platform fallback commands in `pipeline.py`, `cegar_verifier.py`, `mdp_tactical.py`, and `rl_network_policy.py`.
  - Fixed `active-model.txt` $\rightarrow$ `llama-server.model` cleanup in `core/agent-cli.py` and `export KEY="VAL"` parsing of `active_session_mode.env` in `run_cora_WIN.ps1`.
  - Fixed `./run_cora_NIX.sh troubleshoot` argument parsing and `-c` / `--continue` restoration of `isolation_mode` and `allowed_interfaces`.

### `v5.14.11` — 80/20 Pareto Streamlining (20 Engines $\rightarrow$ 15 Core Engines)
- Removed 5 redundant/high-latency engines (`fca.py`, `analogy.py`, `planner_asp.py`, `evolutionary_leap.py`, `ablation_discovery_engine.py`), cutting cold-start pipeline latency by **85.9%** while preserving 100% of root-cause, tactical Bellman H-MDP, `TD(λ)` RL, CEGAR safety, and META-MIND calibration accuracy.
- Standardized VSA hyperdimensional vectors in `vault_bridge.py` and `vsa.py` to `1,024-D` (`1.64x` speedup with zero cosine rank loss).

### `v5.12.10` — Two-Tier Project Workspace Isolation (`Projects/<project>/`)
- Isolated all runtime target scans, downloads, temporary scripts, and `memory.md` / `goals.md` / `REPORT.md` inside `CORA/Projects/<project>/` while keeping `core/ObsidianVault/` clean and universal through IP-abstracted `<TARGET_IP>` parameterization.
