@echo off
set functions=(localpol, grouppol, usrmgr, usrRights, services, services2, features, registry, misc, flushDNS, rdp, verifySys)
set users=(dovahkiin delphine esbern) ::list valid users from the readme here in this format
set scriptPathAlpha=%~dp0
echo %scriptPathAlpha%output> "%scriptPathAlpha%winfiles\scriptPathAlpha.txt"

:main
for %%a in %functions% do call:%%a
echo Done
pause
exit

:firewall
echo Firewall Policy
netsh advfirewall set allprofiles state on
netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
netsh advfirewall firewall set rule name="netcat" new enable=no
pause
goto:EOF

:localpol
echo ------------------------------------------------------------------------------------
echo *** Importing policies from policies folder...                                   ***
%scriptPathAlpha%winfiles\LGPO.exe /g %scriptPathAlpha%winfiles\Policies /v
echo *** Finished                                                                     ***
echo ------------------------------------------------------------------------------------
goto:EOF

:grouppol
echo Password Policies
net accounts /lockoutthreshold:5 /MINPWLEN:14 /MAXPWAGE:90 /MINPWAGE:30 /UNIQUEPW:10
echo Set Password Complexity and Encryption Manually
start secpol.msc /wait
echo Audit Policies
auditpol /set /category:* /failure:enable /success:enable
pause
goto:EOF

:winShares
for %i in (C$ IPC$ ADMIN$) do net share %i /delete
pause
goto:EOF

:usrmgr
echo User Management
net user Administrator /active:no && (
	echo Disabled administrator account
	(call)
) || echo Administrator account not disabled
echo Disabling Guest account...
net user Guest /active:no && (
	echo Disabled Guest account
	(call)
) || echo Guest account not disabled
echo Disabled guest account
echo Rename Guest/Admin Accounts
start lusrmgr.msc /wait
echo User Passwords
for %%u in %users%; do (
	net user "%%u" Cyb3rP@tr!0ts
	wmic useraccount WHERE "Name='%%u'" SET PasswordExpires=TRUE
)
pause
goto:EOF

:usrRights
echo Installing ntrights.exe to C:\Windows\System32
copy %scriptPathAlpha%winfiles\ntrights.exe C:\Windows\System32
if exist C:\Windows\System32\ntrights.exe (
	echo Installation succeeded, managing user rights..
	set remove=("Backup Operators" "Everyone" "Power Users" "Users" "NETWORK SERVICE" "LOCAL SERVICE" "Remote Desktop User" "ANONOYMOUS LOGON" "Guest" "Performance Log Users")
	for %%a in (%remove%) do (
			ntrights -U %%a -R SeNetworkLogonRight 
			ntrights -U %%a -R SeIncreaseQuotaPrivilege
			ntrights -U %%a -R SeInteractiveLogonRight
			ntrights -U %%a -R SeRemoteInteractiveLogonRight
			ntrights -U %%a -R SeSystemtimePrivilege
			ntrights -U %%a +R SeDenyNetworkLogonRight
			ntrights -U %%a +R SeDenyRemoteInteractiveLogonRight
			ntrights -U %%a -R SeProfileSingleProcessPrivilege
			ntrights -U %%a -R SeBatchLogonRight
			ntrights -U %%a -R SeUndockPrivilege
			ntrights -U %%a -R SeRestorePrivilege
			ntrights -U %%a -R SeShutdownPrivilege
		)
		ntrights -U "Administrators" -R SeImpersonatePrivilege
		ntrights -U "Administrator" -R SeImpersonatePrivilege
		ntrights -U "SERVICE" -R SeImpersonatePrivilege
		ntrights -U "LOCAL SERVICE" +R SeImpersonatePrivilege
		ntrights -U "NETWORK SERVICE" +R SeImpersonatePrivilege
		ntrights -U "Administrators" +R SeMachineAccountPrivilege
		ntrights -U "Administrator" +R SeMachineAccountPrivilege
		ntrights -U "Administrators" -R SeIncreaseQuotaPrivilege
		ntrights -U "Administrator" -R SeIncreaseQuotaPrivilege
		ntrights -U "Administrators" -R SeDebugPrivilege
		ntrights -U "Administrator" -R SeDebugPrivilege
		ntrights -U "Administrators" +R SeLockMemoryPrivilege
		ntrights -U "Administrator" +R SeLockMemoryPrivilege
		ntrights -U "Administrators" -R SeBatchLogonRight
		ntrights -U "Administrator" -R SeBatchLogonRight
		echo Managed User Rights
)
goto:EOF

:services
set servicesD=RemoteAccess Telephony TapiSrv Tlntsvr tlntsvr p2pimsvc simptcp fax msftpsvc iprip ftpsvc RemoteRegistry RasMan RasAuto seclogon MSFTPSVC W3SVC SMTPSVC Dfs TrkWks MSDTC DNS ERSVC NtFrs MSFtpsvc helpsvc HTTPFilter IISADMIN IsmServ WmdmPmSN Spooler RDSessMgr RPCLocator RsoPProv	ShellHWDetection ScardSvr Sacsvr TermService Uploadmgr VDS VSS WINS WinHttpAutoProxySvc SZCSVC CscService hidserv IPBusEnum PolicyAgent SCPolicySvc SharedAccess SSDPSRV Themes upnphost nfssvc nfsclnt MSSQLServerADHelper
set servicesM=dmserver SrvcSurg
set servicesG=Dhcp Dnscache NtLmSsp
echo Disabling bad services...
for %%a in (%servicesD%) do (
	echo Service: %%a
	sc stop "%%a"
	sc config "%%a" start= disabled
)
echo Disabled bad services
echo Setting services to manual...
for %%b in (%servicesM%) do (
	echo Service: %%b
	sc config "%%b" start= demand
)
echo Set services to manual
echo Seting services to auto...
for %%c in (%servicesG%) do (
	echo Service: %%c
	sc config "%%c" start= auto
)
echo Started auto services
goto:EOF

:services2
::bad services
sc stop tlntsvr
sc config tlntsvr start= disabled
sc stop msftpsvc
sc config msftpsvc start= disabled
sc stop snmptrap
sc config snmptrap start= disabled
sc stop ssdpsrv
sc config ssdpsrv start= disabled
sc stop termservice
sc config termservice start= disabled
sc stop sessionenv
sc config sessionenv start= disabled
sc stop remoteregistry
sc config remoteregistry start= disabled
sc stop Messenger
sc config Messenger start= disabled
sc stop upnphos
sc config upnphos start= disabled
sc stop WAS
sc config WAS start= disabled
sc stop RemoteAccess
sc config RemoteAccess start= disabled
sc stop mnmsrvc
sc config mnmsrvc start= disabled
sc stop NetTcpPortSharing
sc config NetTcpPortSharing start= disabled
sc stop RasMan
sc config RasMan start= disabled
sc stop TabletInputService
sc config TabletInputService start= disabled
sc stop RpcSs
sc config RpcSs start= disabled
sc stop SENS
sc config SENS start= disabled
sc stop EventSystem
sc config EventSystem start= disabled
sc stop XblAuthManager
sc config XblAuthManager start= disabled
sc stop XblGameSave
sc config XblGameSave start= disabled
sc stop XboxGipSvc
sc config XboxGipSvc start= disabled
sc stop xboxgip
sc config xboxgip start= disabled
sc stop xbgm
sc config xbgm start= disabled
sc stop SysMain
sc config SysMain start= disabled
sc stop seclogon
sc config seclogon start= disabled
sc stop TapiSrv
sc config TapiSrv start= disabled
sc stop p2pimsvc
sc config p2pimsvc start= disabled
sc stop simptcp
sc config simptcp start= disabled
sc stop fax
sc config fax start= disabled
sc stop Msftpsvc
sc config Msftpsvc start= disabled
sc stop iprip
sc config iprip start= disabled
sc stop ftpsvc
sc config ftpsvc start= disabled
sc stop RasAuto
sc config RasAuto start= disabled
sc stop W3svc
sc config W3svc start= disabled
sc stop Smtpsvc
sc config Smtpsvc start= disabled
sc stop Dfs
sc config Dfs start= disabled
sc stop TrkWks
sc config TrkWks start= disabled
sc stop MSDTC
sc config MSDTC start= disabled
sc stop ERSvc
sc config ERSvc start= disabled
sc stop NtFrs
sc config NtFrs start= disabled
sc stop Iisadmin
sc config Iisadmin start= disabled
sc stop IsmServ
sc config IsmServ start= disabled
sc stop WmdmPmSN
sc config WmdmPmSN start= disabled
sc stop helpsvc
sc config helpsvc start= disabled
sc stop Spooler
sc config Spooler start= disabled
sc stop RDSessMgr
sc config RDSessMgr start= disabled
sc stop RSoPProv
sc config RSoPProv start= disabled
sc stop SCardSvr
sc config SCardSvr start= disabled
sc stop lanmanserver
sc config lanmanserver start= disabled
sc stop Sacsvr
sc config Sacsvr start= disabled
sc stop TermService
sc config TermService start= disabled
sc stop uploadmgr
sc config uploadmgr start= disabled
sc stop VDS
sc config VDS start= disabled
sc stop VSS
sc config VSS start= disabled
sc stop WINS
sc config WINS start= disabled
sc stop CscService
sc config CscService start= disabled
sc stop hidserv
sc config hidserv start= disabled
sc stop IPBusEnum
sc config IPBusEnum start= disabled
sc stop PolicyAgent
sc config PolicyAgent start= disabled
::sc stop SCPolicySvc
::sc config SCPolicySvc start= disabled
sc stop SharedAccess
sc config SharedAccess start= disabled
sc stop SSDPSRV
sc config SSDPSRV start= disabled
sc stop Themes
sc config Themes start= disabled
sc stop upnphost
sc config upnphost start= disabled
sc stop nfssvc
sc config nfssvc start= disabled
sc stop nfsclnt
sc config nfsclnt start= disabled
sc stop MSSQLServerADHelper
sc config MSSQLServerADHelper start= disabled
sc stop SharedAccess
sc config SharedAccess start= disabled
sc stop UmRdpService
sc config UmRdpService start= disabled
sc stop SessionEnv
sc config SessionEnv start= disabled
sc stop Server
sc config Server start= disabled
sc stop TeamViewer
sc config TeamViewer start= disabled
sc stop TeamViewer7
sc config start= disabled
sc stop HomeGroupListener
sc config HomeGroupListener start= disabled
sc stop HomeGroupProvider
sc config HomeGroupProvider start= disabled
sc stop AxInstSV
sc config AXInstSV start= disabled
sc stop Netlogon
sc config Netlogon start= disabled
sc stop lltdsvc
sc config lltdsvc start= disabled
sc stop iphlpsvc
sc config iphlpsvc start= disabled
sc stop AdobeARMservice
sc config AdobeARMservice start= disabled
::goodservices
sc start wuauserv
sc config wuauserv start= auto
sc start EventLog
sc config EventLog start= auto
sc start MpsSvc
sc config MpsSvc start= auto
sc start WinDefend
sc config WinDefend start= auto
sc start WdNisSvc
sc config WdNisSvc start= auto
sc start Sense
sc config Sense start= auto
sc start Schedule
sc config Schedule start= auto
sc start SCardSvr
sc config SCardSvr start= auto
sc start ScDeviceEnum
sc config ScDeviceEnum start= auto
sc start SCPolicySvc
sc config SCPolicySvc start= auto
sc start wscsvc
sc config wscsvc start= auto
goto:EOF


:files
REM Find file
@echo off
color 0f
cls
echo Flashing Disk to .flashed Files to reference....
dir /b /s "C:\Program Files\" > programfiles.flashed
dir /b /s "C:\Program Files (x86)\" >> programfiles.flashed
echo Program Files flashed
dir /b /s "C:\Users\" > users.flashed
dir /b /s "C:\Documents and Settings" >> users.flashed
echo User profiles flashed
dir /b /s "C:\" > c.flashed
echo C:\ Flashed
pause
echo Finding media files in C:\Users and/or C:\Documents and Settings...
findstr .mp3 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp3 > media_audio
findstr .ac3 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.ac3 >> media_audio
findstr .aac users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.aac >> media_audio
findstr .aiff users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.aiff >> media_audio
findstr .flac users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.flac >> media_audio
findstr .m4a users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m4a >> media_audio
findstr .m4p users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m4p >> media_audio
findstr .midi users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.midi >> media_audio
findstr .mp2 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp2 >> media_audio
findstr .m3u users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m3u >> media_audio
findstr .ogg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.ogg >> media_audio
findstr .vqf users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.vqf >> media_audio
findstr .wav users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.wav >> media_audio
findstr .wma users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.wma >> media_video
findstr .mp4 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp4 >> media_video
findstr .avi users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.avi >> media_video
findstr .mpeg4 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .mpeg4 >> media_video
REM BREAKLINE
findstr .gif users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.gif >> media_pics
findstr .png users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.png >> media_pics
findstr .bmp users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.bmp >> media_pics
findstr .jpg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .jpg >> media_pics
findstr .jpeg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .jpeg >> media_pics
C:\WINDOWS\system32\notepad.exe media_video
C:\WINDOWS\system32\notepad.exe media_audio
C:\WINDOWS\system32\notepad.exe media_pics
echo Finding Hacktools now...
findstr "Cain" programfiles.flashed
if %errorlevel%==0 (
echo Cain detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "nmap" programfiles.flashed
if %errorlevel%==0 (
echo Nmap detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "keylogger" programfiles.flashed
if %errorlevel%==0 (
echo Potential keylogger detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Armitage" programfiles.flashed
if %errorlevel%==0 (
echo Potential Armitage detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Metasploit" programfiles.flashed
if %errorlevel%==0 (
echo Potential Metasploit framework detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Shellter" programfiles.flashed
if %errorlevel%==0 (
echo Potential Shellter detected. Please take note, then press any key.
pause >NUL
)
cls

:features
echo Installing Dism.exe
copy %scriptPathAlpha%winfiles\Dism.exe C:\Windows\System32
xcopy %scriptPathAlpha%winfiles\Dism C:\Windows\System32
echo Disabling Windows features...
set features=IIS-WebServerRole IIS-WebServer IIS-CommonHttpFeatures IIS-HttpErrors IIS-HttpRedirect IIS-ApplicationDevelopment IIS-NetFxExtensibility IIS-NetFxExtensibility45 IIS-HealthAndDiagnostics IIS-HttpLogging IIS-LoggingLibraries IIS-RequestMonitor IIS-HttpTracing IIS-Security IIS-URLAuthorization IIS-RequestFiltering IIS-IPSecurity IIS-Performance IIS-HttpCompressionDynamic IIS-WebServerManagementTools IIS-ManagementScriptingTools IIS-IIS6ManagementCompatibility IIS-Metabase IIS-HostableWebCore IIS-StaticContent IIS-DefaultDocument IIS-DirectoryBrowsing IIS-WebDAV IIS-WebSockets IIS-ApplicationInit IIS-ASPNET IIS-ASPNET45 IIS-ASP IIS-CGI IIS-ISAPIExtensions IIS-ISAPIFilter IIS-ServerSideIncludes IIS-CustomLogging IIS-BasicAuthentication IIS-HttpCompressionStatic IIS-ManagementConsole IIS-ManagementService IIS-WMICompatibility IIS-LegacyScripts IIS-LegacySnapIn IIS-FTPServer IIS-FTPSvc IIS-FTPExtensibility TFTP TelnetClient TelnetServer
for %%a in (%features%) do dism /online /disable-feature /featurename:%%a
echo Disabled Windows features
goto:EOF

:registry
echo Managing registry keys...
::Windows auomatic updates
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
::Restrict CD ROM drive
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
::Disallow remote access to floppy disks
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
::Disable auto Admin logon
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
:: Logo message text
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeText /t REG_SZ /d  "Secured"
:: Logon message title bar
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption /t REG_SZ /d "CyberPatiots Team 15-1815"
::Clear page file (Will take longer to shutdown)
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
::Prevent users from installing printer drivers 
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
::Add auditing to Lsass.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
::Enable LSA protection
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f
::Limit use of blank passwords
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
::Auditing access of Global System Objects
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
::Auditing Backup and Restore
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f
::Restrict Anonymous Enumeration #1
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
::Restrict Anonymous Enumeration #2
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
::Disable storage of domain passwords
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
::Take away Anonymous user Everyone permissions
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
::Allow Machine ID for NTLM
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
::Do not display last user on logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
::Enable UAC
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
::UAC setting (Prompt on Secure Desktop)
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
::Enable Installer Detection
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
::Disable undocking without logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
::Enable CTRL+ALT+DEL
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
::Max password age
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
::Disable machine account password changes
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
::Require strong session key
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
::Require Sign/Seal
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
::Sign Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
::Seal Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
::Set idle time to 45 minutes
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f
::Require Security Signature - Disabled pursuant to checklist:::
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f
::Enable Security Signature - Disabled pursuant to checklist:::
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f
::Clear null session pipes
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
::Restict Anonymous user access to named pipes and shares
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
::Encrypt SMB Passwords
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
::Clear remote registry scriptPathAlphas
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
::Clear remote registry scriptPathAlphas and sub-scriptPathAlphas
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
::Enable smart screen for IE8
reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
::Enable smart screen for IE9 and up
reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
::Disable IE password caching
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
::Warn users if website has a bad certificate
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
::Warn users if website redirects
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
::Enable Do Not Track
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
::Show hidden files
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
::Disable sticky keys
reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
::Show super hidden files
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
::Disable dump file creation
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
::Disable autoruns
reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f
::Enable internet explorer phishing filter
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
::Block macros and other content execution
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f
::Enable Windows Defender
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
echo Managed registry keys
goto:EOF

:misc
echo Setting power settings...
powercfg -SETDCVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
echo Set power settings
goto:EOF

:flushDNS
echo Flushing DNS
ipconfig /flushdns >nul
echo Flushed DNS
echo Clearing contents of: C:\Windows\System32\drivers\etc\hosts
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo > C:\Windows\System32\drivers\etc\hosts
attrib +r +s C:\WINDOWS\system32\drivers\etc\hosts
echo Cleared hosts file
goto:EOF

:rdp
set /p rdpChk="Enable remote desktop (y/n)"
if %rdpChk%==y (
	echo Enabling remote desktop...
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=yes
	echo Please select "Allow connections only from computers running Remote Desktop with Network Level Authentication (more secure)"
	start SystemPropertiesRemote.exe /wait
	echo Enabled remote desktop
	goto:EOF
)
if %rdpChk%==n (
	echo Disabling remote desktop...
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=no
	echo Disabled remote desktop
	goto:EOF
)
echo Invalid input %rdpChk%
goto rdp

:verifySys
sfc /verifyonly
goto:EOF

:stigServer
echo stigServer
:: Danger - Schroder wrote this
:: V-73669
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictAnonymous /t REG_DWORD /d 1 /f 
::V-73545
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
:: V-73547
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoAutorun /t REG_DWORD /d 1 /f
:: V-73667
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
:: V-73549
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 1 /f
:: V-73599
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service /v AllowBasic /t REG_DWORD /d 0 /f
::enableDefender
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender /v DisableAntiSpyware /t REG_DWORD /d 0 /f
::V-73691
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
::V-73675
reg add HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
::V-73687
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v NoLMHash /t REG_DWORD /d 1 /f
::V-78123 smb1 disable
reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v SMB1 /t REG_DWORD /d 0 /f
::V-73497
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest /v UseLogonCredential /t REG_DWORD /d 0 /f
::V-73559 Enable SmartScreen
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\System /v EnableSmartScreen /t REG_DWORD /d 1 /f
goto:EOF

