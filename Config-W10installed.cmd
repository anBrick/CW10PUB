rem check Escalated
IF EXIST %SYSTEMROOT%\SYSTEM32\WDI\LOGFILES GOTO GOTADMIN
color 4f
Echo !! U R NOT ADMIN DUDE! PLEASE RUN THIS SCRIPT AGAIN ESCALATED!!!
timeout /t 15
EXIT
:GOTADMIN

rem Startin Download Windows Update packs
UsoClient /StartDownload
REM Calling WIN Update
wuauclt /detectnow /updatenow
rem Disable Defender Tamper Protection and other Defender features
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 0 /f
rem disable Defender 
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; Set-MpPreference -PUAProtection disable"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; Set-MpPreference -DisableRealtimeMonitoring $true"
rem Disable Telemetry
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f
reg ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f 
sc config DiagTrack start= disabled
sc config dmwappushservice start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
color 2f
timeout /t 10
color 0f
REM --- Disable job scheduler to collect your information to send, and others. --- 
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\HypervisorFlightingTask" /Disable 
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable 
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable 
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable
DEL /p C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
REM --- The frequency of the formation of reviews "Never" ---
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f 
color 2f
timeout /t 10
color 0f
rem Disable Cortana
rem reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0
rem Solve Error 513
sc sdset MSLLDP D:(D;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BG)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)(A;;LCRPWP;;;S-1-5-80-3141615172-2057878085-1754447212-2405740020-3916490453)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
rem Enable net connections for elevated processes
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLinkedConnections /t REG_DWORD /d 1 /f
rem Enable Adv Boot options
bcdedit /set {bootmgr} displaybootmenu yes
bcdedit /timeout 4
rem Enable MS INstaller in SAFE Mode
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\MSIServer" /VE /T REG_SZ /F /D "Service"
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\MSIServer" /VE /T REG_SZ /F /D "Service"
rem Enable Last Known Good
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v BackupCount /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration ManagerLastKnownGood"
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager\LastKnownGood" /v Enabled /t REG_DWORD /d 1 /f
rem disable first logon animation
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v EnableFirstLogonAnimation  /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableFirstLogonAnimation  /t REG_DWORD /d 0 /f
rem Speedup app startup
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /V StartupDelayInMSec /t REG_DWORD /d 0 /f
rem configure MSEdge
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v HideFirstRunExperience /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v AutoImportAtFirstRun /t REG_DWORD /d 4 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v BrowserSignin /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageContentEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageQuickLinksEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageHideDefaultTopSites /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageAllowedBackgroundTypes /t REG_DWORD /d 3 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v HubsSidebarEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v PersonalizationReportingEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SearchSuggestEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SpotlightExperiencesAndRecommendationsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v ShowRecommendationsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v VisualSearchEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v QuickSearchShowMiniMenu /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderEnabled /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v AddressBarMicrosoftSearchInBingProviderEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v AdsSettingForIntrusiveAdsSites /t REG_DWORD /d 2 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderName /t REG_SZ /d "Google" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderSearchURL /t REG_SZ /d "url: {google:baseURL}search?q=%s&{google:RLZ}{google:originalQueryForSuggestion}{google:assistedQueryStats}{google:searchFieldtrialParameter}{google:iOSSearchLanguage}{google:searchClient}{google:sourceId}{google:contextualSearchVersion}ie={inputEncoding}" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderSuggestURL /t REG_SZ /d "{google:baseURL}complete/search?output=chrome&q={searchTerms}" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v ConfigureDoNotTrack /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v EdgeShoppingAssistantEnabled /t REG_DWORD /d 0 /f 
rem install optional componets
@echo off
color 5f
echo Please Insert Windows Instalation source in any drive...
timeout /t 25
color 0f
Title Components Installer
for %%I in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist "%%I:\\sources\install.wim" set setupdrv=%%I
if defined setupdrv (
echo Found drive %setupdrv%
echo Installing components...
Dism /online /enable-feature /featurename:NetFX3 /All /Source:%setupdrv%:\sources\sxs /LimitAccess
Dism /online /enable-feature /featurename:TelnetClient /All /Source:%setupdrv%:\sources\sxs /LimitAccess
Dism /online /enable-feature /featurename:Printing-PrintToPDFServices-Features /All /Source:%setupdrv%:\sources\sxs /LimitAccess
Dism /online /enable-feature /featurename:Windows-Defender-ApplicationGuard /All /Source:%setupdrv%:\sources\sxs /LimitAccess
Dism /online /enable-feature /featurename:WindowsMediaPlayer /All /Source:%setupdrv%:\sources\sxs /LimitAccess
Dism /online /enable-feature /featurename:MediaPlayback /All /Source:%setupdrv%:\sources\sxs /LimitAccess
Dism /online /enable-feature /featurename:WorkFolders-Client /All /Source:%setupdrv%:\sources\sxs /LimitAccess
rem Dism /online /Enable-Feature /FeatureName:Client-UnifiedWriteFilter /All /Source:%setupdrv%:\sources\sxs /LimitAccess /NoRestart
rem Dism /online /enable-feature /featurename:SNMP /All /Source:%setupdrv%:\sources\sxs /LimitAccess
rem Dism /online /enable-feature /featurename:WMISnmpProvider /All /Source:%setupdrv%:\sources\sxs /LimitAccess
echo.
echo components were installed
echo.
) else (
color 4f
echo No installation media found!
echo Insert DVD or USB flash drive and run this file once again. 
echo.
timeout /t 15
)
color 0f
rem config remote management
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-PSRemoting -Force"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Set-Item wsman:\localhost\client\trustedhosts *"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-WSManCredSSP -Role server"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Restart-Service WinRM"
rem add firewall rules for RM
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-NetFireWallRule -DisplayName 'Windows Management Instrumentation (DCOM-In)'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-NetFireWallRule -DisplayName 'Windows Remote Management (HTTP-In)'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-NetFireWallRule -DisplayGroup 'Windows Firewall Remote Management'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-NetFireWallRule -DisplayGroup 'Windows Defender Firewall Remote Management'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-NetFireWallRule -DisplayGroup 'Remote Scheduled Tasks Management'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-NetFireWallRule -DisplayGroup 'Remote Event Log Management'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-NetFireWallRule -DisplayGroup 'Remote Service Management'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-NetFireWallRule -DisplayGroup 'Remote Volume Management'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-NetFireWallRule -DisplayGroup 'File and Printer Sharing'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-NetFireWallRule -DisplayGroup 'Windows Management Instrumentation (WMI)'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Enable-NetFireWallRule -DisplayGroup 'Windows Remote Management'"
rem configure AV Exclusions
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Add-MpPreference -ExclusionPath c:\Windows\System32\spool"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Add-MpPreference -ExclusionPath 'c:\Program Files\RDP Wrapper'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Add-MpPreference -ExclusionPath 'c:\AT'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Add-MpPreference -ExclusionPath 'c:\ProgramData\chocolatey'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Add-MpPreference -ExclusionPath 'c:\Program Files\Oinstall'"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Add-MpPreference -ExclusionProcess oinstall.exe"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Add-MpPreference -ExclusionProcess RDPWInst.exe"
color 2f
timeout /t 6
rem install KMS ServersManager
for %%I in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist "%%I:\\OOB\\kmsmgr.zip" set OIN="%%I:\OOB"
powershell.exe -nologo -noprofile -command "& { $shell = New-Object -COM Shell.Application; $target = $shell.NameSpace((Resolve-Path $ENV:OIN).Path); $zip = $shell.NameSpace((Resolve-Path ($ENV:OIN + '\kmsmgr.zip')).Path); $target.CopyHere($zip.Items(), 16); }"
for %%I in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist "%%I:\\KMSServersManager\\KMSServersManager.cmd" set OIN="%%I:\KMSServersManager"
for %%I in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist "%%I:\\OOB\\KMSServersManager\\KMSServersManager.cmd" set OIN="%%I:\OOB\KMSServersManager"
if defined OIN (
echo Found drive %OIN%
echo Installing components...
xcopy "%OIN%" "c:\Program Files" /C /R /S /I /Y
call "c:\Program Files\KMSServersManager\KMSServersManager.cmd"
call "c:\Program Files\KMSServersManager\Install_Task_KMSServersManager.cmd"
echo components were installed
echo.
) else (
color 4f
echo No KMSServersManager found!
echo Insert USB flash drive and run this command once again.
echo.
rem install OINSTALL
for %%I in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist "%%I:\\OINSTALL\\OInstall.exe" set OIN="%%I:\OINSTALL"
for %%I in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist "%%I:\\OOB\\OInstall.exe" set OIN="%%I:\OOB"
for %%I in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist "%%I:\\OOB\\OINSTALL\\OInstall.exe" set OIN="%%I:\OOB\OINSTALL"
if defined OIN (
echo Found drive %OIN%
echo Installing components...
xcopy "%OIN%" "c:\Program Files" /C /R /S /I /Y
MKLINK C:\Users\Public\Desktop\OINSTALL.EXE "c:\Program Files\OINSTALL\OINSTALL.EXE"
echo components were installed
echo.
) else (
color 4f
for %%I in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist "%%I:\\OOB" set OIN="%%I:\OOB"
for /f "delims=" %%i in ('dir %OIN% /s /b ^| findstr /i .7z ^| findstr /i office') do echo %%~i
echo.
timeout /t 15
)
REM SET CZ-Locale
@echo off
echo ^<gs:GlobalizationServices xmlns:gs="urn:longhornGlobalizationUnattend"^> >.\czlocale.xml
echo ^<gs:UserList^> >>.\czlocale.xml
echo ^<gs:User UserID="Current" CopySettingsToDefaultUserAcct="false" CopySettingsToSystemAcct="false"/^> >>.\czlocale.xml
echo ^</gs:UserList^> >>.\czlocale.xml
echo ^<!-- system locale --^>^<gs:SystemLocale Name="cs-CZ" /^> >>.\czlocale.xml
echo ^<gs:MUILanguagePreferences^> >>.\czlocale.xml
echo ^<gs:MUILanguage Value="en-US"/^> >>.\czlocale.xml
echo ^<gs:MUIFallback Value="en-US"/^> >>.\czlocale.xml
echo ^</gs:MUILanguagePreferences^> >>.\czlocale.xml
echo ^<!-- user locale --^> >>.\czlocale.xml
echo ^<gs:UserLocale^> >>.\czlocale.xml
echo ^<gs:Locale Name="cs-CZ" SetAsCurrent="true" ResetAllSettings="false"^> >>.\czlocale.xml
echo ^</gs:Locale^> >>.\czlocale.xml
echo ^</gs:UserLocale^> >>.\czlocale.xml
echo ^</gs:GlobalizationServices^> >>.\czlocale.xml
control.exe ".\czlocale.xml"
xcopy ".\czlocale.xml" "C:\ProgramData\" /C /R /S /I /Y
echo control.exe "C:\ProgramData\czlocale.xml" >"C:\Users\Public\Desktop\Set-CZlocale.cmd"
REM Setting CETIME
tzutil /s "Central Europe Standard Time"
color 0f
timeout /t 5
del /Q /F %LocalAppData%\Microsoft\Windows\ActionCenterCache

REM Disable WU Desktop Notification:

cd /d "%Windir%\System32"
takeown /f musnotification.exe
icacls musnotification.exe /deny Everyone:(X)
takeown /f musnotificationux.exe
icacls musnotificationux.exe /deny Everyone:(X)

rem Call Coco install batch
rem call "Install-Chocolately.CMD"

rem Cleaning Image
vssadmin delete shadows /All /Quiet
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
del %windir%\SoftwareDistribution\Download\*.* /f /s /q
Cleanmgr /sagerun:1
for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"
Clear-RecycleBin -Force

rem Enable Defender Tamper Protection 
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 5 /f
rem Enable Defender 
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; Set-MpPreference -DisableRealtimeMonitoring $false"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; Set-MpPreference -PUAProtection enable"