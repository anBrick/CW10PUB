@echo off
rem check Escalated
IF EXIST %SYSTEMROOT%\SYSTEM32\WDI\LOGFILES GOTO GOTADMIN
color 4f
Echo !! U R NOT ADMIN DUDE! PLEASE RUN THIS SCRIPT AGAIN ESCALATED!!!
timeout /t 15
EXIT
:GOTADMIN

@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command " [System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"

choco feature enable -n allowGlobalConfirmation
choco feature enable -n useRememberedArgumentsForUpgrades
choco feature enable -n ignoreInvalidOptionsSwitches
rem choco list --local-only

choco install chocolatey-core.extension

rem install mandatory apps
TIMEOUT /T 3
choco install autohotkey.portable

choco install vcredist-all
choco install LAVFilters
choco install vlc
choco install croc
choco install sumatrapdf
choco install sysinternals --params "/InstallDir:C:\WINDOWS"

choco install hackfont

TIMEOUT /T 5
rem install optional apps
Choice /M "Do you want to install RUSTDesk (remote support tool)?"
IF %ERRORLEVEL% EQU 1 choco install rustdesk
Choice /M "Do you want to install xnviewmp?"
IF %ERRORLEVEL% EQU 1 choco install xnviewmp.install
Choice /M "Do you want to install tixati?"
IF %ERRORLEVEL% EQU 1 choco install tixati

Choice /M "Do you want to install gsmartcontrol?"
IF %ERRORLEVEL% EQU 1 choco install gsmartcontrol smartmontools
Choice /M "Do you want to install rdpwrapper?"
IF %ERRORLEVEL% EQU 1 choco install rdpwrapper 

Choice /M "Do you want to install putty?"
IF %ERRORLEVEL% EQU 1 choco install putty.install
Choice /M "Do you want to install synctrayzor?"
IF %ERRORLEVEL% EQU 1 choco install synctrayzor
Choice /M "Do you want to install zerotier-one?"
IF %ERRORLEVEL% EQU 1 choco install zerotier-one

Choice /M "Do you want to install Mozilla Firefox?"
IF %ERRORLEVEL% EQU 1 choco install firefox

Choice /M "Do you want to install microsoft-edge?"
IF %ERRORLEVEL% EQU 1 choco install microsoft-edge
Choice /M "Do you want to install microsoft-skype?"
IF %ERRORLEVEL% EQU 1 choco install skype
Choice /M "Do you want to install microsoft-teams?"
IF %ERRORLEVEL% EQU 1 choco install microsoft-teams
Choice /M "Do you want to install Adobe Reader PDF?"
IF %ERRORLEVEL% EQU 1 choco install adobereader

Choice /M "Do you want to install JAVA?"
IF %ERRORLEVEL% EQU 1 choco install jre8  
Choice /M "Do you want to install gpg4win-vanilla?"
IF %ERRORLEVEL% EQU 1 choco install gpg4win-vanilla 
Choice /M "Do you want to install vcredist2013?"
IF %ERRORLEVEL% EQU 1 chocolatey install vcredist2013
Choice /M "Do you want to install vcredist2005?"
IF %ERRORLEVEL% EQU 1 chocolatey install vcredist2005
Choice /M "Do you want to install vcredist2007?"
IF %ERRORLEVEL% EQU 1 chocolatey install vcredist2017

TIMEOUT /T 15
rem choco install synctrayzor 
rem choco install zerotier-one
rem chocolatey install openvpn
rem chocolatey install owncloud-client
rem chocolatey install PowerShell
rem chocolatey install rocketchat
rem chocolatey install tixati
rem choco install secunia.psi
rem choco install linkshellextension 
rem choco install doublecmd 
rem choco install smartmontools
rem chocolatey install DotNet4.5.2
rem choco install dotnetfx
rem choco install AdobeAIR

rem choco update task
%systemroot%\System32\schtasks.exe /create /F /sc MONTHLY /MO THIRD /D THU /ST 12:10 /tn "CHOCO UPDATES" /RL HIGHEST /ru "SYSTEM" /tr "cmd.exe /c cup all -y"
 