<#	
	.NOTES
	===========================================================================
	 Created with: 	PowerShell
	 Updated:	09.01.2023 - select NIC to configure LAN IP; Install WAC by Choco
	 Created on:   	26.02.2021 10:02
	 Created by:   	vlad jandjuk, jandjuk@o30.cz
	 Organization: 	O30
	 Filename:     	Deploy-DomainServer.ps1
	===========================================================================
	.DESCRIPTION
		Basic Config Fresh Windows Server Installation
#>
#GLOBAL VARS AND CONSTANTS
$ErrorActionPreference = "SilentlyContinue"
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[String]$GLOBAL:WorkingFolder = ($ENV:windir + "\Temp")
[String]$GLOBAL:LogFolder = $ENV:HomeDrive
[String]$GLOBAL:StageDoneFileName = "\StageDone.txt"
[Boolean]$GLOBAL:OnLan = $true
[Boolean]$GLOBAL:OnInternet = $true

Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value ByPass
Set-Location $GLOBAL:WorkingFolder
#Verify Escalated Execution and x64 environment
#############################################################################
#If Powershell is running the 32-bit version on a 64-bit machine, we 
#need to force powershell to run in 64-bit mode .
#############################################################################
if (($pshome -like "*syswow64*") -and ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -like "64*"))
{
	write-warning "Restarting script under 64 bit powershell"
	
	# relaunch this script under Escalated 64 bit shell
	#& (join-path ($pshome -replace "syswow64", "sysnative")\powershell.exe) -ExecutionPolicy ByPass -file $myinvocation.mycommand.Definition @args
	Start-Process (join-path ($pshome -replace "syswow64", "sysnative")\powershell.exe) "-ExecutionPolicy ByPass -File", ('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
	# This will exit the original powershell process. This will only be done in case of an x86 process on a x64 OS.
	exit
}
else
{
	$IsAdmin = [Security.Principal.WindowsIdentity]::GetCurrent()
	If ((New-Object Security.Principal.WindowsPrincipal $IsAdmin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $FALSE)
	{
		Start-Process powershell.exe "-File", ('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
		exit
	}
	
}

#FUNCTIONS == Service Routines ==
function Test-NetWork
{
	$DGWavailable = Test-Connection -ComputerName (Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1 | Select-Object -ExpandProperty NextHop) -count 1 -Quiet
	if ($DGWavailable) { $GLOBAL:OnLan = $true }
	else { $GLOBAL:OnLan = $false }
	IF ([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet -eq $True) { $GLOBAL:OnInternet = $true }
	else { $GLOBAL:OnInternet = $false }
}
Function Ask-YesOrNo
# Description: Ask a user to answer a question with either yes or no.
# Example use: 
# If (Ask-YesOrNo) { User has confirmed
#	...
#	}
#	Else	{ User did not confirm
#	...
#	}
{
	param ([string]$title = "Confirm",
		[string]$message = "Are you sure?")
	$choiceYes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Answer Yes."
	$choiceNo = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Answer No."
	$options = [System.Management.Automation.Host.ChoiceDescription[]]($choiceYes, $choiceNo)
	$result = $host.ui.PromptForChoice($title, $message, $options, 1)
	switch ($result)
	{
		0 { Return $true }
		1 { Return $false}
	}
}
Function Write-Log
{
	[CmdletBinding()]
	param (
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$LogName,
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Message,
		[Parameter()]
		[ValidateSet('Information', 'Warning', 'Error')]
		[string]$Severity = 'Information'
	)
	switch ($Severity) {
		'Information' 	{Write-Output $Message}
		'Warning'		{Write-Warning $Message}
		'Error'			{Write-Error $Message}
	}  
	[pscustomobject]@{
		Time = (Get-Date -Format g)
		Severity = $Severity
		Message = $Message
	} | Export-Csv -LiteralPath ($GLOBAL:LogFolder + "\" + $LogName) -Append -NoTypeInformation
	$source = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.PSCommandPath)
	if ([string]::IsNullOrEmpty($source)) {$source = [IO.Path]::GetFileNameWithoutExtension($PSCommandPath)}
	if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {[System.Diagnostics.EventLog]::CreateEventSource($source, "Application")} #register EvtLog Source
	Write-EventLog -LogName Application -Source $source -EntryType $Status -EventID 33033 -Message $(( '{0} Runtime message:: {1}') -f $MyInvocation.myCommand.name,$Message) -ea 0 
}

function Save-PersistedState
{
	[CmdletBinding()]
	param (
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[int]$StageDone
	)
	$StageDone | Out-File -FilePath ($GLOBAL:LogFolder + $GLOBAL:StageDoneFileName) -Force
}

function Get-PersistedState
{
	[string]$StageDone = Get-Content -Path ($GLOBAL:LogFolder + $GLOBAL:StageDoneFileName)
	if ([string]::IsNullOrEmpty($StageDone)) { $StageDone = "0"}
	return [int]$StageDone
}
#END FUNCTIONS

#BEGIN MAIN SCRIPT
Test-NetWork
if ($GLOBAL:OnLan) { Write-Log -LogName "OS_Deployment.log" -Message 'Environment : LAN connection available'}
if ($GLOBAL:OnInternet) { Write-Log -LogName "OS_Deployment.log" -Message 'Environment : Internet connection available' }
Write-Host 'This script do basic Windows Server fresh installed host config. The next steps will be done:' -ForegroundColor Green
Write-Host ' > Setup IP address and DNS addresses' -ForegroundColor Green
Write-Host ' > Configure WinRM and RDP for remote access' -ForegroundColor Green
Write-Host ' > Enable besic FW exclusions' -ForegroundColor Green
Write-Host ' > Install Basic features' -ForegroundColor Green
Write-Host ' > Install CHOCO and optional components' -ForegroundColor Green
Write-Host ' > Rename Host and local admin account to LOCALADMIN' -ForegroundColor Green
Write-Host ' > Join Host to Domain' -ForegroundColor Green
Write-Host 'We are going to configure fresh server install. Please, check this mandatory requirements:' -ForegroundColor Yellow
Write-Host ' > You have active NIC (drivers installed and LAN connected)' -ForegroundColor Yellow
Write-Host ' > You have the IP config for this host (IP address, Default GW and DNS servers addresses)' -ForegroundColor Yellow
Write-Host ' > You have the New Name and Domain Name for this host' -ForegroundColor Yellow
Write-Host ' > You have the source ISO attached to any letter (like D:)' -ForegroundColor Yellow
Write-Host ' > You have the Internet Connection for install DLLs and other tools' -ForegroundColor Yellow
Write-Host ('Log is writing to : {0}' -f $GLOBAL:LogFolder)
$Stage = Get-PersistedState
If (!(Ask-YesOrNo -Message ('Are You ready to begin stage {0}?' -f $Stage))) { Write-Host 'You are not ready, skrip was ternminated.'; break}
Write-Log -LogName "OS_Deployment.log" -Message ('Les`s go to the stage {0}' -f $Stage)
switch ($Stage)
{
	"0" {
		#BLOCK 0 == Set Host IP config ==
			if (([object[]](Get-NetAdapter)).count -lt 1) {Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : No NIC, Skip Network Config. Try to install custom NIC Drivers') -Severity 'Error'} #No NIC installed
			else {
				Write-Host ('Running Stage {0}. Setting Host IP Configuration...' -f $Stage)
				$LANNICs = Get-NetAdapter | where {$_.Status -eq 'Up' -and $_.Name -match 'Ether'}
				if (!$LANNICs) { 
					Write-Host 'You have no active network connection. Please select a NIC for LAN (Domain network)';
					$LANNIC = Get-NetAdapter | Out-Gridview -Title "Select a NIC for LAN (Domain network)" -OutputMode Single
				}
				else { #Select an Active NIC for config
					$LANNIC = $LANNICs | Out-Gridview -Title "Select a NIC for LAN (Domain network)" -OutputMode Single
				}
				If (Ask-YesOrNo -Message 'Set IP for $LANNIC ?') {
					Write-Host ('Going to configure IP for the NIC: ' + $LANNIC.Name) 
					while ([string]::IsNullOrEmpty($IPAddress)) { $IPAddress = Read-Host -Prompt 'Enter New Server IP Address:' }
					while ([string]::IsNullOrEmpty($DGW)) { $DGW = Read-Host -Prompt 'Enter Default Gateway Address:' }
					Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Configuring NIC: {3} , Host IP : {1} , Gateway : {2}' -f $Stage, $IPAddress, $DGW, $LANNIC.Name)
					New-NetIPAddress -InterfaceIndex $LANNIC.ifIndex -IPAddress $IPAddress -PrefixLength 24 -DefaultGateway $DGW
					#Setting DNS servers Addresses
					#Externally set input value as string
					[string[]]$DNSAddresses = @()
					while ($DNSAddresses.Count -lt 1) { $DNSAddresses = Read-Host -Prompt 'Enter DNS Addresses separated by comma, like 1.1.1.1,8.8.8.8 :' }
					$DNSAddresses = $DNSAddresses.Split(',').Split(' ')
					Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Configuring DNS Addresses : {1} , {2}' -f $Stage, $DNSAddresses[0], $DNSAddresses[1])
					Set-DnsClientServerAddress -InterfaceIndex $LANNIC.ifIndex -ServerAddresses $DNSAddresses
					Test-NetWork
					if ($GLOBAL:OnLan) { Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: { 0 } : LAN connection available after IP changed.' -f $Stage)}
					if ($GLOBAL:OnInternet) { Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: { 0 } : Internet connection available after IP changed.' -f $Stage)}
				}
				else {Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Skip Network Config by user choise.') -Severity 'Warning'}
			}
		#BLOCK 0 == Configure Time Sync Service for local time sources ==
			& "cmd.exe" "/c w32tm /query /computer:LOCALHOST /configuration"
			& "cmd.exe" "/c w32tm /config /manualpeerlist:'tik.cesnet.cz ntp.nic.cz 2.cz.pool.ntp.org' /syncfromflags:manual /update"
			& "cmd.exe" "/c net stop w32time & net start w32time"
		#BLOCK 0 == Enable PS Remoting ==
			Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Enable PS Remote Access...' -f $Stage)
			Enable-PSRemoting -SkipNetworkProfileCheck -Force
			Set-Item wsman:\localhost\client\trustedhosts *
			Enable-WSManCredSSP -Role server
			Restart-Service WinRM -Force
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : PS Remote Access configured.' -f $Stage)
			#Disable Firewall Temporary
			Get-NetFirewallProfile | Set-NetFirewallProfile -enabled false
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Windows Firewall Disabled.' -f $Stage)
		#BLOCK 0 == Enable Remote Desktop ==
			Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Enable RDP...' -f $Stage)
			#cscript //nologo C:\Windows\System32\Scregedit.wsf /ar 0
			& "cmd.exe" "/c cscript //nologo C:\Windows\System32\Scregedit.wsf /ar 0"
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : RDP configuration done.' -f $Stage)
		#BLOCK 0 == Set FW rules for remote management ==
			Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Add FW rules for remote management...' -f $Stage)
			Enable-NetFireWallRule -DisplayName "Windows Management Instrumentation (DCOM-In)"
			Enable-NetFireWallRule -DisplayName "Windows Remote Management (HTTP-In)"
			try {Enable-NetFireWallRule -DisplayGroup "Windows Firewall Remote Management"}
			catch {Enable-NetFireWallRule -DisplayGroup "Windows Defender Firewall Remote Management" } #(on SERVER 2019+)
			Enable-NetFireWallRule -DisplayGroup "Remote Scheduled Tasks Management"
			Enable-NetFireWallRule -DisplayGroup "Remote Event Log Management"
			Enable-NetFireWallRule -DisplayGroup "Remote Service Management"
			Enable-NetFireWallRule -DisplayGroup "Remote Volume Management"
			Enable-NetFireWallRule -DisplayGroup "File and Printer Sharing"
			Enable-NetFireWallRule -DisplayGroup "Windows Management Instrumentation (WMI)"
			Enable-NetFireWallRule -DisplayGroup "Windows Remote Management"
			Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : FW configured for Remote OS Management.' -f $Stage)
			#Set FW rule for WAC (Honolulu) Need to install later from https://go.microsoft.com/fwlink/?linkid=2220149&clcid=0x409&culture=en-us&country=us
			#Going Installed by Choco below
			New-NetFirewallRule -Name "WAC Honolulu on Port 6516 (in)" -Description "Enable Incoming connection on port TPC:6516 for WAC" -DisplayName "WAC IN 6516" -Enabled:True -Profile Any -Direction Inbound -Action Allow -Protocol TCP -LocalPort 6516
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : FW configured for HONOLULU ON TCP6516.' -f $Stage)
		#BLOCK 0 == Install Basic Windows Features (.NET, Telnet Client etc.) ==
			Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Begin Base Windows Features install...' -f $Stage)
			#Find Instalation source like d:\sources\SXS
			[string]$InstallSource = (get-psdrive -p "FileSystem" | ForEach-Object {Write-host -ForegroundColor Green "Searching for Instalation source" $_.Root; get-childitem -Directory $_.Root -include "SXS" -r -Depth 1 | Select-Object FullName| Select-Object -first 1 }).FullName
			if ([string]::IsNullOrEmpty($InstallSource))
			{
				Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Installation source not found. Please, mount install source for feature installation and try again. Faeture installation skipped' -f $Stage) -Severity Error
				}
			else
			{
				Install-WindowsFeature -Name "Telnet-Client" -Verbose -Source $InstallSource
				Install-WindowsFeature -Name "Net-Framework-Core" -IncludeAllSubFeature -Verbose -Source $InstallSource
				Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Installed Basic Windows Features (Telnet Client, .NET 3.5).' -f $Stage)
			}
			Get-WindowsFeature | Where-Object { $_.installstate -eq "installed" }
		#BLOCK 0 == Increase Event Logs space ==
			get-eventlog * | select Log,OverflowAction,MaximumKilobytes | foreach {Limit-EventLog -LogName $_.log -MaximumSize $((([math]::Ceiling(($_.MaximumKilobytes * 22000)/65536)) * 65536)) -OverflowAction OverwriteAsNeeded -ea 0}
		#BLOCK 0 == Disable Shutdown reason requirements ==
			Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Disable Shutdown reason requirements.' -f $Stage)
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name ShutdownReasonOn -Value 0	
		#BLOCK 0 == Hide Logon background Picture ==
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLogonBackgroundImage" -Value 1
		#BLOCK 0 == Disable Windows Update Notification ==
			Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Disable Windows Update Notification.' -f $Stage)
			Get-ScheduledTask -TaskPath "\Microsoft\Windows\UpdateOrchestrator\" | Where-Object { $_.Actions.execute -like "*MusNotification*" -and $_.state -eq "Ready" } | Unregister-ScheduledTask
			Invoke-Expression "cmd.exe /c takeown /f %Windir%\System32\musnotification.exe"
			& "cmd.exe" " /c icacls %Windir%\System32\musnotification.exe /deny Everyone:(X)"
			Invoke-Expression "cmd.exe /c takeown /f %Windir%\System32\musnotificationux.exe"
			& "cmd.exe" " /c icacls %Windir%\System32\musnotificationux.exe /deny Everyone:(X)"
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Windows Update Desktop Notification was Disabled.' -f $Stage)
		#BLOCK 0 == Run Windows Update ==
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Try to run Windows Update.' -f $Stage)
			if ($GLOBAL:OnInternet)
			{
				#BLOCK 0 == Run Windows Update and install all updates ==
				#install PSWindowsUpdate from Gallery
				Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. PSWindowsUpdate Module...' -f $Stage)
				Install-Module -Name PSWindowsUpdate
				Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Installed PSWindowsUpdate. Run Windows Update and install latest updates...' -f $Stage)
				if (Get-Module PSWindowsUpdate)
				{
					Get-WindowsUpdate -Download -Verbose
					Install-WindowsUpdate -AcceptAll -Install -force -Verbose
				}
				while ((Get-WUInstallerStatus).IsBusy) { Write-Host ('Running Stage {0}. Installing Windows Updates, please wait...' -f $Stage); Start-Sleep -Seconds 10 }
				Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Windows Updates installed. Reboot OS now...' -f $Stage)
			}
			else { Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Windows Updates installation skipped. No Internet connection.' -f $Stage) -Severity 'Warning'}
		#Set Windows Update to Download Only
		& "cmd.exe" "/c cscript C:\Windows\System32\Scregedit.wsf /AU /v 3"
		#BLOCK 0 IS DONE == REBOOT OS ==
			Save-PersistedState ([int]$Stage + 1)
			Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Windows Updates installed. Reboot OS now.' -f $Stage)
			Start-sleep -Seconds 6
			Restart-Computer -Force
			break
	}
	"1" {
		#BLOCK 1 == Install DLLs, tools and applications ==
		#Disable Windows Defender temporary
			Set-MpPreference -DisableRealtimeMonitoring $true
			Test-NetWork
			if ($GLOBAL:OnInternet)
			{
				Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Begin CHOCOLATELY installations...' -f $Stage)
				Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
				Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Chocolately been installed.' -f $Stage)
				choco feature enable -n allowGlobalConfirmation
				choco feature enable -n useRememberedArgumentsForUpgrades
				choco feature enable -n ignoreInvalidOptionsSwitches
				choco list --local-only
				Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Begin install tools by Chocolately...' -f $Stage)
				choco install chocolatey-core.extension
				choco install autohotkey.portable
				choco install hackfont
				choco install sysinternals --params "'/InstallDir:C:\WINDOWS'"
				choco install vcredist-all
				choco install windows-admin-center --params "'/Port:6516'"
				choco install idle-logoff
				#choco install rdpwrapper
				choco install linkshellextension
				choco install totalcommander --params="'/InstallPath=c:\totalcmd'"
				choco install croc
				choco install sumatrapdf
				Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Tools installation finished.' -f $Stage)
			}
			else { Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : CHOCO installation skipped. No Internet connection.' -f $Stage) -Severity 'Warning'}
		#BLOCK 1 == Create Choco Update TASK ==
			Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Create CHOCO update task (weekly).' -f $Stage)
			$chocotask = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c cup all -y'
			$chocotasktrigger = New-ScheduledTaskTrigger -Weekly -At 4AM -RandomDelay (new-Timespan -Minutes 15) -DaysOfWeek 0, 3, 6
			Register-ScheduledTask -TaskName "CHOCO UPDATES WEEKLY" -Action $chocotask -Trigger $chocotasktrigger -Description "Update CHOCO Packages" -User "SYSTEM" -RunLevel Highest -Force
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Choco Task Created.' -f $Stage)
		#BLOCK 1 == Configure basic AV Exclusions ==
			Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Configure basic AV exclusions...' -f $Stage)
			Add-MpPreference -ExclusionPath c:\Windows\System32\spool
			Add-MpPreference -ExclusionPath %OneDriveConsumer%\APPz\
			Add-MpPreference -ExclusionPath C:\work\
			Add-MpPreference -ExclusionPath %ALLUSERSPROFILE%\chocolatey\
			Add-MpPreference -ExclusionPath "%ProgramFiles%\RDP Wrapper\"
			Add-MpPreference -ExclusionPath %ProgramFiles%\VAS\
			Add-MpPreference -ExclusionProcess rdpwrap.dll
			Add-MpPreference -ExclusionProcess RDPWInst.exe
			Add-MpPreference -ExclusionProcess Oinstall.exe
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Basic AV Exclusions added.' -f $Stage)
		#BLOCK 1 == Enable Firewall ==
			Get-NetFirewallProfile | Set-NetFirewallProfile -enabled true
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : FW Enabled.' -f $Stage)
		#BLOCK 1 == Do a few tweaks ==
		#Disable Download map manager service (do not need at server OS usually)
			Set-Service -Name MapsBroker -StartupType Disabled
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Maps Broker disabled.' -f $Stage)
			Set-Service -Name DiagTrack -StartupType Disabled
			Set-Service -Name dmwappushservice -StartupType Disabled
			Set-Service -Name diagnosticshub.standardcollector.service -StartupType Disabled
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Unnessesary services disabled.' -f $Stage)
		#Set CE Time Zone
			Set-TimeZone -Id "Central Europe Standard Time" -PassThru
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : TimeZone changed To CE and System Locale to cs-CZ.' -f $Stage)
			Set-WinSystemLocale -SystemLocale cs-CZ
		#Install Languages
			Get-InstalledLanguage
			#Install-Language cs-CZ,sk-SK
		#BLOCK 1 IS DONE == REBOOT OS ==
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Stage is done. Reboot OS.' -f $Stage)
			Save-PersistedState ([int]$Stage + 1)
			Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Stage is done. Reboot OS now.' -f $Stage)
			Start-sleep -Seconds 6
		Restart-Computer -Force
		break
	}
	"2" {
		#BLOCK 2 == Rename Local Host ==
			Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Renaming Host and built in Administrator account...' -f $Stage)
			while ([string]::IsNullOrEmpty($NewName)) { $NewName = Read-Host -Prompt 'Enter New Server Name:' }
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Host was renamed. New Name is : {1}' -f $Stage, $NewName)
			Rename-Computer -NewName $NewName
		#BLOCK 2 == Rename Local Adnministrator ==
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Local Administrator was renamed. New Name is : .\LOCALADMIN' -f $Stage)
			Rename-LocalUser -Name "Administrator" -NewName "localadmin"
		#BLOCK 2 IS DONE == REBOOT OS ==
			Save-PersistedState ([int]$Stage + 1)
			Write-Log -LogName "OS_Deployment.log" -Message 'Reboot will be initiated...  Please use LOCALADMIN username to logon after reboot.' -ForegroundColor Yellow
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Reboot to next stage' -f $Stage)
			Start-sleep -Seconds 6
		Restart-Computer -Force
		break
	}
	"3" {
		#BLOCK 3 == Join Host to Domain ==
			Test-NetWork
			if ($GLOBAL:OnLan)
			{
				If (Ask-YesOrNo -Message 'Join host to DOMAIN?') {
					Write-Log -LogName "OS_Deployment.log" -Message ('Running Stage {0}. Join Computer to Domain, prepare domain name and credentials...' -f $Stage)
					while ([string]::IsNullOrEmpty($DomainName)) { $DomainName = Read-Host -Prompt 'Enter Domain Name To Join:' }
					Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Computer joind to domain {1}' -f $Stage, $DomainName)
					Add-Computer -DomainName $DomainName
				}
				else {Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Skip joining Computer to domain' -f $Stage)}
			}
			else { Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Domain joining skipped. No LAN connection.' -f $Stage) }
			Save-PersistedState ([int]$Stage + 1)
			Write-Log -LogName "OS_Deployment.log" -Message ('STAGE: {0} : Reboot to next stage' -f $Stage)
			Write-Log -LogName "OS_Deployment.log" -Message 'That`s all for now. All settings are set. System will be ready after reboot. Please use LOCALADMIN username to logon.'
			Write-Log -LogName "OS_Deployment.log" -Message 'Last Reboot will be initiated. Do not forget to use .\LOCALADMIN to logon '
			Start-sleep -Seconds 6
		#BLOCK 3 IS DONE == REBOOT OS ==
		Restart-Computer -Force
		break
	}
	default {
        Write-Host ('Undefined Script State. Please, check Log {0} and run again. Tx :)' -f ($GLOBAL:LogFolder + "\" + $LogName))
        Write-Log -LogName "OS_Deployment.log" -Message ('Undefined Script State: {0} ' -f $Stage) -Severity 'Error'
    }
}
# == END SCRIPT ==
