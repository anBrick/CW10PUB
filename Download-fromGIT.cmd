rem download Windows Workstation Post Install Config from GIT & run
rem run escalated
rem check internet

rem check Escalated
IF EXIST %SYSTEMROOT%\SYSTEM32\WDI\LOGFILES GOTO GOTADMIN
color 4f
Echo !! U R NOT ADMIN DUDE! PLEASE RUN THIS SCRIPT AGAIN ESCALATED!!!
timeout /t 15
EXIT
:GOTADMIN
rem check Internet

cd %SYSTEMROOT%\temp
md oobc
cd oobc
color 2f

rem Download OOB Config & RUN
del Config-W10installed.cmd
wget -N --tries=1 --timeout=5 "https://raw.githubusercontent.com/anBrick/CW10PUB/main/Config-W10installed.cmd"
if exist Config-W10installed.cmd (
	color 2f
	echo Config-W10installed.cmd downloaded. Execution begin
   start /wait Config-W10installed.cmd
   rem del Config-W10installed.cmd
) else (
	color 4f
   echo Unable to download Config-W10installed.cmd :(
)

rem Download Choco install & RUN :: Install-Chocolately.CMD
del Install-Chocolately.CMD
wget -N --tries=1 --timeout=5 "https://raw.githubusercontent.com/anBrick/CW10PUB/main/Install-Chocolately.CMD"
if exist Install-Chocolately.CMD (
	color 2f
	echo Install-Chocolately.CMD downloaded. Execution begin
   start /wait Install-Chocolately.CMD
   rem del Install-Chocolately.CMD
) else (
	color 4f
   echo Unable to download Install-Chocolately.CMD :(
)
rem Download KMSconfig & RUN

rem Downooad customization script & RUN
rem curl -kOL "https://raw.githubusercontent.com/anBrick/CW10PUB/main/Customize-USERDesktop.cmd"
del Customize-USERDesktop.cmd
wget -N --tries=1 --timeout=5 "https://raw.githubusercontent.com/anBrick/CW10PUB/main/Customize-USERDesktop.cmd"
if exist Customize-USERDesktop.cmd (
	color 2f
	echo Customize-USERDesktop.cmd downloaded. Execution begin
   start /wait Customize-USERDesktop.cmd
   rem del Customize-USERDesktop.cmd
) else (
	color 4f
   echo Unable to download Customize-USERDesktop.cmd :(
)

