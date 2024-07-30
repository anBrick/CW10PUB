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
control.exe .\czlocale.xml