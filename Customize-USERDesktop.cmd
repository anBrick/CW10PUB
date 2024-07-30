@echo off
color 0f

REM Change Default User registry keys...
reg load HKU\DefaultUser c:\users\default\ntuser.dat

REM Advertising ID disabled
reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f

REM Disable Game DVR
reg add "HKU\DefaultUser\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f

REM Set Google as default search provider in IE
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Internet Explorer\SearchScopes" /v DefaultScope /t REG_SZ /d {e913ede7-630e-4d2a-a6af-2b28e7ce735b} /f
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{e913ede7-630e-4d2a-a6af-2b28e7ce735b}" /v DisplayName /t REG_SZ /d Google /f
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{e913ede7-630e-4d2a-a6af-2b28e7ce735b}" /v FaviconURL /t REG_SZ /d https://www.google.com/favicon.ico /f
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{e913ede7-630e-4d2a-a6af-2b28e7ce735b}" /v ShowSearchSuggestions /t REG_DWORD /d 1 /f
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{e913ede7-630e-4d2a-a6af-2b28e7ce735b}" /v SuggestionsURL /t REG_SZ /d "https://www.google.com/complete/search?q={searchTerms}&client=ie8&mw={ie:maxWidth}&sh={ie:sectionHeight}&rh={ie:rowHeight}&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{e913ede7-630e-4d2a-a6af-2b28e7ce735b}" /v URL /t REG_SZ /d "https://www.google.com/search?q={searchTerms}&sourceid=ie7&rls=com.microsoft:{language}:{referrer:source}&ie={inputEncoding?}&oe={outputEncoding?}" /f
rem Setup MSEdge
reg.exe add "HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v HideFirstRunExperience /t REG_DWORD /d 1 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v AutoImportAtFirstRun /t REG_DWORD /d 4 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v BrowserSignin /t REG_DWORD /d 0 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageContentEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageQuickLinksEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageHideDefaultTopSites /t REG_DWORD /d 1 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageAllowedBackgroundTypes /t REG_DWORD /d 3 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v HubsSidebarEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v PersonalizationReportingEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v SearchSuggestEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v SpotlightExperiencesAndRecommendationsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v ShowRecommendationsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v VisualSearchEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v QuickSearchShowMiniMenu /t REG_DWORD /d 0 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderEnabled /t REG_DWORD /d 1 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v AddressBarMicrosoftSearchInBingProviderEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v AdsSettingForIntrusiveAdsSites /t REG_DWORD /d 2 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderName /t REG_SZ /d "Google" /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderSearchURL /t REG_SZ /d "url: {google:baseURL}search?q=%s&{google:RLZ}{google:originalQueryForSuggestion}{google:assistedQueryStats}{google:searchFieldtrialParameter}{google:iOSSearchLanguage}{google:searchClient}{google:sourceId}{google:contextualSearchVersion}ie={inputEncoding}" /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderSuggestURL /t REG_SZ /d "{google:baseURL}complete/search?output=chrome&q={searchTerms}" /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v ConfigureDoNotTrack /t REG_DWORD /d 1 /f
reg.exe add "HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Edge" /v EdgeShoppingAssistantEnabled /t REG_DWORD /d 0 /f 

rem Disable MS Office Welkom prompt
reg add "HKU\DefaultUser\Software\Policies\Microsoft\Office\16.0\common\general" /V FirstRun /t REG_DWORD /d 00000000 /f
reg add "HKU\DefaultUser\Software\Policies\Microsoft\Office\16.0\common\general" /V ShownFirstRunOptin /t REG_DWORD /d 00000001 /f
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Office\16.0\Registration" /V AcceptAllEulas /t REG_DWORD /d 00000001 /f
reg add "HKU\DefaultUser\Software\Policies\Microsoft\Office\16.0\common\general" /V ShownOptIn /t REG_DWORD /d 00000001 /f
reg add "HKU\DefaultUser\Software\Policies\Microsoft\Office\16.0\common\general" /V OptInDisable /t REG_DWORD /d 00000001 /f

rem put My Computer icon on desktop
reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /t REG_DWORD /d 0 /f
reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /t REG_DWORD /d 0 /f

rem Enable autocomplete in RUN
reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "Append Completion" /t REG_DWORD /d 1 /f
REM Change LaguageID to CZ
reg add "HKU\DefaultUser\Control Panel\Desktop" /v MultiUILanguageId /t REG_DWORD /d 405 /f
reg import International.reg

rem Prevent OneDrive Installation
reg delete "HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f


REM Save RED DATA
reg unload HKU\DefaultUser
color 2f
timeout /t 4
color 0f


rem configure icons on desktop
rem rundll32.exe shell32.dll,Control_RunDLL desk.cpl,,0