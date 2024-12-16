<#
.SYNOPSIS
Configures Microsoft Edge using group policies.

.DESCRIPTION
The script configures Microsoft Edge by creating group policy settings in the registry.
You can set the policies for all users or for the current user only.

.PARAMETER scope
Accepts HKLM (all users, default behavior) or HKCU (current user).

.EXAMPLE
PS> .\edge-policy.ps1
Applies the policy to the current user only.

.EXAMPLE
PS> .\context-menu.ps1 -scope HKLM
Applies the policy to all users.

.LINK
Blog: https://www.outsidethebox.ms/22326
Documentation: https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies
#>

# # # # # # # # # # # # # # # # # # # # 
# параметр, задающий область применения политик
param(
    [Parameter()]
    [string]$scope = 'HKLM'
    )

if ( ($scope -ne 'HKCU') -and ($scope -ne 'HKLM') ) {
	Write-Error 'Unacceptable scope. Use HKLM or HKCU.' -ErrorAction Stop
	}

# # # # # # # # # # # # # # # # # # # # 
# создание раздела форсируемых политик, если его нет
$path = "$($scope):SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path $(Split-Path $path -Parent) -Name $(Split-Path $path -Leaf) -ErrorAction SilentlyContinue | Out-Null
$searchpath = "$($scope):SOFTWARE\Policies\Microsoft\Edge\DefaultSearchProviderSearchURL"
New-Item -Path $(Split-Path $searchpath -Parent) -Name $(Split-Path $searchpath -Leaf) -ErrorAction SilentlyContinue | Out-Null

# # # # # # # # # # # # # # # # # # # # 
# политики
[hashtable]$hash = @{

# # # # # # # # # # # # # # # # # # # # 
# первый запуск браузера

# отключить предложение первоначальной настройки персонализации
HideFirstRunExperience = 1
# запретить автоматический импорт данных из других браузеров
AutoImportAtFirstRun = 4
# запретить синхронизацию и предложение включить ее
# SyncDisabled = 1
# запретить вход в браузер и предложение войти (также отключает синхронизацию)
BrowserSignin = 0

# # # # # # # # # # # # # # # # # # # # 
# новая вкладка

# удалить заданные адреса домашней страницы и новой вкладки
# Remove-ItemProperty -Path $path -Name HomePageLocation -ErrorAction SilentlyContinue
# Remove-ItemProperty -Path $path -Name NewTabPageLocation -ErrorAction SilentlyContinue

# вид и содержимое новой вкладки
NewTabPageContentEnabled = 0
NewTabPageQuickLinksEnabled = 0
NewTabPageHideDefaultTopSites = 1
# NewTabPageAllowedBackgroundTypes: DisableImageOfTheDay = 1, DisableCustomImage = 2, DisableAll = 3
NewTabPageAllowedBackgroundTypes = 3

# # # # # # # # # # # # # # # # # # # # 
# прочие раздражители

# отключить кнопку бинг/копилот 
# https://t.me/sterkin_ru/1465
HubsSidebarEnabled = 0
# отключить предложение персонализировать веб-серфинг
# https://t.me/sterkin_ru/1473
PersonalizationReportingEnabled = 0
# отключить переход в поисковик после ввода адреса сайта в адресную строку
# https://t.me/sterkin_ru/1514
SearchSuggestEnabled = 0
# отключить предложение восстановить страницы после неожиданного завершения работы
# https://t.me/sterkin_ru/1421
# HideRestoreDialogEnabled = 1
# отключить всякие рекомендации
SpotlightExperiencesAndRecommendationsEnabled = 0
ShowRecommendationsEnabled = 0
# отключить визуальный поиск (оверлей на изображениях)
VisualSearchEnabled = 0
# отключить мини-меню при выделении текста
QuickSearchShowMiniMenu = 0
# Enable Default Search Engine
DefaultSearchProviderEnabled = 1
AddressBarMicrosoftSearchInBingProviderEnabled = 0
AdsSettingForIntrusiveAdsSites = 2
DefaultSearchProviderName = 'Google'
DefaultSearchProviderSearchURL = 'url: {google:baseURL}search?q=%s&{google:RLZ}{google:originalQueryForSuggestion}{google:assistedQueryStats}{google:searchFieldtrialParameter}{google:iOSSearchLanguage}{google:searchClient}{google:sourceId}{google:contextualSearchVersion}ie={inputEncoding}'
DefaultSearchProviderSuggestURL = '{google:baseURL}complete/search?output=chrome&q={searchTerms}'
# Other tweaks
ConfigureDoNotTrack = 1
EdgeShoppingAssistantEnabled = 0
}

# # # # # # # # # # # # # # # # # # # # 
# запись политик в реестр 

foreach ($key in $hash.keys) {
	if (($hash[$Key]).GetType().Name -match 'byte|short|int32|long|sbyte|ushort|uint32|ulong|float|double|decimal') {New-ItemProperty -Path $path -Name $key -PropertyType Dword -Value $($hash[$Key]) -Force | Out-Null}
	else {New-ItemProperty -Path $path -Name $key -PropertyType String -Value $($hash[$Key]) -Force | Out-Null}
    
}

# # # # # # # # # # # # # # # # # # # #
# Configure Default Search Engine
New-ItemProperty -Path $searchpath -Name "1" -Value 'https://www.google.com/search?q={searchTerms}' -Force | Out-Null


# # # # # # # # # # # # # # # # # # # # 
# применение настроек

# завершить все процессы браузера у текущего пользователя
Get-Process msedge -IncludeUserName -ErrorAction SilentlyContinue | where UserName -match $ENV:USERNAME | Stop-Process

# обновить политики
if ($scope -eq 'HKCU') { gpupdate /force /target:user }
else { gpupdate /force /target:computer }	