<#
.SYNOPSIS
    MDE Managed EDR Reporting - Microsoft Defender for Endpoint haftalik ve aylik KPI raporu.

.DESCRIPTION
    Haftalik mod  : kisa yonetici ozeti, tek sayfa, gecen tam hafta (Pazartesi-Pazar).
    Aylik mod     : ayrintili 3 bolumlu rapor, trend karsilastirmali, gecen takvim ayi.

.EXAMPLE
    .\New-MDEReport.ps1 -Mode Weekly -DryRun
    .\New-MDEReport.ps1 -Mode Monthly
    .\New-MDEReport.ps1 -Mode Monthly -Date 2026-07-15 -ExportCsv
    .\New-MDEReport.ps1 -Test
#>
[CmdletBinding()]
param(
    [ValidateSet('Weekly','Monthly')][string] $Mode = 'Monthly',
    [datetime] $Date,
    [string]   $ConfigPath,
    [switch]   $DryRun,
    [switch]   $Test,
    [switch]   $ExportCsv,
    [switch]   $Pdf,
    [string]   $ProxyUrl
)

$ErrorActionPreference = 'Stop'
$script:Root = $PSScriptRoot
. (Join-Path $script:Root 'MDEReport.Core.ps1')
. (Join-Path $script:Root 'MDEReport.Html.ps1')

if (-not $ConfigPath) { $ConfigPath = Join-Path $script:Root 'customer.json' }
if (-not (Test-Path $ConfigPath)) { throw "Yapilandirma bulunamadi: $ConfigPath  (once Install-MDEReport.ps1 calistirin)" }
$cfg = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json

if ($ProxyUrl) { [Net.WebRequest]::DefaultWebProxy = New-Object Net.WebProxy($ProxyUrl) }
elseif ($cfg.ProxyUrl) { [Net.WebRequest]::DefaultWebProxy = New-Object Net.WebProxy($cfg.ProxyUrl) }

foreach ($d in 'Output','Archive','Logs') {
    $p = Join-Path $script:Root $d
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}
$script:LogFile = Join-Path $script:Root ('Logs\{0}-{1}.log' -f $Mode.ToLower(), (Get-Date -Format 'yyyyMMdd-HHmmss'))

# --------------------------------------------------------------- donem ------
function Get-Period {
    param([string]$Mode, [datetime]$Ref, [bool]$Explicit)
    if ($Mode -eq 'Weekly') {
        # Referans gunun icinde bulundugu haftanin pazartesisi
        $dow = [int]$Ref.DayOfWeek; if ($dow -eq 0) { $dow = 7 }   # Pazar = 7
        $thisMon = $Ref.Date.AddDays(1 - $dow)
        # Tarih verilmediyse gecen tam hafta, verildiyse o tarihin haftasi
        $start = if ($Explicit) { $thisMon } else { $thisMon.AddDays(-7) }
        return @{ Start = $start; End = $start.AddDays(7) }
    }
    $first = (Get-Date -Year $Ref.Year -Month $Ref.Month -Day 1).Date
    $start = if ($Explicit) { $first } else { $first.AddMonths(-1) }
    return @{ Start = $start; End = $start.AddMonths(1) }
}

$explicit = $PSBoundParameters.ContainsKey('Date')
$ref      = if ($Date) { $Date } else { Get-Date }
$period   = Get-Period -Mode $Mode -Ref $ref -Explicit $explicit
$start    = $period.Start; $end = $period.End

Write-Log ('=== {0} | {1} raporu | {2:dd.MM.yyyy} - {3:dd.MM.yyyy} ===' -f $cfg.CustomerName, $Mode, $start, $end.AddDays(-1))
Write-Log ('Tenant: {0} | Uygulama: {1} | Kimlik: {2} | Mail: {3}' -f `
    (Get-Masked $cfg.TenantId), (Get-Masked $cfg.ClientId), $cfg.AuthMode, $cfg.Mail.Method)

# ----------------------------------------------------------------- TEST -----
if ($Test) {
    $script:fail = 0
    function Test-Step {
        param([string]$Name, [scriptblock]$Action)
        try { $r = & $Action; Write-Log ("{0,-40} OK   {1}" -f $Name, $r) 'OK' }
        catch { $script:fail++; Write-Log ("{0,-40} HATA {1}" -f $Name, $_.Exception.Message) 'ERROR' }
    }
    Write-Host ''
    Write-Host '  KURULUM DOGRULAMA TESTLERI' -ForegroundColor Cyan
    Write-Host '  --------------------------' -ForegroundColor Cyan

    Test-Step '1. Defender API jetonu'        { $script:mdeTok = Get-AppToken $cfg $script:MdeResource; 'jeton alindi' }
    Test-Step '2. Cihaz listesi erisimi'      { $r = Invoke-RestMethod "$script:MdeResource/api/machines?`$top=1" -Headers @{Authorization="Bearer $script:mdeTok"}; "$($r.value.Count) ornek kayit" }
    Test-Step '3. Alert listesi erisimi'      { $r = Invoke-RestMethod "$script:MdeResource/api/alerts?`$top=1" -Headers @{Authorization="Bearer $script:mdeTok"}; "$($r.value.Count) ornek kayit" }
    Test-Step '4. Machine action erisimi'     { $r = Invoke-RestMethod "$script:MdeResource/api/machineactions?`$top=1" -Headers @{Authorization="Bearer $script:mdeTok"}; "$($r.value.Count) ornek kayit" }
    Test-Step '5. Advanced Hunting erisimi'   { $b = @{Query='DeviceInfo | take 1'} | ConvertTo-Json
                                                $r = Invoke-RestMethod -Method Post "$script:MdeResource/api/advancedqueries/run" -Headers @{Authorization="Bearer $script:mdeTok"} -ContentType 'application/json' -Body $b
                                                "$(@($r.Results).Count) satir" }
    Test-Step '6. Graph jetonu'               { $script:grTok = Get-AppToken $cfg $script:GraphResource; 'jeton alindi' }
    Test-Step '7. Incident erisimi'           { $r = Invoke-RestMethod "$script:GraphResource/v1.0/security/incidents?`$top=1" -Headers @{Authorization="Bearer $script:grTok"}; "$($r.value.Count) ornek kayit" }
    if ($cfg.Mail.Method -eq 'Graph') {
        Test-Step '8. Mail kutusu erisimi'    { $r = Invoke-RestMethod "$script:GraphResource/v1.0/users/$($cfg.Mail.From)" -Headers @{Authorization="Bearer $script:grTok"}; $r.userPrincipalName }
    }
    Test-Step '9. PDF motoru (Edge)'          { if (Get-EdgePath) { 'bulundu' } else { throw 'Edge yok - rapor HTML olarak uretilecek' } }

    Write-Host ''
    if ($script:fail -eq 0) { Write-Log 'TUM TESTLER BASARILI. Rapor uretimine hazir.' 'OK'; exit 0 }
    Write-Log "$($script:fail) test basarisiz. Yukaridaki hatalari giderin." 'ERROR'
    exit 1
}

# --------------------------------------------------------------- uretim -----
try {
    $data = Get-MdeData -Config $cfg -Start $start -End $end -Mode $Mode
    $k    = Build-Kpi -Data $data -Config $cfg

    # Onceki donem (trend)
    $prevTag = if ($Mode -eq 'Weekly') { $start.AddDays(-7).ToString('yyyy-MM-dd') + '-hafta' }
               else                    { $start.AddMonths(-1).ToString('yyyy-MM') }
    $prev = $null
    $prevFile = Join-Path $script:Root "Archive\$Mode\$prevTag\kpi.json"
    if (Test-Path $prevFile) {
        try { $prev = Get-Content $prevFile -Raw -Encoding UTF8 | ConvertFrom-Json; Write-Log "Onceki donem ($prevTag) trend icin yuklendi." }
        catch { Write-Log 'Onceki donem dosyasi okunamadi, trend gosterilmeyecek.' 'WARN' }
    } else { Write-Log 'Onceki donem verisi yok; trend sutunlari bos gelecek.' }

    # Arsiv
    $arch = Join-Path $script:Root "Archive\$Mode\$($k.Etiket)"
    if (-not (Test-Path $arch)) { New-Item -ItemType Directory -Path $arch -Force | Out-Null }
    $data.Devices   | ConvertTo-Json -Depth 6 | Set-Content "$arch\raw-devices.json"   -Encoding UTF8
    $data.Alerts    | ConvertTo-Json -Depth 6 | Set-Content "$arch\raw-alerts.json"    -Encoding UTF8
    $data.Incidents | ConvertTo-Json -Depth 6 | Set-Content "$arch\raw-incidents.json" -Encoding UTF8
    $data.Actions   | ConvertTo-Json -Depth 6 | Set-Content "$arch\raw-actions.json"   -Encoding UTF8
    $k              | ConvertTo-Json -Depth 6 | Set-Content "$arch\kpi.json"           -Encoding UTF8

    if ($ExportCsv) {
        $csv = Join-Path $arch 'CSV'
        if (-not (Test-Path $csv)) { New-Item -ItemType Directory -Path $csv | Out-Null }
        $data.Devices | Select-Object computerDnsName, osPlatform, healthStatus, onboardingStatus, firstSeen, lastSeen, riskScore |
            Export-Csv "$csv\cihazlar.csv" -NoTypeInformation -Encoding UTF8
        $data.Alerts  | Select-Object id, title, severity, category, status, detectionSource, computerDnsName, alertCreationTime |
            Export-Csv "$csv\alertler.csv" -NoTypeInformation -Encoding UTF8
        if (@($data.Incidents).Count) {
            $data.Incidents | Select-Object id, displayName, severity, status, classification, determination, assignedTo, createdDateTime, lastUpdateDateTime |
                Export-Csv "$csv\incidentlar.csv" -NoTypeInformation -Encoding UTF8
        }
        $data.Actions | Select-Object id, type, status, machineId, computerDnsName, requestor, creationDateTimeUtc |
            Export-Csv "$csv\aksiyonlar.csv" -NoTypeInformation -Encoding UTF8
        Write-Log "CSV dosyalari yazildi: $csv"
    }

    # HTML
    $html = if ($Mode -eq 'Weekly') { New-WeeklyHtml  $k $cfg $script:Root $prev }
            else                    { New-MonthlyHtml $k $cfg $script:Root $prev }

    $safe     = ($cfg.CustomerName -replace '[^A-Za-z0-9]','')
    if (-not $safe) { $safe = 'Organization' }
    $baseName = if ($Mode -eq 'Weekly') { "${safe}_MDE_Haftalik_$($k.Etiket)" } else { "${safe}_MDE_Aylik_$($k.Etiket)" }
    $htmlPath = Join-Path $script:Root "Output\$baseName.html"
    $html | Set-Content -Path $htmlPath -Encoding UTF8
    Write-Log "HTML uretildi: $htmlPath" 'OK'

    $attach = @($htmlPath)
    if ($Pdf -or $cfg.Report.AttachPdf) {
        $pdfPath = Join-Path $script:Root "Output\$baseName.pdf"
        if (Convert-ToPdf $htmlPath $pdfPath) { $attach = @($pdfPath); Write-Log "PDF uretildi: $pdfPath" 'OK' }
        else { Write-Log 'PDF uretilemedi, HTML gonderilecek.' 'WARN' }
    }

    if ($DryRun) { Write-Log 'DryRun: mail gonderilmedi.' 'WARN' }
    else {
        Send-Report -Config $cfg -Kpi $k -Html $html -Attachments $attach -Mode $Mode
        Write-Log 'Rapor gonderildi.' 'OK'
    }

    Write-Log '=== Calisma basariyla tamamlandi ===' 'OK'
    exit 0
}
catch {
    Write-Log "HATA: $($_.Exception.Message)" 'ERROR'
    Write-Log $_.ScriptStackTrace 'ERROR'
    Send-FailureNotice -Config $cfg -Message $_.Exception.Message -LogPath $script:LogFile
    exit 1
}
finally {
    if ($script:TokenCache) { $script:TokenCache.Clear() }
    [GC]::Collect()
}
