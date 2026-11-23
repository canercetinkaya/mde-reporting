<#
    MDE Managed EDR Reporting
    MDEReport.Core.ps1  -  ortak fonksiyon kutuphanesi

    Bu dosya tek basina calistirilmaz. New-MDEReport.ps1 ve Install-MDEReport.ps1
    tarafindan dot-source ile yuklenir.
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:TokenCache = @{}
$script:LogFile    = $null

$script:MdeResource   = 'https://api.securitycenter.microsoft.com'
$script:GraphResource = 'https://graph.microsoft.com'

# --------------------------------------------------------------------- log --
function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level = 'INFO')
    $line = '{0}  {1,-5}  {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'OK'    { Write-Host $line -ForegroundColor Green }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 }
}

function Get-Masked {
    param([string]$Value, [int]$Visible = 4)
    if ([string]::IsNullOrEmpty($Value)) { return '****' }
    if ($Value.Length -le $Visible)      { return '****' }
    ('*' * ($Value.Length - $Visible)) + $Value.Substring($Value.Length - $Visible)
}

function Get-ProviderName {
    param($Config)
    if ($Config -and $Config.PSObject.Properties['ProviderName'] -and -not [string]::IsNullOrWhiteSpace([string]$Config.ProviderName)) {
        return [string]$Config.ProviderName
    }
    return 'Security Operations'
}

function Invoke-WithRetry {
    param([scriptblock]$Script, [int]$MaxAttempt = 5)
    for ($i = 1; $i -le $MaxAttempt; $i++) {
        try { return & $Script }
        catch {
            $code = 0
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if ($i -eq $MaxAttempt -or ($code -ne 429 -and $code -lt 500)) { throw }
            $wait = [math]::Min(60, [math]::Pow(2, $i))
            Write-Log "HTTP $code - $wait sn sonra yeniden denenecek ($i/$MaxAttempt)" 'WARN'
            Start-Sleep -Seconds $wait
        }
    }
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

# ---------------------------------------------------------------- kimlik ----
function Get-AppToken {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)][string]$Resource)

    if ($script:TokenCache.ContainsKey($Resource) -and
        $script:TokenCache[$Resource].Expires -gt (Get-Date).AddMinutes(5)) {
        return $script:TokenCache[$Resource].Token
    }

    $tokenUri = "https://login.microsoftonline.com/$($Config.TenantId)/oauth2/v2.0/token"
    $body = @{
        client_id  = $Config.ClientId
        scope      = "$Resource/.default"
        grant_type = 'client_credentials'
    }

    if ($Config.AuthMode -eq 'Certificate') {
        $cert = @(Get-ChildItem 'Cert:\LocalMachine\My','Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Thumbprint -eq $Config.CertificateThumbprint })[0]
        if (-not $cert) { throw "Sertifika bulunamadi: $($Config.CertificateThumbprint)" }

        $now     = [DateTimeOffset]::UtcNow
        $header  = @{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-Base64Url $cert.GetCertHash()) } | ConvertTo-Json -Compress
        $payload = @{ aud = $tokenUri; iss = $Config.ClientId; sub = $Config.ClientId
                      jti = [guid]::NewGuid().ToString()
                      nbf = $now.ToUnixTimeSeconds(); exp = $now.AddMinutes(10).ToUnixTimeSeconds() } | ConvertTo-Json -Compress
        $h   = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header))
        $p   = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payload))
        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if (-not $rsa) { throw 'Sertifikanin ozel anahtarina erisilemiyor.' }
        $sig = $rsa.SignData([Text.Encoding]::UTF8.GetBytes("$h.$p"),
                             [Security.Cryptography.HashAlgorithmName]::SHA256,
                             [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $body.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        $body.client_assertion      = "$h.$p." + (ConvertTo-Base64Url $sig)
    }
    else {
        $secretFile = Join-Path $script:Root 'secret.txt'
        if (-not (Test-Path $secretFile)) { throw 'secret.txt bulunamadi. Once Install-MDEReport.ps1 calistirin.' }
        $sec  = Get-Content $secretFile | ConvertTo-SecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try {
            $body.client_secret = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    $resp = Invoke-WithRetry { Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded' }
    $script:TokenCache[$Resource] = @{ Token = $resp.access_token; Expires = (Get-Date).AddSeconds([int]$resp.expires_in) }
    $body.Clear()
    return $resp.access_token
}

# ------------------------------------------------------------------- REST ---
function Invoke-PagedApi {
    param([string]$Uri, [string]$Token, [int]$MaxPage = 100)
    $all  = New-Object System.Collections.ArrayList
    $next = $Uri; $page = 0
    while ($next -and $page -lt $MaxPage) {
        $r = Invoke-WithRetry { Invoke-RestMethod -Method Get -Uri $next -Headers @{ Authorization = "Bearer $Token" } }
        if ($null -ne $r.value) { foreach ($x in $r.value) { [void]$all.Add($x) } }
        $next = $r.'@odata.nextLink'
        $page++
    }
    if ($next) { Write-Log "Sayfalama ust siniri ($MaxPage) asildi, veri kismi olabilir." 'WARN' }
    ,$all
}

function Invoke-Hunting {
    param([string]$Name, [string]$Query, [string]$Token)
    try {
        $body = @{ Query = $Query } | ConvertTo-Json -Depth 3
        $r = Invoke-WithRetry { Invoke-RestMethod -Method Post `
                -Uri "$script:MdeResource/api/advancedqueries/run" `
                -Headers @{ Authorization = "Bearer $Token" } `
                -ContentType 'application/json' -Body $body }
        Start-Sleep -Milliseconds 1500
        $rows = @($r.Results)
        Write-Log "  KQL [$Name] -> $($rows.Count) satir"
        return $rows
    }
    catch {
        Write-Log "  KQL [$Name] basarisiz: $($_.Exception.Message)" 'WARN'
        return @()
    }
}

function Get-Sum {
    param($Rows, [string]$Field = 'Adet')
    if (-not $Rows -or @($Rows).Count -eq 0) { return 0 }
    $s = ($Rows | Measure-Object -Property $Field -Sum).Sum
    if ($null -eq $s) { 0 } else { [int]$s }
}

# ------------------------------------------------------------------- KQL ----
function Get-MdeQueries {
    param([datetime]$Start, [datetime]$End, [ValidateSet('Weekly','Monthly')][string]$Mode, $Thresholds)

    $s   = $Start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $e   = $End.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $win = "| where Timestamp >= datetime($s) and Timestamp < datetime($e)"
    $ren = [int]$Thresholds.RansomRenameCount
    if ($ren -lt 1) { $ren = 100 }

    $q = [ordered]@{}

    $q.Antivirus = @"
DeviceEvents
$win
| where ActionType == "AntivirusDetection"
| extend AF = parse_json(AdditionalFields)
| extend Tehdit = tostring(AF.ThreatName), Temizlendi = tostring(AF.WasRemediated)
| summarize Adet = count(), Cihaz = dcount(DeviceId) by Tehdit, Temizlendi
"@

    $q.WebKoruma = @"
DeviceEvents
$win
| where ActionType in ("SmartScreenUrlWarning","SmartScreenUserOverride","SmartScreenAppWarning","ExploitGuardNetworkProtectionBlocked")
| extend AF = parse_json(AdditionalFields)
| summarize Adet = count(), Cihaz = dcount(DeviceId) by ActionType, Deneyim = tostring(AF.Experience)
"@

    $q.Asr = @"
DeviceEvents
$win
| where ActionType startswith "Asr" and ActionType endswith "Blocked"
| summarize Adet = count(), Cihaz = dcount(DeviceId) by ActionType
"@

    $q.ExploitGuard = @"
DeviceEvents
$win
| where ActionType startswith "ExploitGuard"
| where ActionType !startswith "ExploitGuardNetworkProtection"
| summarize Adet = count(), Cihaz = dcount(DeviceId) by ActionType
"@

    $q.FidyeDavranisi = @"
DeviceFileEvents
$win
| where ActionType == "FileRenamed"
| summarize Gunluk = count() by DeviceName, Gun = bin(Timestamp, 1d)
| where Gunluk > $ren
| summarize Adet = count(), Toplam = sum(Gunluk) by DeviceName
"@

    if ($Mode -eq 'Monthly') {

        $q.SupheliKomut = @"
DeviceProcessEvents
$win
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe")
| where ProcessCommandLine has_any ("-enc","-EncodedCommand","FromBase64String","Invoke-Expression","DownloadString","bitsadmin")
| summarize Adet = count(), Cihaz = dcount(DeviceId) by FileName
"@

        $q.KimlikBilgisiErisimi = @"
DeviceProcessEvents
$win
| where ProcessCommandLine has_any ("mimikatz","sekurlsa","lsadump","procdump")
| summarize Adet = count(), Cihaz = dcount(DeviceId) by DeviceName
"@

        $q.SupheliCikisTrafigi = @"
DeviceNetworkEvents
$win
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe","regsvr32.exe")
| summarize Adet = count(), Cihaz = dcount(DeviceId) by InitiatingProcessFileName
"@

        $q.YeniYerelHesap = @"
DeviceEvents
$win
| where ActionType in ("UserAccountCreated","UserAccountAddedToLocalGroup")
| summarize Adet = count(), Cihaz = dcount(DeviceId) by ActionType
"@

        $q.ServisKurulumu = @"
DeviceEvents
$win
| where ActionType == "ServiceInstalled"
| summarize Adet = count(), Cihaz = dcount(DeviceId)
"@

        $q.OlagandisiKonum = @"
DeviceProcessEvents
$win
| where FolderPath has_any ("\\Users\\Public\\","\\AppData\\Local\\Temp\\","\\ProgramData\\","\\Windows\\Temp\\")
| where FileName endswith ".exe"
| summarize Adet = count(), Cihaz = dcount(DeviceId) by FileName
| top 10 by Adet desc
"@
    }

    return $q
}

# ------------------------------------------------------------- veri toplama -
function Get-MdeData {
    param($Config, [datetime]$Start, [datetime]$End, [ValidateSet('Weekly','Monthly')][string]$Mode)

    $startZ = $Start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $endZ   = $End.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    $mde = Get-AppToken $Config $script:MdeResource
    Write-Log 'Defender for Endpoint API jetonu alindi.' 'OK'

    Write-Log 'Cihaz envanteri cekiliyor...'
    $devices = @((Invoke-PagedApi "$script:MdeResource/api/machines" $mde) |
                 Where-Object { $_.onboardingStatus -eq 'Onboarded' })
    Write-Log "  $($devices.Count) onboard cihaz"

    Write-Log 'Alert verisi cekiliyor...'
    $alerts = @(Invoke-PagedApi ("$script:MdeResource/api/alerts?`$filter=alertCreationTime ge $startZ and alertCreationTime lt $endZ") $mde)
    Write-Log "  $($alerts.Count) alert"

    Write-Log 'Response aksiyonlari cekiliyor...'
    $actions = @(Invoke-PagedApi ("$script:MdeResource/api/machineactions?`$filter=creationDateTimeUtc ge $startZ and creationDateTimeUtc lt $endZ") $mde)
    Write-Log "  $($actions.Count) machine action"

    $incidents = @(); $incidentSource = 'Graph'
    try {
        Write-Log 'Incident verisi cekiliyor (Microsoft Graph)...'
        $g = Get-AppToken $Config $script:GraphResource
        $incidents = @(Invoke-PagedApi ("$script:GraphResource/v1.0/security/incidents?`$filter=createdDateTime ge $startZ and createdDateTime lt $endZ&`$top=100") $g)
        Write-Log "  $($incidents.Count) incident"
    }
    catch {
        $incidentSource = 'Alert'
        Write-Log "Incident verisi alinamadi: $($_.Exception.Message)" 'WARN'
        Write-Log 'Siddet dagilimi alert verisinden uretilecek.' 'WARN'
    }

    Write-Log "Advanced Hunting sorgulari calistiriliyor ($Mode)..."
    $queries = Get-MdeQueries -Start $Start -End $End -Mode $Mode -Thresholds $Config.Thresholds
    $hunt = @{}
    foreach ($name in $queries.Keys) { $hunt["$name"] = Invoke-Hunting $name $queries[$name] $mde }

    [pscustomobject]@{
        Devices        = $devices
        Alerts         = $alerts
        Actions        = $actions
        Incidents      = $incidents
        IncidentSource = $incidentSource
        Hunt           = $hunt
        Start          = $Start
        End            = $End
        Mode           = $Mode
    }
}

# ------------------------------------------------------------ KPI hesabi ----
function Build-Kpi {
    param($Data, $Config)

    $d = @($Data.Devices); $a = @($Data.Alerts); $ac = @($Data.Actions); $inc = @($Data.Incidents); $h = $Data.Hunt
    $th = $Config.Thresholds

    $activeLimit = if ($Data.Mode -eq 'Weekly') { $Data.End.AddDays(-7) } else { $Data.End.AddDays(-30) }
    $active = @($d | Where-Object { $_.lastSeen -and ([datetime]$_.lastSeen) -ge $activeLimit })
    $new    = @($d | Where-Object { $_.firstSeen -and ([datetime]$_.firstSeen) -ge $Data.Start -and ([datetime]$_.firstSeen) -lt $Data.End })

    $health = @{}; foreach ($g in ($d | Group-Object healthStatus)) { $health["$($g.Name)"] = $g.Count }
    $os     = @{}; foreach ($g in ($d | Group-Object osPlatform))   { $os["$($g.Name)"]     = $g.Count }

    $av         = $h['Antivirus']
    $avBlocked  = Get-Sum ($av | Where-Object { "$($_.Temizlendi)".ToLower() -eq 'true' })
    $avDetected = Get-Sum ($av | Where-Object { "$($_.Temizlendi)".ToLower() -ne 'true' })
    $topThreats = @($av | Group-Object Tehdit | ForEach-Object {
                      [pscustomobject]@{
                          Ad    = if ($_.Name) { $_.Name } else { 'Bilinmiyor' }
                          Adet  = ($_.Group | Measure-Object Adet -Sum).Sum
                          Cihaz = ($_.Group | Measure-Object Cihaz -Maximum).Maximum } } |
                    Sort-Object Adet -Descending | Select-Object -First 10)

    $web          = $h['WebKoruma']
    $phishBlocked = Get-Sum ($web | Where-Object { $_.ActionType -in @('SmartScreenUrlWarning','SmartScreenAppWarning') -and "$($_.Deneyim)" -match 'Phish' })
    $phishOver    = Get-Sum ($web | Where-Object { $_.ActionType -eq 'SmartScreenUserOverride' })
    $urlBlocked   = Get-Sum ($web | Where-Object { $_.ActionType -in @('SmartScreenUrlWarning','ExploitGuardNetworkProtectionBlocked') })

    if ($Data.IncidentSource -eq 'Graph') {
        $sevHigh = @($inc | Where-Object { $_.severity -eq 'high'   }).Count
        $sevMed  = @($inc | Where-Object { $_.severity -eq 'medium' }).Count
        $sevLow  = @($inc | Where-Object { $_.severity -eq 'low'    }).Count
        $sevInf  = @($inc | Where-Object { $_.severity -eq 'informational' }).Count
    } else {
        $sevHigh = @($a | Where-Object { $_.severity -eq 'High'   }).Count
        $sevMed  = @($a | Where-Object { $_.severity -eq 'Medium' }).Count
        $sevLow  = @($a | Where-Object { $_.severity -eq 'Low'    }).Count
        $sevInf  = @($a | Where-Object { $_.severity -eq 'Informational' }).Count
    }

    $closed   = @($inc | Where-Object { $_.status -eq 'resolved' })
    $avgClose = 0
    if ($closed.Count -gt 0) {
        $avgClose = [math]::Round((($closed | ForEach-Object {
            ([datetime]$_.lastUpdateDateTime - [datetime]$_.createdDateTime).TotalHours }) |
            Measure-Object -Average).Average, 1)
    }

    $cls = @{}
    foreach ($g in ($inc | Group-Object classification)) {
        $n = if ($g.Name) { $g.Name } else { 'Siniflandirilmadi' }; $cls[$n] = $g.Count
    }
    $actTypes = @{}; foreach ($g in ($ac | Group-Object type)) { $actTypes["$($g.Name)"] = $g.Count }
    $succeeded = @($ac | Where-Object { $_.status -eq 'Succeeded' }).Count

    $riskyHosts = @($a | Group-Object computerDnsName |
                     Where-Object { $_.Count -ge $th.RiskyHostAlerts } |
                     Sort-Object Count -Descending |
                     ForEach-Object { [pscustomobject]@{ Cihaz = $_.Name; Alert = $_.Count } })

    $k = [ordered]@{
        Mode                  = $Data.Mode
        DonemBaslangic        = $Data.Start.ToString('yyyy-MM-dd')
        DonemBitis            = $Data.End.AddDays(-1).ToString('yyyy-MM-dd')
        Etiket                = if ($Data.Mode -eq 'Weekly') { $Data.Start.ToString('yyyy-MM-dd') + '-hafta' } else { $Data.Start.ToString('yyyy-MM') }

        TotalDevices          = $d.Count
        ActiveDevices         = $active.Count
        InactiveDevices       = $d.Count - $active.Count
        InactivePct           = if ($d.Count) { [math]::Round((($d.Count - $active.Count) / $d.Count) * 100, 1) } else { 0 }
        NewDevices            = $new.Count
        SensorHealth          = $health
        SensorProblem         = ([int]$health['ImpairedCommunication'] + [int]$health['NoSensorData'] + [int]$health['NoSensorDataImpairedCommunication'])
        OsBreakdown           = $os

        MalwareBlocked        = $avBlocked
        MalwareDetected       = $avDetected
        PhishBlocked          = $phishBlocked
        PhishOverridden       = $phishOver
        UrlBlocked            = $urlBlocked
        AsrBlocked            = (Get-Sum $h['Asr'])
        ExploitEvents         = (Get-Sum $h['ExploitGuard'])
        RansomwareAlerts      = @($a | Where-Object { "$($_.category)" -match 'Ransom' }).Count
        RansomBehaviorHosts   = @($h['FidyeDavranisi']).Count
        TopThreats            = $topThreats

        TotalAlerts           = $a.Count
        AlertHigh             = @($a | Where-Object { $_.severity -eq 'High' }).Count
        TotalIncidents        = $inc.Count
        IncHigh               = $sevHigh
        IncMedium             = $sevMed
        IncLow                = $sevLow
        IncInfo               = $sevInf
        IncClosed             = $closed.Count
        IncOpen               = @($inc | Where-Object { $_.status -in @('active','inProgress') }).Count
        AvgCloseHours         = $avgClose
        Classification        = $cls
        SeveritySource        = $Data.IncidentSource

        RiskyHostCount        = $riskyHosts.Count
        RiskyHosts            = @($riskyHosts | Select-Object -First 10)
        TopDevices            = @($a | Group-Object computerDnsName | Sort-Object Count -Descending |
                                  Select-Object -First 10 |
                                  ForEach-Object { [pscustomobject]@{ Cihaz = $_.Name; Alert = $_.Count } })

        InvestigatedIncidents = @($inc | Where-Object { $_.classification -and $_.classification -ne 'unknown' }).Count
        IsolatedDevices       = @($ac | Where-Object { $_.type -eq 'Isolate' } | Select-Object -ExpandProperty machineId -Unique).Count
        TotalActions          = $ac.Count
        ActionBreakdown       = $actTypes
        ActionSuccessPct      = if ($ac.Count) { [math]::Round(($succeeded / $ac.Count) * 100, 0) } else { 0 }
    }

    if ($Data.Mode -eq 'Monthly') {
        $k.HuntSupheliKomut    = (Get-Sum $h['SupheliKomut'])
        $k.HuntKimlikErisimi   = (Get-Sum $h['KimlikBilgisiErisimi'])
        $k.HuntCikisTrafigi    = (Get-Sum $h['SupheliCikisTrafigi'])
        $k.HuntYeniYerelHesap  = (Get-Sum $h['YeniYerelHesap'])
        $k.HuntServisKurulumu  = (Get-Sum $h['ServisKurulumu'])
        $k.HuntOlagandisiKonum = @($h['OlagandisiKonum'] | Select-Object -First 5)
    }

    [pscustomobject]$k
}

# ------------------------------------------------------------ PDF / MAIL ----
function Get-EdgePath {
    $c = @("$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
           "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")
    $c | Where-Object { Test-Path $_ } | Select-Object -First 1
}

function Convert-ToPdf {
    param([string]$HtmlPath, [string]$PdfPath)
    $edge = Get-EdgePath
    if (-not $edge) { return $false }
    $uri = 'file:///' + ($HtmlPath -replace '\\','/')
    $argList = @('--headless=new','--disable-gpu','--no-first-run','--no-pdf-header-footer',
                 "--print-to-pdf=$PdfPath", $uri)
    Start-Process -FilePath $edge -ArgumentList $argList -Wait -NoNewWindow
    Start-Sleep -Seconds 2
    Test-Path $PdfPath
}

function Get-MailSubject {
    param($Config, $Kpi, [string]$Mode)
    $tr = [Globalization.CultureInfo]::GetCultureInfo('tr-TR')
    if ($Mode -eq 'Weekly') {
        $b = [datetime]$Kpi.DonemBaslangic; $e = [datetime]$Kpi.DonemBitis
        return "$($Config.CustomerName) - MDE Haftalik EDR Ozeti - $($b.ToString('dd.MM')) - $($e.ToString('dd.MM.yyyy'))"
    }
    "$($Config.CustomerName) - MDE Aylik Guvenlik Raporu - $(([datetime]$Kpi.DonemBaslangic).ToString('MMMM yyyy', $tr))"
}

function New-SmtpClientFromConfig {
    param($Config)
    $smtp = New-Object Net.Mail.SmtpClient($Config.Smtp.Server, [int]$Config.Smtp.Port)
    $smtp.EnableSsl = [bool]$Config.Smtp.UseSsl
    if ($Config.Smtp.User) {
        $smtpFile = Join-Path $script:Root 'smtp.txt'
        if (Test-Path $smtpFile) {
            $sec  = Get-Content $smtpFile | ConvertTo-SecureString
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
            try {
                $smtp.Credentials = New-Object Net.NetworkCredential($Config.Smtp.User, [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr))
            }
            finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }
    return $smtp
}

function Send-Report {
    param($Config, $Kpi, [string]$Html, [string[]]$Attachments, [string]$Mode)

    $subject = Get-MailSubject $Config $Kpi $Mode
    $to = @($Config.Mail.To | Where-Object { $_ })
    $cc = @($Config.Mail.Cc | Where-Object { $_ })

    if ($Config.Mail.Method -eq 'Graph') {
        $token = Get-AppToken $Config $script:GraphResource
        $atts = @()
        foreach ($f in $Attachments) {
            if (-not (Test-Path $f)) { continue }
            $bytes = [IO.File]::ReadAllBytes($f)
            if ($bytes.Length -gt 3MB) { Write-Log "Ek 3 MB uzeri, atlandi: $f" 'WARN'; continue }
            $atts += @{
                '@odata.type' = '#microsoft.graph.fileAttachment'
                name          = [IO.Path]::GetFileName($f)
                contentType   = if ($f.EndsWith('.pdf')) { 'application/pdf' } else { 'text/html' }
                contentBytes  = [Convert]::ToBase64String($bytes)
            }
        }
        $msg = @{
            message = @{
                subject      = $subject
                body         = @{ contentType = 'HTML'; content = $Html }
                toRecipients = @($to | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
                ccRecipients = @($cc | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
                attachments  = $atts
            }
            saveToSentItems = $true
        } | ConvertTo-Json -Depth 10

        Invoke-WithRetry { Invoke-RestMethod -Method Post `
            -Uri "$script:GraphResource/v1.0/users/$($Config.Mail.From)/sendMail" `
            -Headers @{ Authorization = "Bearer $token" } `
            -ContentType 'application/json; charset=utf-8' `
            -Body ([Text.Encoding]::UTF8.GetBytes($msg)) } | Out-Null
    }
    else {
        $smtp = New-SmtpClientFromConfig $Config
        $mail = New-Object Net.Mail.MailMessage
        try {
            $mail.From = $Config.Mail.From
            foreach ($x in $to) { $mail.To.Add($x) }
            foreach ($x in $cc) { $mail.CC.Add($x) }
            $mail.Subject = $subject; $mail.Body = $Html; $mail.IsBodyHtml = $true
            $mail.BodyEncoding = [Text.Encoding]::UTF8
            foreach ($f in $Attachments) { if (Test-Path $f) { $mail.Attachments.Add((New-Object Net.Mail.Attachment($f))) } }
            $smtp.Send($mail)
        }
        finally {
            $mail.Dispose()
            $smtp.Dispose()
        }
    }
}

function Send-FailureNotice {
    param($Config, [string]$Message, [string]$LogPath)
    if (-not $Config.Mail.AlertTo) { return }
    try {
        $body = "MDE rapor uretimi basarisiz oldu.`n`nKurum   : $($Config.CustomerName)`nSunucu  : $env:COMPUTERNAME`nHata    : $Message`nLog     : $LogPath"
        if ($Config.Mail.Method -eq 'Graph') {
            $t = Get-AppToken $Config $script:GraphResource
            $m = @{ message = @{
                        subject      = "HATA - $($Config.CustomerName) MDE raporu uretilemedi"
                        body         = @{ contentType = 'Text'; content = $body }
                        toRecipients = @(@{ emailAddress = @{ address = $Config.Mail.AlertTo } }) } } | ConvertTo-Json -Depth 8
            Invoke-RestMethod -Method Post -Uri "$script:GraphResource/v1.0/users/$($Config.Mail.From)/sendMail" `
                -Headers @{ Authorization = "Bearer $t" } -ContentType 'application/json; charset=utf-8' `
                -Body ([Text.Encoding]::UTF8.GetBytes($m)) | Out-Null
        }
        else {
            $smtp = New-SmtpClientFromConfig $Config
            try {
                $smtp.Send($Config.Mail.From, $Config.Mail.AlertTo, "HATA - $($Config.CustomerName) MDE raporu uretilemedi", $body)
            }
            finally {
                $smtp.Dispose()
            }
        }
        Write-Log 'Hata bildirimi gonderildi.' 'WARN'
    }
    catch { Write-Log 'Hata bildirimi gonderilemedi.' 'WARN' }
}
