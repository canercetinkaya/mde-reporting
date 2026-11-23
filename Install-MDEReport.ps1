<#
.SYNOPSIS
    MDE Managed EDR Reporting : tek ekran kurulum sihirbazi.

.DESCRIPTION
    Adim adim ilerler ve sirasiyla su isleri yapar:
      1. Onkosul kontrolu (PowerShell, internet, Edge, klasorler)
      2. Kurum bilgileri ve rapor periyodu secimi
      3. Entra ID uygulama kaydini OLUSTURUR, API izinlerini EKLER ve
         yonetici onayini (app role assignment) OTOMATIK VERIR
      4. Istemci gizli anahtarini uretir ve DPAPI ile sifreleyip saklar
      5. customer.json dosyasini yazar
      6. Butun erisim testlerini calistirir ve OK / HATA ciktisi verir
      7. Secilen periyoda gore Task Scheduler gorevlerini olusturur
      8. Istege bagli olarak ilk raporu deneme modunda uretir

    Yonetici onayi adimi icin oturum acacak kisinin tenantta
    Global Administrator veya Privileged Role Administrator olmasi gerekir.

.EXAMPLE
    .\Install-MDEReport.ps1
    .\Install-MDEReport.ps1 -UseExistingApp
#>
[CmdletBinding()]
param(
    [switch] $UseExistingApp,
    [switch] $SkipTasks
)

$ErrorActionPreference = 'Stop'
$script:Root = $PSScriptRoot
. (Join-Path $script:Root 'MDEReport.Core.ps1')

# Microsoft Graph Command Line Tools - genel istemci, cihaz kodu akisi icin
$script:CliClientId  = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
$script:MdeAppId     = 'fc780465-2017-40d4-a0c5-307022471b92'
$script:GraphAppId   = '00000003-0000-0000-c000-000000000000'

$script:BaseRoles = @(
    @{ Resource = $script:MdeAppId;   Name = 'Machine.Read.All';         Aciklama = 'Cihaz envanteri, sensor sagligi, response aksiyonlari' }
    @{ Resource = $script:MdeAppId;   Name = 'Alert.Read.All';           Aciklama = 'Alert verisi' }
    @{ Resource = $script:MdeAppId;   Name = 'AdvancedQuery.Read.All';   Aciklama = 'Advanced Hunting sorgulari' }
    @{ Resource = $script:GraphAppId; Name = 'SecurityIncident.Read.All';Aciklama = 'Incident verisi' }
)

# ------------------------------------------------------------------ ekran ---
function Write-Head {
    param([string]$Text)
    Write-Host ''
    Write-Host ('  ' + $Text) -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * $Text.Length)) -ForegroundColor Cyan
}
function Write-Step { param([string]$T) Write-Host "   -> $T" -ForegroundColor Gray }
function Write-Ok   { param([string]$T) Write-Host "   OK   $T" -ForegroundColor Green }
function Write-Bad  { param([string]$T) Write-Host "   HATA $T" -ForegroundColor Red }
function Write-Warn { param([string]$T) Write-Host "   !    $T" -ForegroundColor Yellow }

function Read-Value {
    param([string]$Prompt, [string]$Default, [switch]$Required)
    while ($true) {
        $suffix = if ($Default) { " [$Default]" } else { '' }
        $v = Read-Host "   $Prompt$suffix"
        if (-not $v -and $Default) { return $Default }
        if ($v) { return $v.Trim() }
        if (-not $Required) { return '' }
        Write-Warn 'Bu alan zorunlu.'
    }
}
function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $true)
    $d = if ($Default) { 'E' } else { 'H' }
    $v = Read-Host "   $Prompt (E/H) [$d]"
    if (-not $v) { return $Default }
    return ($v.Trim().ToUpper() -eq 'E')
}

function Resolve-Tenant {
    param([string]$Value)
    $t = $Value.Trim()
    if ($t -match '@') { $t = ($t -split '@')[-1] }
    $t = $t -replace '^https?://', '' -replace '/.*$', ''

    $uri = "https://login.microsoftonline.com/$t/v2.0/.well-known/openid-configuration"
    $r   = Invoke-RestMethod -Uri $uri -TimeoutSec 20
    $tid = ($r.issuer -split '/')[3]
    [pscustomobject]@{ Domain = $t; TenantId = $tid }
}

# ------------------------------------------------------- cihaz kodu akisi ---
function Get-DelegatedToken {
    param([string]$TenantId, [string]$Scope)

    $dcUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
    try {
        $dc = Invoke-RestMethod -Method Post -Uri $dcUri -Body @{
            client_id = $script:CliClientId
            scope     = $Scope
        } -ContentType 'application/x-www-form-urlencoded'
    }
    catch {
        $detay = ''
        try { $detay = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() } catch { }
        throw "Cihaz kodu alinamadi. Tenant: $TenantId`n$detay"
    }

    Write-Host ''
    Write-Host '   ============================================================' -ForegroundColor Yellow
    Write-Host '    Tarayicida asagidaki adresi acin ve kodu girin:' -ForegroundColor Yellow
    Write-Host "      Adres : $($dc.verification_uri)" -ForegroundColor White
    Write-Host "      Kod   : $($dc.user_code)" -ForegroundColor White
    Write-Host '    Global Administrator veya Privileged Role Administrator' -ForegroundColor Yellow
    Write-Host '    yetkisine sahip bir hesapla oturum acin.' -ForegroundColor Yellow
    Write-Host '   ============================================================' -ForegroundColor Yellow
    try { Start-Process $dc.verification_uri } catch { }

    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds ([int]$dc.interval + 1)
        try {
            $t = Invoke-RestMethod -Method Post -Uri $tokenUri -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $script:CliClientId
                device_code = $dc.device_code
            } -ContentType 'application/x-www-form-urlencoded'
            Write-Host ''
            Write-Ok 'Yonetici oturumu acildi.'
            return $t.access_token
        }
        catch {
            $raw = ''
            try { $raw = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() } catch { }
            if ($raw -match 'authorization_pending') { continue }
            if ($raw -match 'slow_down') { Start-Sleep -Seconds 5; continue }
            throw "Oturum acma basarisiz: $raw"
        }
    }
    throw 'Cihaz kodu suresi doldu.'
}

function Invoke-Graph {
    param([string]$Method, [string]$Uri, $Body, [string]$Token)
    $p = @{ Method = $Method; Uri = $Uri; Headers = @{ Authorization = "Bearer $Token" } }
    if ($Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10); $p.ContentType = 'application/json' }
    Invoke-WithRetry { Invoke-RestMethod @p }
}

# =========================================================== 0. ONKOSULLAR ==
Clear-Host
Write-Host ''
Write-Host '  ##############################################################' -ForegroundColor Cyan
Write-Host '  #   MDE Managed EDR Reporting - Kurulum Sihirbazi            #' -ForegroundColor Cyan
Write-Host '  #   Haftalik ozet + Aylik ayrintili KPI raporu               #' -ForegroundColor Cyan
Write-Host '  ##############################################################' -ForegroundColor Cyan

Write-Head '0. Onkosul kontrolu'
$pre = $true

if ($PSVersionTable.PSVersion.Major -ge 5) { Write-Ok "PowerShell $($PSVersionTable.PSVersion)" }
else { Write-Bad 'PowerShell 5.1 veya ustu gerekiyor.'; $pre = $false }

try {
    $null = Invoke-RestMethod 'https://login.microsoftonline.com/common/discovery/instance?api-version=1.1&authorization_endpoint=https://login.microsoftonline.com/common/oauth2/authorize' -TimeoutSec 15
    Write-Ok 'Internet erisimi (login.microsoftonline.com)'
} catch { Write-Bad 'login.microsoftonline.com adresine erisilemiyor. Proxy/firewall kontrol edin.'; $pre = $false }

if (Get-EdgePath) { Write-Ok 'Microsoft Edge bulundu (PDF uretimi mumkun)' }
else { Write-Warn 'Microsoft Edge yok. Rapor HTML olarak uretilecek (sorun degil).' }

foreach ($d in 'Output','Archive','Logs') {
    $p = Join-Path $script:Root $d
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}
Write-Ok "Klasor yapisi hazir: $script:Root"

if (-not $pre) { Write-Host ''; Write-Bad 'Onkosullar saglanmadi, kurulum durduruldu.'; exit 1 }

# ======================================================= 1. KURUM BILGISI ===
Write-Head '1. Kurum ve rapor bilgileri'
$customer = Read-Value 'Kurum / musteri adi (rapor basliginda gorunur)' -Required
$provider = Read-Value 'Hizmet saglayici / SOC ekip adi (rapor altbilgisi)' 'Security Operations'

$tenant = ''
while (-not $tenant) {
    $girdi = Read-Value 'Tenant kimligi, alan adi veya kurumsal e-posta adresiniz' -Required
    try {
        $resolved = Resolve-Tenant $girdi
        $tenant   = $resolved.TenantId
        Write-Ok "Tenant dogrulandi: $($resolved.Domain)  (kimlik: $tenant)"
    }
    catch {
        Write-Bad 'Bu tenant cozumlenemedi. Ornek girdiler: contoso.com  |  contoso.onmicrosoft.com  |  admin@contoso.com  |  GUID'
    }
}

Write-Host ''
Write-Host '   Rapor periyodu:' -ForegroundColor Gray
Write-Host '     1) Sadece haftalik ozet' -ForegroundColor Gray
Write-Host '     2) Sadece aylik ayrintili rapor' -ForegroundColor Gray
Write-Host '     3) Her ikisi (haftalik ozet + aylik ayrintili)' -ForegroundColor Gray
$sel = Read-Value 'Seciminiz (1/2/3)' '3'

$wantWeekly  = $sel -in @('1','3')
$wantMonthly = $sel -in @('2','3')

$weeklyDay = 'MON'; $weeklyTime = '07:30'; $monthlyDay = 1; $monthlyTime = '06:00'
if ($wantWeekly) {
    $weeklyDay  = (Read-Value 'Haftalik rapor gunu (MON/TUE/WED/THU/FRI)' 'MON').ToUpper()
    $weeklyTime = Read-Value 'Haftalik rapor saati (SS:DD)' '07:30'
}
if ($wantMonthly) {
    $monthlyDay  = [int](Read-Value 'Aylik rapor gunu (ayin kacinci gunu)' '1')
    $monthlyTime = Read-Value 'Aylik rapor saati (SS:DD)' '06:00'
}

Write-Head '2. Mail ayarlari'
Write-Host '   1) Exchange Online / Microsoft Graph (onerilen, ek parola gerektirmez)' -ForegroundColor Gray
Write-Host '   2) SMTP sunucusu' -ForegroundColor Gray
$mailSel    = Read-Value 'Seciminiz (1/2)' '1'
$mailMethod = if ($mailSel -eq '2') { 'Smtp' } else { 'Graph' }

$mailFrom = Read-Value 'Gonderen adres (paylasimli posta kutusu, orn. mde-report@contoso.com)' -Required
$mailTo   = (Read-Value 'Alici adresler (virgulle ayirin)' -Required) -split ',' | ForEach-Object { $_.Trim() }
$mailCcIn = Read-Value 'Bilgi (CC) adresleri (bos birakilabilir)' ''
$mailCc   = if ($mailCcIn) { $mailCcIn -split ',' | ForEach-Object { $_.Trim() } } else { @() }
$alertTo  = Read-Value 'Hata bildirimi adresi (SOC / operasyon, bos birakilabilir)' ''

$smtpServer = ''; $smtpPort = 587; $smtpSsl = $true; $smtpUser = ''
if ($mailMethod -eq 'Smtp') {
    $smtpServer = Read-Value 'SMTP sunucusu' 'smtp.office365.com' -Required
    $smtpPort   = [int](Read-Value 'SMTP portu' '587')
    $smtpSsl    = Read-YesNo 'TLS/SSL kullanilsin mi?' $true
    $smtpUser   = Read-Value 'SMTP kullanici adi (anonim relay ise bos birakin)' ''
}

# En az ayricalik: Mail.Send yalnizca Graph gonderimi secildiginde eklenir
$requiredRoles = @($script:BaseRoles)
if ($mailMethod -eq 'Graph') {
    $requiredRoles += @{ Resource = $script:GraphAppId; Name = 'Mail.Send'; Aciklama = 'Rapor mailinin gonderilmesi (Graph sendMail)' }
}

# ============================================ 3. UYGULAMA KAYDI VE IZINLER ==
Write-Head '3. Entra ID uygulama kaydi ve API izinleri'

$clientId = ''
$secretPlain = ''

if ($UseExistingApp) {
    Write-Warn 'Mevcut uygulama kullanilacak (otomatik kayit atlandi).'
    $clientId    = Read-Value 'Uygulama (istemci) kimligi' -Required
    $secretPlain = Read-Value 'Istemci gizli anahtari (client secret)' -Required
}
else {
    Write-Host '   Uygulama kaydi, API izinleri ve yonetici onayi otomatik yapilacaktir.' -ForegroundColor Gray
    Write-Host '   Verilecek izinler:' -ForegroundColor Gray
    foreach ($r in $requiredRoles) { Write-Host ('     - {0,-28} {1}' -f $r.Name, $r.Aciklama) -ForegroundColor Gray }
    if (-not (Read-YesNo 'Devam edilsin mi?' $true)) { Write-Warn 'Kurulum iptal edildi.'; exit 0 }

    $scope = 'https://graph.microsoft.com/Application.ReadWrite.All https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All https://graph.microsoft.com/Directory.Read.All offline_access'
    $adminToken = Get-DelegatedToken -TenantId $tenant -Scope $scope

    $shortName = ($customer -replace '[^A-Za-z0-9]','')
    if (-not $shortName) { $shortName = 'Org' }
    if ($shortName.Length -gt 20) { $shortName = $shortName.Substring(0,20) }
    $appName = "MDE-Report-$shortName"

    Write-Step "Uygulama olusturuluyor: $appName"
    $app = Invoke-Graph POST 'https://graph.microsoft.com/v1.0/applications' @{
        displayName    = $appName
        signInAudience = 'AzureADMyOrg'
        notes          = 'MDE Managed EDR Reporting - haftalik ve aylik salt okunur KPI raporlamasi'
    } $adminToken
    $clientId = $app.appId
    Write-Ok "Uygulama olusturuldu. Client ID: $clientId"

    Write-Step 'Servis sorumlusu (service principal) olusturuluyor'
    $sp = Invoke-Graph POST 'https://graph.microsoft.com/v1.0/servicePrincipals' @{ appId = $clientId } $adminToken
    Write-Ok 'Servis sorumlusu olusturuldu.'

    Write-Step 'Kaynak uygulamalar cozumleniyor'
    $resourceSp = @{}
    foreach ($rid in @($script:MdeAppId, $script:GraphAppId)) {
        $r = Invoke-Graph GET "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$rid'" $null $adminToken
        if (-not $r.value) { throw "Kaynak uygulama tenantta bulunamadi: $rid" }
        $resourceSp[$rid] = $r.value[0]
    }
    Write-Ok 'Kaynak uygulamalar bulundu.'

    Write-Step 'Uygulama izinleri tanimlaniyor (requiredResourceAccess)'
    $rra = @()
    foreach ($rid in $resourceSp.Keys) {
        $roles = @()
        foreach ($need in ($requiredRoles | Where-Object { $_.Resource -eq $rid })) {
            $role = @($resourceSp[$rid].appRoles | Where-Object { $_.value -eq $need.Name -and $_.allowedMemberTypes -contains 'Application' })[0]
            if (-not $role) { Write-Warn "Izin bulunamadi, atlandi: $($need.Name)"; continue }
            $roles += @{ id = $role.id; type = 'Role' }
        }
        if ($roles.Count) { $rra += @{ resourceAppId = $rid; resourceAccess = $roles } }
    }
    Invoke-Graph PATCH "https://graph.microsoft.com/v1.0/applications/$($app.id)" @{ requiredResourceAccess = $rra } $adminToken | Out-Null
    Write-Ok 'Izinler uygulama kaydina islendi.'

    Write-Step 'Yonetici onayi veriliyor (app role assignment)'
    $granted = 0
    foreach ($need in $requiredRoles) {
        $res  = $resourceSp[$need.Resource]
        $role = @($res.appRoles | Where-Object { $_.value -eq $need.Name -and $_.allowedMemberTypes -contains 'Application' })[0]
        if (-not $role) { continue }
        try {
            Invoke-Graph POST "https://graph.microsoft.com/v1.0/servicePrincipals/$($res.id)/appRoleAssignedTo" @{
                principalId = $sp.id; resourceId = $res.id; appRoleId = $role.id
            } $adminToken | Out-Null
            Write-Ok "Onaylandi: $($need.Name)"
            $granted++
        }
        catch { Write-Bad "Onaylanamadi: $($need.Name) - $($_.Exception.Message)" }
    }
    Write-Ok "$granted / $($requiredRoles.Count) izin onaylandi."

    Write-Step 'Istemci gizli anahtari uretiliyor (12 ay gecerli)'
    $pwdCred = Invoke-Graph POST "https://graph.microsoft.com/v1.0/applications/$($app.id)/addPassword" @{
        passwordCredential = @{
            displayName = 'MDE Reporting'
            endDateTime = (Get-Date).AddMonths(12).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
    } $adminToken
    $secretPlain = $pwdCred.secretText
    Write-Ok "Gizli anahtar uretildi. Bitis tarihi: $((Get-Date).AddMonths(12).ToString('dd.MM.yyyy'))"
    Write-Warn 'Bu tarihten once yenilenmelidir; operasyon takvimine isleyin.'

    Clear-Variable adminToken -ErrorAction SilentlyContinue
}

Write-Step 'Gizli anahtar DPAPI ile sifrelenip kaydediliyor'
($secretPlain | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString) |
    Set-Content (Join-Path $script:Root 'secret.txt') -Encoding ASCII
Clear-Variable secretPlain -ErrorAction SilentlyContinue
Write-Ok 'secret.txt olusturuldu (bu makineye ve bu kullaniciya bagli).'

if ($mailMethod -eq 'Smtp' -and $smtpUser) {
    $sp2 = Read-Host '   SMTP parolasi' -AsSecureString
    $sp2 | ConvertFrom-SecureString | Set-Content (Join-Path $script:Root 'smtp.txt') -Encoding ASCII
    Write-Ok 'smtp.txt olusturuldu.'
}

# =============================================== 4. YAPILANDIRMA DOSYASI ====
Write-Head '4. Yapilandirma dosyasi'

$cfg = [ordered]@{
    CustomerName = $customer
    ProviderName = $provider
    TenantId     = $tenant
    ClientId     = $clientId
    AuthMode     = 'Secret'
    CertificateThumbprint = ''
    ProxyUrl     = ''
    Schedule = [ordered]@{
        Weekly      = $wantWeekly
        WeeklyDay   = $weeklyDay
        WeeklyTime  = $weeklyTime
        Monthly     = $wantMonthly
        MonthlyDay  = $monthlyDay
        MonthlyTime = $monthlyTime
    }
    Report = [ordered]@{
        Format    = 'HTML'
        AttachPdf = [bool](Get-EdgePath)
        LogoPath  = 'logo.png'
        Language  = 'tr'
    }
    Mail = [ordered]@{
        Method  = $mailMethod
        From    = $mailFrom
        To      = @($mailTo)
        Cc      = @($mailCc)
        AlertTo = $alertTo
    }
    Smtp = [ordered]@{
        Server = $smtpServer
        Port   = $smtpPort
        UseSsl = $smtpSsl
        User   = $smtpUser
    }
    Thresholds = [ordered]@{
        InactiveDevicePct   = 5
        RiskyHostAlerts     = 3
        RansomRenameCount   = 100
        OpenIncidentAgeDays = 14
    }
}
$cfgPath = Join-Path $script:Root 'customer.json'
$cfg | ConvertTo-Json -Depth 8 | Set-Content $cfgPath -Encoding UTF8
Write-Ok "customer.json yazildi: $cfgPath"

# ====================================================== 5. ERISIM TESTLERI ==
Write-Head '5. Erisim testleri'
Write-Step 'Izinlerin dizinde yayilmasi icin 45 saniye bekleniyor...'
Start-Sleep -Seconds 45

$testScript = Join-Path $script:Root 'New-MDEReport.ps1'
& $testScript -Test
$testOk = ($LASTEXITCODE -eq 0)

if (-not $testOk) {
    Write-Host ''
    Write-Warn 'Bazi testler basarisiz. Izin yayilimi birkac dakika surebilir.'
    if (Read-YesNo 'Testler 60 saniye sonra tekrar denensin mi?' $true) {
        Start-Sleep -Seconds 60
        & $testScript -Test
        $testOk = ($LASTEXITCODE -eq 0)
    }
}

# ==================================================== 6. ZAMANLANMIS GOREV ==
if (-not $SkipTasks) {
    Write-Head '6. Zamanlanmis gorevler'
    $runAs  = Read-Value 'Gorevleri calistiracak hesap (DOMAIN\kullanici)' "$env:USERDOMAIN\$env:USERNAME"
    $ps     = (Get-Command powershell.exe).Source
    $dayMap = @{ MON='Monday'; TUE='Tuesday'; WED='Wednesday'; THU='Thursday'; FRI='Friday'; SAT='Saturday'; SUN='Sunday' }

    function New-TaskXml {
        param([string]$Desc, [string]$TriggerXml, [string]$Arguments, [string]$User, [string]$Exe, [string]$Author)
        $escDesc   = [System.Security.SecurityElement]::Escape($Desc)
        $escAuthor = [System.Security.SecurityElement]::Escape($Author)
        $escUser   = [System.Security.SecurityElement]::Escape($User)
        $escExe    = [System.Security.SecurityElement]::Escape($Exe)
        $escRoot   = [System.Security.SecurityElement]::Escape($script:Root)
@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>$escDesc</Description><Author>$escAuthor</Author></RegistrationInfo>
  <Triggers>$TriggerXml</Triggers>
  <Principal id="Author"><UserId>$escUser</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure><Interval>PT30M</Interval><Count>2</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>$escExe</Command><Arguments>$Arguments</Arguments><WorkingDirectory>$escRoot</WorkingDirectory></Exec>
  </Actions>
</Task>
"@
    }

    function Register-ReportTask {
        param([string]$Name, [string]$Desc, [string]$TriggerXml, [string]$Mode)
        $escScript = [System.Security.SecurityElement]::Escape($testScript)
        $argLine   = "-NoProfile -ExecutionPolicy Bypass -File &quot;$escScript&quot; -Mode $Mode"
        $xml       = New-TaskXml -Desc $Desc -TriggerXml $TriggerXml -Arguments $argLine -User $runAs -Exe $ps -Author $provider
        Write-Step "Gorev olusturuluyor: $Name"
        try {
            Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $Name -Xml $xml -Force | Out-Null
            Write-Ok "$Name olusturuldu."
        }
        catch {
            Write-Warn "$Name S4U modunda olusturulamadi: $($_.Exception.Message)"
            if (Read-YesNo 'Hesap parolasi girilerek tekrar denensin mi?' $true) {
                $pw = Read-Host "   $runAs parolasi" -AsSecureString
                $bs = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw)
                $pt = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bs)
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bs)
                try {
                    $xml2 = $xml -replace '<LogonType>S4U</LogonType>', '<LogonType>Password</LogonType>'
                    Register-ScheduledTask -TaskName $Name -Xml $xml2 -User $runAs -Password $pt -Force | Out-Null
                    Write-Ok "$Name olusturuldu."
                }
                catch { Write-Bad "$Name olusturulamadi: $($_.Exception.Message)" }
                finally { Clear-Variable pt -ErrorAction SilentlyContinue }
            }
        }
    }

    if ($wantWeekly) {
        $day = $dayMap[$weeklyDay]; if (-not $day) { $day = 'Monday' }
        $trg = "<CalendarTrigger><StartBoundary>2026-01-05T$weeklyTime`:00</StartBoundary><Enabled>true</Enabled>" +
               "<ScheduleByWeek><WeeksInterval>1</WeeksInterval><DaysOfWeek><$day /></DaysOfWeek></ScheduleByWeek></CalendarTrigger>"
        Register-ReportTask 'MDE-WeeklyReport' 'MDE haftalik EDR ozeti' $trg 'Weekly'
    }
    if ($wantMonthly) {
        $months = ('<January /><February /><March /><April /><May /><June /><July /><August /><September /><October /><November /><December />')
        $trg = "<CalendarTrigger><StartBoundary>2026-01-01T$monthlyTime`:00</StartBoundary><Enabled>true</Enabled>" +
               "<ScheduleByMonth><DaysOfMonth><Day>$monthlyDay</Day></DaysOfMonth><Months>$months</Months></ScheduleByMonth></CalendarTrigger>"
        Register-ReportTask 'MDE-MonthlyReport' 'MDE aylik guvenlik raporu' $trg 'Monthly'
    }
}

# ======================================================= 7. ILK RAPOR ======
Write-Head '7. Ilk rapor'
if ($testOk -and (Read-YesNo 'Simdi deneme raporu uretilsin mi? (mail gonderilmez)' $true)) {
    $firstMode = if ($wantMonthly) { 'Monthly' } else { 'Weekly' }
    & $testScript -Mode $firstMode -DryRun
    $out = Join-Path $script:Root 'Output'
    Write-Ok "Rapor uretildi. Klasor: $out"
    try { Start-Process $out } catch { }
}

# ============================================================= 8. OZET =====
Write-Head 'Kurulum ozeti'
Write-Host "   Kurum            : $customer"
Write-Host "   Hizmet saglayici : $provider"
Write-Host "   Tenant           : $(Get-Masked $tenant)"
Write-Host "   Uygulama         : $(Get-Masked $clientId)"
Write-Host "   Rapor periyodu   : $(if($wantWeekly){'Haftalik '})$(if($wantMonthly){'Aylik'})"
if ($wantWeekly)  { Write-Host "   Haftalik gorev   : $weeklyDay $weeklyTime" }
if ($wantMonthly) { Write-Host "   Aylik gorev      : ayin $monthlyDay. gunu $monthlyTime" }
Write-Host "   Mail yontemi     : $mailMethod ($mailFrom -> $($mailTo -join ', '))"
Write-Host "   Klasor           : $script:Root"
Write-Host ''
if ($testOk) { Write-Ok 'Kurulum tamamlandi. Sistem otomatik calisacak.' }
else { Write-Warn 'Kurulum tamamlandi ancak testler gecmedi. Izin yayilimini bekleyip su komutu calistirin:'
       Write-Host '     .\New-MDEReport.ps1 -Test' -ForegroundColor White }

Write-Host ''
Write-Host '   Faydali komutlar:' -ForegroundColor Gray
Write-Host '     .\New-MDEReport.ps1 -Test                     ' -NoNewline -ForegroundColor White; Write-Host 'erisim testleri' -ForegroundColor Gray
Write-Host '     .\New-MDEReport.ps1 -Mode Weekly  -DryRun     ' -NoNewline -ForegroundColor White; Write-Host 'haftalik ozet, mail yok' -ForegroundColor Gray
Write-Host '     .\New-MDEReport.ps1 -Mode Monthly -DryRun     ' -NoNewline -ForegroundColor White; Write-Host 'aylik rapor, mail yok' -ForegroundColor Gray
Write-Host '     .\New-MDEReport.ps1 -Mode Monthly             ' -NoNewline -ForegroundColor White; Write-Host 'aylik rapor + mail' -ForegroundColor Gray
Write-Host ''
