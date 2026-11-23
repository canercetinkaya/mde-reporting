<#
    MDE Managed EDR Reporting
    MDEReport.Html.ps1  -  HTML rapor uretimi (haftalik ozet + aylik detay)
#>

function ConvertTo-HtmlSafe {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-ReportCss {
@'
<style>
 @page { size: A4; margin: 12mm 10mm; }
 body { font-family: "Segoe UI", Arial, sans-serif; color:#1a1a1a; font-size:10.5pt; margin:0; background:#fff; }
 .wrap { max-width: 900px; margin: 0 auto; padding: 10px 16px; }
 .page { page-break-after: always; }
 .page:last-child { page-break-after: auto; }
 header { border-bottom:3px solid #0f4c81; padding-bottom:8px; margin-bottom:14px; }
 header h1 { color:#0f4c81; font-size:19pt; margin:0; }
 header .sub { color:#555; font-size:10pt; margin-top:4px; }
 .brand { float:right; color:#0f4c81; font-weight:600; font-size:11pt; }
 .logo { float:right; max-height:42px; }
 h2 { color:#0f4c81; font-size:13pt; margin:18px 0 8px; border-left:4px solid #0f4c81; padding-left:8px; }
 .cards { display:table; width:100%; table-layout:fixed; border-spacing:6px 0; margin-top:6px; }
 .card { display:table-cell; text-align:center; border:1px solid #dfe5ec; border-radius:5px; padding:10px 4px; background:#f7fafd; }
 .card b { display:block; font-size:19pt; color:#0f4c81; line-height:1.15; }
 .card span { font-size:8.5pt; color:#555; }
 .card.warn { background:#fdf3f2; border-color:#f0c8c4; }
 .card.warn b { color:#c00000; }
 .card.good b { color:#1e7d32; }
 table { width:100%; border-collapse:collapse; margin-top:6px; font-size:9.5pt; }
 th { background:#0f4c81; color:#fff; text-align:left; padding:5px 7px; font-weight:600; }
 td { border-bottom:1px solid #e3e8ee; padding:5px 7px; vertical-align:top; }
 td.num { text-align:right; white-space:nowrap; }
 .two { display:table; width:100%; table-layout:fixed; border-spacing:10px 0; }
 .col { display:table-cell; vertical-align:top; }
 .bar { display:table; width:100%; margin:4px 0; font-size:9.5pt; }
 .bl { display:table-cell; width:40%; }
 .bt { display:table-cell; }
 .bt i { display:block; height:11px; border-radius:2px; }
 .bv { display:table-cell; width:12%; text-align:right; font-weight:600; }
 .note { font-size:8.5pt; color:#666; margin-top:10px; line-height:1.45; }
 .up { color:#c00000; font-weight:600; } .down { color:#1e7d32; font-weight:600; }
 .flag { background:#fff8e6; border-left:4px solid #e0a800; padding:8px 10px; margin:6px 0; font-size:9.5pt; }
 .flag.crit { background:#fdf3f2; border-left-color:#c00000; }
 .flag.ok { background:#f2faf4; border-left-color:#1e7d32; }
</style>
'@
}

function Get-Bar {
    param([string]$Label, [double]$Value, [double]$Max, [string]$Color = '#0f4c81')
    $pct = if ($Max -gt 0) { [math]::Round(($Value / $Max) * 100, 0) } else { 0 }
    $safeLabel = ConvertTo-HtmlSafe $Label
    "<div class='bar'><span class='bl'>$safeLabel</span><span class='bt'><i style='width:$pct%;background:$Color'></i></span><span class='bv'>$Value</span></div>"
}

function Get-TrendCells {
    param([string]$Field, [double]$Now, $Prev)
    if (-not $Prev -or $null -eq $Prev.$Field) { return "<td class='num'>-</td><td class='num'>-</td>" }
    $p = [double]$Prev.$Field
    $d = $Now - $p
    if ($d -eq 0) { return "<td class='num'>$p</td><td class='num'>degisim yok</td>" }
    $pct = if ($p -gt 0) { ' (%' + [math]::Abs([math]::Round(($d / $p) * 100, 0)) + ')' } else { '' }
    $cls = if ($d -gt 0) { 'up' } else { 'down' }
    $sgn = if ($d -gt 0) { '+' } else { '' }
    "<td class='num'>$p</td><td class='num $cls'>$sgn$d$pct</td>"
}

function Get-LogoHtml {
    param($Config, [string]$Root)
    if ($Config.Report.LogoPath) {
        $lp = Join-Path $Root $Config.Report.LogoPath
        if (Test-Path $lp) {
            $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($lp))
            return "<img class='logo' alt='Logo' src='data:image/png;base64,$b64'/>"
        }
    }
    $provider = ConvertTo-HtmlSafe (Get-ProviderName $Config)
    "<span class='brand'>$provider</span>"
}

# Esik degerlerine gore otomatik "dikkat gerektiren basliklar" uretir.
function Get-Flags {
    param($k, $Config)
    $th = $Config.Thresholds
    $out = New-Object System.Collections.ArrayList

    if ($k.IncOpen -gt 0) {
        [void]$out.Add("<div class='flag crit'>$($k.IncOpen) incident hala acik durumda ve analist takibindedir.</div>")
    }
    if ($k.InactivePct -gt $th.InactiveDevicePct) {
        [void]$out.Add("<div class='flag'>Pasif cihaz orani %$($k.InactivePct) ile esik degeri olan %$($th.InactiveDevicePct) uzerindedir. $($k.InactiveDevices) cihaz donem boyunca telemetri gondermemistir.</div>")
    }
    if ($k.SensorProblem -gt 0) {
        [void]$out.Add("<div class='flag'>$($k.SensorProblem) cihazin sensor durumu bozuk veya veri gondermiyor; onboarding dogrulamasi gerekir.</div>")
    }
    if ($k.RansomwareAlerts -gt 0 -or $k.RansomBehaviorHosts -gt 0) {
        [void]$out.Add("<div class='flag crit'>Fidye yazilimi ile iliskili bulgu: $($k.RansomwareAlerts) alert, $($k.RansomBehaviorHosts) cihazda toplu dosya yeniden adlandirma davranisi.</div>")
    }
    if ($k.RiskyHostCount -gt 0) {
        [void]$out.Add("<div class='flag'>$($k.RiskyHostCount) cihaz $($th.RiskyHostAlerts) ve uzerinde alert uretmistir; tekrar eden bulgu olarak incelenmelidir.</div>")
    }
    if ($k.PhishOverridden -gt 0) {
        [void]$out.Add("<div class='flag'>$($k.PhishOverridden) kez kullanici SmartScreen uyarisini gecmistir; kullanici farkindalik calismasi onerilir.</div>")
    }
    if ($out.Count -eq 0) {
        [void]$out.Add("<div class='flag ok'>Bu donemde esik degerlerini asan bir bulgu tespit edilmemistir.</div>")
    }
    ($out -join '')
}

# ------------------------------------------------------------------ HAFTALIK
function New-WeeklyHtml {
    param($k, $Config, [string]$Root, $Prev)

    $tr       = [Globalization.CultureInfo]::GetCultureInfo('tr-TR')
    $bas      = [datetime]$k.DonemBaslangic; $bit = [datetime]$k.DonemBitis
    $donem    = '{0} - {1}' -f $bas.ToString('dd MMMM', $tr), $bit.ToString('dd MMMM yyyy', $tr)
    $logo     = Get-LogoHtml $Config $Root
    $flags    = Get-Flags $k $Config
    $customer = ConvertTo-HtmlSafe $Config.CustomerName
    $provider = ConvertTo-HtmlSafe (Get-ProviderName $Config)

    $maxH  = ($k.SensorHealth.Values | Measure-Object -Maximum).Maximum
    $hbars = ($k.SensorHealth.GetEnumerator() | Sort-Object Value -Descending |
                ForEach-Object { Get-Bar $_.Key $_.Value $maxH }) -join ''

    $risky = ''
    foreach ($r in ($k.RiskyHosts | Select-Object -First 5)) {
        $safeHost = ConvertTo-HtmlSafe $r.Cihaz
        $risky += "<tr><td>$safeHost</td><td class='num'>$($r.Alert)</td></tr>"
    }
    if (-not $risky) { $risky = "<tr><td colspan='2'>Esigi asan cihaz yok.</td></tr>" }

@"
<!DOCTYPE html><html lang='tr'><head><meta charset='utf-8'>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
<title>Haftalik EDR Ozeti</title>
$(Get-ReportCss)</head><body><div class='wrap'>
<div class='page'>
  <header>$logo<h1>Haftalik EDR Ozeti</h1>
  <div class='sub'>$customer &nbsp;|&nbsp; Microsoft Defender for Endpoint Yonetilen EDR<br>
  Donem: $donem &nbsp;|&nbsp; Uretim: $(Get-Date -Format 'dd.MM.yyyy HH:mm') &nbsp;|&nbsp; $provider</div></header>

  <div class='cards'>
    <div class='card'><b>$($k.ActiveDevices)</b><span>Aktif cihaz / $($k.TotalDevices)</span></div>
    <div class='card $(if($k.SensorProblem -gt 0){'warn'})'><b>$($k.SensorProblem)</b><span>Sensor sorunlu cihaz</span></div>
    <div class='card'><b>$($k.TotalAlerts)</b><span>Yeni alert</span></div>
    <div class='card $(if($k.AlertHigh -gt 0){'warn'})'><b>$($k.AlertHigh)</b><span>Yuksek siddetli alert</span></div>
    <div class='card $(if($k.IncOpen -gt 0){'warn'})'><b>$($k.IncOpen)</b><span>Acik incident</span></div>
    <div class='card'><b>$($k.TotalActions)</b><span>Response aksiyonu</span></div>
  </div>

  <h2>Dikkat Gerektiren Basliklar</h2>
  $flags

  <div class='two'>
    <div class='col'>
      <h2>Tehdit Korumasi</h2>
      <table>
        <tr><th>Onlenen tehdit</th><th>Adet</th></tr>
        <tr><td>Engellenen / temizlenen zararli yazilim</td><td class='num'>$($k.MalwareBlocked)</td></tr>
        <tr><td>Mudahale gerektiren zararli</td><td class='num'>$($k.MalwareDetected)</td></tr>
        <tr><td>Engellenen kotu amacli URL</td><td class='num'>$($k.UrlBlocked)</td></tr>
        <tr><td>Engellenen phishing sayfasi</td><td class='num'>$($k.PhishBlocked)</td></tr>
        <tr><td>ASR kurali engellemesi</td><td class='num'>$($k.AsrBlocked)</td></tr>
        <tr><td>Exploit onleme engellemesi</td><td class='num'>$($k.ExploitEvents)</td></tr>
      </table>
    </div>
    <div class='col'>
      <h2>Sensor Sagligi</h2>
      $hbars
      <h2>Tekrar Eden Bulgu Ureten Cihazlar</h2>
      <table><tr><th>Cihaz</th><th>Alert</th></tr>$risky</table>
    </div>
  </div>

  <h2>Hizmet Faaliyetleri</h2>
  <table>
    <tr><th>Faaliyet</th><th>Adet</th></tr>
    <tr><td>Incelenen ve siniflandirilan olay</td><td class='num'>$($k.InvestigatedIncidents)</td></tr>
    <tr><td>Izole edilen cihaz</td><td class='num'>$($k.IsolatedDevices)</td></tr>
    <tr><td>Toplam response aksiyonu</td><td class='num'>$($k.TotalActions)</td></tr>
    <tr><td>Aksiyon basari orani</td><td class='num'>%$($k.ActionSuccessPct)</td></tr>
    <tr><td>Yeni onboard edilen cihaz</td><td class='num'>$($k.NewDevices)</td></tr>
  </table>

  <p class='note'>Bu ozet Microsoft Defender for Endpoint API ve Advanced Hunting verisinden otomatik uretilmistir.
  Ayrintili analiz, trend karsilastirmasi ve tehdit avciligi bulgulari aylik raporda yer alir.
  $(if ($k.SeveritySource -ne 'Graph') { 'Not: incident verisine erisilemedigi icin siddet dagilimi alert verisinden uretilmistir.' })
  Gizlilik: Kuruma Ozel.</p>
</div>
</div></body></html>
"@
}

# --------------------------------------------------------------------- AYLIK
function New-MonthlyHtml {
    param($k, $Config, [string]$Root, $Prev)

    $tr       = [Globalization.CultureInfo]::GetCultureInfo('tr-TR')
    $bas      = [datetime]$k.DonemBaslangic
    $donem    = $bas.ToString('MMMM yyyy', $tr)
    $logo     = Get-LogoHtml $Config $Root
    $flags    = Get-Flags $k $Config
    $customer = ConvertTo-HtmlSafe $Config.CustomerName
    $provider = ConvertTo-HtmlSafe (Get-ProviderName $Config)

    $maxH  = ($k.SensorHealth.Values | Measure-Object -Maximum).Maximum
    $hbars = ($k.SensorHealth.GetEnumerator() | Sort-Object Value -Descending |
                ForEach-Object { Get-Bar $_.Key $_.Value $maxH }) -join ''

    $sevMax = @($k.IncHigh, $k.IncMedium, $k.IncLow, $k.IncInfo | Measure-Object -Maximum).Maximum
    $sbars  = (Get-Bar 'High (kritik)' $k.IncHigh   $sevMax '#c00000') +
              (Get-Bar 'Medium'        $k.IncMedium $sevMax '#e0a800') +
              (Get-Bar 'Low'           $k.IncLow    $sevMax '#4a90d9') +
              (Get-Bar 'Informational' $k.IncInfo   $sevMax '#9aa5b1')

    $osRows = ($k.OsBreakdown.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 6 |
                ForEach-Object { "<tr><td>$(ConvertTo-HtmlSafe $_.Key)</td><td class='num'>$($_.Value)</td></tr>" }) -join ''

    $threatRows = ''
    foreach ($t in $k.TopThreats) { $threatRows += "<tr><td>$(ConvertTo-HtmlSafe $t.Ad)</td><td class='num'>$($t.Adet)</td><td class='num'>$($t.Cihaz)</td></tr>" }
    if (-not $threatRows) { $threatRows = "<tr><td colspan='3'>Bu donemde zararli yazilim tespiti yok.</td></tr>" }

    $deviceRows = ''
    foreach ($x in $k.TopDevices) { $deviceRows += "<tr><td>$(ConvertTo-HtmlSafe $x.Cihaz)</td><td class='num'>$($x.Alert)</td></tr>" }
    if (-not $deviceRows) { $deviceRows = "<tr><td colspan='2'>Alert ureten cihaz yok.</td></tr>" }

    $actionRows = ''
    foreach ($x in @($k.ActionBreakdown.GetEnumerator() | Sort-Object Value -Descending)) {
        $actionRows += "<tr><td>$(ConvertTo-HtmlSafe $x.Key)</td><td class='num'>$($x.Value)</td></tr>"
    }
    if (-not $actionRows) { $actionRows = "<tr><td colspan='2'>Bu donemde response aksiyonu alinmadi.</td></tr>" }

    $clsRows = ($k.Classification.GetEnumerator() | Sort-Object Value -Descending |
                ForEach-Object { "<tr><td>$(ConvertTo-HtmlSafe $_.Key)</td><td class='num'>$($_.Value)</td></tr>" }) -join ''
    if (-not $clsRows) { $clsRows = "<tr><td colspan='2'>Siniflandirilmis incident yok.</td></tr>" }

    $konumRows = ''
    foreach ($x in $k.HuntOlagandisiKonum) { $konumRows += "<tr><td>$(ConvertTo-HtmlSafe $x.FileName)</td><td class='num'>$($x.Adet)</td><td class='num'>$($x.Cihaz)</td></tr>" }
    if (-not $konumRows) { $konumRows = "<tr><td colspan='3'>Bulgu yok.</td></tr>" }

    $trendCumle = ''
    if ($Prev) {
        $yon = if ($k.TotalAlerts -ge $Prev.TotalAlerts) { 'artis' } else { 'azalis' }
        $trendCumle = "Onceki doneme gore alert sayisi $yon gostermistir ($($Prev.TotalAlerts) -&gt; $($k.TotalAlerts))."
    }

@"
<!DOCTYPE html><html lang='tr'><head><meta charset='utf-8'>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
<title>Aylik Guvenlik Raporu</title>
$(Get-ReportCss)</head><body><div class='wrap'>

<div class='page'>
  <header>$logo<h1>Aylik Guvenlik Raporu</h1>
  <div class='sub'>$customer &nbsp;|&nbsp; Microsoft Defender for Endpoint Yonetilen EDR Hizmeti<br>
  Donem: $donem &nbsp;|&nbsp; Rapor tarihi: $(Get-Date -Format 'dd.MM.yyyy') &nbsp;|&nbsp; Hizmet saglayici: $provider</div></header>

  <h2>Yonetici Ozeti</h2>
  <p>$donem doneminde $customer ortaminda <b>$($k.TotalDevices)</b> cihaz Microsoft Defender for Endpoint ile izlenmistir.
  Donem boyunca <b>$($k.TotalAlerts)</b> alert ve <b>$($k.TotalIncidents)</b> incident uretilmis, bunlarin <b>$($k.IncClosed)</b> tanesi kapatilmistir.
  $provider tarafindan <b>$($k.TotalActions)</b> response aksiyonu yurutulmus, <b>$($k.IsolatedDevices)</b> cihaz agdan izole edilmistir.
  Rapor tarihi itibariyla <b>$($k.IncOpen)</b> incident acik durumdadir. $trendCumle</p>

  <h2>Dikkat Gerektiren Basliklar</h2>
  $flags

  <h2>Endpoint Kapsami</h2>
  <div class='cards'>
    <div class='card'><b>$($k.TotalDevices)</b><span>Toplam onboard cihaz</span></div>
    <div class='card'><b>$($k.ActiveDevices)</b><span>Son 30 gun aktif</span></div>
    <div class='card $(if($k.InactivePct -gt $Config.Thresholds.InactiveDevicePct){'warn'})'><b>$($k.InactiveDevices)</b><span>Pasif (%$($k.InactivePct))</span></div>
    <div class='card'><b>$($k.NewDevices)</b><span>Yeni onboard</span></div>
    <div class='card $(if($k.SensorProblem -gt 0){'warn'})'><b>$($k.SensorProblem)</b><span>Sensor sorunlu</span></div>
  </div>

  <div class='two'>
    <div class='col'><h2>Sensor Sagligi</h2>$hbars</div>
    <div class='col'><h2>Isletim Sistemi Dagilimi</h2><table><tr><th>Platform</th><th>Cihaz</th></tr>$osRows</table></div>
  </div>
  <p class='note'>Kaynak: Microsoft Defender for Endpoint API (/api/machines) ve Advanced Hunting (DeviceInfo).</p>
</div>

<div class='page'>
  <header><span class='brand'>$provider</span><h1>Tehdit ve Olay Ozeti</h1>
  <div class='sub'>$customer &nbsp;|&nbsp; $donem</div></header>

  <h2>Tehdit Korumasi</h2>
  <table>
    <tr><th>KPI</th><th>Bu donem</th><th>Onceki donem</th><th>Degisim</th></tr>
    <tr><td>Engellenen / temizlenen zararli yazilim</td><td class='num'>$($k.MalwareBlocked)</td>$(Get-TrendCells 'MalwareBlocked' $k.MalwareBlocked $Prev)</tr>
    <tr><td>Mudahale gerektiren zararli</td><td class='num'>$($k.MalwareDetected)</td>$(Get-TrendCells 'MalwareDetected' $k.MalwareDetected $Prev)</tr>
    <tr><td>Engellenen phishing sayfasi</td><td class='num'>$($k.PhishBlocked)</td>$(Get-TrendCells 'PhishBlocked' $k.PhishBlocked $Prev)</tr>
    <tr><td>Kullanicinin uyariyi gectigi phishing</td><td class='num'>$($k.PhishOverridden)</td>$(Get-TrendCells 'PhishOverridden' $k.PhishOverridden $Prev)</tr>
    <tr><td>Engellenen kotu amacli URL</td><td class='num'>$($k.UrlBlocked)</td>$(Get-TrendCells 'UrlBlocked' $k.UrlBlocked $Prev)</tr>
    <tr><td>Exploit onleme engellemesi</td><td class='num'>$($k.ExploitEvents)</td>$(Get-TrendCells 'ExploitEvents' $k.ExploitEvents $Prev)</tr>
    <tr><td>ASR kurali engellemesi</td><td class='num'>$($k.AsrBlocked)</td>$(Get-TrendCells 'AsrBlocked' $k.AsrBlocked $Prev)</tr>
    <tr><td>Ransomware iliskili alert</td><td class='num'>$($k.RansomwareAlerts)</td>$(Get-TrendCells 'RansomwareAlerts' $k.RansomwareAlerts $Prev)</tr>
    <tr><td>Fidye davranisi gorulen cihaz</td><td class='num'>$($k.RansomBehaviorHosts)</td>$(Get-TrendCells 'RansomBehaviorHosts' $k.RansomBehaviorHosts $Prev)</tr>
  </table>

  <div class='two'>
    <div class='col'><h2>Incident Siddet Dagilimi</h2>$sbars
      <p class='note'>Toplam incident: $($k.TotalIncidents) &nbsp;|&nbsp; Kapatilan: $($k.IncClosed) &nbsp;|&nbsp; Acik: $($k.IncOpen)<br>
      Ortalama kapanis suresi: $($k.AvgCloseHours) saat<br>
      $(if ($k.SeveritySource -ne 'Graph') { 'Not: incident verisine erisilemedigi icin dagitim alert verisinden uretilmistir.' })</p>
    </div>
    <div class='col'><h2>En Cok Gorulen Tehditler</h2>
      <table><tr><th>Tehdit</th><th>Adet</th><th>Cihaz</th></tr>$threatRows</table></div>
  </div>

  <h2>En Cok Alert Ureten Cihazlar</h2>
  <table><tr><th>Cihaz</th><th>Alert</th></tr>$deviceRows</table>

  <p class='note'>Phishing verisi uc nokta korumasi (SmartScreen ve ag korumasi) kaynaklidir.
  E-posta kaynakli phishing Microsoft Defender for Office 365 kapsamindadir ve bu raporda yer almaz.</p>
</div>

<div class='page'>
  <header><span class='brand'>$provider</span><h1>Tehdit Avciligi Bulgulari</h1>
  <div class='sub'>$customer &nbsp;|&nbsp; $donem</div></header>

  <p class='note'>Asagidaki bulgular Advanced Hunting sorgulariyla uretilir. Her bulgu tek basina bir tehdit gostergesi degildir;
  yonetilen hizmet kapsaminda anormallik takibi ve triyaj girdisi olarak kullanilir.</p>

  <table>
    <tr><th>Bulgu</th><th>Olay</th><th>Aciklama</th></tr>
    <tr><td>Supheli komut satiri kullanimi</td><td class='num'>$($k.HuntSupheliKomut)</td><td>Kodlanmis PowerShell, indirme komutlari ve script host kullanimi</td></tr>
    <tr><td>Kimlik bilgisi erisim girisimi</td><td class='num'>$($k.HuntKimlikErisimi)</td><td>Bilinen kimlik bilgisi cikarma araclarina ait komut satiri izleri</td></tr>
    <tr><td>Script host kaynakli dis baglanti</td><td class='num'>$($k.HuntCikisTrafigi)</td><td>PowerShell veya benzeri surecin dogrudan internete cikisi</td></tr>
    <tr><td>Yeni yerel hesap / grup uyeligi</td><td class='num'>$($k.HuntYeniYerelHesap)</td><td>Uc noktada olusturulan yerel hesap ve yerel gruba ekleme</td></tr>
    <tr><td>Servis kurulumu</td><td class='num'>$($k.HuntServisKurulumu)</td><td>Kalicilik amacli kullanilabilen yeni Windows servisi</td></tr>
  </table>

  <h2>Olagandisi Konumdan Calistirilan Dosyalar</h2>
  <table><tr><th>Dosya</th><th>Olay</th><th>Cihaz</th></tr>$konumRows</table>

  <h2>Yonetilen Hizmet Faaliyetleri</h2>
  <div class='cards'>
    <div class='card'><b>$($k.InvestigatedIncidents)</b><span>Incelenen olay</span></div>
    <div class='card'><b>$($k.IsolatedDevices)</b><span>Izole edilen cihaz</span></div>
    <div class='card'><b>$($k.TotalActions)</b><span>Response aksiyonu</span></div>
    <div class='card'><b>%$($k.ActionSuccessPct)</b><span>Aksiyon basari orani</span></div>
    <div class='card'><b>$($k.NewDevices)</b><span>Onboarding faaliyeti</span></div>
  </div>

  <div class='two'>
    <div class='col'><h2>Response Aksiyonlari</h2><table><tr><th>Aksiyon turu</th><th>Adet</th></tr>$actionRows</table></div>
    <div class='col'><h2>Incident Siniflandirmasi</h2><table><tr><th>Siniflandirma</th><th>Adet</th></tr>$clsRows</table></div>
  </div>

  <p class='note'>Bu rapor $provider tarafindan Microsoft Defender for Endpoint verisinden otomatik uretilmistir.
  Uretim zamani: $(Get-Date -Format 'dd.MM.yyyy HH:mm'). Gizlilik: Kuruma Ozel.</p>
</div>

</div></body></html>
"@
}
