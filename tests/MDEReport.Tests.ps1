BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:Root = $script:RepoRoot
    . (Join-Path $script:RepoRoot 'MDEReport.Core.ps1')
    . (Join-Path $script:RepoRoot 'MDEReport.Html.ps1')

    $script:SampleConfig = Get-Content (Join-Path $script:RepoRoot 'customer.example.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $script:Start = [datetime]'2026-08-01T00:00:00Z'
    $script:End   = [datetime]'2026-09-01T00:00:00Z'

    $script:SyntheticData = [pscustomobject]@{
        Devices = @(
            [pscustomobject]@{ id = '1'; computerDnsName = 'wkst-01.contoso.com'; osPlatform = 'Windows11'; healthStatus = 'Active'; onboardingStatus = 'Onboarded'; firstSeen = '2026-08-10T10:00:00Z'; lastSeen = '2026-08-31T10:00:00Z' }
            [pscustomobject]@{ id = '2'; computerDnsName = 'srv-02.contoso.com';  osPlatform = 'WindowsServer2022'; healthStatus = 'ImpairedCommunication'; onboardingStatus = 'Onboarded'; firstSeen = '2026-01-10T10:00:00Z'; lastSeen = '2026-07-01T10:00:00Z' }
        )
        Alerts = @(
            [pscustomobject]@{ id = 'a1'; title = 'Test Alert'; severity = 'High';   category = 'Ransomware'; status = 'Resolved'; computerDnsName = 'wkst-01.contoso.com'; alertCreationTime = '2026-08-12T10:00:00Z' }
            [pscustomobject]@{ id = 'a2'; title = 'Alert 2';    severity = 'Medium'; category = 'Malware';    status = 'Resolved'; computerDnsName = 'wkst-01.contoso.com'; alertCreationTime = '2026-08-13T10:00:00Z' }
            [pscustomobject]@{ id = 'a3'; title = 'Alert 3';    severity = 'Low';    category = 'Malware';    status = 'Resolved'; computerDnsName = 'wkst-01.contoso.com'; alertCreationTime = '2026-08-14T10:00:00Z' }
        )
        Actions = @(
            [pscustomobject]@{ id = 'ac1'; type = 'Isolate'; status = 'Succeeded'; machineId = '1'; computerDnsName = 'wkst-01.contoso.com' }
            [pscustomobject]@{ id = 'ac2'; type = 'RunAntiVirusScan'; status = 'Succeeded'; machineId = '1'; computerDnsName = 'wkst-01.contoso.com' }
        )
        Incidents = @(
            [pscustomobject]@{ id = 'inc1'; severity = 'high'; status = 'resolved'; classification = 'truePositive'; createdDateTime = '2026-08-12T10:00:00Z'; lastUpdateDateTime = '2026-08-12T14:00:00Z' }
            [pscustomobject]@{ id = 'inc2'; severity = 'medium'; status = 'active'; classification = ''; createdDateTime = '2026-08-29T10:00:00Z'; lastUpdateDateTime = '2026-08-29T11:00:00Z' }
        )
        IncidentSource = 'Graph'
        Hunt = @{
            Antivirus = @(
                [pscustomobject]@{ Tehdit = 'Trojan:Win32/ContosoTest'; Temizlendi = 'true'; Adet = 5; Cihaz = 2 }
                [pscustomobject]@{ Tehdit = '<script>alert(1)</script>'; Temizlendi = 'false'; Adet = 1; Cihaz = 1 }
            )
            WebKoruma = @(
                [pscustomobject]@{ ActionType = 'SmartScreenUrlWarning'; Deneyim = 'Phishing'; Adet = 4; Cihaz = 2 }
                [pscustomobject]@{ ActionType = 'SmartScreenUserOverride'; Deneyim = 'Phishing'; Adet = 1; Cihaz = 1 }
            )
            Asr                   = @([pscustomobject]@{ ActionType = 'AsrLsassCredentialTheftBlocked'; Adet = 3; Cihaz = 1 })
            ExploitGuard          = @([pscustomobject]@{ ActionType = 'ExploitGuardNonMicrosoftSignedBlocked'; Adet = 2; Cihaz = 1 })
            FidyeDavranisi        = @()
            SupheliKomut          = @([pscustomobject]@{ FileName = 'powershell.exe'; Adet = 2; Cihaz = 1 })
            KimlikBilgisiErisimi  = @()
            SupheliCikisTrafigi   = @([pscustomobject]@{ InitiatingProcessFileName = 'powershell.exe'; Adet = 1; Cihaz = 1 })
            YeniYerelHesap        = @([pscustomobject]@{ ActionType = 'UserAccountCreated'; Adet = 1; Cihaz = 1 })
            ServisKurulumu        = @([pscustomobject]@{ Adet = 3; Cihaz = 2 })
            OlagandisiKonum       = @([pscustomobject]@{ FileName = '<img src=x onerror=alert(1)>.exe'; Adet = 2; Cihaz = 1 })
        }
        Start = $script:Start
        End   = $script:End
        Mode  = 'Monthly'
    }
}

Describe 'PowerShell AST ve Dosya Hijyeni' {
    It 'Tum .ps1 dosyalari sozdizimi hatasi olmadan ayristirilabilir' {
        $psFiles = Get-ChildItem -Path $script:RepoRoot -Filter '*.ps1' -File
        $psFiles.Count | Should -BeGreaterOrEqual 4
        foreach ($file in $psFiles) {
            $tokens = $null; $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0 -Because "Sozdizimi hatasi olmamali: $($file.Name)"
        }
    }

    It 'Public depoda kurum/musteri isim sizintisi bulunmaz' {
        $forbidden = @('KocSistem', 'KoçSistem', 'kocsistem\.com', 'KS-MDE-', 'Eureko')
        $files = Get-ChildItem -Path $script:RepoRoot -Recurse -File |
            Where-Object {
                $_.FullName -notmatch '[\\/]\.git[\\/]' -and
                $_.Name -ne 'MDEReport.Tests.ps1'
            }
        foreach ($file in $files) {
            $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if (-not $content) { continue }
            foreach ($pattern in $forbidden) {
                $content | Should -Not -Match $pattern -Because "$($file.Name) icinde '$pattern' bulunmamali"
            }
        }
    }
}

Describe 'KQL ve KPI Motoru' {
    It 'Haftalik modda 5 temel KQL sorgusu, aylik modda 11 KQL sorgusu uretir' {
        $w = Get-MdeQueries -Start $script:Start -End $script:End -Mode Weekly  -Thresholds $script:SampleConfig.Thresholds
        $m = Get-MdeQueries -Start $script:Start -End $script:End -Mode Monthly -Thresholds $script:SampleConfig.Thresholds
        $w.Count | Should -Be 5
        $m.Count | Should -Be 11
        $w.FidyeDavranisi | Should -Match 'where Gunluk > 100'
    }

    It 'Build-Kpi sentetik veriden dogru KPI degerleri hesaplar' {
        $kpi = Build-Kpi -Data $script:SyntheticData -Config $script:SampleConfig
        $kpi.TotalDevices | Should -Be 2
        $kpi.ActiveDevices | Should -Be 1
        $kpi.InactiveDevices | Should -Be 1
        $kpi.SensorProblem | Should -Be 1
        $kpi.MalwareBlocked | Should -Be 5
        $kpi.MalwareDetected | Should -Be 1
        $kpi.PhishBlocked | Should -Be 4
        $kpi.PhishOverridden | Should -Be 1
        $kpi.IsolatedDevices | Should -Be 1
        $kpi.ActionSuccessPct | Should -Be 100
        $kpi.IncClosed | Should -Be 1
        $kpi.IncOpen | Should -Be 1
        $kpi.AvgCloseHours | Should -Be 4
        $kpi.RiskyHostCount | Should -Be 1
    }
}

Describe 'HTML Rapor Guvenligi (XSS & CSP)' {
    It 'Aylik HTML raporu XSS yuklerini kacislar ve siki CSP basligi icerir' {
        $kpi  = Build-Kpi -Data $script:SyntheticData -Config $script:SampleConfig
        $html = New-MonthlyHtml -k $kpi -Config $script:SampleConfig -Root $script:RepoRoot -Prev $null

        $html | Should -Match 'Content-Security-Policy'
        $html | Should -Match "default-src 'none'"
        $html | Should -Not -Match '<script>alert\(1\)</script>'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $html | Should -Not -Match '<img src=x onerror=alert\(1\)>'
        $html | Should -Match '&lt;img src=x onerror=alert\(1\)&gt;\.exe'
        $html | Should -Match 'Contoso Corp'
        $html | Should -Match 'Security Operations'
    }

    It 'Haftalik HTML raporu temiz ve eksiksiz uretilir' {
        $kpi  = Build-Kpi -Data $script:SyntheticData -Config $script:SampleConfig
        $html = New-WeeklyHtml -k $kpi -Config $script:SampleConfig -Root $script:RepoRoot -Prev $null

        $html | Should -Match 'Haftalik EDR Ozeti'
        $html | Should -Match "default-src 'none'"
        $html | Should -Match 'wkst-01\.contoso\.com'
    }
}
