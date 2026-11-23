# Mimari ve KPI Tasarım Dokümanı

Bu doküman, **MDE Reporting** çözümünün teknik mimarisini, veri akışını, ağ gereksinimlerini, 4 bölümlü KPI kataloğunu ve PoC doğrulama adımlarını tanımlar.

## 1. Tasarım İlkeleri

| İlke | Uygulama Kuralı |
| :--- | :--- |
| **Sıfır ek lisans** | Yalnızca mevcut Microsoft Defender for Endpoint lisansı ve Windows yerleşik bileşenleri kullanılır. Power BI, Power Automate, Azure Automation veya harici PowerShell modülleri gerekmez. |
| **Kiracı izolasyonu** | Her kurum kendi Entra ID kiracısında kendi tek kiracılı (single-tenant) App Registration kaydı ve `customer.json` dosyasıyla çalışır. |
| **En az ayrıcalık** | Uygulamaya yalnızca okuma izinleri verilir (`Machine.Read.All`, `Alert.Read.All`, `AdvancedQuery.Read.All`, `SecurityIncident.Read.All`). Cihaz izolasyonu veya tarama gibi yazma izinleri tanımlanmaz. |
| **Kod sabit, yapılandırma değişken** | Kurum adı, sağlayıcı adı, kiracı/uygulama kimlikleri, alıcı listesi, logo ve eşikler `customer.json` dosyasındadır; betikler kuruma göre değiştirilmez. |
| **Tekrar üretilebilirlik** | Ham API yanıtları ve hesaplanan `kpi.json` her dönemde `Archive\<Mode>\<dönem>\` altında saklanır; önceki ayın `kpi.json` dosyası otomatik trend kıyaslaması için okunur. |
| **Veri minimizasyonu ve XSS koruması** | Rapora yalnızca toplulanmış KPI metrikleri ve en fazla ilk 10 kayıt girer; tüm dinamik alanlar `HtmlEncode` ile kaçışlanır ve HTML raporu sıkı çevrimdışı CSP başlığı taşır. |

---

## 2. Mantıksal Mimari ve Veri Akışı

```text
+-------------------------------------------------------------------+
|  KURUM KIRACISI (Microsoft Entra ID + Microsoft 365 Defender)     |
+-------------------------------------------------------------------+
         | (1) OAuth2 client_credentials           ^ (6) Rapor e-postasi
         v     (Sertifika veya DPAPI Secret)       |     (Graph / SMTP)
+-------------------------------------------------------------------+
|  RAPORLAMA SUNUCUSU (Windows Server 2019+ / Windows 10-11)        |
|  Task Scheduler (Haftalik & Aylik) --> New-MDEReport.ps1          |
|                                                                   |
|  customer.json -> MDEReport.Core.ps1 -> Get-MdeData               |
|                                      -> Build-Kpi                 |
|                   MDEReport.Html.ps1 -> New-WeeklyHtml / Monthly  |
|                   Edge Headless      -> Convert-ToPdf             |
|                   Graph / SMTP       -> Send-Report               |
+-------------------------------------------------------------------+
         | (2)-(5) Yalnizca giden HTTPS (TCP 443)
         v
+-------------------------------------------------------------------+
|  api.securitycenter.microsoft.com                                 |
|    /api/machines  |  /api/alerts  |  /api/machineactions          |
|    /api/advancedqueries/run (KQL)                                 |
|  graph.microsoft.com                                              |
|    /v1.0/security/incidents  |  /v1.0/users/{from}/sendMail       |
+-------------------------------------------------------------------+
```

### Ağ Gereksinimleri

| Hedef | Port | Amaç |
| :--- | :--- | :--- |
| `login.microsoftonline.com` | TCP 443 | Entra ID OAuth2 erişim jetonu |
| `api.securitycenter.microsoft.com` | TCP 443 | MDE cihaz, alert, machine action ve Advanced Hunting çağrıları |
| `graph.microsoft.com` | TCP 443 | Incident verisi ve isteğe bağlı Graph `sendMail` |
| `smtp.office365.com` veya kurumsal relay | TCP 587 / 25 | Yalnızca `Mail.Method = "Smtp"` kullanıldığında |
| Gelen bağlantı | **Yok** | Sunucuya dışarıdan gelen bağlantı gerekmez |

---

## 3. KPI Kataloğu

### Bölüm 1 — Endpoint Kapsamı (`EP`)
| Kod | KPI | Veri Kaynağı | Hesaplama Mantığı |
| :--- | :--- | :--- | :--- |
| `EP-01` | Toplam onboard cihaz | `GET /api/machines` | `onboardingStatus == Onboarded` cihaz sayısı |
| `EP-02` | Aktif cihaz | `GET /api/machines` | `lastSeen` değeri dönem sonundan geriye 7 gün (haftalık) veya 30 gün (aylık) içinde olan cihazlar |
| `EP-03` | Pasif cihaz ve oranı | `GET /api/machines` | `EP-01 - EP-02` ve eşik kıyaslaması (`Thresholds.InactiveDevicePct`) |
| `EP-04` | Yeni onboard edilen cihaz | `GET /api/machines` | `firstSeen` değeri rapor dönemi içinde olan cihaz sayısı |
| `EP-05` | Sensör sağlığı dağılımı | `GET /api/machines` | `healthStatus` kırılımı (`Active`, `Inactive`, `ImpairedCommunication`, `NoSensorData`) |
| `EP-06` | Sensör sorunlu cihaz | `GET /api/machines` | `ImpairedCommunication` + `NoSensorData` + `NoSensorDataImpairedCommunication` |
| `EP-07` | İşletim sistemi dağılımı | `GET /api/machines` | `osPlatform` kırılımı (ilk 6 platform) |

### Bölüm 2 — Tehdit Koruması (`TP`)
| Kod | KPI | Veri Kaynağı | Hesaplama Mantığı |
| :--- | :--- | :--- | :--- |
| `TP-01` | Engellenen / temizlenen zararlı | `DeviceEvents` (`AntivirusDetection`) | `AdditionalFields.WasRemediated == true` kayıt sayısı |
| `TP-02` | Müdahale gerektiren zararlı | `DeviceEvents` (`AntivirusDetection`) | `WasRemediated != true` kayıt sayısı |
| `TP-03` | Engellenen phishing | `DeviceEvents` (`SmartScreen*`) | `Experience` alanında `Phish` geçen engellemeler |
| `TP-04` | Kullanıcının geçtiği phishing | `DeviceEvents` | `ActionType == SmartScreenUserOverride` |
| `TP-05` | Engellenen kötü amaçlı URL | `DeviceEvents` | `SmartScreenUrlWarning` + `ExploitGuardNetworkProtectionBlocked` |
| `TP-06` | Exploit önleme engellemeleri | `DeviceEvents` | `ExploitGuard*` (ağ koruması hariç) |
| `TP-07` | Ransomware alert & davranışı | `/api/alerts` + `DeviceFileEvents` | `category` içinde `Ransom` geçen alert'ler + günlük eşik üstü `FileRenamed` cihazları |
| `TP-08` | ASR kural engellemeleri | `DeviceEvents` | `ActionType startswith "Asr" and endswith "Blocked"` |
| `TP-09` | En çok görülen 10 tehdit | `DeviceEvents` | `ThreatName` bazında azalan sırada ilk 10 |

> **Kapsam Notu:** Phishing metrikleri uç nokta (SmartScreen ve Ağ Koruması) kaynaklıdır. E-posta kaynaklı phishing verisi Microsoft Defender for Office 365 kapsamındadır ve raporda dipnot olarak açıkça belirtilir.

### Bölüm 3 — Alerts, Incidents ve Tehdit Avcılığı (`AL` / `HUNT`)
- **Alert & Incident:** Toplam alert, yüksek şiddetli alert, Graph incident şiddet dağılımı (`High`, `Medium`, `Low`, `Informational`), açık/kapatılan incident sayısı, ortalama kapanış süresi (saat), sınıflandırma dağılımı ve en çok alert üreten ilk 10 cihaz.
- **Aylık Tehdit Avcılığı (Advanced Hunting):** Şüpheli komut satırı (`-enc`, `FromBase64String`, `DownloadString`), kimlik bilgisi erişim izleri, script host kaynaklı dış bağlantılar, yeni yerel hesap / grup ekleme, yeni Windows servis kurulumu ve olağandışı konumlardan çalıştırılan `.exe` dosyaları.

### Bölüm 4 — Yönetilen Hizmet Faaliyetleri (`MS`)
- İncelenen ve sınıflandırılan olay sayısı, izole edilen benzersiz cihaz sayısı, toplam response aksiyonu, aksiyon türü kırılımı (`Isolate`, `RunAntiVirusScan`, `StopAndQuarantineFile`, `RestrictCodeExecution`) ve başarı yüzdesi.

---

## 4. Kısıtlar ve Operasyonel Dayanıklılık

- **Advanced Hunting 30 günlük saklama sınırı:** Aylık görev her ayın 1'inde çalıştırılmalıdır; geçmiş aylara `-Date` ile gidildiğinde Advanced Hunting sorguları 30 gün ötesini döndürmez.
- **HTTP 429 / 5xx yönetimi:** `Invoke-WithRetry` üstel geri çekilme ile en fazla 5 kez yeniden dener; KQL sorguları arasında hız sınırı beklemesi (`1500 ms`) uygulanır.
- **Kısmi veri toleransı:** Bir KQL sorgusu veya Graph incident uç noktası erişilemezse çalışma durmaz; incident yoksa şiddet dağılımı alert verisinden üretilir ve dipnotta belirtilir.
- **Sertifika / gizli anahtar yenileme:** Üretimde X.509 sertifika (`AuthMode: "Certificate"`) önerilir; gizli anahtar kullanılıyorsa 12 ay dolmadan yenilenmelidir.
