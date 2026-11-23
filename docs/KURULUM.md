# MDE Reporting — Kurulum ve İşletim Kılavuzu

Haftalık operasyon özeti ve aylık 3 sayfalık yönetim raporu üreten, ek lisans ve harici PowerShell modülü gerektirmeyen Microsoft Defender for Endpoint (MDE) raporlama çözümüdür.

## Dosyalar

| Dosya | Görev |
| :--- | :--- |
| `Install-MDEReport.ps1` | **Tek ekran kurulum sihirbazı.** Entra ID uygulama kaydını oluşturur, izinleri ekler, yönetici onayını verir, gizli anahtarı DPAPI ile şifreler, `customer.json` yazar, erişim testlerini koşar ve Windows Task Scheduler görevlerini kurar. |
| `Kurulum-Baslat.cmd` | Yürütme politikasını yalnızca o oturum için devre dışı bırakır, indirilen dosyaların engelini (`Unblock-File`) kaldırır ve sihirbazı başlatır. |
| `New-MDEReport.ps1` | Ana rapor motoru (`-Mode Weekly` / `-Mode Monthly`, `-DryRun`, `-Test`, `-ExportCsv`, `-Pdf`). |
| `MDEReport.Core.ps1` | OAuth2 kimlik doğrulama (sertifika / DPAPI secret), MDE ve Graph API çağrıları, KQL sorgu paketi, KPI hesaplama, PDF dönüşümü ve e-posta dağıtımı. |
| `MDEReport.Html.ps1` | XSS korumalı ve çevrimdışı CSP başlığı içeren haftalık ve aylık HTML rapor şablonları. |
| `customer.example.json` | Örnek yapılandırma dosyası (sihirbaz canlı `customer.json` dosyasını kendisi üretir). |
| `logo.png` | İsteğe bağlı kurum logosu (dosya yoksa `ProviderName` metni başlıkta gösterilir). |

---

## Kurulum: Tek Komut

Dosyaları sunucuda kısa ve boşluksuz bir yola kopyalayın (örneğin `C:\MDEReport`) ve **`Kurulum-Baslat.cmd`** dosyasına çift tıklayın.

PowerShell üzerinden elle başlatmak isterseniz:

```powershell
cd C:\MDEReport
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Get-ChildItem *.ps1 | Unblock-File
.\Install-MDEReport.ps1
```

### "running scripts is disabled on this system" Hatası Alırsanız

| Yöntem | Komut | Etkisi |
| :--- | :--- | :--- |
| Başlatıcı (en kolay) | `Kurulum-Baslat.cmd` çift tıklama | Kalıcı ayar değişmez |
| Tek seferlik | `powershell -ExecutionPolicy Bypass -File .\Install-MDEReport.ps1` | Yalnızca o çalıştırma |
| Kullanıcı bazında kalıcı | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` | `Unblock-File` ile birlikte gerekir |

Zamanlanmış görevler bu ayardan etkilenmez; sihirbaz görevleri `-ExecutionPolicy Bypass` ile tanımlar.

### Sihirbazın 8 Adımı

1. **Ön koşul kontrolü** — PowerShell sürümü (`5.1+`), `login.microsoftonline.com` erişimi, Microsoft Edge PDF motoru ve klasör yapısı.
2. **Kurum ve rapor bilgileri** — Kurum adı, hizmet sağlayıcı / SOC ekip adı (`ProviderName`), tenant doğrulaması, rapor periyodu (haftalık / aylık / her ikisi), gün ve saat.
3. **Mail ayarları** — Microsoft Graph (`sendMail`, önerilen) veya SMTP; gönderen, alıcılar, CC ve hata bildirimi adresi.
4. **Entra ID uygulama kaydı ve API izinleri** — Cihaz kodu akışıyla (Device Code Flow) yönetici oturumu açılır; sihirbaz `MDE-Report-<Kurum>` tek kiracılı uygulamasını oluşturur, gerekli uygulama izinlerini ekler, yönetici onayını verir ve 12 ay geçerli gizli anahtarı DPAPI ile şifreleyip `secret.txt` dosyasına yazar. (SMTP seçilirse `Mail.Send` izni talep edilmez.)
5. **Yapılandırma dosyası** — `customer.json` yazılır.
6. **Erişim testleri** — İzin yayılımı için 45 saniye beklenir, ardından 9 adımlı erişim doğrulaması (`New-MDEReport.ps1 -Test`) çalıştırılır.
7. **Windows Task Scheduler görevleri** — Seçilen periyoda göre `MDE-WeeklyReport` ve/veya `MDE-MonthlyReport` görevleri **S4U** modunda (parola saklamadan) tanımlanır; S4U başarısız olursa parola seçeneği sunulur.
8. **İlk deneme raporu ve özet** — İsteğe bağlı olarak `-DryRun` (mail göndermeden) ilk rapor üretilir.

### Mevcut Bir Uygulama Kaydını Kullanmak

```powershell
.\Install-MDEReport.ps1 -UseExistingApp
```

---

## Gereken API İzinleri (En Az Ayrıcalık)

Tüm izinler **Application Permission** türündedir; yazma veya cihaz müdahalesi yetkisi (`Machine.Isolate`, `Machine.Scan` vb.) **verilmez**:

| API | İzin | Amaç |
| :--- | :--- | :--- |
| WindowsDefenderATP | `Machine.Read.All` | Cihaz envanteri, sensör sağlığı ve response aksiyonları |
| WindowsDefenderATP | `Alert.Read.All` | Alert envanteri, şiddet ve kategori kırılımı |
| WindowsDefenderATP | `AdvancedQuery.Read.All` | Advanced Hunting KQL sorguları |
| Microsoft Graph | `SecurityIncident.Read.All` | Incident sayıları, durum, sınıflandırma ve kapanış süresi |
| Microsoft Graph | `Mail.Send` *(yalnızca Graph mail seçiliyse)* | Raporun e-posta ile dağıtımı |

`Mail.Send` iznini Exchange Online üzerinde yalnızca tek gönderen posta kutusuyla sınırlandırmanız önerilir:

```powershell
New-DistributionGroup -Name "MDE-Report-Senders" -Type Security -Members mde-report@contoso.com
New-ApplicationAccessPolicy -AppId <ClientId> -PolicyScopeGroupId MDE-Report-Senders@contoso.com `
  -AccessRight RestrictAccess -Description "MDE Reporting mailbox scope restriction"
```

Gerekli giden ağ erişimleri (TCP 443): `login.microsoftonline.com`, `api.securitycenter.microsoft.com`, `graph.microsoft.com` (SMTP seçiliyse ayrıca TCP 587/25).

---

## Günlük Kullanım Komutları

```powershell
.\New-MDEReport.ps1 -Test                              # 9 adımlı erişim testi (salt okunur)
.\New-MDEReport.ps1 -Mode Weekly  -DryRun              # Geçen haftanın özeti, mail göndermez
.\New-MDEReport.ps1 -Mode Monthly -DryRun              # Geçen ayın 3 sayfalık raporu, mail göndermez
.\New-MDEReport.ps1 -Mode Monthly                      # Üret ve e-posta ile gönder
.\New-MDEReport.ps1 -Mode Monthly -Date 2026-07-15 -ExportCsv
.\New-MDEReport.ps1 -Mode Weekly  -Pdf                 # PDF üret ve ekle
```

Çıktılar `Output\`, ham JSON ve KPI geçmişi `Archive\<Mode>\<dönem>\`, çalışma kayıtları `Logs\` altında tutulur.

---

## Geri Dönüş (Kaldırma) Planı

Kurulumu sistemden tamamen kaldırmak için:

1. **Zamanlanmış görevleri kaldırın:**
   ```powershell
   Unregister-ScheduledTask -TaskName 'MDE-WeeklyReport'  -Confirm:$false -ErrorAction SilentlyContinue
   Unregister-ScheduledTask -TaskName 'MDE-MonthlyReport' -Confirm:$false -ErrorAction SilentlyContinue
   ```
2. **Entra ID uygulama kaydını devre dışı bırakın veya silin:** Microsoft Entra admin center → *App registrations* → `MDE-Report-<Kurum>`.
3. **Varsa Exchange Online erişim politikasını kaldırın:** `Remove-ApplicationAccessPolicy`.
4. **Yerel gizli dosyaları ve klasörü temizleyin:** `secret.txt`, `smtp.txt`, `customer.json` ve `C:\MDEReport` dizinini silin.
