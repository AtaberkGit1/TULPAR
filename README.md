> **GÜVENLİK UYARISI: TULPAR'ı yalnızca resmî GitHub sayfamızdan indirin! Üçüncü taraf kaynaklardan indirilen dosyalar değiştirilmiş veya zararlı olabilir.**
>
> Resmî Depo ve Sürümler: https://github.com/AtaberkGit1/TULPAR/releases

# TULPAR

**İnternet özgür olmalı.**

TULPAR; **Windows (PC)**, **Android** ve **Linux** üzerinde çalışan, kullanıcıları DPI tabanlı internet sansüründen, DNS/SNI engellerinden, bant daraltmalarından, reklamlardan, takip sistemlerinden ve DNS/IPv6 bağlantı sızıntılarından **tamamen cihaz üzerinde** koruyan, aynı zamanda gerçek DNS/bağlantı hızlandırma ve ağ tanılama araçları sunan **%100 ücretsiz, açık kaynaklı (MIT) ve sıfır sunucu bağımlılığına sahip** bir ağ koruma uygulamasıdır.

---

## Temel İlkeler

1. **Sıfır Sunucu Maliyeti & Sunucu Bağımsızlığı**: Kendi VPS'imize, merkezi sunuculara, ücretli API'lere veya kullanıcı hesaplarına bağımlı değildir. Trafiğiniz hiçbir zaman bize ait bir sunucuya yönlendirilmez.
2. **Sıfır Telemetri & Sıfır Kayıt**: Bağlantı geçmişi, ziyaret edilen alan adları, IP adresleri veya cihaz kimlikleri diske yazılmaz ve toplanmaz. Önbellekler yalnızca RAM'de tutulur ve koruma kapatıldığında sıfırlanır.
3. **Ultra-Minimalist Tasarım + İsviçre Çakısı Ayarlar**: Ana ekran tamamen `#000000` siyah arka plan ve tek koruma butonudur. Tüm gelişmiş hız, tanılama ve istisna araçları sağ üstteki Ayarlar ekranında sade şekilde yer alır.
4. **Dürüst Teknik Sınırlar**: ISS fiziksel hat limitinin ötesinde bant genişliği vaat edilmez; cihaz üzerinde mümkün olmayan sansür türleri çalışıyormuş gibi gösterilmez (bkz. [docs/TECHNICAL_LIMITATIONS.md](docs/TECHNICAL_LIMITATIONS.md)).

---

## v0.4.0 Yenilikleri (Hız, İsviçre Çakısı & Çok Katmanlı Sertleştirme)

- **Gerçek İnternet Hızlandırma & Gecikme Azaltma (Windows & Android)**:
  - **Turbo Şifreli DNS Motoru**: Açılışta ve ağ değişiminde tüm şifreli DoH/DoT sunucularını paralel ölçerek en düşük gecikmeli sunucuyu otomatik seçer; 250 ms yedekli yarış (hedged DNS), `O(1)` LRU önbellek, **RFC 8767 Stale-While-Revalidate (SWR)** ile anında (`<0.1 ms`) önbellek yanıtı, negatif önbellekleme ve artımlı (incremental) HTTP/1.1 chunked DoH keep-alive havuzu kullanır.
  - **Temizlenmiş Türkiye + Küresel Reklam/İzleyici Engelleme**: Yanlış pozitif oluşturan iş/ödeme/CDN alan adları temizlendi (`3.594` yüksek isabetli kural); web sayfası ve uygulama açılışlarında gereksiz üçüncü taraf ağ yükünü keser.
  - **Windows Çekirdek İçi (In-Kernel) WinDivert 2.2 Bayt Kodu Filtresi**: Oyun, sesli sohbet, video ve büyük dosya indirme paketlerinin **>%99,95'i kullanıcı alanına hiç kopyalanmadan doğrudan Windows çekirdeğinde sıfır gecikmeyle geçer**.
  - **Android Yüksek Verimli TUN & Spekülatif TCP Bağlantısı**: `256 KB` `smoltcp` TCP penceresi, `64 KB` çift yönlü aktarım, `AsyncFd` sıfır-uyanmalı TUN döngüsü, web portlarında paralel TCP ön-bağlantısı (1 RTT tasarruf) ve `protect()` hızlı yolu.
- **Ayarlar İçinde İsviçre Çakısı Araçları**:
  - **Canlı Ağ ve Hız Testi (Windows & Android)**: Tüm şifreli DNS sunucularının gerçek `ms` gecikmelerini, en hızlı seçilen sunucuyu, IPv6 durumunu, engellenen reklam sayısını ve önbellek isabet oranını canlı ölçer.
  - **Tek Tıkla Windows Ağ ve TCP Hızlandır / Onar (Windows)**: Devre dışı kalmış Windows TCP Auto-Tuning (`normal`) ve RSS ayarlarını güvenli/geri alınabilir biçimde onarır, aktif arayüz MTU değerini gösterir, eski WinDivert SCM servis kalıntılarını ve Windows DNS önbelleğini temizler.
  - **İsteğe Bağlı UAC'siz Otomatik Başlatma (Windows)**: Görev Zamanlayıcı üzerinden açılışta yönetici onayı sormadan otomatik başlatma anahtarı + Per-Monitor V2 HiDPI ve titreşimsiz çift tamponlu (double-buffered) kaydırılabilir Win32 arayüz.
  - **Uygulama Hariç Tutma / Split-Tunneling (Android)**: Bankacılık, e-Devlet veya yerel ağ uygulamalarını tek listeden TULPAR tüneli dışında bırakma (`addDisallowedApplication`), Pil Kısıtlaması kısayolu, Android Özel DNS uyarısı ve bildirimden tek dokunuşla **Kapat** düğmesi.
- **Güvenilirlik & Güvenlik Düzeltmeleri**:
  - RFC 6864 pasif DPI sahte `RST` doğrulaması (`DF=1, IP.ID=0` gerçek sunucu paketlerini asla düşürmez), HTTP `POST`/`PUT` >4 KB akış düzeltmesi, Chrome 131+ PQ `ClientHello` tam uzunluk takibi, `WinDivert` driver `%ProgramData%\Tulpar\driver` sertleştirme, Android atomik IPv4↔IPv6 TUN geçişi ve tam LAN/multicast dışlaması (Android 8–15).

---

## Mimari Özeti

Ortak Rust çekirdeği (`core/`) Windows ve Android tarafından paylaşılır:

- `yolac-dpi`: IPv4/IPv6 + TCP/UDP + TLS 1.2/1.3 & PQ `ClientHello` SNI/ECH (`0xFE0D`) ayrıştırıcı, yüksek entropili zararsız sahte ClientHello, sunucu-güvenli `BadChecksum`/`WrongSeq` & otomatik SYN-ACK Hop/TTL kalibratörü, HTTP `Host`/`CONNECT` atlatma, QUIC tespiti ve Discord Ses / Roblox RakNet UDP desync.
- `yolac-blocklist`: Tek bitişik bayt arenasında sıfır dinamik tahsisli (zero-allocation) reklam, izleyici ve zararlı alan adı engelleyici (`3.594` temizlenmiş kural + ters-sıralı alt alan adı izin listesi).
- `yolac-dns`: RFC 1035 & RFC 9460 (`HTTPS` Type 65 ECH), artımlı chunked DoH (RFC 8484) & DoT (RFC 7858), en hızlı sunucu otomatik seçimi, 250 ms hedged DNS, RFC 8767 SWR + `O(1)` RAM-only LRU önbellek ve DNS zehirlenme koruması.
- `yolac-net`: `smoltcp` tabanlı `256 KB` pencereli kullanıcı alanı L3 TUN yönlendiricisi, spekülatif paralel bağlantılı `DpiTcpRelay`, `CaptivePortalMonitor`, paralel IPv6 probu ve `LeakGuard`.
- `yolac-core`: `YolacEngine`, gerçek zamanlı `AdaptiveController`, canlı `DiagnosticReport`, 7 modüllü gerçek `HealthMonitor` ve resmî GitHub Releases güncelleyici.
- `yolac-ffi`: Panik-güvenli `AsyncFd` tabanlı Android JNI köprüsü.

Ayrıntılar için:
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/DESIGN_SPEC.md](docs/DESIGN_SPEC.md)
- [docs/TECHNICAL_LIMITATIONS.md](docs/TECHNICAL_LIMITATIONS.md)
- [SECURITY.md](SECURITY.md)

---

## Platform Durumu & Doğrulama Matrisi

| Platform / Bileşen | Paket Formatı | Uygulama Durumu | Hedef OS / Dağıtım Notu |
|---|---|---|---|
| **Ortak Rust Çekirdeği (`core/`)** | Statik/Dinamik Kütüphane + CLI | Tamamlandı (`v0.4.0`) | Windows ve Android tarafından paylaşılır |
| **Windows (`platforms/windows`)** | `tulpar.exe` / `tulpar-windows-x64.zip` | Tamamlandı (PerMonitorV2 HiDPI `#000000` UI, Sistem Tepsisi, İsviçre Çakısı Ayarlar, WinDivert 2.2.2 in-kernel filtre + SHA-256 & Authenticode doğrulama, TCP/MTU Onarıcı) | Tek dosya `tulpar.exe` (imzalı WinDivert gömülü & doğrulamalı) veya `.zip` paketi |
| **Android (`platforms/android`)** | `tulpar.apk` | Tamamlandı (Kotlin `VpnService`, Split-Tunneling, Canlı Hız Testi, Hızlı Ayarlar Kutucuğu, Always-On VPN, Atomik IPv4↔IPv6 TUN, Android 15 Edge-to-Edge, JNI) | Android 8.0+ (API 26+, `arm64-v8a` & `x86_64`) |
| **Linux (`platforms/linux`)** | `tulpar-linux-x64` / `.tar.gz` | Tamamlandı (Saf Rust Netlink `NFQUEUE` + `IPPROTO_RAW`, sıfır C `.so` bağımlılığı, `nftables` + `iptables` fallback, `fail-open` bypass, şeffaf DNS `:5354`, Zapret/nfqws çakışma onarımı, `systemd`) | Statik ikili dosya — tüm 64-bit Linux dağıtımları (Ubuntu, Debian, Arch, Fedora, Mint, SteamOS, Alpine vb.) |

---

## Hızlı Test & Derleme

### Linux (Tek Komutla Zapret Alternatifi)
```bash
curl -fsSLO https://github.com/AtaberkGit1/TULPAR/releases/latest/download/tulpar-linux-x64
chmod +x tulpar-linux-x64
./tulpar-linux-x64 test            # Canlı şifreli DNS gecikmesi (ms) ve IPv6 testi
sudo ./tulpar-linux-x64 install    # /usr/local/bin/tulpar + systemd servisi (Zapret çakışmalarını temizler)
```

### Rust Çekirdeği (Linux / Windows)
```bash
cd core
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --release
```

### Android
```bash
./platforms/android/scripts/build-rust-android.sh
cd platforms/android && gradle testDebugUnitTest lintVitalRelease assembleRelease
```

### Windows
```powershell
cd platforms/windows
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```
