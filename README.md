> **GÜVENLİK UYARISI: TULPAR'ı yalnızca resmî GitHub sayfamızdan indirin! Üçüncü taraf kaynaklardan indirilen dosyalar değiştirilmiş veya zararlı olabilir.**
>
> Resmî Depo ve Sürümler: https://github.com/AtaberkGit1/YOLAC/releases

# TULPAR

**İnternet özgür olmalı.**

TULPAR; Android, iOS ve Windows üzerinde çalışan, kullanıcıları DPI tabanlı internet sansüründen, DNS/SNI engellerinden, bant daraltmalarından, reklamlardan, takip sistemlerinden ve DNS/IPv6 bağlantı sızıntılarından **tamamen cihaz üzerinde** koruyan, **%100 ücretsiz, açık kaynaklı (MIT) ve sıfır sunucu bağımlılığına sahip** bir ağ koruma uygulamasıdır.

---

## Temel İlkeler

1. **Sıfır Sunucu Maliyeti & Sunucu Bağımsızlığı**: Kendi VPS'imize, merkezi sunuculara, ücretli API'lere veya kullanıcı hesaplarına bağımlı değildir. Trafiğiniz hiçbir zaman bize ait bir sunucuya yönlendirilmez.
2. **Sıfır Telemetri & Sıfır Kayıt**: Bağlantı geçmişi, ziyaret edilen alan adları, IP adresleri veya cihaz kimlikleri diske yazılmaz ve toplanmaz. Önbellekler yalnızca RAM'de tutulur ve koruma kapatıldığında sıfırlanır.
3. **Aynı Ultra-Minimalist Tasarım**: Üç platformda da tamamen `#000000` siyah arka plan, ortada tek koruma butonu ve sağ üstte küçük ayarlar ikonu bulunur. Gereksiz menü, animasyon veya reklam yoktur.
4. **Dürüst Teknik Sınırlar**: Cihaz üzerinde mümkün olmayan sansür türleri çalışıyormuş gibi gösterilmez (bkz. [docs/TECHNICAL_LIMITATIONS.md](docs/TECHNICAL_LIMITATIONS.md)).

---

## v0.2.0 Yenilikleri

- **Yeni Nesil DPI & Protokol Motoru**:
  - **Otomatik SYN-ACK Hop/TTL Kalibrasyonu**: Sabit TTL tahmini yerine gelen `SYN-ACK` paketlerinden hedefin gerçek hop mesafesini hesaplayarak sahte paket TTL değerini dinamik belirler (yakın hedeflerde otomatik `BadChecksum` moduna geçer).
  - **ECH (`DNS HTTPS / Type 65`, RFC 9460) Desteği**: Şifreli DNS üzerinden ECH yapılandırmalarını eksiksiz iletir ve `HTTPS` hedef alan adlarında da reklam/takip engelleyici (Target Uncloaking) çalıştırır.
  - **Akıllı TCP MSS / Window Daraltma**: El sıkışma sırasında güvenli MSS (`536`) daraltması ile sunucu yanıt denetimini bozar, normal veri aktarımında hız kaybı oluşturmaz.
- **Günlük Kullanım ve İşletim Sistemi Entegrasyonu**:
  - **Güvenli Captive Portal Algılama**: Okul/otel/havalimanı Wi-Fi giriş ekranlarını otomatik algılar; yalnızca giriş tamamlanana kadar (en fazla 90 sn) yerel ağ izni verir ve şifreli DNS erişimi döndüğü anda otomatik tam korumaya geçer.
  - **Windows Sistem Tepsisi (System Tray)**: Koruma açıkken `X` tuşuyla kesintisiz olarak sistem tepsisine küçülür; tepsi menüsünden tek tıkla Göster / Korumayı Aç-Kapat / Çıkış yapılabilir.
  - **Android Hızlı Ayarlar Kutucuğu & Always-On VPN**: Bildirim çubuğundaki Hızlı Ayarlar'a `TULPAR` kutucuğu eklenebilir; Android Her Zaman Açık VPN ile uyumludur.
  - **iOS Otomatik Kurtarma & Yerel Ağ Uyumu**: Wi-Fi <-> Hücresel geçişlerinde `NEOnDemandRule` ile kesintisiz toparlanır, yerel LAN/Captive Portal erişimini korur.

---

## Mimari Özeti

Ortak Rust çekirdeği (`core/`) üç platform tarafından paylaşılır:

- `yolac-dpi`: IPv4/IPv6 + TCP/UDP + TLS 1.2/1.3 ClientHello SNI & ECH (`0xFE0D`) ayrıştırıcı, TLS kayıt parçalama, TCP SNI segmentasyonu, akıllı SYN MSS / Window daraltma, otomatik SYN-ACK Hop/TTL kalibratörü, HTTP `Host` atlatma, QUIC tespiti & TCP geri dönüşü, ham paket Disorder / düşük TTL / hatalı checksum planlayıcı.
- `yolac-blocklist`: Tek bitişik bayt arenasında sıfır dinamik tahsisli (zero-allocation) reklam, izleyici ve zararlı alan adı engelleyici (5.500 kural, `152 KB` RAM).
- `yolac-dns`: RFC 1035 & RFC 9460 (`HTTPS` Type 65 ECH) ayrıştırıcı, kalıcı keep-alive havuzlu DoH (RFC 8484) & DoT (RFC 7858) istemcileri, DNS zehirlenme tespiti, CNAME/HTTPS Target Uncloaking ve yalnızca RAM'de tutulan LRU önbellek.
- `yolac-net`: `smoltcp` tabanlı kullanıcı alanı L3 TUN yönlendiricisi, `SocketProtector`, şeffaf ilk-bağlantı tekrar denemeli `DpiTcpRelay`, `CaptivePortalMonitor` ve `LeakGuard` (DNS + dengeli fail-closed IPv6 koruması).
- `yolac-core`: `YolacEngine`, tuzlanmış geçici özetlerle çalışan `AdaptiveController`, 7 modüllü gerçek `HealthMonitor` ve yalnızca kullanıcı isteğiyle çalışan resmî GitHub Releases güncelleyici.
- `yolac-ffi`: Panik-güvenli C-ABI (iOS `NEPacketTunnelProvider`) ve Android JNI köprüsü.

Ayrıntılar için:
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/DESIGN_SPEC.md](docs/DESIGN_SPEC.md)
- [docs/TECHNICAL_LIMITATIONS.md](docs/TECHNICAL_LIMITATIONS.md)
- [docs/IOS_DISTRIBUTION.md](docs/IOS_DISTRIBUTION.md)
- [SECURITY.md](SECURITY.md)

---

## Platform Durumu & Doğrulama Matrisi

| Platform / Bileşen | Paket Formatı | Uygulama Durumu | Hedef OS / Dağıtım Notu |
|---|---|---|---|
| **Ortak Rust Çekirdeği (`core/`)** | Statik/Dinamik Kütüphane + CLI | Tamamlandı (`v0.2.0`) | Tüm platformlar tarafından paylaşılır |
| **Windows (`platforms/windows`)** | `tulpar.exe` / `.zip` | Tamamlandı (Win32 `#000000` UI, Sistem Tepsisi, Ayarlar & 7 modül, UAC, WinDivert 2.2.2 **SHA-256 + Authenticode** doğrulama, Otomatik TTL) | Canlı kernel yakalama için imzalı `WinDivert.dll` + `WinDivert64.sys` gerekir; `release.yml` doğrulamalı `.zip` + `SHA256SUMS.txt` üretir |
| **Android (`platforms/android`)** | `tulpar.apk` | Tamamlandı (Kotlin `VpnService`, Hızlı Ayarlar Kutucuğu, Always-On VPN, `#000000` UI, Ayarlar & 7 modül, JNI) | Android 8.0+ (API 26+) |
| **iOS (`platforms/ios`)** | `tulpar-ios-unsigned.ipa` | Kaynak & proje tamamlandı (SwiftUI `#000000` UI, Ayarlar, `NEPacketTunnelProvider`, `NEOnDemandRule`, `LowMemoryIos`, `PrivacyInfo.xcprivacy`) | `.ipa` imzalaması Apple kısıtlaması gereği **macOS + Xcode + Apple Developer Program** gerektirir |

---

*Ataberk Yıldız tarafından geliştirildi.*

---

## Hızlı Test & Derleme

### Rust Çekirdeği (Linux / macOS / Windows)
```bash
cd core
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --release
```

### Android
```bash
./platforms/android/scripts/build-rust-android.sh
cd platforms/android && gradle testDebugUnitTest assembleRelease
```

### iOS (macOS)
```bash
./platforms/ios/scripts/build-xcframework.sh
cd platforms/ios && xcodegen generate
```

### Windows
```powershell
cd platforms/windows
cargo test
cargo build --release
# İmzalı WinDivert.dll ve WinDivert64.sys dosyalarını target\release\tulpar.exe yanına yerleştirin.
```
