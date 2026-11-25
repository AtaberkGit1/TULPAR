> **GÜVENLİK UYARISI: TULPAR'ı yalnızca resmî GitHub sayfamızdan indirin! Üçüncü taraf kaynaklardan indirilen dosyalar değiştirilmiş veya zararlı olabilir.**
>
> Resmî Depo ve Sürümler: https://github.com/AtaberkGit1/TULPAR/releases

# TULPAR

**İnternet özgür olmalı.**

TULPAR; **Windows (PC)**, **Android** ve **Linux** üzerinde çalışan, kullanıcıları DPI tabanlı internet sansüründen, DNS/SNI engellerinden, protokol bazlı DPI bant daraltmalarından, reklamlardan, takip sistemlerinden ve DNS/IPv6 bağlantı sızıntılarından **tamamen cihaz üzerinde** koruyan, aynı zamanda şifreli DNS ve ağ tanılama araçları sunan **%100 ücretsiz, açık kaynaklı (MIT) ve geliştirici sunucusu bağımlılığı olmayan** bir ağ koruma uygulamasıdır.

---

## Temel İlkeler

1. **Geliştirici Sunucusu Olmayan Mimari**: Kendi VPS'imize, merkezi sunuculara, ücretli API'lere veya kullanıcı hesaplarına bağımlı değildir. Paket işleme doğrudan cihaz üzerinde çalışır.
2. **Sıfır Telemetri, Sıfır Disk Kaydı & Harici DNS Şeffaflığı**: TULPAR diske bağlantı geçmişi, alan adı veya IP kaydı yazmaz ve telemetri toplamaz. Yalnızca yerel engelleme listesinde bulunmayan DNS sorguları, şifreli DoH/DoT üzerinden doğrudan harici genel DNS sağlayıcılarına (Cloudflare, Quad9, Mullvad, Google) iletilir; ilgili sağlayıcı kendi gizlilik politikası kapsamında istemci IP adresinizi ve sorgulanan alan adını görür (ayrıntılar: [SECURITY.md](SECURITY.md)).
3. **Ultra-Minimalist Tasarım + İsviçre Çakısı Ayarlar**: Ana ekran tamamen `#000000` siyah arka plan ve tek koruma butonudur. Tüm gelişmiş tanılama, onarım ve istisna araçları sağ üstteki Ayarlar ekranında sade şekilde yer alır.
4. **Dürüst Teknik Sınırlar**: Fiziksel hat hızının / ISS paket limitinin ötesinde bant genişliği vaat edilmez; yalnızca protokol/SNI bazlı DPI engelleme ve daraltma ile fiziksel hat limitleri açıkça ayrılır (bkz. [docs/TECHNICAL_LIMITATIONS.md](docs/TECHNICAL_LIMITATIONS.md)).

---

## Protokol Bazlı Bant Daraltma (DPI Anti-Throttling) vs. Fiziksel Hat Sınırları

TULPAR fiziksel internet hattınızı hızlandıran bir araç değildir; aşağıdaki iki kavramı teknik olarak birbirinden ayırır:

- **Protokol / SNI / QUIC Bazlı Bant Daraltma (TULPAR'ın Çözdüğü Durum)**:
  - ISS DPI sistemleri şifresiz DNS'i, TLS `ClientHello` içindeki `SNI` bilgisini veya QUIC (`UDP/443`) paketlerini sınıflandırarak belirli servis/uygulamaları yapay olarak yavaşlattığında veya bağlantıyı kestiğinde, TULPAR şifreli DoH/DoT, çoklu TLS parçalama, Windows/Linux'ta desync/disorder sahte paketleri ve QUIC UDP desync / TCP fallback yöntemleriyle DPI sınıflandırmasını önler ve mevcut hattınızın normal kapasitesini kullanabilmenizi sağlar.
- **Fiziksel Hat & Abonelik Hız Sınırları (TULPAR'ın Değiştiremeyeceği Sınırlar)**:
  - Hiçbir cihaz-içi yazılım ISS'nin fiziksel hat profilini (ör. 50 Mbps VDSL/Fiber aboneliğini 100 Mbps'e çıkarmayı), baz istasyonu/Wi-Fi yoğunluğunu veya hedef IP aralığının tamamına uygulanan protokolden bağımsız genel hat hız limitini yükseltemez.
- **DNS Önbelleği ve Reklam Engellemenin Gerçek Etkisi**:
  - RAM-only LRU DNS önbelleği ve RFC 8767 SWR yalnızca **tekrarlanan DNS isim çözümleme gecikmesini** düşürür; yerel alan adı engelleme listesi yalnızca listedeki bilinen reklam/izleyici alan adlarının çözümlenmesini keser. İkisi de fiziksel indirme/yükleme hat kapasitesini artırmaz.

---

## v0.4.0 Özellikleri (Çok Platformlu DPI Koruma & Tanılama Araçları)

- **Şifreli DNS ve Yerel Filtreleme (`yolac-dns`, `yolac-blocklist`)**:
  - **Otomatik En Düşük Gecikmeli DoH/DoT Seçimi**: Açılışta ve ağ değişiminde Cloudflare, Quad9, Mullvad ve Google DoH/DoT uç noktalarını paralel ölçer; 250 ms hedged yedekli sorgu, RAM-only LRU önbellek, RFC 8767 SWR, CNAME uncloaking ve zehirlenme (bogon/BTK IP) tespiti uygular.
  - **Yerel Reklam/İzleyici Engelleme**: Yanlış pozitif oluşturan iş/ödeme/CDN alan adları ayıklanmış `3.594` kurallı RAM-only önek/sonek listesi.
- **Platform Düzeyi DPI Motorları**:
  - **Windows (`WinDivert 2.2`)**: Çekirdek filtresi yalnızca ilgili DNS (`53`), TLS/HTTP (`80`/`443`) ve UDP akışlarını yakalar; geri kalan veri akışı çekirdek üzerinden geçer. SHA-256 doğrulamalı WinDivert + `%ProgramData%\Tulpar\driver\2.2.2` kilitleme.
  - **Android (`VpnService`)**: `256 KB` `smoltcp` TCP penceresi, `64 KB` çift yönlü aktarım, `AsyncFd` olay döngüsü, web portlarında paralel TCP ön-bağlantısı ve `protect()` soket koruması.
  - **Linux (`platforms/linux`)**: Saf Rust Netlink `NFQUEUE` + `IPPROTO_RAW` + `--queue-bypass` (fail-open), `nftables`/`iptables` desteği ve `:5354` yerel şifreli DNS vekili.
- **Ayarlar İçinde Tanılama & Bakım Araçları**:
  - **Canlı Ağ ve DNS Tanılama (Windows, Android & Linux)**: Tüm şifreli DNS sunucularının gerçek `ms` gecikmelerini, seçilen en düşük gecikmeli sunucuyu, IPv6 erişimini, engellenen alan adı sayısını ve DNS önbellek isabet oranını ölçer.
  - **Tek Tıkla Windows Ağ ve TCP Onarımı (Windows)**: Devre dışı kalmış Windows TCP Auto-Tuning (`normal`) ve RSS ayarlarını onarır, aktif arayüz MTU değerini gösterir, eski WinDivert SCM servis kalıntılarını ve Windows DNS önbelleğini temizler.
  - **İsteğe Bağlı UAC'siz Otomatik Başlatma (Windows)**: Görev Zamanlayıcı üzerinden açılışta otomatik başlatma anahtarı + Per-Monitor V2 HiDPI ve çift tamponlu Win32 arayüz.
  - **Uygulama Hariç Tutma / Split-Tunneling (Android)**: Bankacılık, e-Devlet veya yerel ağ uygulamalarını tek listeden TULPAR tüneli dışında bırakma (`addDisallowedApplication`), Pil Kısıtlaması kısayolu, Android Özel DNS uyarısı ve bildirimden tek dokunuşla **Kapat** düğmesi.
- **Güvenilirlik & Güvenlik Sertleştirmeleri**:
  - RFC 6864 pasif DPI sahte `RST` doğrulaması (`DF=1, IP.ID=0`), HTTP `POST`/`PUT` >4 KB akış desteği, Chrome 131+ PQ `ClientHello` tam uzunluk takibi, `%ProgramData%\Tulpar\driver` sertleştirmesi, Android atomik IPv4↔IPv6 TUN geçişi ve tam LAN/multicast dışlaması (Android 8–15).

---

## Mimari Özeti

Ortak Rust çekirdeği (`core/`) Windows, Android ve Linux tarafından paylaşılır:

- `yolac-dpi`: IPv4/IPv6 + TCP/UDP + TLS 1.2/1.3 & PQ `ClientHello` SNI/ECH (`0xFE0D`) ayrıştırıcı, yüksek entropili zararsız sahte ClientHello, sunucu-güvenli `BadChecksum`/`WrongSeq` & otomatik SYN-ACK Hop/TTL kalibratörü, HTTP `Host`/`CONNECT` atlatma, QUIC tespiti ve UDP desync.
- `yolac-blocklist`: Tek bitişik bayt arenasında sıfır dinamik tahsisli (zero-allocation) reklam, izleyici ve zararlı alan adı engelleyici (`3.594` kural).
- `yolac-dns`: RFC 1035 & RFC 9460 (`HTTPS` Type 65 ECH), artımlı chunked DoH (RFC 8484) & DoT (RFC 7858), en düşük gecikmeli sunucu seçimi, 250 ms hedged DNS, RFC 8767 SWR + RAM-only LRU önbellek ve DNS zehirlenme koruması.
- `yolac-net`: `smoltcp` tabanlı `256 KB` pencereli kullanıcı alanı L3 TUN yönlendiricisi, `DpiTcpRelay`, `CaptivePortalMonitor`, paralel IPv6 probu ve `LeakGuard`.
- `yolac-core`: `YolacEngine`, `AdaptiveController`, canlı `DiagnosticReport`, 7 modüllü `HealthMonitor`, **TULPAR Forge çalışma zamanı + devre kesici (auto-rollback)** ve resmî GitHub Releases güncelleyici.
- `yolac-ffi`: Panik-güvenli Android JNI köprüsü (`AsyncFd` + dinamik `.tulpar` strateji yükleme).
- **`forge/` (TULPAR Forge)**: Yeniden derleme gerektirmeyen, deklaratif TSL v1 strateji dili (`.tlp`), SHA-256 mühürlü taşınabilir `.tulpar` paket formatı, statik yetenek doğrulayıcısı (keyfî kod/veri sızdırma/yetkisiz ağ engeli), yerel sansür simülasyon laboratuvarı ve `tulpar-forge` CLI altyapısı (bkz. [forge/README.md](forge/README.md)).

Ayrıntılar için:
- [forge/README.md](forge/README.md) & [forge/docs/STRATEGY_LANGUAGE.md](forge/docs/STRATEGY_LANGUAGE.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/DESIGN_SPEC.md](docs/DESIGN_SPEC.md)
- [docs/TECHNICAL_LIMITATIONS.md](docs/TECHNICAL_LIMITATIONS.md)
- [SECURITY.md](SECURITY.md)

---

## Platform Durumu & Doğrulama Matrisi

| Platform / Bileşen | Paket Formatı | Uygulama Durumu | Hedef OS / Dağıtım Notu |
|---|---|---|---|
| **Ortak Rust Çekirdeği (`core/`)** | Statik/Dinamik Kütüphane + CLI | Tamamlandı (`v0.4.0`) | Windows, Android ve Linux tarafından paylaşılır |
| **Windows (`platforms/windows`)** | `tulpar.exe` / `tulpar-windows-x64.zip` | Tamamlandı (PerMonitorV2 HiDPI `#000000` UI, Sistem Tepsisi, Tanılama & TCP Onarımı, WinDivert 2.2.2 in-kernel filtre + SHA-256 doğrulama) | Tek dosya `tulpar.exe` (imzalı WinDivert gömülü & doğrulamalı) veya `.zip` paketi |
| **Android (`platforms/android`)** | `tulpar.apk` | Tamamlandı (Kotlin `VpnService`, Split-Tunneling, Canlı Ağ/DNS Tanılama, Hızlı Ayarlar Kutucuğu, Always-On VPN, Atomik IPv4↔IPv6 TUN, Android 15 Edge-to-Edge, JNI) | Android 8.0+ (API 26+, `arm64-v8a` & `x86_64`) |
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
