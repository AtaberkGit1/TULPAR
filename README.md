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

## v0.5.0 Özellikleri (Post-Kuantum TLS, Özelleştirilebilir Şifreli DNS & Alan Adı Tanılama)

- **Post-Kuantum TLS (`X25519MLKEM768`) Çok Segmentli ClientHello Desteği (`yolac-dpi`, Windows, Linux, Android)**:
  - Chrome 131+ / Firefox / Chromium tabanlı tarayıcıların ~1.700+ baytlık Post-Kuantum TLS `ClientHello` mesajları iki TCP paketine bölündüğünde (SNI ikinci pakete taşsa bile), Windows (`WinDivert`) ve Linux (`NFQUEUE`) segmentleri kısa süreli RAM arabelleğinde birleştirip gerçek SNI ortasından MTU-uyumlu (`<= 1380` bayt) şekilde parçalar ve sahte paketlerle enjekte eder.
- **Seçilebilir Şifreli DNS Profilleri & RFC 9460 Sızıntı Temizleme (`yolac-dns`)**:
  - **Hazır Profiller + Özel DoH/DoT**: Ayarlar ve CLI üzerinden `AutoFastest`, `Cloudflare`, `Quad9 Güvenlik`, `Mullvad Reklam Engelli`, `AdGuard DNS` veya kullanıcının tanımladığı literal IPv4/IPv6 + TLS konak adlı özel `https://...` / `tls://...` sunucuları seçilebilir.
  - **RFC 9460 `HTTPS`/`SVCB` (`Type 65`) `ipv6hint` Temizliği**: Korumasız IPv6 kapatıldığında (`suppress_aaaa`), `HTTPS` DNS yanıtlarındaki `ipv6hint` parametresi ECH anahtarı (`SvcParamKey 5`) korunarak sıyrılır.
  - **Yetkisiz `TCP/853` DoT Engeli**: Aktif şifreli DNS bootstrap IP'leri dışındaki port 853 ve port 53 sızıntı girişimleri engellenir.
- **Esnek QUIC Politikası & RFC 7323 PAWS Zaman Damgası Yanıltması (`yolac-dpi`)**:
  - Varsayılan `TCP Fallback` moduna ek olarak seçilebilir **`QUIC Desync Paketi`** (`QuicPolicy::DesyncFragment` — düşük TTL ve bozuk UDP sağlama toplamlı QUIC Initial decoy) ve `Allow` modları + Stage 2/3 stratejilerinde `BadTcpTimestamp` desteği.
- **On-Device Site Erişim Testi (Domain Doctor) & Özel Alan Adı Kuralları (`yolac-core`, `yolac-blocklist`)**:
  - `tulpar doctor <alanadi>` (Linux), `--diagnose <alanadi>` (Windows) ve Android Ayarlar içinden doğrudan DoH/DoT + ECH, doğrudan TLS ve parçalı TLS sınaması yaparak DNS, aşılabilir DPI engeli veya aşılamaz sert IP bloğu durumunu dürüstçe raporlar.
  - Kullanıcı tarafından belirlenen **İzin Listesi** (allowlist), **Özel Engel Listesi** (blocklist) ve **DPI Hariç Tutma / Passthrough** kuralları tüm platformlarda desteklenir.
- **Platform Düzeyi İyileştirmeler**:
  - **Windows (`platforms/windows`)**: İsteğe bağlı `WinDivertRecvEx`/`WinDivertSendEx` toplu paket G/Ç desteği, Ayarlar ekranında Şifreli DNS & QUIC politika seçicisi, `%ProgramData%\Tulpar\config.json` kalıcı tercihleri, `SHA256SUMS.txt` doğrulama yardımcısı ve `#000000` tek butonlu ana ekran korunumu.
  - **Linux (`platforms/linux`)**: `CAP_NET_ADMIN` + `CAP_NET_RAW` root'suz yetki desteği (`/proc/self/status`, `tulpar repair --grant-caps`, systemd `AmbientCapabilities`), `ip6tables` NAT `:5354` fallback, `systemd-resolved` tespiti, `/etc/tulpar/config.conf` kalıcı ayarları (`doctor`, `set-dns`, `set-quic`, `allow`, `block`, `exclude`).
  - **Android (`platforms/android`)**: Toplu TUN paket okuma (`recv_packet_batch`), Ayarlar ekranında Şifreli DNS Sağlayıcısı seçimi, Özel Alan Adı Kuralları ve Site Erişim Testi (Domain Doctor), `#000000` tek butonlu ana ekran korunumu.
- **Temel DPI & Koruma Yetenekleri (v0.4.0 mirası)**:
  - Otomatik en düşük gecikmeli DoH/DoT seçimi, 250 ms hedged failover, RAM-only LRU + SWR önbellek, CNAME uncloaking, zehirlenme tespiti, RFC 6864 pasif DPI `RST` filtreleme, HTTP `Host` bölme, Discord/Roblox UDP desync, Per-App Split-Tunneling (Android) ve tek tıkla Windows Ağ/TCP Onarımı.

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
| **Ortak Rust Çekirdeği (`core/`)** | Statik/Dinamik Kütüphane + CLI | Tamamlandı (`v0.5.0`) | Windows, Android ve Linux tarafından paylaşılır |
| **Windows (`platforms/windows`)** | `tulpar.exe` / `tulpar-windows-x64.zip` | Tamamlandı (PerMonitorV2 HiDPI `#000000` UI, Sistem Tepsisi, Tanılama & TCP Onarımı, WinDivert 2.2.2 in-kernel filtre + SHA-256 doğrulama) | Tek dosya `tulpar.exe` (imzalı WinDivert gömülü & doğrulamalı) veya `.zip` paketi |
| **Android (`platforms/android`)** | `tulpar.apk` | Tamamlandı (Kotlin `VpnService`, Split-Tunneling, Canlı Ağ/DNS Tanılama, Hızlı Ayarlar Kutucuğu, Always-On VPN, Atomik IPv4↔IPv6 TUN, Android 15 Edge-to-Edge, JNI) | Android 8.0+ (API 26+, `arm64-v8a` & `x86_64`) |
| **Linux (`platforms/linux`)** | `tulpar-linux-x64` / `.tar.gz` | Tamamlandı (Saf Rust Netlink `NFQUEUE` + `IPPROTO_RAW`, sıfır C `.so` bağımlılığı, `nftables` + `iptables` fallback, `fail-open` bypass, şeffaf DNS `:5354`, Zapret/nfqws çakışma onarımı, `systemd`) | Statik ikili dosya — tüm 64-bit Linux dağıtımları (Ubuntu, Debian, Arch, Fedora, Mint, SteamOS, Alpine vb.) |

---

## Hızlı Test & Derleme

### Linux (Tek Komutla Zapret Alternatifi)
```bash
curl -fsSLO https://github.com/AtaberkGit1/TULPAR/releases/latest/download/tulpar-linux-x64
chmod +x tulpar-linux-x64
./tulpar-linux-x64 test               # Canlı şifreli DNS gecikmesi (ms) ve IPv6 testi
./tulpar-linux-x64 doctor discord.com # Canlı DNS + TLS + DPI atlatma site testi
sudo ./tulpar-linux-x64 install       # /usr/local/bin/tulpar + systemd servisi (Zapret çakışmalarını temizler)
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
