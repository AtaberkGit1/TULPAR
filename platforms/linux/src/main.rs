//! TULPAR Zero-Dependency Linux CLI & Systemd Daemon
//! (Pure-Rust Netlink NFQUEUE + Raw Socket DPI Bypass + Transparent Encrypted DNS + Swiss Army Knife Tools).

mod dns_proxy;
mod engine;
mod firewall;
mod nfqueue;
mod raw_inject;

use std::fs;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use yolac_core::{
    UpdateCheckResult, UserRulesConfig, YolacConfig, YolacEngine, SECURITY_WARNING_TR,
};
use yolac_dns::DnsProfile;
use yolac_dpi::QuicPolicy;

use crate::dns_proxy::{bind_dns_listeners, run_dns_proxy, DNS_PROXY_PORT};
use crate::engine::run_nfqueue_loop;
use crate::firewall::{
    apply_firewall_rules, detect_conflicting_dpi_tools, flush_linux_dns_caches,
    has_active_tulpar_table, is_systemd_resolved_active, remove_firewall_rules,
    stop_conflicting_zapret, FirewallGuard, NFQUEUE_NUM,
};
use crate::raw_inject::LinuxMarkProtector;

const INSTALL_BIN_PATH: &str = "/usr/local/bin/tulpar";
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/tulpar.service";
const LINUX_CONFIG_PATH: &str = "/etc/tulpar/config.conf";

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Parses Linux `CapEff:` bitmask from `/proc/self/status` and checks `CAP_NET_ADMIN` (12)
/// + `CAP_NET_RAW` (13) so non-root capability mode works identically to root.
pub fn cap_eff_has_net_caps(status_text: &str) -> bool {
    for line in status_text.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            if let Ok(mask) = u64::from_str_radix(rest.trim(), 16) {
                const CAP_NET_ADMIN: u64 = 1 << 12;
                const CAP_NET_RAW: u64 = 1 << 13;
                return (mask & (CAP_NET_ADMIN | CAP_NET_RAW)) == (CAP_NET_ADMIN | CAP_NET_RAW);
            }
        }
    }
    false
}

fn has_required_caps() -> bool {
    if is_root() {
        return true;
    }
    fs::read_to_string("/proc/self/status")
        .map(|s| cap_eff_has_net_caps(&s))
        .unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxConfig {
    pub dns: String,
    pub quic: String,
    pub allow: Vec<String>,
    pub block: Vec<String>,
    pub exclude: Vec<String>,
    pub aggressive: Vec<String>,
}

impl Default for LinuxConfig {
    fn default() -> Self {
        Self {
            dns: "auto".into(),
            quic: "fallback".into(),
            allow: Vec::new(),
            block: Vec::new(),
            exclude: Vec::new(),
            aggressive: Vec::new(),
        }
    }
}

fn parse_csv_domains(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for item in raw.split(',') {
        let norm = item.trim().trim_end_matches('.').to_ascii_lowercase();
        if !norm.is_empty() && norm.contains('.') && !out.contains(&norm) {
            out.push(norm);
        }
    }
    out
}

pub fn parse_linux_config_str(raw: &str) -> LinuxConfig {
    let mut cfg = LinuxConfig::default();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            continue;
        };
        let val = v.trim();
        match k.trim() {
            "dns" if !val.is_empty() => cfg.dns = val.to_string(),
            "quic" if !val.is_empty() => cfg.quic = val.to_string(),
            "allow" => cfg.allow = parse_csv_domains(val),
            "block" => cfg.block = parse_csv_domains(val),
            "exclude" => cfg.exclude = parse_csv_domains(val),
            "aggressive" => cfg.aggressive = parse_csv_domains(val),
            _ => {}
        }
    }
    cfg
}

pub fn serialize_linux_config(cfg: &LinuxConfig) -> String {
    format!(
        "# TULPAR Linux Yapılandırması (sıfır telemetri)\ndns={}\nquic={}\nallow={}\nblock={}\nexclude={}\naggressive={}\n",
        cfg.dns,
        cfg.quic,
        cfg.allow.join(","),
        cfg.block.join(","),
        cfg.exclude.join(","),
        cfg.aggressive.join(","),
    )
}

fn load_linux_config() -> LinuxConfig {
    fs::read_to_string(LINUX_CONFIG_PATH)
        .map(|s| parse_linux_config_str(&s))
        .unwrap_or_default()
}

fn save_linux_config(cfg: &LinuxConfig) -> std::io::Result<()> {
    if let Some(parent) = Path::new(LINUX_CONFIG_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(LINUX_CONFIG_PATH, serialize_linux_config(cfg))
}

fn parse_quic_policy_str(raw: &str) -> Option<QuicPolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "fallback" | "block" | "tcp" => Some(QuicPolicy::BlockFallbackToTcp),
        "desync" | "desync_fragment" | "fragment" => Some(QuicPolicy::DesyncFragment),
        "allow" | "off" => Some(QuicPolicy::Allow),
        _ => None,
    }
}

fn apply_config_to_engine(
    engine: &YolacEngine,
    cfg: &LinuxConfig,
    dns_override: Option<&str>,
    quic_override: Option<&str>,
) {
    let dns_spec = dns_override.unwrap_or(&cfg.dns);
    if let Ok(profile) = DnsProfile::parse_spec(dns_spec) {
        engine.set_dns_profile(profile);
    }
    let quic_spec = quic_override.unwrap_or(&cfg.quic);
    if let Some(policy) = parse_quic_policy_str(quic_spec) {
        engine.set_quic_policy(policy);
    }
    engine.set_user_rules(UserRulesConfig {
        allowlist: cfg.allow.clone(),
        blocklist: cfg.block.clone(),
        excluded_dpi: cfg.exclude.clone(),
        aggressive_dpi: cfg.aggressive.clone(),
    });
}

fn print_help() {
    println!(
        r#"TULPAR v{} — Özgür, Sunucusuz ve Sıfır Bağımlılıklı Linux DPI & Sansür/Daraltma Koruması

GÜVENLİK UYARISI: TULPAR'ı yalnızca resmî GitHub sayfamızdan indirin!
Resmî Sürümler: https://github.com/AtaberkGit1/TULPAR/releases

Kullanım:
  sudo tulpar start [--strategy <file.tulpar>] [--dns <profil|url>] [--quic <fallback|desync|allow>]
                          Korumayı ön planda başlatır (CAP_NET_ADMIN+CAP_NET_RAW ile root olmadan da çalışır)
  sudo tulpar install     /usr/local/bin/tulpar + systemd servisini kurar ve hemen başlatır
  sudo tulpar uninstall   Systemd servisini, güvenlik duvarı kurallarını ve kurulumu kaldırır
  tulpar doctor <alanadi> Canlı DNS + doğrudan TLS + parçalı TLS sansür tanılama testi yapar
  tulpar test             Canlı şifreli DNS gecikmesi (ms), IPv6 ve DPI öz-denetimi yapar
  tulpar status           Aktif servis, nftables, DNS/QUIC profili ve systemd-resolved durumunu gösterir
  sudo tulpar repair [--grant-caps]
                          Zapret/nfqws temizler, BBR açar; --grant-caps ile setcap yetkisi verir
  sudo tulpar set-dns <auto|cloudflare|quad9|mullvad_adblock|adguard|https://...>
  sudo tulpar set-quic <fallback|desync|allow>
  sudo tulpar allow|block|exclude <alanadi>
  tulpar update           Resmî GitHub Releases üzerinden yeni sürüm kontrolü yapar
  tulpar --version        Sürüm bilgisini gösterir

Not: Fail-open (queue bypass) mimarisi sayesinde TULPAR kapatıldığında internet asla kesilmez."#,
        env!("CARGO_PKG_VERSION")
    );
}

fn cmd_test() -> ExitCode {
    println!("{SECURITY_WARNING_TR}\n");
    println!("TULPAR Linux — Ağ, Şifreli DNS & DPI Öz-Denetim Testi Başlatılıyor...\n");

    let protector = Arc::new(LinuxMarkProtector);
    let engine = Arc::new(YolacEngine::new(YolacConfig::linux_desktop(), Some(protector)));

    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        eprintln!("HATA: Tokio çalışma zamanı başlatılamadı.");
        return ExitCode::FAILURE;
    };

    let report = rt.block_on(engine.run_live_diagnostics());
    for bench in &report.dns_benchmarks {
        match bench.rtt_ms {
            Some(ms) if bench.ok => println!("  [OK] {:<18} {:<24} {} ms", bench.name, bench.endpoint, ms),
            _ => println!("  [--] {:<18} {:<24} Erişilemedi", bench.name, bench.endpoint),
        }
    }
    println!();
    println!("Özet: {}", report.summary_tr.replace('\n', "\n      "));
    println!("Engelleme Listesi: {} kural (RAM-only, sıfır telemetri)", engine.blocklist().len());

    let conflicts = detect_conflicting_dpi_tools();
    if conflicts.is_empty() {
        println!("Çakışan Araç: Yok (temiz)");
    } else {
        println!(
            "UYARI: Çakışan DPI araçları algılandı ({}). Çakışma önlemek için 'sudo tulpar repair' çalıştırın.",
            conflicts.join(", ")
        );
    }

    if report.fastest_dns_rtt_ms.is_some() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_status() -> ExitCode {
    let cfg = load_linux_config();
    println!("TULPAR Linux v{} Durum Özeti", env!("CARGO_PKG_VERSION"));
    let svc_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "tulpar.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    println!(
        "  Systemd Servisi : {}",
        if svc_active { "Aktif (çalışıyor)" } else { "Pasif / Kurulu değil" }
    );
    println!(
        "  Güvenlik Duvarı : {}",
        if has_active_tulpar_table() {
            "table inet tulpar aktif (fail-open)"
        } else {
            "Pasif"
        }
    );
    println!("  Şifreli DNS     : {}", cfg.dns);
    println!("  QUIC/443 Modu   : {}", cfg.quic);
    println!(
        "  Kullanıcı Kural : izin={}, engel={}, dpi_haric={}, agresif={}",
        cfg.allow.len(),
        cfg.block.len(),
        cfg.exclude.len(),
        cfg.aggressive.len()
    );
    println!(
        "  Yetki Modu      : {}",
        if is_root() {
            "root (uid=0)"
        } else if has_required_caps() {
            "Non-root (CAP_NET_ADMIN + CAP_NET_RAW)"
        } else {
            "Yetersiz yetki"
        }
    );
    println!(
        "  systemd-resolved: {}",
        if is_systemd_resolved_active() {
            "Aktif (127.0.0.53 -> NAT yönlendirme aktif)"
        } else {
            "Pasif"
        }
    );
    let conflicts = detect_conflicting_dpi_tools();
    println!(
        "  Zapret/DPI Çakışması: {}",
        if conflicts.is_empty() {
            "Yok".to_string()
        } else {
            format!("VAR ({}) — 'sudo tulpar repair' önerilir", conflicts.join(", "))
        }
    );
    ExitCode::SUCCESS
}

fn cmd_doctor(domain: &str, dns_override: Option<&str>, quic_override: Option<&str>) -> ExitCode {
    let cfg = load_linux_config();
    let protector = Arc::new(LinuxMarkProtector);
    let engine = Arc::new(YolacEngine::new(YolacConfig::linux_desktop(), Some(protector)));
    apply_config_to_engine(&engine, &cfg, dns_override, quic_override);

    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        eprintln!("HATA: Tokio çalışma zamanı başlatılamadı.");
        return ExitCode::FAILURE;
    };

    let rep = rt.block_on(engine.diagnose_domain(domain));
    println!("TULPAR Domain Doctor — {}", rep.domain);
    println!("  Sonuç     : {}", rep.verdict.as_str());
    println!("  DNS       : {}", if rep.dns_ok { "OK" } else { "BAŞARISIZ" });
    if let Some(ref ip) = rep.resolved_ip {
        println!("  Çözülen IP: {ip}");
    }
    if let Some(rtt) = rep.dns_rtt_ms {
        println!("  DNS RTT   : {rtt} ms");
    }
    println!("  ECH       : {}", if rep.has_ech { "Mevcut" } else { "Yok" });
    println!("  Doğrudan  : {}", if rep.direct_tls_ok { "Açık" } else { "Engelli/Hata" });
    println!("  DPI Split : {}", if rep.evasion_tls_ok { "Başarılı" } else { "Başarısız" });
    println!("  Özet      : {}", rep.summary_tr);
    if rep.dns_ok && (rep.direct_tls_ok || rep.evasion_tls_ok) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_set_dns(spec: &str) -> ExitCode {
    if !is_root() {
        eprintln!("HATA: 'tulpar set-dns' komutu /etc/tulpar/config.conf yazmak için root yetkisi gerektirir.");
        return ExitCode::FAILURE;
    }
    match DnsProfile::parse_spec(spec) {
        Ok(p) => {
            let mut cfg = load_linux_config();
            cfg.dns = spec.trim().to_string();
            if let Err(e) = save_linux_config(&cfg) {
                eprintln!("HATA: {LINUX_CONFIG_PATH} yazılamadı: {e}");
                return ExitCode::FAILURE;
            }
            println!("Şifreli DNS profili güncellendi: {} ({})", p.label_tr(), cfg.dns);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("HATA: Geçersiz DNS tanımı: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_set_quic(mode: &str) -> ExitCode {
    if !is_root() {
        eprintln!("HATA: 'tulpar set-quic' komutu root yetkisi gerektirir.");
        return ExitCode::FAILURE;
    }
    let Some(policy) = parse_quic_policy_str(mode) else {
        eprintln!("HATA: Geçersiz QUIC politikası '{mode}'. Seçenekler: fallback, desync, allow");
        return ExitCode::FAILURE;
    };
    let mut cfg = load_linux_config();
    cfg.quic = match policy {
        QuicPolicy::BlockFallbackToTcp => "fallback".into(),
        QuicPolicy::DesyncFragment => "desync".into(),
        QuicPolicy::Allow => "allow".into(),
    };
    if let Err(e) = save_linux_config(&cfg) {
        eprintln!("HATA: {LINUX_CONFIG_PATH} yazılamadı: {e}");
        return ExitCode::FAILURE;
    }
    println!("QUIC politikası güncellendi: {}", cfg.quic);
    ExitCode::SUCCESS
}

fn cmd_add_rule(kind: &str, raw_domain: &str) -> ExitCode {
    if !is_root() {
        eprintln!("HATA: Kural düzenleme komutu root yetkisi gerektirir.");
        return ExitCode::FAILURE;
    }
    let norm = raw_domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if norm.is_empty() || !norm.contains('.') {
        eprintln!("HATA: Geçersiz alan adı: {raw_domain}");
        return ExitCode::FAILURE;
    }
    let mut cfg = load_linux_config();
    let list = match kind {
        "allow" => &mut cfg.allow,
        "block" => &mut cfg.block,
        "exclude" => &mut cfg.exclude,
        _ => return ExitCode::FAILURE,
    };
    if !list.contains(&norm) {
        list.push(norm.clone());
    }
    if let Err(e) = save_linux_config(&cfg) {
        eprintln!("HATA: {LINUX_CONFIG_PATH} yazılamadı: {e}");
        return ExitCode::FAILURE;
    }
    println!("Kural eklendi ({kind}): {norm}");
    ExitCode::SUCCESS
}

fn cmd_repair(grant_caps: bool) -> ExitCode {
    if !is_root() {
        eprintln!("HATA: 'tulpar repair' komutu root yetkisi gerektirir: sudo tulpar repair");
        return ExitCode::FAILURE;
    }
    println!("TULPAR Ağ & Çakışma Onarımı Çalıştırılıyor...");
    let stopped = stop_conflicting_zapret();
    if stopped.is_empty() {
        println!("  [OK] Çakışan zapret/nfqws servisi bulunmadı.");
    } else {
        println!("  [ONARILDI] Çakışan araçlar durduruldu: {}", stopped.join(", "));
    }

    remove_firewall_rules();
    println!("  [OK] Eski TULPAR güvenlik duvarı kuralları temizlendi.");

    flush_linux_dns_caches();
    println!("  [OK] Sistem DNS önbelleği sıfırlandı.");

    // Safely enable TCP BBR & Path MTU probing if supported by kernel
    if let Ok(avail) = fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control") {
        if avail.split_whitespace().any(|x| x == "bbr") {
            let ok = Command::new("sysctl")
                .args(["-w", "net.core.default_qdisc=fq", "net.ipv4.tcp_congestion_control=bbr"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                println!("  [OK] Linux TCP BBR tıkanıklık kontrolü etkinleştirildi.");
            }
        }
    }
    if grant_caps {
        let cap_target = if Path::new(INSTALL_BIN_PATH).is_file() {
            Path::new(INSTALL_BIN_PATH).to_path_buf()
        } else {
            std::env::current_exe().unwrap_or_else(|_| Path::new(INSTALL_BIN_PATH).to_path_buf())
        };
        let cap_ok = Command::new("setcap")
            .arg("cap_net_admin,cap_net_raw+eip")
            .arg(&cap_target)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if cap_ok {
            println!("  [OK] {} için cap_net_admin,cap_net_raw+eip atandı.", cap_target.display());
        } else {
            println!("  [BİLGİ] setcap başarısız (libcap2-bin kurulu olmayabilir).");
        }
    }
    if Command::new("sysctl")
        .args(["-w", "net.ipv4.tcp_mtu_probing=1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        println!("  [OK] TCP Path-MTU Probing etkinleştirildi. Hazır!");
    } else {
        println!("  [OK] Onarım tamamlandı. Hazır!");
    }
    ExitCode::SUCCESS
}

fn cmd_update() -> ExitCode {
    let protector = Arc::new(LinuxMarkProtector);
    let engine = Arc::new(YolacEngine::new(YolacConfig::linux_desktop(), Some(protector)));
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    match rt.block_on(engine.check_updates_manual(None)) {
        UpdateCheckResult::UpToDate { current_version } => {
            println!("Uygulama güncel (v{current_version}).");
            ExitCode::SUCCESS
        }
        UpdateCheckResult::UpdateAvailable {
            current_version,
            latest_version,
            release_url,
        } => {
            println!("Yeni sürüm bulundu: v{latest_version} (mevcut: v{current_version})");
            println!("Resmî İndirme Bağlantısı: {release_url}");
            ExitCode::SUCCESS
        }
        UpdateCheckResult::Error(err) => {
            eprintln!("Güncelleme kontrolü hatası: {err}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_install() -> ExitCode {
    if !is_root() {
        eprintln!("HATA: 'tulpar install' komutu root yetkisi gerektirir: sudo tulpar install");
        return ExitCode::FAILURE;
    }

    let stopped = stop_conflicting_zapret();
    if !stopped.is_empty() {
        println!("Bilgi: Çakışan servis/süreçler otomatik kapatıldı: {}", stopped.join(", "));
    }

    let Ok(self_exe) = std::env::current_exe() else {
        eprintln!("HATA: Çalıştırılabilir dosya yolu okunamadı.");
        return ExitCode::FAILURE;
    };
    if self_exe != Path::new(INSTALL_BIN_PATH) {
        if let Some(parent) = Path::new(INSTALL_BIN_PATH).parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Err(e) = fs::copy(&self_exe, INSTALL_BIN_PATH) {
            eprintln!("HATA: {INSTALL_BIN_PATH} kopyalanamadı: {e}");
            return ExitCode::FAILURE;
        }
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(INSTALL_BIN_PATH, fs::Permissions::from_mode(0o755));
    }

    let unit = format!(
        r#"[Unit]
Description=TULPAR Free On-Device DPI, Anti-Throttling & Encrypted DNS Service
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={INSTALL_BIN_PATH} start
ExecStopPost={INSTALL_BIN_PATH} stop-rules
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"#
    );

    if let Err(e) = fs::write(SYSTEMD_UNIT_PATH, unit) {
        eprintln!("HATA: Systemd birim dosyası yazılamadı ({SYSTEMD_UNIT_PATH}): {e}");
        return ExitCode::FAILURE;
    }

    let reload_ok = Command::new("systemctl")
        .arg("daemon-reload")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let enable_ok = Command::new("systemctl")
        .args(["enable", "--now", "tulpar.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if reload_ok && enable_ok {
        println!("TULPAR başarıyla kuruldu ve başlatıldı!");
        println!("Durum için: tulpar status | Ağ testi için: tulpar test");
        ExitCode::SUCCESS
    } else {
        eprintln!("HATA: systemd servisi başlatılamadı (journalctl -u tulpar -n 30 ile kontrol edin).");
        ExitCode::FAILURE
    }
}

fn cmd_uninstall() -> ExitCode {
    if !is_root() {
        eprintln!("HATA: 'tulpar uninstall' komutu root yetkisi gerektirir: sudo tulpar uninstall");
        return ExitCode::FAILURE;
    }
    let _ = Command::new("systemctl")
        .args(["disable", "--now", "tulpar.service"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    remove_firewall_rules();
    let _ = fs::remove_file(SYSTEMD_UNIT_PATH);
    let _ = fs::remove_file(INSTALL_BIN_PATH);
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    flush_linux_dns_caches();
    println!("TULPAR sistemden tamamen kaldırıldı ve tüm ağ kuralları temizlendi.");
    ExitCode::SUCCESS
}

fn cmd_start(
    strategy_path: Option<&Path>,
    dns_override: Option<&str>,
    quic_override: Option<&str>,
) -> ExitCode {
    if !has_required_caps() {
        eprintln!(
            "HATA: Paket yakalama için root yetkisi veya CAP_NET_ADMIN+CAP_NET_RAW gerekir: sudo tulpar start (veya sudo tulpar repair --grant-caps)"
        );
        return ExitCode::FAILURE;
    }

    let conflicts = detect_conflicting_dpi_tools();
    if !conflicts.is_empty() {
        println!(
            "Bilgi: Çakışan DPI aracı durduruluyor ({})...",
            conflicts.join(", ")
        );
        let _ = stop_conflicting_zapret();
    }

    let cfg = load_linux_config();
    let protector = Arc::new(LinuxMarkProtector);
    let engine = Arc::new(YolacEngine::new(YolacConfig::linux_desktop(), Some(protector)));
    apply_config_to_engine(&engine, &cfg, dns_override, quic_override);
    println!(
        "TULPAR Yapılandırması: DNS={}, QUIC={:?}",
        engine.dns_engine().active_profile().label_tr(),
        engine.quic_policy()
    );

    // Load explicit --strategy <file.tulpar|.tlp> or optional root-managed /etc/tulpar/active.tulpar
    let active_strategy = strategy_path.or_else(|| {
        let p = Path::new("/etc/tulpar/active.tulpar");
        p.is_file().then_some(p)
    });
    if let Some(spath) = active_strategy {
        match engine.load_forge_package_file(spath) {
            Ok(rep) => {
                let snap = engine.forge_status();
                println!(
                    "TULPAR Forge Stratejisi Yüklendi: {} v{} [sha256:{}.., Linux={:?}]",
                    snap.package_name.as_deref().unwrap_or("?"),
                    snap.package_version.as_deref().unwrap_or("?"),
                    snap.sha256_prefix.as_deref().unwrap_or(""),
                    rep.compatibility.linux
                );
            }
            Err(e) => {
                eprintln!("UYARI: Forge stratejisi yüklenemedi ({e}); güvenli temel strateji kullanılacak.");
            }
        }
    }

    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
    else {
        eprintln!("HATA: Tokio çalışma zamanı başlatılamadı.");
        return ExitCode::FAILURE;
    };

    // Select fastest encrypted upstream before intercepting system DNS
    if let Some(_best_idx) = rt.block_on(engine.dns_engine().probe_fastest_upstream()) {
        println!("TULPAR En Düşük Gecikmeli Şifreli DNS Seçildi (RAM Önbellek + SWR Aktif)");
    }

    // Bind local DNS proxy listeners synchronously BEFORE touching firewall NAT rules!
    let dns_listeners = match rt.block_on(bind_dns_listeners()) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("HATA: Yerel DNS proxy portu ({DNS_PROXY_PORT}) açılamadı: {e}");
            return ExitCode::FAILURE;
        }
    };

    let stop_flag = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Spawn local encrypted DNS + ad-blocker UDP/TCP proxy (:5354)
    let dns_ref = Arc::clone(engine.dns_engine());
    let dns_handle = rt.spawn(async move {
        run_dns_proxy(dns_listeners, dns_ref, false, shutdown_rx).await;
    });

    // Spawn SIGINT / SIGTERM clean teardown listener
    let stop_sig = Arc::clone(&stop_flag);
    let tx_sig = shutdown_tx.clone();
    rt.spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = sigterm.recv() => {}
                }
            } else {
                let _ = ctrl_c.await;
            }
        }
        #[cfg(not(unix))]
        let _ = ctrl_c.await;

        stop_sig.store(true, Ordering::Relaxed);
        let _ = tx_sig.send(true);
    });

    // Apply fail-open nftables/iptables rules with automatic Drop cleanup
    let _fw_guard = match apply_firewall_rules() {
        Ok(backend) => {
            println!("TULPAR Aktif (Mod: {backend:?}, NFQUEUE: {NFQUEUE_NUM}, DNS: 127.0.0.1:{DNS_PROXY_PORT})");
            FirewallGuard
        }
        Err(e) => {
            let _ = shutdown_tx.send(true);
            eprintln!("HATA: Güvenlik duvarı kuralı uygulanamadı: {e}");
            return ExitCode::FAILURE;
        }
    };
    flush_linux_dns_caches();

    let res = run_nfqueue_loop(
        NFQUEUE_NUM,
        Arc::clone(engine.dns_engine()),
        Arc::clone(engine.adaptive()),
        Arc::clone(&stop_flag),
    );

    stop_flag.store(true, Ordering::Relaxed);
    let _ = shutdown_tx.send(true);
    let _ = rt.block_on(dns_handle);
    drop(_fw_guard);
    flush_linux_dns_caches();

    match res {
        Ok(()) => {
            println!("TULPAR temiz şekilde durduruldu ve ağ kuralları kaldırıldı.");
            ExitCode::SUCCESS
        }
        Err((_code, detail)) => {
            eprintln!("HATA: {detail}");
            ExitCode::FAILURE
        }
    }
}

fn parse_flag_val(args: &[String], idx: &mut usize, name: &str) -> Option<String> {
    if args[*idx] == name {
        if let Some(v) = args.get(*idx + 1) {
            *idx += 2;
            return Some(v.clone());
        }
    } else if let Some(rest) = args[*idx].strip_prefix(&format!("{name}=")) {
        *idx += 1;
        return Some(rest.to_string());
    }
    None
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "--version" | "-V" | "version" => {
            println!("TULPAR Linux v{}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            print_help();
            ExitCode::SUCCESS
        }
        "test" => cmd_test(),
        "status" => cmd_status(),
        "repair" => {
            let grant_caps = args.iter().any(|a| a == "--grant-caps");
            cmd_repair(grant_caps)
        }
        "update" => cmd_update(),
        "install" => cmd_install(),
        "uninstall" => cmd_uninstall(),
        "doctor" | "diagnose" => {
            let Some(domain) = args.get(2) else {
                eprintln!("Kullanım: tulpar doctor <alanadi> [--dns <profil>] [--quic <mod>]");
                return ExitCode::FAILURE;
            };
            let mut dns_ovr: Option<String> = None;
            let mut quic_ovr: Option<String> = None;
            let mut i = 3usize;
            while i < args.len() {
                if let Some(v) = parse_flag_val(&args, &mut i, "--dns") {
                    dns_ovr = Some(v);
                    continue;
                }
                if let Some(v) = parse_flag_val(&args, &mut i, "--quic") {
                    quic_ovr = Some(v);
                    continue;
                }
                i += 1;
            }
            cmd_doctor(domain, dns_ovr.as_deref(), quic_ovr.as_deref())
        }
        "set-dns" => match args.get(2) {
            Some(spec) => cmd_set_dns(spec),
            None => {
                eprintln!("Kullanım: sudo tulpar set-dns <auto|cloudflare|quad9|mullvad_adblock|adguard|https://...>");
                ExitCode::FAILURE
            }
        },
        "set-quic" => match args.get(2) {
            Some(mode) => cmd_set_quic(mode),
            None => {
                eprintln!("Kullanım: sudo tulpar set-quic <fallback|desync|allow>");
                ExitCode::FAILURE
            }
        },
        "allow" | "block" | "exclude" => match args.get(2) {
            Some(dom) => cmd_add_rule(cmd, dom),
            None => {
                eprintln!("Kullanım: sudo tulpar {cmd} <alanadi>");
                ExitCode::FAILURE
            }
        },
        "start" | "run" => {
            let mut strat: Option<String> = None;
            let mut dns_ovr: Option<String> = None;
            let mut quic_ovr: Option<String> = None;
            let mut i = 2usize;
            while i < args.len() {
                if let Some(v) = parse_flag_val(&args, &mut i, "--strategy") {
                    strat = Some(v);
                    continue;
                }
                if let Some(v) = parse_flag_val(&args, &mut i, "--dns") {
                    dns_ovr = Some(v);
                    continue;
                }
                if let Some(v) = parse_flag_val(&args, &mut i, "--quic") {
                    quic_ovr = Some(v);
                    continue;
                }
                i += 1;
            }
            cmd_start(
                strat.as_deref().map(Path::new),
                dns_ovr.as_deref(),
                quic_ovr.as_deref(),
            )
        }
        "stop-rules" => {
            if has_required_caps() {
                remove_firewall_rules();
                flush_linux_dns_caches();
            }
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("Bilinmeyen komut: {other}\n");
            print_help();
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_config_roundtrips_and_parses_capabilities() {
        let cfg = LinuxConfig {
            dns: "mullvad_adblock".into(),
            quic: "desync".into(),
            allow: vec!["doubleclick.net".into()],
            block: vec!["tracker.example.com".into()],
            exclude: vec!["banka.local.tr".into()],
            ..Default::default()
        };

        let raw = serialize_linux_config(&cfg);
        let parsed = parse_linux_config_str(&raw);
        assert_eq!(parsed, cfg);

        // CAP_NET_ADMIN (bit 12 = 0x1000) | CAP_NET_RAW (bit 13 = 0x2000) = 0x3000
        assert!(cap_eff_has_net_caps("Name:\ttulpar\nCapEff:\t0000000000003000\n"));
        assert!(!cap_eff_has_net_caps("Name:\ttulpar\nCapEff:\t0000000000001000\n"));
        assert!(!cap_eff_has_net_caps("Name:\ttulpar\nCapEff:\t0000000000000000\n"));
    }
}
