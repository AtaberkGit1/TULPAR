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

use yolac_core::{UpdateCheckResult, YolacConfig, YolacEngine, SECURITY_WARNING_TR};

use crate::dns_proxy::{bind_dns_listeners, run_dns_proxy, DNS_PROXY_PORT};
use crate::engine::run_nfqueue_loop;
use crate::firewall::{
    apply_firewall_rules, detect_conflicting_dpi_tools, flush_linux_dns_caches,
    has_active_tulpar_table, remove_firewall_rules, stop_conflicting_zapret, FirewallGuard,
    NFQUEUE_NUM,
};
use crate::raw_inject::LinuxMarkProtector;

const INSTALL_BIN_PATH: &str = "/usr/local/bin/tulpar";
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/tulpar.service";

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn print_help() {
    println!(
        r#"TULPAR v{} — Özgür, Sunucusuz ve Sıfır Bağımlılıklı Linux DPI & Sansür/Daraltma Koruması

GÜVENLİK UYARISI: TULPAR'ı yalnızca resmî GitHub sayfamızdan indirin!
Resmî Sürümler: https://github.com/AtaberkGit1/TULPAR/releases

Kullanım:
  sudo tulpar start       Korumayı ön planda başlatır (Ctrl+C ile tüm kuralları temizleyip çıkar)
  sudo tulpar install     /usr/local/bin/tulpar + systemd servisini kurar ve hemen başlatır
  sudo tulpar uninstall   Systemd servisini, güvenlik duvarı kurallarını ve kurulumu kaldırır
  tulpar test             Canlı şifreli DNS gecikmesi (ms), IPv6 ve DPI öz-denetimi yapar
  tulpar status           Aktif servis, nftables durumu ve Zapret/nfqws çakışmalarını gösterir
  sudo tulpar repair      Zapret/nfqws çakışmalarını temizler, TCP BBR'ı etkinleştirir, DNS sıfırlar
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

fn cmd_repair() -> ExitCode {
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

fn cmd_start() -> ExitCode {
    if !is_root() {
        eprintln!("HATA: Paket yakalama için root yetkisi gerekir: sudo tulpar start");
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

    let protector = Arc::new(LinuxMarkProtector);
    let engine = Arc::new(YolacEngine::new(YolacConfig::linux_desktop(), Some(protector)));

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
        println!("TULPAR En Hızlı Şifreli DNS Otomatik Seçildi (Turbo Önbellek + SWR Aktif)");
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
        "repair" => cmd_repair(),
        "update" => cmd_update(),
        "install" => cmd_install(),
        "uninstall" => cmd_uninstall(),
        "start" | "run" => cmd_start(),
        "stop-rules" => {
            if is_root() {
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
