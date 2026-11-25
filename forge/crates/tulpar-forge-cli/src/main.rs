//! TULPAR Forge CLI (`tulpar-forge`): create, check, verify, lab-test, package (.tulpar), inspect & benchmark strategies.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use tulpar_forge::{format_tsl, parse_tsl, ForgePackage, ForgeVerifier, StrategySpec};
use tulpar_forge_lab::{
    evaluate_lab_assertions, run_benchmark, run_lab_scenarios,
    run_rollback_circuit_breaker_simulation, run_security_audit, ScenarioOutcome,
};

fn print_usage() {
    println!(
        r#"TULPAR Forge v{} — Deklaratif, Güvenli ve Taşınabilir Strateji Altyapısı (.tulpar)

Kullanım:
  tulpar-forge new <dosya.tlp>                   Örnek güvenli TSL v1 strateji şablonu oluşturur
  tulpar-forge check <girdi.tlp|.tulpar>         Sözdizimi, güvenlik/amplifikasyon ve platform uyumluluğunu doğrular
  tulpar-forge build <girdi.tlp> [-o <ç.tulpar>] Stratejiyi derler, doğrular ve SHA-256 mühürlü .tulpar paketine dönüştürür
  tulpar-forge inspect <paket.tulpar>            .tulpar paketinin başlık, SHA-256 ve okunabilir TSL dökümünü gösterir
  tulpar-forge test <girdi.tlp|.tulpar>          Yerel sansür/daraltma simülasyon laboratuvarını + rollback testini çalıştırır
  tulpar-forge bench <girdi.tlp|.tulpar>         RAM, derleme, doğrulama ve el sıkışma başına mikro-karşılaştırma yapar
  tulpar-forge verify-security                   Olumsuz güvenlik ve sanal alan (sandbox) izolasyon testlerini çalıştırır
  tulpar-forge --version                         Sürüm bilgisini gösterir

Güvenlik: .tulpar paketleri keyfî kod çalıştıramaz, kullanıcı verisine erişemez ve yetkisiz ağ bağlantısı kuramaz."#,
        env!("CARGO_PKG_VERSION")
    );
}

fn load_spec_from_any(path: &Path) -> Result<(StrategySpec, Option<String>), String> {
    let raw = fs::read(path).map_err(|e| format!("Dosya okunamadı {:?}: {e}", path))?;
    if raw.starts_with(tulpar_forge::PACKAGE_MAGIC) {
        let pkg = ForgePackage::decode_verified(&raw).map_err(|e| e.to_string())?;
        Ok((pkg.spec, Some(pkg.sha256_hex)))
    } else {
        let src = std::str::from_utf8(&raw).map_err(|_| "Geçersiz UTF-8 strateji dosyası".to_string())?;
        let spec = parse_tsl(src).map_err(|e| e.to_string())?;
        Ok((spec, None))
    }
}

fn cmd_new(path: &Path) -> ExitCode {
    if path.exists() {
        eprintln!("HATA: {:?} zaten var.", path);
        return ExitCode::FAILURE;
    }
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("custom-strategy");
    let template = format!(
        r#"# TULPAR Strategy Language (TSL v1)
strategy "{name}" {{
  version = "1.0.0"
  author = "Community Author"
  description = "Custom cross-platform anti-DPI strategy"
  min_core_version = "0.4.0"
  requires_raw_fallback = "auto_degrade"

  rollback {{
    max_consecutive_failures = 4
    min_samples = 6
    max_failure_pct = 65
  }}

  rule tls_default {{
    priority = 100
    match proto == tls, port in [443, 8443], min_payload = 9
    raw_actions {{
      tcp_split = [2, sni_mid]
      disorder = true
      decoy_sni = "www.iana.org"
      decoys = [bad_checksum, low_ttl_wrong_seq(auto), bad_checksum_wrong_seq]
    }}
    socket_actions {{
      tls_record = offset_and_sni_mid(2)
      tcp_split = [1, first_record_end]
      paced_flush = true
    }}
  }}

  rule quic_policy {{
    priority = 70
    match proto == quic, port == 443
    quic_mode = block_fallback_tcp
  }}

  lab_assert {{
    expect_pass = [shallow_sni_reset, stateful_sni_reassembly, hop_sensitive_inline_dpi, quic_throttle]
    expect_honest_unbypassable = [hard_ip_blackhole]
  }}
}}
"#
    );
    match fs::write(path, template) {
        Ok(()) => {
            println!("Şablon oluşturuldu: {:?}", path);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("HATA: Yazılamadı: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_check(path: &Path) -> ExitCode {
    let (spec, existing_hash) = match load_spec_from_any(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("HATA: {e}");
            return ExitCode::FAILURE;
        }
    };
    match ForgeVerifier::verify(&spec) {
        Ok(rep) => {
            println!("DOĞRULANDI: {} v{}", spec.name, spec.version);
            if let Some(h) = existing_hash {
                println!("  SHA-256 : {h}");
            }
            println!(
                "  Platformlar : Windows={:?} · Linux={:?} · Android={:?}",
                rep.compatibility.windows, rep.compatibility.linux, rep.compatibility.android
            );
            println!(
                "  Bütçe       : max {} sahte paket · max {} segment · ~{} B RAM",
                rep.max_decoy_burst, rep.max_split_segments, rep.estimated_ram_bytes
            );
            for w in &rep.warnings {
                println!("  [Uyarı] {w}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_build(input: &Path, output: Option<&Path>) -> ExitCode {
    let (spec, _) = match load_spec_from_any(input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("HATA: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (pkg, bytes) = match ForgePackage::compile(&spec) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("DERLEME HATASI: {e}");
            return ExitCode::FAILURE;
        }
    };
    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => input.with_extension("tulpar"),
    };
    if let Err(e) = fs::write(&out_path, &bytes) {
        eprintln!("Yazma hatası {:?}: {e}", out_path);
        return ExitCode::FAILURE;
    }
    println!(
        "PAKETLENDİ: {:?} ({} bayt · sha256:{})",
        out_path,
        bytes.len(),
        pkg.sha256_hex
    );
    ExitCode::SUCCESS
}

fn cmd_inspect(path: &Path) -> ExitCode {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Okuma hatası: {e}");
            return ExitCode::FAILURE;
        }
    };
    let pkg = match ForgePackage::decode_verified(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("HATA: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("Paket   : {} v{}", pkg.spec.name, pkg.spec.version);
    println!("Yazar   : {}", pkg.spec.author);
    println!("SHA-256 : {}", pkg.sha256_hex);
    println!(
        "Uyum    : Windows={:?}, Linux={:?}, Android={:?}",
        pkg.report.compatibility.windows,
        pkg.report.compatibility.linux,
        pkg.report.compatibility.android
    );
    println!("\n--- Canonical TSL v1 ---\n{}", format_tsl(&pkg.spec));
    ExitCode::SUCCESS
}

fn cmd_test(path: &Path) -> ExitCode {
    let (spec, _) = match load_spec_from_any(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("HATA: {e}");
            return ExitCode::FAILURE;
        }
    };

    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    else {
        eprintln!("Tokio başlatılamadı");
        return ExitCode::FAILURE;
    };

    println!("TULPAR Forge Yerel Sansür Laboratuvarı: {} v{}\n", spec.name, spec.version);
    let results = rt.block_on(run_lab_scenarios(&spec));
    let mut hard_fail = false;
    for r in &results {
        let tag = match r.outcome {
            ScenarioOutcome::Pass => "[PASS]",
            ScenarioOutcome::Fail => {
                hard_fail = true;
                "[FAIL]"
            }
            ScenarioOutcome::UnbypassableOnDevice => "[HONEST-LIMIT]",
            ScenarioOutcome::SkippedIncompatible => "[SKIP-CAP]",
        };
        println!("  {:<14} {:<26} {} ms — {}", tag, r.id, r.elapsed_ms, r.detail);
    }

    match rt.block_on(run_rollback_circuit_breaker_simulation(&spec)) {
        Ok(msg) => println!("  [PASS]         circuit_breaker_rollback   — {msg}"),
        Err(e) => {
            hard_fail = true;
            println!("  [FAIL]         circuit_breaker_rollback   — {e}");
        }
    }

    if let Err(assert_errs) = evaluate_lab_assertions(&spec, &results) {
        hard_fail = true;
        for err in assert_errs {
            eprintln!("ASSERT FAIL: {err}");
        }
    }

    if hard_fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn cmd_verify_security() -> ExitCode {
    let results = run_security_audit();
    let mut failed = false;
    println!("TULPAR Forge Güvenlik ve İzolasyon Denetimi:\n");
    for r in &results {
        println!(
            "  [{}] {:<44} — {}",
            if r.passed { "OK" } else { "FAIL" },
            r.name,
            r.detail
        );
        if !r.passed {
            failed = true;
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn cmd_bench(path: &Path) -> ExitCode {
    let (spec, _) = match load_spec_from_any(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("HATA: {e}");
            return ExitCode::FAILURE;
        }
    };
    let src = format_tsl(&spec);
    match run_benchmark(&src) {
        Ok(b) => {
            println!("TULPAR Forge Performans Raporu ({:?}):", path);
            println!("  .tulpar Boyutu       : {} bayt", b.package_bytes);
            println!("  Tahmini RAM          : {} bayt", b.estimated_ram_bytes);
            println!("  Derleme + SHA-256    : {} µs", b.compile_seal_us);
            println!("  Yükleme + Doğrulama  : {} µs", b.decode_verify_us);
            println!("  Kural Eşleştirme     : {} ns / el sıkışma", b.per_handshake_eval_ns);
            println!("  Ham Paket Dönüşümü   : {} µs / el sıkışma", b.raw_transform_us);
            println!("  El Sıkışma Tel Oranı : {:.2}x (yalnızca ilk paket)", b.wire_expansion_ratio);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Benchmark hatası: {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let Some(cmd) = args.get(1).map(|s| s.as_str()) else {
        print_usage();
        return ExitCode::SUCCESS;
    };

    match cmd {
        "--version" | "-V" | "version" => {
            println!("tulpar-forge v{}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        "verify-security" => cmd_verify_security(),
        "new" => args
            .get(2)
            .map(|p| cmd_new(Path::new(p)))
            .unwrap_or_else(|| {
                eprintln!("Kullanım: tulpar-forge new <dosya.tlp>");
                ExitCode::FAILURE
            }),
        "check" => args
            .get(2)
            .map(|p| cmd_check(Path::new(p)))
            .unwrap_or_else(|| {
                eprintln!("Kullanım: tulpar-forge check <dosya>");
                ExitCode::FAILURE
            }),
        "build" => {
            let Some(inp) = args.get(2) else {
                eprintln!("Kullanım: tulpar-forge build <girdi.tlp> [-o <ç.tulpar>]");
                return ExitCode::FAILURE;
            };
            let mut out: Option<&Path> = None;
            if args.get(3).map(|s| s.as_str()) == Some("-o") {
                out = args.get(4).map(|s| Path::new(s.as_str()));
            }
            cmd_build(Path::new(inp), out)
        }
        "inspect" => args
            .get(2)
            .map(|p| cmd_inspect(Path::new(p)))
            .unwrap_or_else(|| {
                eprintln!("Kullanım: tulpar-forge inspect <paket.tulpar>");
                ExitCode::FAILURE
            }),
        "test" => args
            .get(2)
            .map(|p| cmd_test(Path::new(p)))
            .unwrap_or_else(|| {
                eprintln!("Kullanım: tulpar-forge test <dosya.tlp|.tulpar>");
                ExitCode::FAILURE
            }),
        "bench" => args
            .get(2)
            .map(|p| cmd_bench(Path::new(p)))
            .unwrap_or_else(|| {
                eprintln!("Kullanım: tulpar-forge bench <dosya.tlp|.tulpar>");
                ExitCode::FAILURE
            }),
        other => {
            eprintln!("Bilinmeyen komut: {other}");
            print_usage();
            ExitCode::FAILURE
        }
    }
}
