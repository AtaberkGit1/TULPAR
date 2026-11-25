use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tulpar_forge::{
    format_tsl, parse_tsl, ForgePackage, ForgePlatformCaps, ForgeRuntime, ForgeStatus,
    ForgeVerifier, FormatError, MatchProtocol, PlatformSupport,
};

const SAMPLE_TSL: &str = r#"
strategy "unit-sample-turkey" {
  version = "1.0.0"
  author = "TULPAR Audit"
  description = "Balanced unit test strategy"
  min_core_version = "0.4.0"
  requires_raw_fallback = "auto_degrade"

  rollback {
    max_consecutive_failures = 3
    min_samples = 4
    max_failure_pct = 60
  }

  rule tls_base {
    priority = 100
    match proto == tls, port in [443, 8443], min_payload = 9
    raw_actions {
      tcp_split = [2, sni_mid]
      disorder = true
      decoy_sni = "www.iana.org"
      decoys = [bad_checksum, low_ttl_wrong_seq(auto), bad_checksum_wrong_seq]
    }
    socket_actions {
      tls_record = offset_and_sni_mid(2)
      tcp_split = [1, first_record_end]
      paced_flush = true
    }
  }

  rule tls_retry_1 {
    priority = 95
    when on_retry >= 1
    match proto == tls, port == 443
    raw_actions {
      tcp_split = [1, 2, sni_mid]
      disorder = true
      decoy_sni = "example.org"
      decoys = [low_ttl_wrong_seq(3), bad_checksum, bad_checksum_wrong_seq]
      syn_mss_clamp = 536
    }
    socket_actions {
      tls_record = small_chunks(24)
      tcp_oob = true
    }
  }

  rule quic_guard {
    priority = 70
    match proto == quic, port == 443
    quic_mode = block_fallback_tcp
  }

  lab_assert {
    expect_pass = [shallow_sni_reset, stateful_sni_reassembly]
    expect_honest_unbypassable = [hard_ip_blackhole]
  }
}
"#;

#[test]
fn dsl_compile_seal_decode_and_decompile_roundtrip() {
    let spec = parse_tsl(SAMPLE_TSL).expect("valid TSL parses");
    let (pkg, bytes) = ForgePackage::compile(&spec).expect("compiles cleanly");
    assert_eq!(pkg.report.compatibility.windows, PlatformSupport::Native);
    assert_eq!(pkg.report.compatibility.linux, PlatformSupport::Native);
    assert_eq!(pkg.report.compatibility.android, PlatformSupport::Native);

    let decoded = ForgePackage::decode_verified(&bytes).expect("decodes & verifies SHA-256");
    assert_eq!(decoded.spec, spec);
    assert_eq!(decoded.sha256, pkg.sha256);

    let decompiled = format_tsl(&decoded.spec);
    let reparsed = parse_tsl(&decompiled).expect("canonical decompiled TSL re-parses cleanly");
    assert_eq!(reparsed, spec);
}

#[test]
fn integrity_seal_rejects_any_tampered_byte_or_malformed_container() {
    let spec = parse_tsl(SAMPLE_TSL).unwrap();
    let (_, orig_bytes) = ForgePackage::compile(&spec).unwrap();

    // Flip 1 bit in header, middle, and trailer digest -> ALL must fail SHA-256 check!
    for &idx in &[14usize, orig_bytes.len() / 2, orig_bytes.len() - 5] {
        let mut tampered = orig_bytes.clone();
        tampered[idx] ^= 0x01;
        let err = ForgePackage::decode_verified(&tampered).unwrap_err();
        assert_eq!(err, FormatError::IntegrityCheckFailed);
    }

    assert_eq!(
        ForgePackage::decode_verified(b"NOT_TULPAR_MAGIC_0000000000000000000000000000"),
        Err(FormatError::InvalidMagic)
    );
    assert_eq!(
        ForgePackage::decode_verified(&orig_bytes[..20]),
        Err(FormatError::Truncated)
    );
}

#[test]
fn verifier_blocks_disallowed_decoy_hosts_amplification_arbitrary_directives_and_unsafe_ttl() {
    // 1. Disallowed victim decoy host
    let evil_decoy = SAMPLE_TSL.replace("\"www.iana.org\"", "\"victim-target.com\"");
    assert!(ForgeVerifier::verify(&parse_tsl(&evil_decoy).unwrap()).is_err());

    // 2. Amplification bomb (> 4 decoys)
    let amp = SAMPLE_TSL.replace(
        "[bad_checksum, low_ttl_wrong_seq(auto), bad_checksum_wrong_seq]",
        "[bad_checksum, bad_checksum, bad_checksum, bad_checksum, bad_checksum]",
    );
    assert!(ForgeVerifier::verify(&parse_tsl(&amp).unwrap()).is_err());

    // 3. Disabling circuit breaker (max_consecutive_failures = 99)
    let no_cb = SAMPLE_TSL.replace("max_consecutive_failures = 3", "max_consecutive_failures = 99");
    assert!(ForgeVerifier::verify(&parse_tsl(&no_cb).unwrap()).is_err());

    // 4. Micro-fragmentation flood (small_chunks(2))
    let flood = SAMPLE_TSL.replace("small_chunks(24)", "small_chunks(2)");
    assert!(ForgeVerifier::verify(&parse_tsl(&flood).unwrap()).is_err());

    // 5. Arbitrary code execution / network redirect injection syntax rejected at parse time
    let exec_attempt = SAMPLE_TSL.replace(
        "disorder = true",
        "exec_shell = \"curl https://evil.invalid\"",
    );
    assert!(parse_tsl(&exec_attempt).is_err());

    // 6. Unsafe SYN MSS clamp
    let tiny_mss = SAMPLE_TSL.replace("syn_mss_clamp = 536", "syn_mss_clamp = 64");
    assert!(ForgeVerifier::verify(&parse_tsl(&tiny_mss).unwrap()).is_err());
}

#[test]
fn runtime_hot_reload_escalation_and_automatic_circuit_breaker_rollback() {
    let spec = parse_tsl(SAMPLE_TSL).unwrap();
    let (_, bytes) = ForgePackage::compile(&spec).unwrap();

    let rt = ForgeRuntime::new(ForgePlatformCaps::WINDOWS);
    assert!(!rt.is_active());
    assert_eq!(rt.snapshot().status, ForgeStatus::BaselineOnly);

    rt.load_package_bytes(&bytes).expect("loads cleanly");
    assert!(rt.is_active());

    let raw0 = rt
        .select_raw_rule(MatchProtocol::Tls, 443, Some("blocked.test"), 120, false, 0)
        .expect("matches attempt 0");
    assert_eq!(raw0.decoy_sni, "www.iana.org");

    let raw1 = rt
        .select_raw_rule(MatchProtocol::Tls, 443, Some("blocked.test"), 120, false, 1)
        .expect("escalates on retry >= 1");
    assert_eq!(raw1.syn_mss_clamp, Some(536));

    // Single healthy flow does not trip
    let dst1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
    let dst2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)), 443);
    assert!(!rt.report_flow_outcome(dst1, Some("a.test"), true));

    // Inject consecutive failures across >=2 distinct destinations (policy max_consecutive_failures = 3)
    assert!(!rt.report_flow_outcome(dst1, Some("bad1.test"), false));
    assert!(!rt.report_flow_outcome(dst2, Some("bad2.test"), false));
    let tripped = rt.report_flow_outcome(dst1, Some("bad3.test"), false);
    assert!(tripped, "Circuit breaker MUST auto-disable broken Forge package");
    assert!(!rt.is_active());
    assert!(matches!(
        rt.snapshot().status,
        ForgeStatus::DisabledRollback { .. }
    ));
    assert!(rt
        .select_raw_rule(MatchProtocol::Tls, 443, Some("blocked.test"), 120, false, 0)
        .is_none());
}
