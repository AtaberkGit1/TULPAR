//! Adversarial security isolation & sandbox verification suite for TULPAR Forge.

use tulpar_forge::{
    parse_tsl, ForgePackage, ForgePlatformCaps, ForgeRuntime, ForgeVerifier, MatchProtocol,
};

#[derive(Debug, Clone)]
pub struct SecurityCheckResult {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

const VALID_BASE: &str = r#"
strategy "sec-baseline" {
  version = "1.0.0"
  author = "Security Audit"
  description = "Valid base template for adversarial mutation testing"
  requires_raw_fallback = "auto_degrade"

  rollback {
    max_consecutive_failures = 4
    min_samples = 6
    max_failure_pct = 65
  }

  rule tls_main {
    priority = 100
    match proto == tls, port == 443
    raw_actions {
      tcp_split = [2, sni_mid]
      disorder = true
      decoy_sni = "www.iana.org"
      decoys = [bad_checksum, low_ttl_wrong_seq(auto)]
    }
    socket_actions {
      tls_record = offset_and_sni_mid(2)
      tcp_split = [1, first_record_end]
      paced_flush = true
    }
  }
}
"#;

pub fn run_security_audit() -> Vec<SecurityCheckResult> {
    let mut out = Vec::new();
    let base_spec = parse_tsl(VALID_BASE).unwrap();
    let (_, valid_pkg_bytes) = ForgePackage::compile(&base_spec).unwrap();

    // 1. Arbitrary code execution / shell escape / fs access attempts rejected at DSL layer
    let code_exec_attempts = [
        VALID_BASE.replace("disorder = true", "exec = \"/bin/sh\""),
        VALID_BASE.replace("disorder = true", "read_file = \"/etc/passwd\""),
        VALID_BASE.replace("disorder = true", "connect = \"198.51.100.99:4444\""),
        VALID_BASE.replace("disorder = true", "redirect_ip = \"203.0.113.1\""),
    ];
    let exec_blocked = code_exec_attempts.iter().all(|s| parse_tsl(s).is_err());
    out.push(SecurityCheckResult {
        name: "arbitrary_code_fs_network_directive_rejection",
        passed: exec_blocked,
        detail: "Parser strictly rejects exec/filesystem/unauthorized-network directives".into(),
    });

    // 2. Victim domain attribution / decoy amplification abuse blocked
    let victim = VALID_BASE.replace("\"www.iana.org\"", "\"target-victim.example.invalid\"");
    let victim_blocked = parse_tsl(&victim)
        .ok()
        .is_some_and(|s| ForgeVerifier::verify(&s).is_err());
    out.push(SecurityCheckResult {
        name: "benign_decoy_host_allowlist",
        passed: victim_blocked,
        detail: "Verifier enforces RFC 2606 / IANA inert decoy hosts only".into(),
    });

    // 3. Packet amplification ceiling (>4 decoys or >6 cuts rejected)
    let amp = VALID_BASE.replace(
        "[bad_checksum, low_ttl_wrong_seq(auto)]",
        "[bad_checksum, bad_checksum, bad_checksum, bad_checksum, bad_checksum]",
    );
    let amp_blocked = parse_tsl(&amp)
        .ok()
        .is_some_and(|s| ForgeVerifier::verify(&s).is_err());
    out.push(SecurityCheckResult {
        name: "packet_amplification_ceiling",
        passed: amp_blocked,
        detail: "Verifier caps decoy burst <= 4 and split cuts <= 6".into(),
    });

    // 4. Mandatory rollback guard cannot be crippled
    let no_rb = VALID_BASE.replace("max_consecutive_failures = 4", "max_consecutive_failures = 0");
    let rb_enforced = parse_tsl(&no_rb)
        .ok()
        .is_some_and(|s| ForgeVerifier::verify(&s).is_err());
    out.push(SecurityCheckResult {
        name: "mandatory_circuit_breaker_enforcement",
        passed: rb_enforced,
        detail: "Verifier rejects attempts to disable or bypass rollback circuit breaker".into(),
    });

    // 5. Cryptographic SHA-256 tamper resistance on binary `.tulpar`
    let mut corrupted = valid_pkg_bytes.clone();
    corrupted[24] ^= 0x80;
    let tamper_rejected = ForgePackage::decode_verified(&corrupted).is_err();
    out.push(SecurityCheckResult {
        name: "sha256_package_seal_integrity",
        passed: tamper_rejected,
        detail: "1-bit mutation anywhere in .tulpar fails FIPS 180-4 SHA-256 verification".into(),
    });

    // 6. Crafted malformed binary framing never panics (OOM / length-overflow guards)
    let mut length_bomb = b"TULPARF1\x00\x01\x00\x00".to_vec();
    length_bomb.extend_from_slice(&[0xFFu8; 64]);
    let fuzz_safe = ForgePackage::decode_verified(&length_bomb).is_err()
        && ForgePackage::decode_verified(&vec![0u8; 256 * 1024]).is_err();
    out.push(SecurityCheckResult {
        name: "malformed_binary_oom_panic_immunity",
        passed: fuzz_safe,
        detail: "Oversized containers (>128 KiB) & malformed length headers rejected without panic".into(),
    });

    // 7. Strict raw-only strategy cannot silently execute on unprivileged Android sandbox
    let strict = VALID_BASE.replace("\"auto_degrade\"", "\"strict\"");
    let strict_pkg = ForgePackage::compile(&parse_tsl(&strict).unwrap()).unwrap().1;
    let android_rt = ForgeRuntime::new(ForgePlatformCaps::ANDROID);
    let android_strict_rejected = android_rt.load_package_bytes(&strict_pkg).is_err();
    out.push(SecurityCheckResult {
        name: "platform_capability_boundary_enforcement",
        passed: android_strict_rejected,
        detail: "Android runtime enforces requires_raw_fallback = strict capability gate".into(),
    });

    // 8. Inactive fast-path & rule isolation checks (excluded port 22 SSH never mangled)
    let win_rt = ForgeRuntime::new(ForgePlatformCaps::WINDOWS);
    win_rt.load_package_bytes(&valid_pkg_bytes).unwrap();
    let ssh_untouched = win_rt
        .select_raw_rule(MatchProtocol::Tls, 22, None, 100, false, 0)
        .is_none();
    out.push(SecurityCheckResult {
        name: "non_targeted_port_isolation",
        passed: ssh_untouched,
        detail: "Port 22/untargeted services remain completely untouched by TLS strategy rules".into(),
    });

    out
}
