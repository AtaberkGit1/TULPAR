//! Static capability, security-sandbox, amplification, and platform-compatibility verifier.
//!
//! Acts as an eBPF-style gatekeeper before any `.tlp` or `.tulpar` strategy is packaged or executed.

use std::collections::HashSet;
use std::fmt;

use crate::ast::{
    DecoySpec, DecoyTtlMode, ForgePlatformCaps, MatchProtocol, QuicMode, RawFallbackPolicy,
    SplitCutSpec, StrategySpec, TlsRecordMode, ALLOWED_BENIGN_DECOY_HOSTS, MAX_DECOYS_PER_RULE,
    MAX_DECOY_TTL, MAX_FIXED_OFFSET, MAX_PORTS_PER_RULE, MAX_ROLLBACK_CONSECUTIVE, MAX_RULES,
    MAX_SNI_SUFFIXES_PER_RULE, MAX_SPLIT_CUTS, MAX_SYN_MSS, MAX_UDP_DESYNC_TTL, MIN_SAFE_SYN_MSS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformSupport {
    Native,
    AutoDegraded,
    Incompatible,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityMatrix {
    pub windows: PlatformSupport,
    pub linux: PlatformSupport,
    pub android: PlatformSupport,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub compatibility: CompatibilityMatrix,
    pub max_decoy_burst: usize,
    pub max_split_segments: usize,
    pub estimated_ram_bytes: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    pub violations: Vec<String>,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "TULPAR Forge Verifier rejected strategy:")?;
        for v in &self.violations {
            writeln!(f, "  - {v}")?;
        }
        Ok(())
    }
}

impl std::error::Error for VerifyError {}

fn is_safe_identifier(s: &str, max_len: usize) -> bool {
    !s.is_empty()
        && s.len() <= max_len
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !s.contains("..")
}

fn is_safe_text(s: &str, max_len: usize) -> bool {
    s.len() <= max_len && !s.chars().any(|c| c.is_control() && c != ' ')
}

fn is_valid_sni_suffix(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.len() > 128 || trimmed.contains("..") {
        return false;
    }
    trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

pub struct ForgeVerifier;

impl ForgeVerifier {
    /// Statically verifies safety, non-amplification, zero-exfiltration, benign decoy allowlist,
    /// mandatory rollback policy, and cross-platform capability compatibility.
    pub fn verify(spec: &StrategySpec) -> Result<VerifyReport, VerifyError> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        if !is_safe_identifier(&spec.name, 64) {
            errors.push(format!(
                "invalid strategy name '{}' (must be 1..=64 safe ASCII chars, no '..' or paths)",
                spec.name
            ));
        }
        if !is_safe_identifier(&spec.version, 32) {
            errors.push(format!("invalid version '{}'", spec.version));
        }
        if !is_safe_text(&spec.author, 64) {
            errors.push("author exceeds 64 chars or contains control characters".into());
        }
        if !is_safe_text(&spec.description, 256) {
            errors.push("description exceeds 256 chars or contains control characters".into());
        }

        // Mandatory circuit-breaker bounds (cannot be disabled by strategy authors)
        if spec.rollback.max_consecutive_failures == 0
            || spec.rollback.max_consecutive_failures > MAX_ROLLBACK_CONSECUTIVE
        {
            errors.push(format!(
                "rollback.max_consecutive_failures={} must be in 1..={MAX_ROLLBACK_CONSECUTIVE}",
                spec.rollback.max_consecutive_failures
            ));
        }
        if !(3..=64).contains(&spec.rollback.min_samples) {
            errors.push(format!(
                "rollback.min_samples={} must be in 3..=64",
                spec.rollback.min_samples
            ));
        }
        if !(20..=90).contains(&spec.rollback.max_failure_pct) {
            errors.push(format!(
                "rollback.max_failure_pct={} must be in 20..=90",
                spec.rollback.max_failure_pct
            ));
        }

        if spec.rules.is_empty() {
            errors.push("strategy must define at least 1 rule".into());
        }
        if spec.rules.len() > MAX_RULES {
            errors.push(format!(
                "rule count {} exceeds ceiling of {MAX_RULES}",
                spec.rules.len()
            ));
        }

        let mut seen_rule_names = HashSet::new();
        let mut max_decoy_burst = 0usize;
        let mut max_split_segments = 1usize;
        let mut any_uses_raw_only = false;
        let mut any_missing_socket = false;

        for rule in &spec.rules {
            if !is_safe_identifier(&rule.name, 48) {
                errors.push(format!("invalid rule identifier '{}'", rule.name));
            }
            if !seen_rule_names.insert(&rule.name) {
                errors.push(format!("duplicate rule name '{}'", rule.name));
            }
            if rule.matcher.protocols.is_empty() {
                errors.push(format!("rule '{}' must match at least one protocol", rule.name));
            }
            if rule.matcher.ports.len() > MAX_PORTS_PER_RULE {
                errors.push(format!(
                    "rule '{}' specifies {} ports (max {MAX_PORTS_PER_RULE})",
                    rule.name,
                    rule.matcher.ports.len()
                ));
            }
            if rule.matcher.ports.contains(&0) {
                errors.push(format!("rule '{}' cannot match reserved port 0", rule.name));
            }
            if rule.matcher.sni_suffixes.len() > MAX_SNI_SUFFIXES_PER_RULE {
                errors.push(format!(
                    "rule '{}' exceeds max {MAX_SNI_SUFFIXES_PER_RULE} sni_suffix entries",
                    rule.name
                ));
            }
            for suf in &rule.matcher.sni_suffixes {
                if !is_valid_sni_suffix(suf) {
                    errors.push(format!(
                        "rule '{}' contains unsafe sni_suffix '{}'",
                        rule.name, suf
                    ));
                }
            }

            if rule.raw_actions.is_none()
                && rule.socket_actions.is_none()
                && rule.quic_mode.is_none()
                && rule.udp_desync_ttl.is_none()
            {
                errors.push(format!("rule '{}' defines no actions", rule.name));
            }

            if let Some(raw) = &rule.raw_actions {
                if raw.tcp_splits.len() > MAX_SPLIT_CUTS {
                    errors.push(format!(
                        "rule '{}' raw tcp_split count {} exceeds {MAX_SPLIT_CUTS}",
                        rule.name,
                        raw.tcp_splits.len()
                    ));
                }
                for cut in &raw.tcp_splits {
                    if let SplitCutSpec::FixedOffset(off) = cut {
                        if *off == 0 || *off > MAX_FIXED_OFFSET {
                            errors.push(format!(
                                "rule '{}' fixed split offset {} out of 1..={MAX_FIXED_OFFSET}",
                                rule.name, off
                            ));
                        }
                    }
                }
                max_split_segments = max_split_segments.max(raw.tcp_splits.len() + 1);

                if raw.decoys.len() > MAX_DECOYS_PER_RULE {
                    errors.push(format!(
                        "rule '{}' emits {} decoys (amplification limit: {MAX_DECOYS_PER_RULE})",
                        rule.name,
                        raw.decoys.len()
                    ));
                }
                max_decoy_burst = max_decoy_burst.max(raw.decoys.len());

                let host_lower = raw.decoy_sni.trim().to_ascii_lowercase();
                if !ALLOWED_BENIGN_DECOY_HOSTS.contains(&host_lower.as_str()) {
                    errors.push(format!(
                        "rule '{}' decoy_sni '{}' rejected: must be an inert RFC 2606 / IANA allowlisted host ({:?})",
                        rule.name, raw.decoy_sni, ALLOWED_BENIGN_DECOY_HOSTS
                    ));
                }

                for d in &raw.decoys {
                    match d {
                        DecoySpec::LowTtl(DecoyTtlMode::Fixed(t)) if *t == 0 || *t > 5 => {
                            errors.push(format!(
                                "rule '{}' exact-seq low_ttl({t}) unsafe (max 5; use low_ttl_wrong_seq or low_ttl(auto) to prevent Anycast stream corruption)",
                                rule.name
                            ));
                        }
                        DecoySpec::LowTtlWrongSeq(DecoyTtlMode::Fixed(t))
                            if *t == 0 || *t > MAX_DECOY_TTL =>
                        {
                            errors.push(format!(
                                "rule '{}' low_ttl_wrong_seq({t}) TTL out of safe 1..={MAX_DECOY_TTL}",
                                rule.name
                            ));
                        }
                        _ => {}
                    }
                }

                if let Some(mss) = raw.syn_mss_clamp {
                    if !(MIN_SAFE_SYN_MSS..=MAX_SYN_MSS).contains(&mss) {
                        errors.push(format!(
                            "rule '{}' syn_mss_clamp={mss} unsafe (allowed {MIN_SAFE_SYN_MSS}..={MAX_SYN_MSS})",
                            rule.name
                        ));
                    }
                }

                let uses_raw_primitives =
                    raw.disorder || !raw.decoys.is_empty() || raw.syn_mss_clamp.is_some();
                if uses_raw_primitives {
                    any_uses_raw_only = true;
                    if rule.socket_actions.is_none()
                        && (rule.matcher.protocols.contains(&MatchProtocol::Tls)
                            || rule.matcher.protocols.contains(&MatchProtocol::Http)
                            || rule.matcher.protocols.contains(&MatchProtocol::Any))
                    {
                        any_missing_socket = true;
                    }
                }
            }

            if let Some(sock) = &rule.socket_actions {
                if sock.tcp_splits.len() > MAX_SPLIT_CUTS {
                    errors.push(format!(
                        "rule '{}' socket tcp_split count {} exceeds {MAX_SPLIT_CUTS}",
                        rule.name,
                        sock.tcp_splits.len()
                    ));
                }
                for cut in &sock.tcp_splits {
                    if let SplitCutSpec::FixedOffset(off) = cut {
                        if *off == 0 || *off > MAX_FIXED_OFFSET {
                            errors.push(format!(
                                "rule '{}' socket split offset {} out of 1..={MAX_FIXED_OFFSET}",
                                rule.name, off
                            ));
                        }
                    }
                }
                if let Some(TlsRecordMode::OffsetAndSniMid(off)) = sock.tls_record {
                    if off == 0 || off > 64 {
                        errors.push(format!(
                            "rule '{}' offset_and_sni_mid({off}) must be in 1..=64",
                            rule.name
                        ));
                    }
                }
                if let Some(TlsRecordMode::SmallChunks(sz)) = sock.tls_record {
                    if !(16..=512).contains(&sz) {
                        errors.push(format!(
                            "rule '{}' small_chunks({sz}) must be in 16..=512 bytes (prevents micro-fragmentation flood)",
                            rule.name
                        ));
                    }
                }
            }

            if let Some(QuicMode::DesyncTtl(t)) = rule.quic_mode {
                if t == 0 || t > MAX_DECOY_TTL {
                    errors.push(format!(
                        "rule '{}' quic_mode desync_ttl({t}) must be in 1..={MAX_DECOY_TTL}",
                        rule.name
                    ));
                }
            }

            if let Some(uttl) = rule.udp_desync_ttl {
                if uttl == 0 || uttl > MAX_UDP_DESYNC_TTL {
                    errors.push(format!(
                        "rule '{}' udp_desync_ttl={uttl} must be in 1..={MAX_UDP_DESYNC_TTL}",
                        rule.name
                    ));
                }
            }
        }

        if !errors.is_empty() {
            return Err(VerifyError { violations: errors });
        }

        let mut compat_notes = Vec::new();
        let android_support = if !any_uses_raw_only {
            PlatformSupport::Native
        } else {
            match spec.fallback_policy {
                RawFallbackPolicy::Strict => {
                    compat_notes.push(
                        "requires_raw_fallback = strict: rejected on unprivileged Android VpnService sockets"
                            .into(),
                    );
                    PlatformSupport::Incompatible
                }
                RawFallbackPolicy::AutoDegrade => {
                    if any_missing_socket {
                        warnings.push(
                            "One or more raw_actions rules omit explicit socket_actions; Android auto-degrades deterministically to multi-record TLS/TCP splitting."
                                .into(),
                        );
                        compat_notes.push(
                            "Android VpnService auto-degrades raw decoys/disorder to safe userspace TLS/TCP splitting"
                                .into(),
                        );
                        PlatformSupport::AutoDegraded
                    } else {
                        compat_notes.push(
                            "Explicit socket_actions provided for Android VpnService alongside Windows/Linux raw_actions"
                                .into(),
                        );
                        PlatformSupport::Native
                    }
                }
            }
        };

        let estimated_ram_bytes = 512
            + spec.rules.len() * 192
            + spec.rules.iter().map(|r| r.matcher.sni_suffixes.len() * 32).sum::<usize>();

        Ok(VerifyReport {
            compatibility: CompatibilityMatrix {
                windows: PlatformSupport::Native,
                linux: PlatformSupport::Native,
                android: android_support,
                notes: compat_notes,
            },
            max_decoy_burst,
            max_split_segments,
            estimated_ram_bytes,
            warnings,
        })
    }

    pub fn supports_platform(spec: &StrategySpec, caps: ForgePlatformCaps) -> Result<PlatformSupport, VerifyError> {
        let rep = Self::verify(spec)?;
        if caps.supports_raw_packets {
            Ok(PlatformSupport::Native)
        } else {
            Ok(rep.compatibility.android)
        }
    }
}
