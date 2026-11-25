//! Lock-free fast-path ForgeRuntime with dynamic hot-reload and transactional circuit-breaker rollback.

use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::fs;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use crate::ast::{
    ForgePlatformCaps, MatchProtocol, QuicMode, RawActionSpec, SocketActionSpec, StrategyRule,
    TlsRecordMode, MAX_PACKAGE_BYTES,
};
use crate::dsl::parse_tsl;
use crate::format::{ForgePackage, FormatError};
use crate::verifier::{PlatformSupport, VerifyReport};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForgeStatus {
    /// No external `.tulpar` package loaded; built-in verified core strategies active.
    BaselineOnly,
    /// Verified `.tulpar` strategy package active cleanly.
    Active,
    /// Loaded package failed live connectivity thresholds and was automatically disabled/rolled back.
    DisabledRollback { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeStatusSnapshot {
    pub status: ForgeStatus,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub sha256_prefix: Option<String>,
    pub consecutive_failures: u8,
    pub total_samples: u32,
    pub failed_samples: u32,
    pub distinct_failed_targets: usize,
}

#[derive(Debug, Clone)]
struct CircuitState {
    disabled: bool,
    disabled_reason: Option<String>,
    consecutive_failures: u8,
    total_samples: u32,
    failed_samples: u32,
    hash_builder: RandomState,
    distinct_failed_hashes: HashSet<u64>,
}

impl CircuitState {
    fn new() -> Self {
        Self {
            disabled: false,
            disabled_reason: None,
            consecutive_failures: 0,
            total_samples: 0,
            failed_samples: 0,
            hash_builder: RandomState::new(),
            distinct_failed_hashes: HashSet::new(),
        }
    }

    fn hash_target(&self, dst: SocketAddr, sni: Option<&str>) -> u64 {
        let mut h = self.hash_builder.build_hasher();
        if let Some(s) = sni.map(str::trim).filter(|s| !s.is_empty()) {
            h.write_u8(1);
            for &b in s.as_bytes() {
                h.write_u8(b.to_ascii_lowercase());
            }
        } else {
            h.write_u8(2);
            dst.ip().hash(&mut h);
        }
        dst.port().hash(&mut h);
        h.finish()
    }
}

struct LoadedRuntimePackage {
    pkg: ForgePackage,
    circuit: std::sync::Mutex<CircuitState>,
}

/// Thread-safe, hot-reloadable Forge package executor embedded in `yolac-core::YolacEngine`.
///
/// Fast-path guarantee: when no `.tulpar` package is active (or after auto-rollback),
/// `is_active()` performs only a single relaxed/acquire `AtomicBool` load (~1 CPU cycle).
pub struct ForgeRuntime {
    caps: ForgePlatformCaps,
    active_fast_flag: AtomicBool,
    loaded: RwLock<Option<Arc<LoadedRuntimePackage>>>,
}

impl ForgeRuntime {
    pub fn new(caps: ForgePlatformCaps) -> Self {
        Self {
            caps,
            active_fast_flag: AtomicBool::new(false),
            loaded: RwLock::new(None),
        }
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.active_fast_flag.load(Ordering::Acquire)
    }

    /// Loads & atomically swaps in a `.tulpar` binary package (or declarative `.tlp` source if prefixed cleanly),
    /// verifying SHA-256 seal + capability safety + platform compatibility BEFORE activation.
    pub fn load_package_bytes(&self, bytes: &[u8]) -> Result<VerifyReport, String> {
        let pkg = if bytes.starts_with(crate::format::PACKAGE_MAGIC) {
            ForgePackage::decode_verified(bytes).map_err(|e| e.to_string())?
        } else {
            let src = std::str::from_utf8(bytes)
                .map_err(|_| FormatError::InvalidUtf8.to_string())?;
            let spec = parse_tsl(src).map_err(|e| e.to_string())?;
            let (pkg, _) = ForgePackage::compile(&spec).map_err(|e| e.to_string())?;
            pkg
        };

        if !self.caps.supports_raw_packets && pkg.report.compatibility.android == PlatformSupport::Incompatible {
            return Err(format!(
                "strategy '{}' has requires_raw_fallback = \"strict\" and is incompatible with socket-only sandbox platforms",
                pkg.spec.name
            ));
        }

        let report = pkg.report.clone();
        let loaded = Arc::new(LoadedRuntimePackage {
            pkg,
            circuit: std::sync::Mutex::new(CircuitState::new()),
        });
        if let Ok(mut guard) = self.loaded.write() {
            *guard = Some(loaded);
            self.active_fast_flag.store(true, Ordering::Release);
        }
        Ok(report)
    }

    pub fn load_package_file(&self, path: &Path) -> Result<VerifyReport, String> {
        let meta = fs::metadata(path).map_err(|e| format!("failed to stat {:?}: {e}", path))?;
        if meta.len() as usize > MAX_PACKAGE_BYTES {
            return Err(format!(
                "strategy file size {} exceeds limit of {MAX_PACKAGE_BYTES} bytes",
                meta.len()
            ));
        }
        let bytes = fs::read(path).map_err(|e| format!("failed to read {:?}: {e}", path))?;
        self.load_package_bytes(&bytes)
    }

    /// Explicitly unloads any Forge package and restores TULPAR's verified built-in baseline.
    pub fn unload(&self) {
        self.active_fast_flag.store(false, Ordering::Release);
        if let Ok(mut guard) = self.loaded.write() {
            *guard = None;
        }
    }

    pub fn snapshot(&self) -> ForgeStatusSnapshot {
        let guard = match self.loaded.read() {
            Ok(g) => g,
            Err(_) => {
                return ForgeStatusSnapshot {
                    status: ForgeStatus::BaselineOnly,
                    package_name: None,
                    package_version: None,
                    sha256_prefix: None,
                    consecutive_failures: 0,
                    total_samples: 0,
                    failed_samples: 0,
                    distinct_failed_targets: 0,
                }
            }
        };
        let Some(entry) = guard.as_ref() else {
            return ForgeStatusSnapshot {
                status: ForgeStatus::BaselineOnly,
                package_name: None,
                package_version: None,
                sha256_prefix: None,
                consecutive_failures: 0,
                total_samples: 0,
                failed_samples: 0,
                distinct_failed_targets: 0,
            };
        };
        let c = entry.circuit.lock().map(|g| g.clone()).unwrap_or_else(|_| CircuitState::new());
        let status = if let Some(reason) = c.disabled_reason {
            ForgeStatus::DisabledRollback { reason }
        } else {
            ForgeStatus::Active
        };
        ForgeStatusSnapshot {
            status,
            package_name: Some(entry.pkg.spec.name.clone()),
            package_version: Some(entry.pkg.spec.version.clone()),
            sha256_prefix: Some(entry.pkg.sha256_hex[..16].to_string()),
            consecutive_failures: c.consecutive_failures,
            total_samples: c.total_samples,
            failed_samples: c.failed_samples,
            distinct_failed_targets: c.distinct_failed_hashes.len(),
        }
    }

    /// Evaluates the active Forge package for a raw packet flow (Windows WinDivert / Linux NFQUEUE).
    pub fn select_raw_rule(
        &self,
        proto: MatchProtocol,
        dst_port: u16,
        sni: Option<&str>,
        payload_len: usize,
        is_sensitive: bool,
        retry_count: u8,
    ) -> Option<RawActionSpec> {
        if !self.is_active() {
            return None;
        }
        let guard = self.loaded.read().ok()?;
        let entry = guard.as_ref()?;
        let rule = pick_matching_rule(&entry.pkg.spec.rules, proto, dst_port, sni, payload_len, is_sensitive, retry_count)?;
        if is_sensitive && rule.matcher.exclude_sensitive && retry_count == 0 {
            return Some(RawActionSpec {
                passthrough: true,
                ..Default::default()
            });
        }
        rule.raw_actions.clone()
    }

    /// Evaluates the active Forge package for a userspace socket flow (Android VpnService / DpiTcpRelay).
    pub fn select_socket_rule(
        &self,
        proto: MatchProtocol,
        dst_port: u16,
        sni: Option<&str>,
        payload_len: usize,
        is_sensitive: bool,
        retry_count: u8,
    ) -> Option<SocketActionSpec> {
        if !self.is_active() {
            return None;
        }
        let guard = self.loaded.read().ok()?;
        let entry = guard.as_ref()?;
        let rule = pick_matching_rule(&entry.pkg.spec.rules, proto, dst_port, sni, payload_len, is_sensitive, retry_count)?;
        if is_sensitive && rule.matcher.exclude_sensitive && retry_count == 0 {
            return Some(SocketActionSpec {
                passthrough: true,
                ..Default::default()
            });
        }
        if let Some(sock) = &rule.socket_actions {
            return Some(sock.clone());
        }
        // AutoDegrade: derive a safe socket strategy from `raw_actions` deterministically
        rule.raw_actions.as_ref().map(|raw| {
            if raw.passthrough {
                return SocketActionSpec {
                    passthrough: true,
                    ..Default::default()
                };
            }
            let tls_record = if !raw.decoys.is_empty() || raw.tcp_splits.len() >= 2 {
                Some(TlsRecordMode::OffsetAndSniMid(2))
            } else {
                Some(TlsRecordMode::SniMid)
            };
            SocketActionSpec {
                passthrough: false,
                tls_record,
                tcp_splits: raw.tcp_splits.clone(),
                paced_flush: true,
                tcp_oob: false,
                http_split_host: raw.http_split_host,
                http_host_case: raw.http_host_case,
            }
        })
    }

    /// Evaluates active QUIC policy from the loaded package, if specified.
    pub fn select_quic_mode(&self, dst_port: u16) -> Option<QuicMode> {
        if !self.is_active() {
            return None;
        }
        let guard = self.loaded.read().ok()?;
        let entry = guard.as_ref()?;
        entry
            .pkg
            .spec
            .rules
            .iter()
            .filter(|r| r.matcher.protocols.contains(&MatchProtocol::Quic))
            .filter(|r| r.matcher.ports.is_empty() || r.matcher.ports.contains(&dst_port))
            .max_by_key(|r| r.priority)
            .and_then(|r| r.quic_mode)
    }

    /// Evaluates UDP real-time desync policy from the loaded package, if specified.
    pub fn select_udp_desync(&self, proto: MatchProtocol, dst_port: u16) -> Option<(u8, bool)> {
        if !self.is_active() {
            return None;
        }
        let guard = self.loaded.read().ok()?;
        let entry = guard.as_ref()?;
        let rule = pick_matching_rule(&entry.pkg.spec.rules, proto, dst_port, None, 64, false, 0)?;
        rule.udp_desync_ttl.map(|t| (t, rule.udp_bad_checksum_decoy))
    }

    /// Records a handshake outcome on a Forge-handled flow and triggers atomic rollback
    /// to SafeBaseline if the loaded strategy fails beyond verified thresholds.
    ///
    /// Returns `true` if the circuit breaker just tripped & disabled the Forge package.
    pub fn report_flow_outcome(&self, dst: SocketAddr, sni: Option<&str>, success: bool) -> bool {
        if !self.is_active() {
            return false;
        }
        let Ok(guard) = self.loaded.read() else {
            return false;
        };
        let Some(entry) = guard.as_ref() else {
            return false;
        };
        let policy = entry.pkg.spec.rollback;
        let Ok(mut c) = entry.circuit.lock() else {
            return false;
        };
        if c.disabled {
            return false;
        }

        c.total_samples = c.total_samples.saturating_add(1);
        if success {
            c.consecutive_failures = 0;
            return false;
        }

        c.consecutive_failures = c.consecutive_failures.saturating_add(1);
        c.failed_samples = c.failed_samples.saturating_add(1);
        if c.distinct_failed_hashes.len() < 32 {
            let h = c.hash_target(dst, sni);
            c.distinct_failed_hashes.insert(h);
        }

        let fail_pct = c
            .failed_samples
            .saturating_mul(100)
            .checked_div(c.total_samples)
            .unwrap_or(0);

        // Trip if failures hit >= max_consecutive across >=2 targets (or 2x single target to ignore isolated IP blackholes),
        // OR if failure ratio >= max_failure_pct after min_samples.
        let consec_tripped = c.consecutive_failures >= policy.max_consecutive_failures
            && (c.distinct_failed_hashes.len() >= 2
                || c.consecutive_failures >= policy.max_consecutive_failures.saturating_mul(2));
        let pct_tripped = c.total_samples >= policy.min_samples as u32
            && fail_pct >= policy.max_failure_pct as u32;

        if consec_tripped || pct_tripped {
            let reason = format!(
                "Otomatik devre dışı bırakıldı ve güvenli temel stratejiye dönüldü (ardışık hata: {}, toplam hata: {}/{}, farklı hedef: {})",
                c.consecutive_failures,
                c.failed_samples,
                c.total_samples,
                c.distinct_failed_hashes.len()
            );
            c.disabled = true;
            c.disabled_reason = Some(reason);
            self.active_fast_flag.store(false, Ordering::Release);
            return true;
        }

        false
    }
}

fn pick_matching_rule<'a>(
    rules: &'a [StrategyRule],
    proto: MatchProtocol,
    dst_port: u16,
    sni: Option<&str>,
    payload_len: usize,
    _is_sensitive: bool,
    retry_count: u8,
) -> Option<&'a StrategyRule> {
    rules
        .iter()
        .filter(|r| r.when_on_retry <= retry_count)
        .filter(|r| {
            r.matcher.protocols.contains(&MatchProtocol::Any) || r.matcher.protocols.contains(&proto)
        })
        .filter(|r| r.matcher.ports.is_empty() || r.matcher.ports.contains(&dst_port))
        .filter(|r| payload_len >= r.matcher.min_payload as usize)
        .filter(|r| {
            if r.matcher.sni_suffixes.is_empty() {
                return true;
            }
            let Some(host) = sni.map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase()) else {
                return false;
            };
            r.matcher.sni_suffixes.iter().any(|suf| {
                let s = suf.trim().trim_start_matches('.').to_ascii_lowercase();
                host == s || host.ends_with(&format!(".{s}"))
            })
        })
        .max_by_key(|r| (r.when_on_retry, r.priority))
}
