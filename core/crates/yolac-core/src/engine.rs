//! Unified TULPAR engine orchestrator (Windows & Android).

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use yolac_blocklist::Blocklist;
use yolac_dns::{default_public_upstreams, DnsConfig, DnsEngine};
use yolac_dpi::{DpiStrategy, PlatformCapabilities, QuicPolicy};
use yolac_net::{
    probe_ipv6_leak_mode, CaptivePortalMonitor, Ipv6LeakMode, MemoryProfile, NoopProtector,
    PacketDevice, ProtectedDialer, SocketProtector, TunConfig, TunEngine,
};

use crate::adaptive::AdaptiveController;
use crate::diagnostics::DiagnosticReport;
use crate::health::{HealthMonitor, ModuleHealthReport};
use crate::state::{EngineState, EphemeralMetrics, ErrorCode};
use crate::updater::{check_github_release_with_protector, UpdateCheckResult};

#[derive(Debug, Clone)]
pub struct YolacConfig {
    pub profile: MemoryProfile,
    pub capabilities: PlatformCapabilities,
    pub initial_strategy: DpiStrategy,
    pub ipv6_mode: Ipv6LeakMode,
    pub quic_policy: QuicPolicy,
    pub mtu: usize,
}

impl YolacConfig {
    pub fn mobile_android() -> Self {
        Self {
            profile: MemoryProfile::Standard,
            capabilities: PlatformCapabilities::MOBILE_SANDBOX,
            initial_strategy: DpiStrategy::TlsMultiRecordAndTcpSplit,
            ipv6_mode: Ipv6LeakMode::DualStackProtected,
            quic_policy: QuicPolicy::BlockFallbackToTcp,
            mtu: 1500,
        }
    }

    pub fn mobile_ios() -> Self {
        Self {
            profile: MemoryProfile::LowMemoryIos,
            capabilities: PlatformCapabilities::MOBILE_SANDBOX,
            initial_strategy: DpiStrategy::TlsMultiRecordAndTcpSplit,
            ipv6_mode: Ipv6LeakMode::DualStackProtected,
            quic_policy: QuicPolicy::BlockFallbackToTcp,
            mtu: 1500,
        }
    }

    pub fn windows_desktop() -> Self {
        Self {
            profile: MemoryProfile::Standard,
            capabilities: PlatformCapabilities::WINDOWS_WINDIVERT,
            initial_strategy: DpiStrategy::TurkeyDesyncAuto,
            ipv6_mode: Ipv6LeakMode::DualStackProtected,
            quic_policy: QuicPolicy::BlockFallbackToTcp,
            mtu: 1500,
        }
    }

    pub fn linux_desktop() -> Self {
        Self {
            profile: MemoryProfile::Standard,
            capabilities: PlatformCapabilities::LINUX_NFQUEUE,
            initial_strategy: DpiStrategy::TurkeyDesyncAuto,
            ipv6_mode: Ipv6LeakMode::DualStackProtected,
            quic_policy: QuicPolicy::BlockFallbackToTcp,
            mtu: 1500,
        }
    }
}

struct RunningTask {
    shutdown_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

pub struct YolacEngine {
    config: YolacConfig,
    blocklist: Arc<Blocklist>,
    dns: Arc<DnsEngine>,
    adaptive: Arc<AdaptiveController>,
    captive_portal: Arc<CaptivePortalMonitor>,
    block_ipv6_dynamic: Arc<AtomicBool>,
    probe_gen: Arc<AtomicU64>,
    protector: Arc<dyn SocketProtector>,
    metrics: Arc<EphemeralMetrics>,
    health: Arc<HealthMonitor>,
    state_tx: watch::Sender<EngineState>,
    _state_rx: watch::Receiver<EngineState>,
    running: Mutex<Option<RunningTask>>,
}

impl YolacEngine {
    pub fn new(config: YolacConfig, protector: Option<Arc<dyn SocketProtector>>) -> Self {
        let protector: Arc<dyn SocketProtector> =
            protector.unwrap_or_else(|| Arc::new(NoopProtector));
        let blocklist = Arc::new(Blocklist::embedded_default());

        let cache_max = match config.profile {
            MemoryProfile::Standard => 8192,
            MemoryProfile::LowMemoryIos => 1024,
        };
        let suppress_aaaa = config.ipv6_mode == Ipv6LeakMode::BlockUnprotectedIpv6;
        let dns_cfg = DnsConfig {
            upstreams: default_public_upstreams(),
            cache_max_entries: cache_max,
            upstream_timeout: Duration::from_millis(2500),
            block_with_nxdomain: false,
            suppress_aaaa,
        };
        let dialer = Arc::new(ProtectedDialer::new(Arc::clone(&protector)));
        let dns = Arc::new(DnsEngine::new(dns_cfg, Arc::clone(&blocklist), Some(dialer)));

        let strategy_cap = match config.profile {
            MemoryProfile::Standard => 1024,
            MemoryProfile::LowMemoryIos => 256,
        };
        let adaptive = Arc::new(AdaptiveController::with_quic_policy(
            config.capabilities,
            config.initial_strategy,
            strategy_cap,
            config.quic_policy,
        ));

        let (state_tx, state_rx) = watch::channel(EngineState::Inactive);

        Self {
            config,
            blocklist,
            dns,
            adaptive,
            captive_portal: Arc::new(CaptivePortalMonitor::new()),
            block_ipv6_dynamic: Arc::new(AtomicBool::new(suppress_aaaa)),
            probe_gen: Arc::new(AtomicU64::new(0)),
            protector,
            metrics: Arc::new(EphemeralMetrics::default()),
            health: Arc::new(HealthMonitor::new()),
            state_tx,
            _state_rx: state_rx,
            running: Mutex::new(None),
        }
    }

    pub fn state(&self) -> EngineState {
        *self.state_tx.borrow()
    }

    pub fn subscribe_state(&self) -> watch::Receiver<EngineState> {
        self.state_tx.subscribe()
    }

    pub fn dns_engine(&self) -> &Arc<DnsEngine> {
        &self.dns
    }

    pub fn adaptive(&self) -> &Arc<AdaptiveController> {
        &self.adaptive
    }

    pub fn captive_portal(&self) -> &Arc<CaptivePortalMonitor> {
        &self.captive_portal
    }

    pub fn blocklist(&self) -> &Arc<Blocklist> {
        &self.blocklist
    }

    pub fn metrics(&self) -> &Arc<EphemeralMetrics> {
        &self.metrics
    }

    pub fn health_monitor(&self) -> &Arc<HealthMonitor> {
        &self.health
    }

    pub fn set_state(&self, new_state: EngineState) {
        if let EngineState::Error(code) = new_state {
            self.health.record_platform_error(Some(code));
        } else if matches!(new_state, EngineState::Active | EngineState::Activating) {
            self.health.record_platform_error(None);
        }
        self.state_tx.send_replace(new_state);
    }

    pub fn record_platform_error(&self, code: ErrorCode) {
        self.health.record_platform_error(Some(code));
        self.state_tx.send_replace(EngineState::Error(code));
    }

    pub fn record_platform_error_with_detail(&self, code: ErrorCode, detail: impl Into<String>) {
        self.health
            .record_platform_error_with_detail(Some(code), Some(detail.into()));
        self.state_tx.send_replace(EngineState::Error(code));
    }

    pub fn clear_platform_error(&self) {
        self.health.record_platform_error(None);
    }

    pub fn set_dynamic_ipv6_block(&self, block: bool) {
        self.block_ipv6_dynamic.store(block, Ordering::Relaxed);
        self.dns.set_suppress_aaaa(block);
    }

    /// Evaluates and returns real health reports for all 7 TULPAR modules.
    pub fn health_snapshot(&self) -> [ModuleHealthReport; 7] {
        self.health.evaluate_all(
            self.state(),
            self.config.capabilities,
            &self.blocklist,
            &self.dns,
            &self.captive_portal,
        )
    }

    /// User-triggered manual GitHub Releases update check (never runs automatically in background).
    pub async fn check_updates_manual(&self, repo_override: Option<&str>) -> UpdateCheckResult {
        let res =
            check_github_release_with_protector(repo_override, Some(self.protector.as_ref())).await;
        self.health.record_update_result(&res);
        res
    }

    /// Runs live zero-telemetry Swiss-Army-Knife diagnostics: benchmarks all 5+ encrypted DNS
    /// upstreams concurrently (promoting the fastest one), tests real IPv6 reachability,
    /// and compiles live ad-blocking & cache hit-rate stats.
    pub async fn run_live_diagnostics(&self) -> DiagnosticReport {
        let forced_v4_only = self.block_ipv6_dynamic.load(Ordering::Relaxed)
            || self.config.ipv6_mode == Ipv6LeakMode::BlockUnprotectedIpv6;
        let (benchmarks, ipv6_mode) = tokio::join!(
            self.dns.benchmark_all_upstreams(),
            probe_ipv6_leak_mode(self.protector.as_ref(), None, Duration::from_millis(600))
        );
        let ipv6_ok = !forced_v4_only && ipv6_mode == Ipv6LeakMode::DualStackProtected;
        if self.config.ipv6_mode == Ipv6LeakMode::DualStackProtected && !ipv6_ok {
            self.block_ipv6_dynamic.store(true, Ordering::Relaxed);
            self.dns.set_suppress_aaaa(true);
        }
        let stats = self.dns.stats_snapshot();
        DiagnosticReport::build(
            benchmarks,
            ipv6_ok,
            stats.blocked_queries,
            stats.total_queries,
            stats.cache_hits,
        )
    }

    /// Handles Wi-Fi <-> Cellular or sleep-wake transitions cleanly:
    /// clears stale DPI tables & dead keep-alive DNS sockets, re-probes fastest DNS + IPv6.
    pub fn notify_network_change(&self) {
        self.adaptive.on_network_change();
        self.captive_portal.reset();
        let gen = self.probe_gen.fetch_add(1, Ordering::SeqCst) + 1;

        if let Ok(rt_handle) = tokio::runtime::Handle::try_current() {
            let dns = Arc::clone(&self.dns);
            let protector = Arc::clone(&self.protector);
            let block_v6 = Arc::clone(&self.block_ipv6_dynamic);
            let probe_gen = Arc::clone(&self.probe_gen);
            let dual_stack = self.config.ipv6_mode == Ipv6LeakMode::DualStackProtected;

            rt_handle.spawn(async move {
                dns.on_network_change().await;
                if probe_gen.load(Ordering::SeqCst) != gen {
                    return;
                }
                let dns_probe = dns.probe_fastest_upstream();
                if dual_stack {
                    let v6_probe =
                        probe_ipv6_leak_mode(protector.as_ref(), None, Duration::from_millis(600));
                    let (_, mode) = tokio::join!(dns_probe, v6_probe);
                    if probe_gen.load(Ordering::SeqCst) == gen {
                        let should_block = mode == Ipv6LeakMode::BlockUnprotectedIpv6;
                        block_v6.store(should_block, Ordering::Relaxed);
                        dns.set_suppress_aaaa(should_block);
                    }
                } else {
                    let _ = dns_probe.await;
                }
            });
        } else {
            self.dns.reset_preferred_upstream();
        }
    }

    /// Starts the userspace TUN packet engine on the given `PacketDevice`.
    pub async fn start_tun<D: PacketDevice + 'static>(&self, device: Arc<D>) -> io::Result<()> {
        let mut running_guard = self.running.lock().await;
        if let Some(prev) = running_guard.as_ref() {
            if !prev.handle.is_finished() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "TULPAR engine is already running",
                ));
            }
            // Reap finished handle cleanly so engine never gets permanently locked out
            running_guard.take();
        }

        self.set_state(EngineState::Activating);
        let gen = self.probe_gen.fetch_add(1, Ordering::SeqCst) + 1;

        let tun_cfg = TunConfig {
            mtu: self.config.mtu,
            profile: self.config.profile,
            ipv6_mode: self.config.ipv6_mode,
            quic_policy: self.config.quic_policy,
        };
        let tun = TunEngine::with_runtime_controls(
            tun_cfg,
            Arc::clone(&self.dns),
            Arc::clone(&self.protector),
            Arc::clone(&self.adaptive) as Arc<dyn yolac_net::StrategyAdvisor>,
            Arc::clone(&self.captive_portal),
            Arc::clone(&self.block_ipv6_dynamic),
        );

        // Background startup acceleration:
        // 1. Race all encrypted DNS upstreams and warm-pool the fastest responder for this ISP
        // 2. If DualStackProtected, run concurrent 600ms IPv6 probe with generation counter
        {
            let protector = Arc::clone(&self.protector);
            let dns = Arc::clone(&self.dns);
            let block_v6 = Arc::clone(&self.block_ipv6_dynamic);
            let probe_gen = Arc::clone(&self.probe_gen);
            let dual_stack = self.config.ipv6_mode == Ipv6LeakMode::DualStackProtected;
            tokio::spawn(async move {
                let dns_probe = dns.probe_fastest_upstream();
                if dual_stack {
                    let v6_probe =
                        probe_ipv6_leak_mode(protector.as_ref(), None, Duration::from_millis(600));
                    let (_, mode) = tokio::join!(dns_probe, v6_probe);
                    if probe_gen.load(Ordering::SeqCst) == gen {
                        let should_block = mode == Ipv6LeakMode::BlockUnprotectedIpv6;
                        block_v6.store(should_block, Ordering::Relaxed);
                        dns.set_suppress_aaaa(should_block);
                    }
                } else {
                    let _ = dns_probe.await;
                }
            });
        }

        let (shut_tx, shut_rx) = watch::channel(false);
        let state_tx = self.state_tx.clone();
        state_tx.send_replace(EngineState::Active);
        let handle = tokio::spawn(async move {
            if let Err(_e) = tun.run(device, shut_rx).await {
                state_tx.send_replace(EngineState::Error(ErrorCode::InternalError));
            } else {
                state_tx.send_replace(EngineState::Inactive);
            }
        });
        *running_guard = Some(RunningTask {
            shutdown_tx: shut_tx,
            handle,
        });
        Ok(())
    }

    /// Gracefully stops the engine and wipes all ephemeral DNS/strategy caches from RAM.
    pub async fn stop(&self) {
        self.probe_gen.fetch_add(1, Ordering::SeqCst);

        let running_task = {
            let mut guard = self.running.lock().await;
            guard.take()
        };

        if let Some(task) = running_task {
            self.set_state(EngineState::Deactivating);
            let _ = task.shutdown_tx.send(true);
            let _ = task.handle.await;
        }

        self.dns.clear_ephemeral_state().await;
        let default_suppress = self.config.ipv6_mode == Ipv6LeakMode::BlockUnprotectedIpv6;
        self.block_ipv6_dynamic
            .store(default_suppress, Ordering::Relaxed);
        self.dns.set_suppress_aaaa(default_suppress);
        self.adaptive.clear();
        self.captive_portal.reset();
        self.metrics.reset();
        self.health.record_platform_error(None);
        self.set_state(EngineState::Inactive);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ios_profile_respects_memory_bounds_and_clean_lifecycle() {
        let engine = YolacEngine::new(YolacConfig::mobile_ios(), None);
        assert_eq!(engine.state(), EngineState::Inactive);
        assert!(engine.blocklist().memory_bytes() < 512 * 1024);
        engine.stop().await;
        assert_eq!(engine.state(), EngineState::Inactive);
    }

    #[test]
    fn captive_portal_status_reflects_in_connection_security_module_and_brand_strings() {
        use crate::health::{ModuleHealthStatus, ModuleId};
        use crate::updater::{APP_VERSION, SECURITY_WARNING_TR};

        assert_eq!(APP_VERSION, "0.4.0");
        assert!(SECURITY_WARNING_TR.contains("TULPAR'ı"));

        let engine = YolacEngine::new(YolacConfig::mobile_android(), None);
        engine.set_state(EngineState::Active);

        // Normal mode -> ConnectionSecurity is Green (Healthy)
        let normal = engine.health_snapshot();
        assert_eq!(
            normal[ModuleId::ConnectionSecurity as usize].status,
            ModuleHealthStatus::Healthy
        );

        // Trigger Captive Portal temporary allowance -> ConnectionSecurity reports Turkish portal notice
        engine.captive_portal().trigger_portal_bypass();
        let portal = engine.health_snapshot();
        let cs = &portal[ModuleId::ConnectionSecurity as usize];
        assert_eq!(cs.status, ModuleHealthStatus::PassiveOrUnchecked);
        assert!(cs.detail_tr.contains("Captive Portal"));

        // DNS recovery -> immediately back to Green (Healthy)
        engine.captive_portal().on_dns_upstream_success();
        let recovered = engine.health_snapshot();
        assert_eq!(
            recovered[ModuleId::ConnectionSecurity as usize].status,
            ModuleHealthStatus::Healthy
        );
    }
}
