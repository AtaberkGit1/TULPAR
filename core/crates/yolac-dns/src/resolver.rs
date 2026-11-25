//! Unified TULPAR Encrypted DNS Engine:
//! - Local blocklist + CNAME/HTTPS uncloaking (<5 µs)
//! - Bounded O(1) RAM LRU + Stale-While-Revalidate (RFC 8767) + negative caching (<0.1 ms hits)
//! - Singleflight in-flight query coalescing
//! - Auto-fastest encrypted upstream selection + 250 ms Hedged DNS failover + poisoning protection

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use rustls::ClientConfig;
use tokio::sync::Notify;
use yolac_blocklist::Blocklist;

use crate::cache::{CacheLookup, DnsCache};
use crate::poison::{detect_poisoning, detect_poisoning_tls, PoisonReason};
use crate::pool::UpstreamPool;
use crate::upstream::{
    connect_upstream_tls, default_dot_rustls_config, default_public_upstreams,
    default_rustls_config, exchange_on_tls_stream, DefaultUpstreamDialer, UpstreamConfig,
    UpstreamDialer, UpstreamProtocol,
};
use crate::wire::{
    build_blocked_response, build_dns_query, build_empty_noerror_response, parse_dns_query,
    parse_dns_response, DnsQuery, DnsRecordData, DnsResponse, QType,
};

/// Hedged DNS backup trigger: if preferred upstream hasn't answered within 250 ms, race #2 concurrently.
const HEDGE_DELAY: Duration = Duration::from_millis(250);
/// Shorter read timeout for reused pooled sockets so dead NAT-aged TLS connections fail fast.
const POOLED_TIMEOUT: Duration = Duration::from_millis(650);

#[derive(Clone)]
pub struct DnsConfig {
    pub upstreams: Vec<UpstreamConfig>,
    pub cache_max_entries: usize,
    pub upstream_timeout: Duration,
    /// Return NXDOMAIN instead of `0.0.0.0`/`::` for blocked queries.
    pub block_with_nxdomain: bool,
    /// Suppress AAAA queries when IPv6 leak guard is set to block unprotected IPv6.
    pub suppress_aaaa: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstreams: default_public_upstreams(),
            cache_max_entries: 4096,
            upstream_timeout: Duration::from_millis(2500),
            block_with_nxdomain: false,
            suppress_aaaa: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOutcome {
    BlockedDomain,
    BlockedCnameUncloak,
    SuppressedIpv6,
    CacheHit,
    UpstreamResolved,
    Failed,
}

#[derive(Debug, Clone)]
pub struct UpstreamBenchmark {
    pub index: usize,
    pub name: &'static str,
    pub endpoint: String,
    pub rtt_ms: Option<u64>,
    pub ok: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DnsStatsSnapshot {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub cache_hits: u64,
    pub poisoning_failovers: u64,
    pub failed_queries: u64,
    pub ech_records_served: u64,
    pub upstream_count: usize,
    pub active_upstream_name: &'static str,
    pub active_upstream_rtt_ms: u64,
}

type InflightKey = (String, QType);

pub struct DnsEngine {
    config: DnsConfig,
    blocklist: Arc<Blocklist>,
    cache: StdMutex<DnsCache>,
    inflight: StdMutex<HashMap<InflightKey, Arc<Notify>>>,
    pool: UpstreamPool,
    dialer: Arc<dyn UpstreamDialer>,
    doh_tls: Arc<ClientConfig>,
    dot_tls: Arc<ClientConfig>,
    preferred_upstream: AtomicUsize,
    active_upstream_rtt_ms: AtomicU64,
    suppress_aaaa: AtomicBool,
    total_queries: AtomicU64,
    blocked_queries: AtomicU64,
    cache_hits: AtomicU64,
    poisoning_failovers: AtomicU64,
    failed_queries: AtomicU64,
    ech_records_served: AtomicU64,
    consecutive_failures: AtomicU64,
}

impl DnsEngine {
    pub fn new(
        config: DnsConfig,
        blocklist: Arc<Blocklist>,
        dialer: Option<Arc<dyn UpstreamDialer>>,
    ) -> Self {
        let cache_cap = config.cache_max_entries;
        let suppress = config.suppress_aaaa;
        Self {
            config,
            blocklist,
            cache: StdMutex::new(DnsCache::new(cache_cap)),
            inflight: StdMutex::new(HashMap::new()),
            pool: UpstreamPool::new(),
            dialer: dialer.unwrap_or_else(|| Arc::new(DefaultUpstreamDialer)),
            doh_tls: default_rustls_config(),
            dot_tls: default_dot_rustls_config(),
            preferred_upstream: AtomicUsize::new(0),
            active_upstream_rtt_ms: AtomicU64::new(0),
            suppress_aaaa: AtomicBool::new(suppress),
            total_queries: AtomicU64::new(0),
            blocked_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            poisoning_failovers: AtomicU64::new(0),
            failed_queries: AtomicU64::new(0),
            ech_records_served: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
        }
    }

    fn tls_for(&self, upstream: &UpstreamConfig) -> &Arc<ClientConfig> {
        match upstream.protocol {
            UpstreamProtocol::DoH => &self.doh_tls,
            UpstreamProtocol::DoT => &self.dot_tls,
        }
    }

    /// Ultra-fast (<50 µs), zero-async local resolution path for Windows WinDivert fast-path:
    /// resolves AAAA suppression, local blocklist hits, and fresh RAM cache hits synchronously
    /// without consuming Tokio semaphore permits or spawning tasks!
    /// Returns `None` if an encrypted upstream lookup (or SWR refresh) is required.
    pub fn try_resolve_local(&self, query_wire: &[u8]) -> Option<(Option<Vec<u8>>, DnsOutcome)> {
        let query = parse_dns_query(query_wire)?;

        if self.suppress_aaaa.load(Ordering::Relaxed) && query.qtype == QType::AAAA {
            self.total_queries.fetch_add(1, Ordering::Relaxed);
            return Some((
                build_empty_noerror_response(query_wire),
                DnsOutcome::SuppressedIpv6,
            ));
        }

        if self.blocklist.is_blocked(&query.qname) {
            self.total_queries.fetch_add(1, Ordering::Relaxed);
            self.blocked_queries.fetch_add(1, Ordering::Relaxed);
            return Some((
                build_blocked_response(query_wire, self.config.block_with_nxdomain),
                DnsOutcome::BlockedDomain,
            ));
        }

        if let Ok(mut cache) = self.cache.try_lock() {
            match cache.lookup(&query.qname, query.qtype, query.id) {
                CacheLookup::Fresh(cached) => {
                    self.total_queries.fetch_add(1, Ordering::Relaxed);
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Some((Some(cached), DnsOutcome::CacheHit));
                }
                CacheLookup::StaleNeedsRefresh(_) => {
                    // Undo the `refreshing` flag so async `resolve_with_swr` spawns background refresh!
                    cache.clear_refreshing(&query.qname, query.qtype);
                }
                CacheLookup::Miss => {}
            }
        }

        None
    }

    /// Full resolution with RFC 8767 background Stale-While-Revalidate (SWR) when called on `&Arc<DnsEngine>`.
    pub async fn resolve_with_swr(self: &Arc<Self>, query_wire: &[u8]) -> (Option<Vec<u8>>, DnsOutcome) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);

        let query = match parse_dns_query(query_wire) {
            Some(q) => q,
            None => {
                self.failed_queries.fetch_add(1, Ordering::Relaxed);
                return (None, DnsOutcome::Failed);
            }
        };

        if self.suppress_aaaa.load(Ordering::Relaxed) && query.qtype == QType::AAAA {
            return (
                build_empty_noerror_response(query_wire),
                DnsOutcome::SuppressedIpv6,
            );
        }

        if self.blocklist.is_blocked(&query.qname) {
            self.blocked_queries.fetch_add(1, Ordering::Relaxed);
            return (
                build_blocked_response(query_wire, self.config.block_with_nxdomain),
                DnsOutcome::BlockedDomain,
            );
        }

        let cache_lookup = self
            .cache
            .lock()
            .map(|mut c| c.lookup(&query.qname, query.qtype, query.id))
            .unwrap_or(CacheLookup::Miss);
        match cache_lookup {
            CacheLookup::Fresh(cached) => {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return (Some(cached), DnsOutcome::CacheHit);
            }
            CacheLookup::StaleNeedsRefresh(stale_pkt) => {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                let this = Arc::clone(self);
                let bg_query = query_wire.to_vec();
                let qname = query.qname.clone();
                let qtype = query.qtype;
                if let Ok(rt) = tokio::runtime::Handle::try_current() {
                    rt.spawn(async move {
                        let (_, outcome) = this.resolve_upstream_only(&bg_query, &query).await;
                        if outcome != DnsOutcome::UpstreamResolved {
                            if let Ok(mut c) = this.cache.lock() {
                                c.clear_refreshing(&qname, qtype);
                            }
                        }
                    });
                } else if let Ok(mut c) = self.cache.lock() {
                    c.clear_refreshing(&qname, qtype);
                }
                return (Some(stale_pkt), DnsOutcome::CacheHit);
            }
            CacheLookup::Miss => {}
        }

        self.resolve_singleflight(query_wire, &query).await
    }

    pub async fn resolve(&self, query_wire: &[u8]) -> (Option<Vec<u8>>, DnsOutcome) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);

        let query = match parse_dns_query(query_wire) {
            Some(q) => q,
            None => {
                self.failed_queries.fetch_add(1, Ordering::Relaxed);
                return (None, DnsOutcome::Failed);
            }
        };

        // 1. IPv6 leak guard AAAA suppression (dynamic runtime flag)
        if self.suppress_aaaa.load(Ordering::Relaxed) && query.qtype == QType::AAAA {
            return (
                build_empty_noerror_response(query_wire),
                DnsOutcome::SuppressedIpv6,
            );
        }

        // 2. Local ad/tracker/malware blocklist (zero network traffic)
        if self.blocklist.is_blocked(&query.qname) {
            self.blocked_queries.fetch_add(1, Ordering::Relaxed);
            return (
                build_blocked_response(query_wire, self.config.block_with_nxdomain),
                DnsOutcome::BlockedDomain,
            );
        }

        // 3. RAM-only O(1) LRU cache
        let cache_lookup = self
            .cache
            .lock()
            .map(|mut c| c.lookup(&query.qname, query.qtype, query.id))
            .unwrap_or(CacheLookup::Miss);
        match cache_lookup {
            CacheLookup::Fresh(cached) => {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return (Some(cached), DnsOutcome::CacheHit);
            }
            CacheLookup::StaleNeedsRefresh(stale_pkt) => {
                if let Ok(mut c) = self.cache.lock() {
                    c.clear_refreshing(&query.qname, query.qtype);
                }
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return (Some(stale_pkt), DnsOutcome::CacheHit);
            }
            CacheLookup::Miss => {}
        }

        self.resolve_singleflight(query_wire, &query).await
    }

    async fn resolve_singleflight(
        &self,
        query_wire: &[u8],
        query: &DnsQuery,
    ) -> (Option<Vec<u8>>, DnsOutcome) {
        struct InflightGuard<'a> {
            inflight: &'a std::sync::Mutex<HashMap<(String, QType), Arc<Notify>>>,
            key: Option<(String, QType)>,
        }
        impl Drop for InflightGuard<'_> {
            fn drop(&mut self) {
                if let Some(key) = self.key.take() {
                    if let Ok(mut guard) = self.inflight.lock() {
                        if let Some(notify) = guard.remove(&key) {
                            notify.notify_waiters();
                        }
                    }
                }
            }
        }

        let sf_key = (query.qname.clone(), query.qtype);
        let existing_fut = {
            let mut guard = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = guard.get(&sf_key) {
                let n = Arc::clone(n);
                // Register waiter BEFORE releasing the lock so we never miss `notify_waiters()`!
                Some(async move {
                    n.notified().await;
                })
            } else {
                guard.insert(sf_key.clone(), Arc::new(Notify::new()));
                None
            }
        };

        if let Some(wait_fut) = existing_fut {
            let _ = tokio::time::timeout(self.config.upstream_timeout, wait_fut).await;
            if let Ok(mut cache) = self.cache.lock() {
                if let CacheLookup::Fresh(cached) = cache.lookup(&query.qname, query.qtype, query.id) {
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return (Some(cached), DnsOutcome::CacheHit);
                }
            }
            // Leader failed or returned uncacheable response -> proceed independently
            return self.resolve_upstream_only(query_wire, query).await;
        }

        let _inflight_guard = InflightGuard {
            inflight: &self.inflight,
            key: Some(sf_key),
        };
        self.resolve_upstream_only(query_wire, query).await
    }

    async fn resolve_upstream_only(
        &self,
        query_wire: &[u8],
        query: &DnsQuery,
    ) -> (Option<Vec<u8>>, DnsOutcome) {
        let count = self.config.upstreams.len();
        if count == 0 {
            self.failed_queries.fetch_add(1, Ordering::Relaxed);
            self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
            return (None, DnsOutcome::Failed);
        }

        let start = self.preferred_upstream.load(Ordering::Relaxed) % count;

        // Track first private/loopback TLS reply so if a SECOND independent TLS upstream agrees
        // (e.g. `*.plex.direct` or `*.nip.io`), we accept it instead of failing all 6 upstreams!
        let mut first_private_candidate: Option<(usize, Vec<u8>, DnsResponse)> = None;

        // Hedged fast-path when >= 2 upstreams exist: fire preferred upstream #0, and if no valid
        // answer arrives in HEDGE_DELAY (250 ms), race upstream #1 concurrently!
        let mut skipped_second = false;
        if count >= 2 {
            let idx0 = start;
            let idx1 = (start + 1) % count;
            let up0 = &self.config.upstreams[idx0];
            let up1 = &self.config.upstreams[idx1];

            let t0 = Instant::now();
            let fut0 = self.query_with_pool(idx0, up0, query_wire);
            tokio::pin!(fut0);

            match tokio::time::timeout(HEDGE_DELAY, &mut fut0).await {
                Ok(Ok(resp_wire)) => {
                    if let Some(done) = self.evaluate_upstream_reply(
                        idx0,
                        t0.elapsed(),
                        query,
                        query_wire,
                        resp_wire,
                        &mut first_private_candidate,
                    ) {
                        return done;
                    }
                }
                Ok(Err(_)) => {
                    // Immediate error on primary -> fall straight into backup loop starting at idx1
                }
                Err(_) => {
                    // Primary exceeded 250ms -> hedge concurrently against secondary upstream!
                    skipped_second = true;
                    let t1 = Instant::now();
                    let fut1 = self.query_with_pool(idx1, up1, query_wire);
                    tokio::pin!(fut1);

                    let mut done0 = false;
                    let mut done1 = false;
                    while !done0 || !done1 {
                        tokio::select! {
                            res0 = &mut fut0, if !done0 => {
                                done0 = true;
                                if let Ok(resp_wire) = res0 {
                                    if let Some(done) = self.evaluate_upstream_reply(
                                        idx0, t0.elapsed(), query, query_wire, resp_wire, &mut first_private_candidate,
                                    ) {
                                        return done;
                                    }
                                }
                            }
                            res1 = &mut fut1, if !done1 => {
                                done1 = true;
                                if let Ok(resp_wire) = res1 {
                                    if let Some(done) = self.evaluate_upstream_reply(
                                        idx1, t1.elapsed(), query, query_wire, resp_wire, &mut first_private_candidate,
                                    ) {
                                        return done;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Sequential fallback over remaining upstreams
        let first_offset = if count == 1 {
            0
        } else if skipped_second {
            2
        } else {
            1
        };
        for offset in first_offset..count {
            let idx = (start + offset) % count;
            let upstream = &self.config.upstreams[idx];
            let started = Instant::now();
            let Ok(resp_wire) = self.query_with_pool(idx, upstream, query_wire).await else {
                continue;
            };
            if let Some(done) = self.evaluate_upstream_reply(
                idx,
                started.elapsed(),
                query,
                query_wire,
                resp_wire,
                &mut first_private_candidate,
            ) {
                return done;
            }
        }

        self.failed_queries.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        (None, DnsOutcome::Failed)
    }

    fn evaluate_upstream_reply(
        &self,
        idx: usize,
        elapsed: Duration,
        query: &DnsQuery,
        query_wire: &[u8],
        resp_wire: Vec<u8>,
        first_private_candidate: &mut Option<(usize, Vec<u8>, DnsResponse)>,
    ) -> Option<(Option<Vec<u8>>, DnsOutcome)> {
        let parsed_resp = parse_dns_response(&resp_wire)?;

        // Fail over immediately on SERVFAIL (2), FORMERR (1), REFUSED (5), etc.
        if parsed_resp.rcode != 0 && parsed_resp.rcode != 3 {
            return None;
        }

        // Always reject TLS integrity mismatches & known BTK/ISP censorship sinkholes
        if detect_poisoning_tls(query, &parsed_resp).is_some() {
            self.poisoning_failovers.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Check bogon/private answers: reject single-upstream poison, but accept if 2 independent
        // TLS-authenticated upstreams agree (legitimate `*.plex.direct` / `*.nip.io` / split-horizon)
        if let Some(reason) = detect_poisoning(query, &parsed_resp) {
            match reason {
                PoisonReason::PrivateRangeHijack(_) | PoisonReason::LoopbackOrUnspecifiedHijack(_) => {
                    if let Some((prev_idx, _, prev_parsed)) = first_private_candidate.as_ref() {
                        if *prev_idx != idx && prev_parsed.answers == parsed_resp.answers {
                            // 2 independent TLS resolvers agree -> legitimate private DNS record!
                        } else {
                            self.poisoning_failovers.fetch_add(1, Ordering::Relaxed);
                            return None;
                        }
                    } else {
                        *first_private_candidate = Some((idx, resp_wire, parsed_resp));
                        self.poisoning_failovers.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                }
                _ => {
                    self.poisoning_failovers.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }
        }

        // Promote healthy responder & track live RTT
        let prev_pref = self.preferred_upstream.load(Ordering::Relaxed);
        if prev_pref != idx {
            self.preferred_upstream.store(idx, Ordering::Relaxed);
        }
        self.active_upstream_rtt_ms
            .store(elapsed.as_millis().max(1) as u64, Ordering::Relaxed);

        // CNAME & HTTPS TargetName uncloaking: check every target against local blocklist
        let target_blocked = parsed_resp.answers.iter().any(|ans| match &ans.data {
            DnsRecordData::CNAME(target) => self.blocklist.is_blocked(target),
            DnsRecordData::Https { target, .. } if !target.is_empty() => {
                self.blocklist.is_blocked(target)
            }
            _ => false,
        });
        if target_blocked {
            self.blocked_queries.fetch_add(1, Ordering::Relaxed);
            return Some((
                build_blocked_response(query_wire, self.config.block_with_nxdomain),
                DnsOutcome::BlockedCnameUncloak,
            ));
        }

        if parsed_resp
            .answers
            .iter()
            .any(|ans| matches!(ans.data, DnsRecordData::Https { has_ech: true, .. }))
        {
            self.ech_records_served.fetch_add(1, Ordering::Relaxed);
        }

        // Never cache truncated (`TC=1`) DNS replies
        if !parsed_resp.truncated {
            if let Ok(mut cache) = self.cache.lock() {
                if parsed_resp.rcode == 0 && !parsed_resp.answers.is_empty() {
                    cache.insert(
                        &query.qname,
                        query.qtype,
                        resp_wire.clone(),
                        parsed_resp.min_ttl,
                    );
                } else if parsed_resp.rcode == 3
                    || (parsed_resp.rcode == 0 && parsed_resp.answers.is_empty())
                {
                    // Short negative cache (NXDOMAIN / NODATA) cuts redundant AAAA/HTTPS RTTs!
                    cache.insert_negative(
                        &query.qname,
                        query.qtype,
                        resp_wire.clone(),
                        parsed_resp.min_ttl,
                    );
                }
            }
        }

        self.consecutive_failures.store(0, Ordering::Relaxed);
        Some((Some(resp_wire), DnsOutcome::UpstreamResolved))
    }

    pub fn consecutive_failures(&self) -> u64 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    pub fn upstream_count(&self) -> usize {
        self.config.upstreams.len()
    }

    pub fn reset_preferred_upstream(&self) {
        self.preferred_upstream.store(0, Ordering::Relaxed);
    }

    pub fn active_upstream_name(&self) -> &'static str {
        if self.config.upstreams.is_empty() {
            return "Yok";
        }
        let idx = self.preferred_upstream.load(Ordering::Relaxed) % self.config.upstreams.len();
        self.config.upstreams[idx].name
    }

    /// Flushes dead keep-alive TLS sockets & resets upstream preference on Wi-Fi <-> Cellular changes.
    pub async fn on_network_change(&self) {
        self.pool.clear().await;
        self.reset_preferred_upstream();
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    pub fn set_suppress_aaaa(&self, suppress: bool) {
        self.suppress_aaaa.store(suppress, Ordering::Relaxed);
    }

    pub fn is_suppressing_aaaa(&self) -> bool {
        self.suppress_aaaa.load(Ordering::Relaxed)
    }

    /// Probes all configured encrypted upstreams concurrently, promotes the fastest healthy responder
    /// (requiring `NOERROR` + non-empty answers), and keeps the winning warm TLS stream in `pool`!
    pub async fn probe_fastest_upstream(&self) -> Option<usize> {
        if self.config.upstreams.is_empty() {
            return None;
        }
        let probe_wire = build_dns_query(0x594F, "one.one.one.one", QType::A);
        let probe_query = parse_dns_query(&probe_wire)?;

        let mut set = tokio::task::JoinSet::new();
        for (idx, upstream) in self.config.upstreams.iter().cloned().enumerate() {
            let wire = probe_wire.clone();
            let dialer = Arc::clone(&self.dialer);
            let tls = Arc::clone(self.tls_for(&upstream));
            let timeout = self.config.upstream_timeout;
            set.spawn(async move {
                let started = Instant::now();
                let res = tokio::time::timeout(timeout, async {
                    let mut stream = connect_upstream_tls(&upstream, dialer.as_ref(), &tls).await?;
                    let (resp, reusable) = exchange_on_tls_stream(&upstream, &mut stream, &wire).await?;
                    Ok::<_, std::io::Error>((resp, reusable, stream))
                })
                .await
                .ok()?
                .ok()?;
                let rtt_ms = started.elapsed().as_millis().max(1) as u64;
                let parsed = parse_dns_response(&res.0)?;
                Some((idx, parsed, rtt_ms, res.1, res.2))
            });
        }

        while let Some(res) = set.join_next().await {
            if let Ok(Some((idx, parsed, rtt_ms, reusable, stream))) = res {
                if parsed.rcode == 0
                    && !parsed.answers.is_empty()
                    && detect_poisoning(&probe_query, &parsed).is_none()
                {
                    self.preferred_upstream.store(idx, Ordering::Relaxed);
                    self.active_upstream_rtt_ms.store(rtt_ms, Ordering::Relaxed);
                    if reusable {
                        self.pool.put(idx, stream).await;
                    }
                    set.abort_all();
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Concurrently benchmarks every configured encrypted DNS upstream, returning real `ms` latency
    /// for each and automatically selecting the fastest healthy server (Swiss Army Knife diagnostic).
    pub async fn benchmark_all_upstreams(&self) -> Vec<UpstreamBenchmark> {
        if self.config.upstreams.is_empty() {
            return Vec::new();
        }
        let probe_wire = build_dns_query(0x5455, "one.one.one.one", QType::A);
        let Some(probe_query) = parse_dns_query(&probe_wire) else {
            return Vec::new();
        };

        let mut set = tokio::task::JoinSet::new();
        for (idx, upstream) in self.config.upstreams.iter().cloned().enumerate() {
            let wire = probe_wire.clone();
            let pq = probe_query.clone();
            let dialer = Arc::clone(&self.dialer);
            let tls = Arc::clone(self.tls_for(&upstream));
            let timeout = Duration::from_millis(2000);
            let endpoint = format!("{}:{}", upstream.bootstrap_ip, upstream.port);
            let name = upstream.name;
            set.spawn(async move {
                let started = Instant::now();
                let res = tokio::time::timeout(timeout, async {
                    let mut stream = connect_upstream_tls(&upstream, dialer.as_ref(), &tls).await?;
                    let (resp, reusable) = exchange_on_tls_stream(&upstream, &mut stream, &wire).await?;
                    Ok::<_, std::io::Error>((resp, reusable, stream))
                })
                .await;
                let rtt_ms = started.elapsed().as_millis().max(1) as u64;
                if let Ok(Ok((resp, reusable, stream))) = res {
                    if let Some(parsed) = parse_dns_response(&resp) {
                        if parsed.rcode == 0
                            && !parsed.answers.is_empty()
                            && detect_poisoning(&pq, &parsed).is_none()
                        {
                            return (
                                UpstreamBenchmark {
                                    index: idx,
                                    name,
                                    endpoint,
                                    rtt_ms: Some(rtt_ms),
                                    ok: true,
                                },
                                if reusable { Some(stream) } else { None },
                            );
                        }
                    }
                }
                (
                    UpstreamBenchmark {
                        index: idx,
                        name,
                        endpoint,
                        rtt_ms: None,
                        ok: false,
                    },
                    None,
                )
            });
        }

        let mut results = Vec::with_capacity(self.config.upstreams.len());
        while let Some(res) = set.join_next().await {
            if let Ok((bench, stream_opt)) = res {
                if let Some(stream) = stream_opt {
                    self.pool.put(bench.index, stream).await;
                }
                results.push(bench);
            }
        }

        results.sort_by_key(|b| b.rtt_ms.unwrap_or(u64::MAX));
        if let Some(fastest) = results.iter().find(|b| b.ok) {
            self.preferred_upstream.store(fastest.index, Ordering::Relaxed);
            if let Some(ms) = fastest.rtt_ms {
                self.active_upstream_rtt_ms.store(ms, Ordering::Relaxed);
            }
        }
        results
    }

    async fn query_with_pool(
        &self,
        idx: usize,
        upstream: &UpstreamConfig,
        query_wire: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        // 1. Try reusing freshest warm keep-alive TLS stream from LIFO pool (short 650ms timeout)
        if let Some(mut pooled) = self.pool.take(idx).await {
            let pool_wait = self.config.upstream_timeout.min(POOLED_TIMEOUT);
            if let Ok(Ok((resp, reusable))) = tokio::time::timeout(
                pool_wait,
                exchange_on_tls_stream(upstream, &mut pooled, query_wire),
            )
            .await
            {
                if reusable {
                    self.pool.put(idx, pooled).await;
                }
                return Ok(resp);
            }
        }

        // 2. Establish fresh DPI-evasive TLS connection and return it to pool if reusable
        let tls_cfg = self.tls_for(upstream);
        tokio::time::timeout(self.config.upstream_timeout, async {
            let mut tls = connect_upstream_tls(upstream, self.dialer.as_ref(), tls_cfg).await?;
            let (resp, reusable) = exchange_on_tls_stream(upstream, &mut tls, query_wire).await?;
            if reusable {
                self.pool.put(idx, tls).await;
            }
            Ok(resp)
        })
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "encrypted DNS upstream timeout"))?
    }

    pub async fn clear_ephemeral_state(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
        self.pool.clear().await;
        self.reset_preferred_upstream();
        self.active_upstream_rtt_ms.store(0, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    pub fn stats_snapshot(&self) -> DnsStatsSnapshot {
        DnsStatsSnapshot {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            poisoning_failovers: self.poisoning_failovers.load(Ordering::Relaxed),
            failed_queries: self.failed_queries.load(Ordering::Relaxed),
            ech_records_served: self.ech_records_served.load(Ordering::Relaxed),
            upstream_count: self.config.upstreams.len(),
            active_upstream_name: self.active_upstream_name(),
            active_upstream_rtt_ms: self.active_upstream_rtt_ms.load(Ordering::Relaxed),
        }
    }
}
