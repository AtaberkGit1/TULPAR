//! Unified YOLAÇ DNS Engine: blocklist + CNAME uncloaking + RAM LRU + poisoning failover.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use tokio::sync::Mutex;
use yolac_blocklist::Blocklist;

use crate::cache::DnsCache;
use crate::poison::detect_poisoning;
use crate::pool::UpstreamPool;
use crate::upstream::{
    connect_upstream_tls, default_public_upstreams, default_rustls_config, exchange_on_tls_stream,
    query_upstream, DefaultUpstreamDialer, UpstreamConfig, UpstreamDialer,
};
use crate::wire::{
    build_blocked_response, build_dns_query, build_empty_noerror_response, parse_dns_query,
    parse_dns_response, DnsRecordData, QType,
};

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

#[derive(Debug, Clone, Copy, Default)]
pub struct DnsStatsSnapshot {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub cache_hits: u64,
    pub poisoning_failovers: u64,
    pub failed_queries: u64,
    pub ech_records_served: u64,
    pub upstream_count: usize,
}

pub struct DnsEngine {
    config: DnsConfig,
    blocklist: Arc<Blocklist>,
    cache: Mutex<DnsCache>,
    pool: UpstreamPool,
    dialer: Arc<dyn UpstreamDialer>,
    default_tls: Arc<ClientConfig>,
    preferred_upstream: AtomicUsize,
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
            cache: Mutex::new(DnsCache::new(cache_cap)),
            pool: UpstreamPool::new(),
            dialer: dialer.unwrap_or_else(|| Arc::new(DefaultUpstreamDialer)),
            default_tls: default_rustls_config(),
            preferred_upstream: AtomicUsize::new(0),
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

    pub async fn resolve(&self, query_wire: &[u8]) -> (Option<Vec<u8>>, DnsOutcome) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);

        let query = match parse_dns_query(query_wire) {
            Some(q) => q,
            None => return (None, DnsOutcome::Failed),
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

        // 3. RAM-only LRU cache
        {
            let mut cache = self.cache.lock().await;
            if let Some(cached) = cache.get(&query.qname, query.qtype, query.id) {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return (Some(cached), DnsOutcome::CacheHit);
            }
        }

        // 4. Encrypted upstream failover loop starting from preferred_upstream
        let count = self.config.upstreams.len();
        if count > 0 {
            let start = self.preferred_upstream.load(Ordering::Relaxed) % count;
            for offset in 0..count {
                let idx = (start + offset) % count;
                let upstream = &self.config.upstreams[idx];
                let Ok(resp_wire) = self.query_with_pool(idx, upstream, query_wire).await else {
                    continue;
                };

                let Some(parsed_resp) = parse_dns_response(&resp_wire) else {
                    continue;
                };

                if detect_poisoning(&query, &parsed_resp).is_some() {
                    self.poisoning_failovers.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                if offset > 0 {
                    // Promote healthy fallback upstream so future queries skip dead/poisoned endpoints
                    self.preferred_upstream.store(idx, Ordering::Relaxed);
                }

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
                    return (
                        build_blocked_response(query_wire, self.config.block_with_nxdomain),
                        DnsOutcome::BlockedCnameUncloak,
                    );
                }

                if parsed_resp
                    .answers
                    .iter()
                    .any(|ans| matches!(ans.data, DnsRecordData::Https { has_ech: true, .. }))
                {
                    self.ech_records_served.fetch_add(1, Ordering::Relaxed);
                }

                if parsed_resp.rcode == 0 && !parsed_resp.answers.is_empty() {
                    let mut cache = self.cache.lock().await;
                    cache.insert(
                        &query.qname,
                        query.qtype,
                        resp_wire.clone(),
                        parsed_resp.min_ttl,
                    );
                }

                self.consecutive_failures.store(0, Ordering::Relaxed);
                return (Some(resp_wire), DnsOutcome::UpstreamResolved);
            }
        }

        self.failed_queries.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        (None, DnsOutcome::Failed)
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

    pub fn set_suppress_aaaa(&self, suppress: bool) {
        self.suppress_aaaa.store(suppress, Ordering::Relaxed);
    }

    pub fn is_suppressing_aaaa(&self) -> bool {
        self.suppress_aaaa.load(Ordering::Relaxed)
    }

    /// Probes configured encrypted upstreams concurrently and promotes the fastest healthy responder.
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
            let tls = Arc::clone(&self.default_tls);
            let timeout = self.config.upstream_timeout;
            set.spawn(async move {
                let resp = query_upstream(&upstream, &wire, dialer.as_ref(), &tls, timeout)
                    .await
                    .ok()?;
                let parsed = parse_dns_response(&resp)?;
                Some((idx, parsed))
            });
        }

        while let Some(res) = set.join_next().await {
            if let Ok(Some((idx, parsed))) = res {
                if detect_poisoning(&probe_query, &parsed).is_none() {
                    self.preferred_upstream.store(idx, Ordering::Relaxed);
                    return Some(idx);
                }
            }
        }
        None
    }

    async fn query_with_pool(
        &self,
        idx: usize,
        upstream: &UpstreamConfig,
        query_wire: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        // 1. Try reusing an idle keep-alive TLS stream from pool
        if let Some(mut pooled) = self.pool.take(idx).await {
            if let Ok(Ok((resp, reusable))) = tokio::time::timeout(
                self.config.upstream_timeout,
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
        tokio::time::timeout(self.config.upstream_timeout, async {
            let mut tls =
                connect_upstream_tls(upstream, self.dialer.as_ref(), &self.default_tls).await?;
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
        self.cache.lock().await.clear();
        self.pool.clear().await;
        self.reset_preferred_upstream();
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
        }
    }
}
