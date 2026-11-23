//! Safe Captive Portal detection and bounded temporary local-portal allowance.
//!
//! Security invariant:
//! - Temporary bypass ONLY activates when encrypted DNS has consecutive failures (`>= 2`)
//!   AND an OS captive-portal check domain is queried.
//! - Temporary bypass is strictly capped at `max_duration` (default 90 seconds) and
//!   automatically closes the instant encrypted DNS succeeds again (fail-closed).
//! - Local TUN virtual addresses (`10.219.0.0/30`, `fd79:6f6c:6163::/126`) are NEVER treated
//!   as LAN bypass targets so local encrypted DNS interception remains intact.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_PORTAL_BYPASS_MAX: Duration = Duration::from_secs(90);

const CAPTIVE_PORTAL_PROBES: &[&str] = &[
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "captive.apple.com",
    "www.msftconnecttest.com",
    "www.msftncsi.com",
    "dns.msftncsi.com",
    "detectportal.firefox.com",
    "nmcheck.gnome.org",
    "networkcheck.kde.org",
];

/// Returns `true` if `domain` is a standard OS/browser captive-portal connectivity check host.
pub fn is_captive_portal_probe_domain(domain: &str) -> bool {
    let trimmed = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    CAPTIVE_PORTAL_PROBES.iter().any(|&p| p == trimmed)
}

/// Returns `true` if `ip` belongs to a private local LAN / link-local subnet (RFC 1918,
/// RFC 3927, RFC 4193, fe80::/10) EXCEPT the engine's own internal TUN addresses
/// (`10.219.0.0/30` and `fd79:6f6c:6163::/126`).
pub fn is_local_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_local_lan_v4(v4),
        IpAddr::V6(v6) => is_local_lan_v6(v6),
    }
}

fn is_local_lan_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    // Exclude our own virtual TUN subnet 10.219.0.0/30 (10.219.0.0 .. 10.219.0.3)
    if o[0] == 10 && o[1] == 219 && o[2] == 0 && (o[3] & 0xFC) == 0 {
        return false;
    }
    v4.is_private() || v4.is_link_local()
}

fn is_local_lan_v6(v6: Ipv6Addr) -> bool {
    let segs = v6.segments();
    // Exclude our own virtual TUN subnet fd79:6f6c:6163::/126
    if segs[0] == 0xfd79
        && segs[1] == 0x6f6c
        && segs[2] == 0x6163
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0
        && segs[6] == 0
        && (segs[7] & 0xFFFC) == 0
    {
        return false;
    }
    // Link-local fe80::/10 or Unique Local fc00::/7
    (segs[0] & 0xFFC0) == 0xFE80 || (segs[0] & 0xFE00) == 0xFC00
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptivePortalState {
    Normal,
    PortalBypassActive { remaining_secs: u64 },
}

pub struct CaptivePortalMonitor {
    max_duration: Duration,
    bypass_started_at: Mutex<Option<Instant>>,
}

impl CaptivePortalMonitor {
    pub fn new() -> Self {
        Self::with_max_duration(DEFAULT_PORTAL_BYPASS_MAX)
    }

    pub fn with_max_duration(max_duration: Duration) -> Self {
        Self {
            max_duration,
            bypass_started_at: Mutex::new(None),
        }
    }

    /// Evaluates whether an incoming DNS query indicates a captive-portal network while
    /// encrypted DNS is failing (`consecutive_dns_failures >= 2`).
    /// Returns `true` if temporary portal allowance is now active.
    pub fn on_dns_query_and_failure_state(
        &self,
        qname: &str,
        consecutive_dns_failures: u64,
    ) -> bool {
        if consecutive_dns_failures >= 2 && is_captive_portal_probe_domain(qname) {
            if let Ok(mut guard) = self.bypass_started_at.lock() {
                if guard.is_none() {
                    *guard = Some(Instant::now());
                }
            }
            return self.is_bypass_active();
        }
        self.is_bypass_active()
    }

    /// Manually activates temporary portal allowance (bounded by `max_duration`).
    pub fn trigger_portal_bypass(&self) {
        if let Ok(mut guard) = self.bypass_started_at.lock() {
            if guard.is_none() {
                *guard = Some(Instant::now());
            }
        }
    }

    /// Immediately ends temporary portal allowance once encrypted DoH/DoT connectivity returns.
    pub fn on_dns_upstream_success(&self) {
        self.reset();
    }

    /// Returns the live state, automatically expiring back to `Normal` once `max_duration` elapses.
    pub fn state(&self) -> CaptivePortalState {
        let Ok(mut guard) = self.bypass_started_at.lock() else {
            return CaptivePortalState::Normal;
        };
        if let Some(started) = *guard {
            let elapsed = started.elapsed();
            if elapsed < self.max_duration {
                let remaining = self.max_duration.saturating_sub(elapsed).as_secs().max(1);
                return CaptivePortalState::PortalBypassActive {
                    remaining_secs: remaining,
                };
            }
            // Fail-closed automatic expiration
            *guard = None;
        }
        CaptivePortalState::Normal
    }

    pub fn is_bypass_active(&self) -> bool {
        matches!(self.state(), CaptivePortalState::PortalBypassActive { .. })
    }

    pub fn reset(&self) {
        if let Ok(mut guard) = self.bypass_started_at.lock() {
            *guard = None;
        }
    }
}

impl Default for CaptivePortalMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_standard_captive_portal_probe_domains() {
        assert!(is_captive_portal_probe_domain("connectivitycheck.gstatic.com"));
        assert!(is_captive_portal_probe_domain("CAPTIVE.APPLE.COM."));
        assert!(is_captive_portal_probe_domain("www.msftconnecttest.com"));
        assert!(is_captive_portal_probe_domain("detectportal.firefox.com"));
        assert!(!is_captive_portal_probe_domain("wikipedia.org"));
        assert!(!is_captive_portal_probe_domain("example.com"));
    }

    #[test]
    fn distinguishes_local_lan_ips_from_tun_and_public_ips() {
        assert!(is_local_lan_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_local_lan_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_local_lan_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 5, 1))));
        assert!(is_local_lan_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(is_local_lan_ip(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));

        // Virtual TUN subnet must NEVER be classified as local LAN bypass
        assert!(!is_local_lan_ip(IpAddr::V4(Ipv4Addr::new(10, 219, 0, 1))));
        assert!(!is_local_lan_ip(IpAddr::V4(Ipv4Addr::new(10, 219, 0, 2))));
        assert!(!is_local_lan_ip(IpAddr::V6(Ipv6Addr::new(
            0xfd79, 0x6f6c, 0x6163, 0, 0, 0, 0, 2
        ))));

        // Public IPs must NEVER be classified as local LAN
        assert!(!is_local_lan_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_local_lan_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn captive_portal_lifecycle_activates_recovers_and_expires_fail_closed() {
        let mon = CaptivePortalMonitor::with_max_duration(Duration::from_millis(60));
        assert_eq!(mon.state(), CaptivePortalState::Normal);

        // Single failure or non-portal domain must NOT open bypass
        assert!(!mon.on_dns_query_and_failure_state("connectivitycheck.gstatic.com", 1));
        assert!(!mon.on_dns_query_and_failure_state("example.com", 5));
        assert_eq!(mon.state(), CaptivePortalState::Normal);

        // >=2 encrypted DNS failures + OS portal probe -> activates temporary bypass
        assert!(mon.on_dns_query_and_failure_state("captive.apple.com", 2));
        assert!(matches!(
            mon.state(),
            CaptivePortalState::PortalBypassActive { .. }
        ));

        // Encrypted DNS returning online immediately closes bypass
        mon.on_dns_upstream_success();
        assert_eq!(mon.state(), CaptivePortalState::Normal);

        // Fail-closed automatic expiration after max_duration
        mon.trigger_portal_bypass();
        assert!(mon.is_bypass_active());
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(mon.state(), CaptivePortalState::Normal);
    }
}
