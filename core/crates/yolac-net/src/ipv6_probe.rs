//! Balanced fail-closed IPv6 connectivity & leak-risk prober.
//!
//! Probes protected IPv6 reachability on activation or network transitions.
//! If IPv6 connectivity is broken or unreachable through the protected path,
//! recommends switching cleanly to `Ipv6LeakMode::BlockUnprotectedIpv6` + AAAA suppression
//! so host IPv6 never leaks around the protection engine.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::time::timeout;

use crate::leak_guard::Ipv6LeakMode;
use crate::protect::{connect_protected_tcp, SocketProtector};

/// Public no-log bootstrap IPv6 endpoints (Cloudflare & Quad9) used strictly for TCP reachability check.
const DEFAULT_IPV6_PROBES: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)), 443),
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)), 443),
];

/// Determines the safest IPv6 leak mode for the current network using a short bounded TCP probe.
pub async fn probe_ipv6_leak_mode(
    protector: &dyn SocketProtector,
    custom_targets: Option<&[SocketAddr]>,
    probe_timeout: Duration,
) -> Ipv6LeakMode {
    let targets = custom_targets.unwrap_or(&DEFAULT_IPV6_PROBES);
    for &addr in targets {
        if let Ok(Ok(_stream)) = timeout(probe_timeout, connect_protected_tcp(addr, protector)).await
        {
            return Ipv6LeakMode::DualStackProtected;
        }
    }
    Ipv6LeakMode::BlockUnprotectedIpv6
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protect::NoopProtector;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn selects_block_mode_when_ipv6_path_fails_and_dual_stack_when_reachable() {
        // Unreachable local closed port -> fails closed to BlockUnprotectedIpv6
        let unreachable = [SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1)];
        let mode_closed = probe_ipv6_leak_mode(
            &NoopProtector,
            Some(&unreachable),
            Duration::from_millis(150),
        )
        .await;
        assert_eq!(mode_closed, Ipv6LeakMode::BlockUnprotectedIpv6);

        // Reachable IPv6 listener (if host has IPv6 loopback enabled)
        if let Ok(listener) = TcpListener::bind("[::1]:0").await {
            let addr = listener.local_addr().unwrap();
            let mode_open = probe_ipv6_leak_mode(
                &NoopProtector,
                Some(&[addr]),
                Duration::from_millis(300),
            )
            .await;
            assert_eq!(mode_open, Ipv6LeakMode::DualStackProtected);
        }
    }
}
