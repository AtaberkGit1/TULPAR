//! DNS, DoT bypass, and IPv6 leak guard policies.

use yolac_dpi::{IpProtocol, ParsedIpPacket, parse_tcp, parse_udp};

use crate::captive_portal::is_local_lan_ip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6LeakMode {
    /// Route IPv6 traffic through the protected engine identically to IPv4.
    DualStackProtected,
    /// Block outbound IPv6 flows (and suppress AAAA DNS answers) so leaky host IPv6 cannot bypass VPN.
    BlockUnprotectedIpv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakDecision {
    Allow,
    InterceptDnsUdp,
    BlockDnsBypassTcp,
    BlockIpv6Leak,
}

#[derive(Debug, Clone, Copy)]
pub struct LeakGuard {
    pub ipv6_mode: Ipv6LeakMode,
    /// Block direct outbound port-53 TCP or port-853 DoT attempts from apps trying to bypass local DNS/blocklist.
    pub block_plaintext_dns_tcp_bypass: bool,
}

impl Default for LeakGuard {
    fn default() -> Self {
        Self {
            ipv6_mode: Ipv6LeakMode::DualStackProtected,
            block_plaintext_dns_tcp_bypass: true,
        }
    }
}

impl LeakGuard {
    pub fn inspect_outbound(&self, ip: &ParsedIpPacket<'_>) -> LeakDecision {
        self.inspect_outbound_with_portal(ip, false)
    }

    /// Evaluates leak-prevention rules while optionally permitting local LAN router DNS
    /// during an active, time-bounded Captive Portal login window.
    pub fn inspect_outbound_with_portal(
        &self,
        ip: &ParsedIpPacket<'_>,
        portal_bypass_active: bool,
    ) -> LeakDecision {
        // 0. During active captive-portal login window, allow direct traffic to local LAN gateways
        //    (e.g., 192.168.1.1 / 10.0.0.1 router portal DNS & login HTTP) without leaking to public DNS.
        if portal_bypass_active && is_local_lan_ip(ip.dst_ip) {
            return LeakDecision::Allow;
        }

        // 1. IPv6 leak guard
        if ip.version == 6 && self.ipv6_mode == Ipv6LeakMode::BlockUnprotectedIpv6 {
            // Still allow IPv6 DNS UDP/53 so local DnsEngine can return suppressed AAAA / blocked reply cleanly
            if ip.protocol == IpProtocol::Udp {
                if let Some(udp) = parse_udp(ip.payload) {
                    if udp.dst_port == 53 {
                        return LeakDecision::InterceptDnsUdp;
                    }
                }
            }
            return LeakDecision::BlockIpv6Leak;
        }

        // 2. DNS leak prevention
        match ip.protocol {
            IpProtocol::Udp => {
                if let Some(udp) = parse_udp(ip.payload) {
                    if udp.dst_port == 53 {
                        return LeakDecision::InterceptDnsUdp;
                    }
                }
            }
            IpProtocol::Tcp if self.block_plaintext_dns_tcp_bypass => {
                if let Some(tcp) = parse_tcp(ip.payload) {
                    if tcp.dst_port == 53 {
                        return LeakDecision::BlockDnsBypassTcp;
                    }
                }
            }
            _ => {}
        }

        LeakDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use yolac_dpi::{build_ipv4_tcp_packet, build_ipv6_udp_packet, parse_ip_packet, ParsedTcp};

    #[test]
    fn enforces_dns_and_ipv6_leak_policies() {
        let guard = LeakGuard {
            ipv6_mode: Ipv6LeakMode::BlockUnprotectedIpv6,
            block_plaintext_dns_tcp_bypass: true,
        };

        let v6_dns = build_ipv6_udp_packet(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
            50000,
            53,
            64,
            b"query",
        );
        let parsed_v6_dns = parse_ip_packet(&v6_dns).unwrap();
        assert_eq!(guard.inspect_outbound(&parsed_v6_dns), LeakDecision::InterceptDnsUdp);

        let v6_other = build_ipv6_udp_packet(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1),
            50001,
            443,
            64,
            b"quic",
        );
        let parsed_v6_other = parse_ip_packet(&v6_other).unwrap();
        assert_eq!(guard.inspect_outbound(&parsed_v6_other), LeakDecision::BlockIpv6Leak);

        let v4_tcp_53 = build_ipv4_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            50002,
            53,
            1,
            0,
            ParsedTcp::SYN,
            65535,
            64,
            1,
            &[],
            &[],
        );
        let parsed_v4_tcp_53 = parse_ip_packet(&v4_tcp_53).unwrap();
        assert_eq!(guard.inspect_outbound(&parsed_v4_tcp_53), LeakDecision::BlockDnsBypassTcp);
    }
}
