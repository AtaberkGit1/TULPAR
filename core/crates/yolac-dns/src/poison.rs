//! DNS poisoning & ISP hijacking detector.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::wire::{is_local_lan_hostname, DnsQuery, DnsRecordData, DnsResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoisonReason {
    TransactionIdMismatch,
    QuestionMismatch,
    LoopbackOrUnspecifiedHijack(IpAddr),
    PrivateRangeHijack(IpAddr),
    KnownCensorshipSinkhole(IpAddr),
}

fn is_known_sinkhole_v4(ip: Ipv4Addr) -> bool {
    // Known public Turkish ISP / BTK censorship sinkhole IPs
    matches!(ip.octets(), [195, 175, 254, 2] | [195, 175, 254, 3])
}

fn is_bogon_v4(ip: Ipv4Addr) -> Option<PoisonReason> {
    if is_known_sinkhole_v4(ip) {
        return Some(PoisonReason::KnownCensorshipSinkhole(IpAddr::V4(ip)));
    }
    if ip.is_loopback() || ip.is_unspecified() {
        return Some(PoisonReason::LoopbackOrUnspecifiedHijack(IpAddr::V4(ip)));
    }
    if ip.is_private() || ip.is_link_local() {
        return Some(PoisonReason::PrivateRangeHijack(IpAddr::V4(ip)));
    }
    None
}

fn is_bogon_v6(ip: Ipv6Addr) -> Option<PoisonReason> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        if let Some(reason) = is_bogon_v4(v4) {
            return Some(reason);
        }
    }
    if ip.is_loopback() || ip.is_unspecified() {
        return Some(PoisonReason::LoopbackOrUnspecifiedHijack(IpAddr::V6(ip)));
    }
    // Unique local address (fc00::/7) or link-local (fe80::/10)
    let seg0 = ip.segments()[0];
    if (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80 {
        return Some(PoisonReason::PrivateRangeHijack(IpAddr::V6(ip)));
    }
    None
}

/// Checks whether a DNS response shows signs of spoofing or ISP sinkhole hijacking.
/// Suitable for untrusted/plaintext paths (rejects private, loopback, and known sinkholes).
pub fn detect_poisoning(query: &DnsQuery, resp: &DnsResponse) -> Option<PoisonReason> {
    if resp.id != query.id {
        return Some(PoisonReason::TransactionIdMismatch);
    }
    if resp.qname != query.qname {
        return Some(PoisonReason::QuestionMismatch);
    }
    if query.qname.is_empty() || is_local_lan_hostname(&query.qname) || query.qname.ends_with(".localhost") {
        return None;
    }

    for ans in &resp.answers {
        match ans.data {
            DnsRecordData::A(ip) => {
                if let Some(reason) = is_bogon_v4(ip) {
                    return Some(reason);
                }
            }
            DnsRecordData::AAAA(ip) => {
                if let Some(reason) = is_bogon_v6(ip) {
                    return Some(reason);
                }
            }
            _ => {}
        }
    }

    None
}

/// Strict integrity & censorship-sinkhole check for TLS-authenticated DoH/DoT responses.
/// Because TLS verifies the upstream resolver cryptographically, legitimate private/loopback
/// records (e.g. `*.plex.direct`, `*.nip.io`, `*.sslip.io`, split-horizon corporate domains)
/// are permitted unless they match a known censorship sinkhole or header mismatch!
pub fn detect_poisoning_tls(query: &DnsQuery, resp: &DnsResponse) -> Option<PoisonReason> {
    if resp.id != query.id {
        return Some(PoisonReason::TransactionIdMismatch);
    }
    if resp.qname != query.qname {
        return Some(PoisonReason::QuestionMismatch);
    }
    for ans in &resp.answers {
        match ans.data {
            DnsRecordData::A(ip) if is_known_sinkhole_v4(ip) => {
                return Some(PoisonReason::KnownCensorshipSinkhole(IpAddr::V4(ip)));
            }
            DnsRecordData::AAAA(ip) => {
                if let Some(v4) = ip.to_ipv4_mapped() {
                    if is_known_sinkhole_v4(v4) {
                        return Some(PoisonReason::KnownCensorshipSinkhole(IpAddr::V6(ip)));
                    }
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DnsAnswer, QType};

    #[test]
    fn flags_loopback_and_private_hijacks_for_public_domains() {
        let q = DnsQuery {
            id: 42,
            flags: 0x0100,
            qname: "example.org".into(),
            qtype: QType::A,
            qclass: 1,
            question_end: 29,
        };
        let poisoned = DnsResponse {
            id: 42,
            rcode: 0,
            truncated: false,
            qname: "example.org".into(),
            qtype: QType::A,
            answers: vec![DnsAnswer {
                rtype: 1,
                ttl: 60,
                data: DnsRecordData::A(Ipv4Addr::new(127, 0, 0, 1)),
            }],
            min_ttl: 60,
        };
        assert_eq!(
            detect_poisoning(&q, &poisoned),
            Some(PoisonReason::LoopbackOrUnspecifiedHijack(IpAddr::V4(
                Ipv4Addr::LOCALHOST
            )))
        );

        let clean = DnsResponse {
            id: 42,
            rcode: 0,
            truncated: false,
            qname: "example.org".into(),
            qtype: QType::A,
            answers: vec![DnsAnswer {
                rtype: 1,
                ttl: 300,
                data: DnsRecordData::A(Ipv4Addr::new(93, 184, 216, 34)),
            }],
            min_ttl: 300,
        };
        assert!(detect_poisoning(&q, &clean).is_none());
    }
}
