//! DNS poisoning & ISP hijacking detector.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::wire::{DnsQuery, DnsRecordData, DnsResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoisonReason {
    TransactionIdMismatch,
    QuestionMismatch,
    LoopbackOrUnspecifiedHijack(IpAddr),
    PrivateRangeHijack(IpAddr),
}

fn is_local_or_special_domain(domain: &str) -> bool {
    domain == "localhost"
        || domain.ends_with(".localhost")
        || domain.ends_with(".local")
        || domain.ends_with(".lan")
        || domain.ends_with(".internal")
        || domain.ends_with(".arpa")
}

fn is_bogon_v4(ip: Ipv4Addr) -> Option<PoisonReason> {
    if ip.is_loopback() || ip.is_unspecified() {
        return Some(PoisonReason::LoopbackOrUnspecifiedHijack(IpAddr::V4(ip)));
    }
    if ip.is_private() || ip.is_link_local() {
        return Some(PoisonReason::PrivateRangeHijack(IpAddr::V4(ip)));
    }
    None
}

fn is_bogon_v6(ip: Ipv6Addr) -> Option<PoisonReason> {
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
pub fn detect_poisoning(query: &DnsQuery, resp: &DnsResponse) -> Option<PoisonReason> {
    if resp.id != query.id {
        return Some(PoisonReason::TransactionIdMismatch);
    }
    if !resp.qname.is_empty() && resp.qname != query.qname {
        return Some(PoisonReason::QuestionMismatch);
    }
    if is_local_or_special_domain(&query.qname) {
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
