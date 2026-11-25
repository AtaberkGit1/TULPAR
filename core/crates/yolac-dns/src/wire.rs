//! Cycle-safe RFC 1035 DNS wire parser & response synthesizer.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QType {
    A,
    AAAA,
    CNAME,
    TXT,
    HTTPS,
    Other(u16),
}

impl From<u16> for QType {
    fn from(v: u16) -> Self {
        match v {
            1 => Self::A,
            28 => Self::AAAA,
            5 => Self::CNAME,
            16 => Self::TXT,
            65 => Self::HTTPS,
            other => Self::Other(other),
        }
    }
}

impl From<QType> for u16 {
    fn from(q: QType) -> Self {
        match q {
            QType::A => 1,
            QType::AAAA => 28,
            QType::CNAME => 5,
            QType::TXT => 16,
            QType::HTTPS => 65,
            QType::Other(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub id: u16,
    pub flags: u16,
    pub qname: String,
    pub qtype: QType,
    pub qclass: u16,
    /// Byte offset immediately following the Question section.
    pub question_end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    /// RFC 9460 HTTPS (Type 65) service binding record, including ECH (SvcParamKey 5) detection.
    Https {
        priority: u16,
        target: String,
        has_ech: bool,
    },
    Other(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub rtype: u16,
    pub ttl: u32,
    pub data: DnsRecordData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    pub id: u16,
    pub rcode: u8,
    pub truncated: bool,
    pub qname: String,
    pub qtype: QType,
    pub answers: Vec<DnsAnswer>,
    pub min_ttl: u32,
}

/// Decodes a DNS domain name starting at `offset` with compression pointer loop protection.
/// Returns `(decoded_lowercase_name, next_offset_after_field)`.
pub fn decode_dns_name(packet: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut pos = offset;
    let mut next_pos: Option<usize> = None;
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0usize;
    let mut total_len = 0usize;

    loop {
        if pos >= packet.len() {
            return None;
        }
        let len_byte = packet[pos];
        if (len_byte & 0xC0) == 0xC0 {
            if pos + 1 >= packet.len() {
                return None;
            }
            let ptr = (((len_byte & 0x3F) as usize) << 8) | (packet[pos + 1] as usize);
            if ptr >= packet.len() {
                return None;
            }
            if next_pos.is_none() {
                next_pos = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 32 {
                // Compression loop detected
                return None;
            }
            pos = ptr;
        } else if (len_byte & 0xC0) != 0 {
            return None;
        } else if len_byte == 0 {
            if next_pos.is_none() {
                next_pos = Some(pos + 1);
            }
            break;
        } else {
            let label_len = len_byte as usize;
            pos += 1;
            if pos + label_len > packet.len() {
                return None;
            }
            total_len += label_len + 1;
            if total_len > 255 {
                return None;
            }
            let label = String::from_utf8_lossy(&packet[pos..pos + label_len]);
            labels.push(label.to_ascii_lowercase());
            pos += label_len;
        }
    }

    let name = if labels.is_empty() {
        String::new()
    } else {
        labels.join(".")
    };
    Some((name, next_pos.unwrap_or(pos)))
}

/// Parses an RFC 1035 DNS query packet safely.
pub fn parse_dns_query(packet: &[u8]) -> Option<DnsQuery> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    // Must be a standard query (QR == 0)
    if (flags & 0x8000) != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }
    let (qname, after_name) = decode_dns_name(packet, 12)?;
    if after_name + 4 > packet.len() {
        return None;
    }
    let qtype = QType::from(u16::from_be_bytes([packet[after_name], packet[after_name + 1]]));
    let qclass = u16::from_be_bytes([packet[after_name + 2], packet[after_name + 3]]);

    Some(DnsQuery {
        id,
        flags,
        qname,
        qtype,
        qclass,
        question_end: after_name + 4,
    })
}

/// Parses an RFC 1035 DNS response packet, extracting answer RRs and CNAME targets.
pub fn parse_dns_response(packet: &[u8]) -> Option<DnsResponse> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    // Must be a response (QR == 1)
    if (flags & 0x8000) == 0 {
        return None;
    }
    let rcode = (flags & 0x000F) as u8;
    let truncated = (flags & 0x0200) != 0;
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);

    let mut pos = 12usize;
    let mut qname = String::new();
    let mut qtype = QType::Other(0);

    for i in 0..qdcount {
        let (name, next) = decode_dns_name(packet, pos)?;
        if next + 4 > packet.len() {
            return None;
        }
        if i == 0 {
            qname = name;
            qtype = QType::from(u16::from_be_bytes([packet[next], packet[next + 1]]));
        }
        pos = next + 4;
    }

    let mut answers = Vec::with_capacity(ancount.min(32) as usize);
    let mut min_ttl = u32::MAX;

    for _ in 0..ancount.min(128) {
        let (_rr_name, after_name) = decode_dns_name(packet, pos)?;
        if after_name + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[after_name], packet[after_name + 1]]);
        let _rclass = u16::from_be_bytes([packet[after_name + 2], packet[after_name + 3]]);
        let ttl = u32::from_be_bytes([
            packet[after_name + 4],
            packet[after_name + 5],
            packet[after_name + 6],
            packet[after_name + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[after_name + 8], packet[after_name + 9]]) as usize;
        let rdata_start = after_name + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > packet.len() {
            return None;
        }

        min_ttl = min_ttl.min(ttl);
        let data = match rtype {
            1 if rdlength == 4 => DnsRecordData::A(Ipv4Addr::new(
                packet[rdata_start],
                packet[rdata_start + 1],
                packet[rdata_start + 2],
                packet[rdata_start + 3],
            )),
            28 if rdlength == 16 => {
                let mut octs = [0u8; 16];
                octs.copy_from_slice(&packet[rdata_start..rdata_end]);
                DnsRecordData::AAAA(Ipv6Addr::from(octs))
            }
            5 => {
                let (cname, next_end) = decode_dns_name(packet, rdata_start)?;
                if next_end > rdata_end {
                    return None;
                }
                DnsRecordData::CNAME(cname)
            }
            65 => parse_https_rdata(packet, rdata_start, rdata_end)
                .unwrap_or(DnsRecordData::Other(65)),
            other => DnsRecordData::Other(other),
        };

        answers.push(DnsAnswer { rtype, ttl, data });
        pos = rdata_end;
    }

    if min_ttl == u32::MAX {
        min_ttl = 60;
    }

    Some(DnsResponse {
        id,
        rcode,
        truncated,
        qname,
        qtype,
        answers,
        min_ttl,
    })
}

/// Parses RFC 9460 HTTPS (Type 65) RDATA: SvcPriority (2 bytes), TargetName (wire name),
/// followed by zero or more SvcParams (Key u16, Len u16, Value). Detects ECH (`key == 5`).
fn parse_https_rdata(packet: &[u8], rdata_start: usize, rdata_end: usize) -> Option<DnsRecordData> {
    if rdata_end.saturating_sub(rdata_start) < 3 {
        return None;
    }
    let priority = u16::from_be_bytes([packet[rdata_start], packet[rdata_start + 1]]);
    let (target, mut pos) = decode_dns_name(packet, rdata_start + 2)?;
    if pos > rdata_end {
        return None;
    }

    let mut has_ech = false;
    while pos + 4 <= rdata_end {
        let key = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let val_len = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]) as usize;
        pos += 4;
        if pos + val_len > rdata_end {
            break;
        }
        // RFC 9460 Section 14.3.2: SvcParamKey 5 = ech (Encrypted Client Hello config list)
        if key == 5 && val_len > 0 {
            has_ech = true;
        }
        pos += val_len;
    }

    Some(DnsRecordData::Https {
        priority,
        target,
        has_ech,
    })
}

fn collect_compression_ptrs_in_name(
    packet: &[u8],
    mut pos: usize,
    ptrs: &mut Vec<(usize, usize)>,
) -> Option<usize> {
    let mut jumped = false;
    let mut after_field = None;
    let mut hops = 0usize;
    loop {
        if pos >= packet.len() {
            return None;
        }
        let b = packet[pos];
        if (b & 0xC0) == 0xC0 {
            if pos + 1 >= packet.len() {
                return None;
            }
            let target = (((b & 0x3F) as usize) << 8) | (packet[pos + 1] as usize);
            ptrs.push((pos, target));
            if !jumped {
                after_field = Some(pos + 2);
                jumped = true;
            }
            hops += 1;
            if hops > 32 || target >= packet.len() {
                return None;
            }
            pos = target;
        } else if (b & 0xC0) != 0 {
            return None;
        } else if b == 0 {
            return Some(after_field.unwrap_or(pos + 1));
        } else {
            let l = b as usize;
            pos += 1;
            if pos + l > packet.len() {
                return None;
            }
            pos += l;
        }
    }
}

/// Strips RFC 9460 `SvcParamKey 6` (`ipv6hint`) parameters from `HTTPS` (65) and `SVCB` (64)
/// records in a wire DNS response while preserving `ECH` (`key 5`), `ALPN` (`key 1`), `ipv4hint`
/// (`key 4`), and recalculating RDLENGTH & compression pointers accurately.
/// Returns `None` when no `ipv6hint` was present or if the response layout is unsafe to rewrite.
pub fn strip_https_ipv6_hints(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 12 || (packet[2] & 0x80) == 0 {
        return None;
    }
    let qd = u16::from_be_bytes([packet[4], packet[5]]);
    let an = u16::from_be_bytes([packet[6], packet[7]]);
    let ns = u16::from_be_bytes([packet[8], packet[9]]);
    let ar = u16::from_be_bytes([packet[10], packet[11]]);

    let mut pos = 12usize;
    let mut ptrs: Vec<(usize, usize)> = Vec::new();
    let mut cuts: Vec<(usize, usize, usize)> = Vec::new(); // (rdlen_pos, cut_start, cut_end)

    for _ in 0..qd {
        pos = collect_compression_ptrs_in_name(packet, pos, &mut ptrs)?;
        if pos + 4 > packet.len() {
            return None;
        }
        pos += 4;
    }

    let total_rr = (an as usize).saturating_add(ns as usize).saturating_add(ar as usize);
    if total_rr > 256 {
        return None;
    }
    for _ in 0..total_rr {
        pos = collect_compression_ptrs_in_name(packet, pos, &mut ptrs)?;
        if pos + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rdlen_pos = pos + 8;
        let rdlen = u16::from_be_bytes([packet[rdlen_pos], packet[rdlen_pos + 1]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start + rdlen;
        if rdata_end > packet.len() {
            return None;
        }

        match rtype {
            5 | 2 | 12 => {
                // CNAME / NS / PTR RDATA starts with a domain name that may carry compression pointers
                let _ = collect_compression_ptrs_in_name(packet, rdata_start, &mut ptrs)?;
            }
            6 => {
                // SOA RDATA has MNAME followed by RNAME
                let after_mname = collect_compression_ptrs_in_name(packet, rdata_start, &mut ptrs)?;
                if after_mname < rdata_end {
                    let _ = collect_compression_ptrs_in_name(packet, after_mname, &mut ptrs)?;
                }
            }
            15 if rdlen >= 3 => {
                // MX: 2-byte preference + exchange name
                let _ = collect_compression_ptrs_in_name(packet, rdata_start + 2, &mut ptrs)?;
            }
            64 | 65 if rdlen >= 3 => {
                // SVCB / HTTPS: SvcPriority(2) + TargetName(wire) + SvcParams
                let mut sp = collect_compression_ptrs_in_name(packet, rdata_start + 2, &mut ptrs)?;
                while sp + 4 <= rdata_end {
                    let key = u16::from_be_bytes([packet[sp], packet[sp + 1]]);
                    let val_len = u16::from_be_bytes([packet[sp + 2], packet[sp + 3]]) as usize;
                    let param_end = sp + 4 + val_len;
                    if param_end > rdata_end {
                        break;
                    }
                    if key == 6 {
                        cuts.push((rdlen_pos, sp, param_end));
                    }
                    sp = param_end;
                }
            }
            _ => {}
        }
        pos = rdata_end;
    }

    if cuts.is_empty() {
        return None;
    }

    ptrs.sort_unstable();
    ptrs.dedup();
    let mut out = packet.to_vec();

    // Patch all compression pointers before splicing bytes (cumulative shifts for target >= cut_end)
    for &(ptr_pos, target_pos) in &ptrs {
        if cuts
            .iter()
            .any(|&(_, cs, ce)| target_pos >= cs && target_pos < ce)
        {
            return None;
        }
        let shift: usize = cuts
            .iter()
            .filter(|&&(_, _, ce)| ce <= target_pos)
            .map(|&(_, cs, ce)| ce - cs)
            .sum();
        if shift > 0 {
            let new_target = target_pos.checked_sub(shift)?;
            if new_target > 0x3FFF {
                return None;
            }
            let encoded = (0xC000u16 | (new_target as u16)).to_be_bytes();
            out[ptr_pos..ptr_pos + 2].copy_from_slice(&encoded);
        }
    }

    // Update each affected RDLENGTH in place
    for &(rdlen_pos, cs, ce) in &cuts {
        let cur = u16::from_be_bytes([out[rdlen_pos], out[rdlen_pos + 1]]) as usize;
        let next = u16::try_from(cur.checked_sub(ce - cs)?).ok()?;
        out[rdlen_pos..rdlen_pos + 2].copy_from_slice(&next.to_be_bytes());
    }

    // Remove cut slices back-to-front so earlier indices stay valid
    cuts.sort_unstable_by_key(|a| std::cmp::Reverse(a.1));
    for (_, cs, ce) in cuts {
        out.drain(cs..ce);
    }

    Some(out)
}

/// Rewrites the 2-byte transaction ID of a cached DNS wire packet.
pub fn patch_transaction_id(packet: &mut [u8], new_id: u16) {
    if packet.len() >= 2 {
        packet[0..2].copy_from_slice(&new_id.to_be_bytes());
    }
}

/// Synthesizes a local blocked DNS response (`0.0.0.0` for A, `::` for AAAA, or `NXDOMAIN`).
pub fn build_blocked_response(query_packet: &[u8], nxdomain: bool) -> Option<Vec<u8>> {
    let query = parse_dns_query(query_packet)?;
    let question_section = &query_packet[12..query.question_end];

    let mut out = Vec::with_capacity(12 + question_section.len() + 32);
    out.extend_from_slice(&query.id.to_be_bytes());

    let rd = query.flags & 0x0100;
    let rcode = if nxdomain { 0x0003 } else { 0x0000 };
    // QR=1, AA=0, TC=0, RD preserved, RA=1
    let resp_flags = 0x8080 | rd | rcode;
    out.extend_from_slice(&resp_flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1

    if nxdomain {
        out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
        out.extend_from_slice(question_section);
        return Some(out);
    }

    let (add_answer, rtype, rdlen): (bool, u16, u16) = match query.qtype {
        QType::A => (true, 1, 4),
        QType::AAAA => (true, 28, 16),
        _ => (false, 0, 0),
    };

    out.extend_from_slice(&(if add_answer { 1u16 } else { 0u16 }).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(question_section);

    if add_answer {
        out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // Pointer to QNAME at offset 12
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
        out.extend_from_slice(&rdlen.to_be_bytes());
        out.resize(out.len() + rdlen as usize, 0);
    }

    Some(out)
}

/// Synthesizes an empty `NOERROR` response (used for `AAAA` suppression on IPv6 leak guard).
pub fn build_empty_noerror_response(query_packet: &[u8]) -> Option<Vec<u8>> {
    let query = parse_dns_query(query_packet)?;
    let question_section = &query_packet[12..query.question_end];

    let mut out = Vec::with_capacity(12 + question_section.len());
    out.extend_from_slice(&query.id.to_be_bytes());
    let rd = query.flags & 0x0100;
    out.extend_from_slice(&(0x8080 | rd).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(question_section);
    Some(out)
}

/// Builds a minimal RFC 1035 DNS query packet (helper for tests & probes).
pub fn build_dns_query(id: u16, domain: &str, qtype: QType) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(32 + domain.len());
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Standard query, RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    for label in domain.trim_end_matches('.').split('.') {
        if !label.is_empty() && label.len() <= 63 {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
    }
    pkt.push(0);
    pkt.extend_from_slice(&u16::from(qtype).to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
    pkt
}

/// Returns `true` if `qname` is a local-only / private-LAN hostname (single-label hostnames
/// like `DESKTOP-PC` / `wpad`, or RFC 6762/6761 local suffixes `.local`, `.lan`, `.home`,
/// `.internal`, `.arpa`, `.localdomain`, `.corp`). These should resolve via the local LAN DNS
/// rather than public DoH/DoT so printers, NAS devices, routers, and intranets keep working.
pub fn is_local_lan_hostname(qname: &str) -> bool {
    let norm = qname.trim().trim_end_matches('.').to_ascii_lowercase();
    if norm.is_empty() {
        return false;
    }
    if !norm.contains('.') {
        return true;
    }
    const LOCAL_SUFFIXES: &[&str] = &[
        ".local",
        ".lan",
        ".home",
        ".internal",
        ".arpa",
        ".localdomain",
        ".corp",
        ".intranet",
        ".localnet",
    ];
    LOCAL_SUFFIXES.iter().any(|&s| norm.ends_with(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_query_and_synthesizes_blocked_answer() {
        let q = build_dns_query(0x1234, "doubleclick.net", QType::A);
        let parsed_q = parse_dns_query(&q).unwrap();
        assert_eq!(parsed_q.id, 0x1234);
        assert_eq!(parsed_q.qname, "doubleclick.net");
        assert_eq!(parsed_q.qtype, QType::A);

        let resp_bytes = build_blocked_response(&q, false).unwrap();
        let resp = parse_dns_response(&resp_bytes).unwrap();
        assert_eq!(resp.id, 0x1234);
        assert_eq!(resp.rcode, 0);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].data, DnsRecordData::A(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn rejects_compression_pointer_loop() {
        // Malformed DNS query with self-referential pointer at offset 12 -> 0xC00C
        let mut pkt = vec![0u8; 18];
        pkt[0..2].copy_from_slice(&0x1111u16.to_be_bytes());
        pkt[4..6].copy_from_slice(&1u16.to_be_bytes());
        pkt[12] = 0xC0;
        pkt[13] = 0x0C;
        assert!(parse_dns_query(&pkt).is_none());
    }

    #[test]
    fn parses_https_type65_record_with_ech_param() {
        let q = build_dns_query(0x7777, "crypto.cloudflare.com", QType::HTTPS);
        let parsed_q = parse_dns_query(&q).unwrap();
        let q_sec = &q[12..parsed_q.question_end];

        // Build RFC 9460 HTTPS RDATA: priority=1, target="." (0x00), SvcParam alpn(1)="h2", SvcParam ech(5)=[0x01,0x02,0x03,0x04]
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // priority
        rdata.push(0x00); // root target "."
        // alpn key=1, len=3, "\x02h2"
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend_from_slice(&3u16.to_be_bytes());
        rdata.extend_from_slice(&[2, b'h', b'2']);
        // ech key=5, len=4
        rdata.extend_from_slice(&5u16.to_be_bytes());
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(&[0x00, 0x02, 0xFE, 0x0D]);

        let mut resp = Vec::new();
        resp.extend_from_slice(&0x7777u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(q_sec);
        resp.extend_from_slice(&0xC00Cu16.to_be_bytes());
        resp.extend_from_slice(&65u16.to_be_bytes()); // HTTPS
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);

        let parsed = parse_dns_response(&resp).expect("valid HTTPS RR response");
        assert_eq!(parsed.qtype, QType::HTTPS);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(
            parsed.answers[0].data,
            DnsRecordData::Https {
                priority: 1,
                target: String::new(),
                has_ech: true,
            }
        );
    }

    #[test]
    fn distinguishes_local_lan_hostnames_from_public_domains() {
        assert!(is_local_lan_hostname("DESKTOP-1234"));
        assert!(is_local_lan_hostname("wpad"));
        assert!(is_local_lan_hostname("printer.local."));
        assert!(is_local_lan_hostname("router.lan"));
        assert!(is_local_lan_hostname("1.1.168.192.in-addr.arpa"));
        assert!(is_local_lan_hostname("portal.corp"));
        assert!(!is_local_lan_hostname("www.roblox.com"));
        assert!(!is_local_lan_hostname("g.whatsapp.net"));
    }

    #[test]
    fn strips_https_ipv6hint_while_preserving_ech_and_compressed_trailing_records() {
        let q = build_dns_query(0x9988, "ech.example.org", QType::HTTPS);
        let parsed_q = parse_dns_query(&q).unwrap();
        let q_sec = &q[12..parsed_q.question_end];

        // HTTPS RR RDATA: priority=1, target="." (0x00), alpn(1), ipv4hint(4), ech(5), ipv6hint(6)
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.push(0x00);
        // key 1 (alpn)
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend_from_slice(&3u16.to_be_bytes());
        rdata.extend_from_slice(&[2, b'h', b'2']);
        // key 4 (ipv4hint)
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(&[93, 184, 216, 34]);
        // key 5 (ech)
        rdata.extend_from_slice(&5u16.to_be_bytes());
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(&[0x00, 0x02, 0xFE, 0x0D]);
        // key 6 (ipv6hint: 2001:db8::1 -> 16 bytes -> total param 20 bytes removed)
        rdata.extend_from_slice(&6u16.to_be_bytes());
        rdata.extend_from_slice(&16u16.to_be_bytes());
        rdata.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let mut resp = Vec::new();
        resp.extend_from_slice(&0x9988u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        resp.extend_from_slice(&2u16.to_be_bytes()); // ANCOUNT=2
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(q_sec);

        // Answer 1: HTTPS record at owner ptr 0xC00C
        resp.extend_from_slice(&0xC00Cu16.to_be_bytes());
        resp.extend_from_slice(&65u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&120u32.to_be_bytes());
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        let target_label_anchor = resp.len() + 2; // byte offset after cut would shift only records after this!
        let _ = target_label_anchor;
        resp.extend_from_slice(&rdata);

        // Answer 2: CNAME record pointing to a label defined inside Additional/Answer 2? Use uncompressed owner
        // and compressed pointer referencing Answer 2's own owner (located AFTER Answer 1 cut -> must shift by -20!)
        let rr2_owner_offset = resp.len();
        resp.extend_from_slice(&[3, b'c', b'd', b'n', 0xC0, 0x0C]); // "cdn.ech.example.org"
        resp.extend_from_slice(&5u16.to_be_bytes()); // CNAME
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&120u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        // RDATA: label "v" + ptr to rr2_owner_offset (located AFTER Answer 1 cut!)
        resp.extend_from_slice(&[1, b'v']);
        resp.extend_from_slice(&(0xC000u16 | (rr2_owner_offset as u16)).to_be_bytes());

        let stripped = strip_https_ipv6_hints(&resp).expect("should strip ipv6hint cleanly");
        assert_eq!(stripped.len(), resp.len() - 20);
        // Confirm stripping twice returns None (no ipv6hint remains)
        assert!(strip_https_ipv6_hints(&stripped).is_none());

        let parsed = parse_dns_response(&stripped).expect("stripped response + shifted compression ptrs must parse");
        assert_eq!(parsed.answers.len(), 2);
        assert_eq!(
            parsed.answers[0].data,
            DnsRecordData::Https {
                priority: 1,
                target: String::new(),
                has_ech: true,
            }
        );
        assert_eq!(
            parsed.answers[1].data,
            DnsRecordData::CNAME("v.cdn.ech.example.org".to_string())
        );
    }
}
