//! Bounds-checked IPv4/IPv6 + TCP/UDP packet parser, builder, and RFC 1071 checksums.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Other(u8),
}

impl From<u8> for IpProtocol {
    fn from(val: u8) -> Self {
        match val {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 => Self::Icmp,
            58 => Self::IcmpV6,
            other => Self::Other(other),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(proto: IpProtocol) -> Self {
        match proto {
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Icmp => 1,
            IpProtocol::IcmpV6 => 58,
            IpProtocol::Other(v) => v,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedIpPacket<'a> {
    pub version: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: IpProtocol,
    pub ttl: u8,
    /// IPv4 identification field (`0` for IPv6).
    pub ip_id: u16,
    /// IPv4 Don't Fragment flag (`true` for IPv6).
    pub df: bool,
    pub ip_header_len: usize,
    pub total_len: usize,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedTcp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub header_len: usize,
    pub payload: &'a [u8],
}

impl<'a> ParsedTcp<'a> {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;

    pub fn is_syn_only(&self) -> bool {
        (self.flags & (Self::SYN | Self::ACK)) == Self::SYN
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedUdp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Parses an IPv4 or IPv6 L3 packet safely without panicking on truncated/malformed input.
/// Note: IPv6 extension headers are walked in bounded fashion until TCP/UDP/ICMPv6 or end.
pub fn parse_ip_packet(buf: &[u8]) -> Option<ParsedIpPacket<'_>> {
    if buf.is_empty() {
        return None;
    }
    let version = buf[0] >> 4;
    match version {
        4 => {
            if buf.len() < 20 {
                return None;
            }
            let ihl = ((buf[0] & 0x0F) as usize) * 4;
            if ihl < 20 || buf.len() < ihl {
                return None;
            }
            let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            if total_len < ihl || buf.len() < total_len {
                return None;
            }
            // Reject ALL fragmented IPv4 packets (both MF=1 first fragment and non-zero offset)
            let frag = u16::from_be_bytes([buf[6], buf[7]]);
            if (frag & 0x3FFF) != 0 {
                return None;
            }
            let ip_id = u16::from_be_bytes([buf[4], buf[5]]);
            let df = (frag & 0x4000) != 0;
            let ttl = buf[8];
            let proto = IpProtocol::from(buf[9]);
            let src_ip = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));
            Some(ParsedIpPacket {
                version: 4,
                src_ip,
                dst_ip,
                protocol: proto,
                ttl,
                ip_id,
                df,
                ip_header_len: ihl,
                total_len,
                payload: &buf[ihl..total_len],
            })
        }
        6 => {
            if buf.len() < 40 {
                return None;
            }
            let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
            let total_len = 40usize.checked_add(payload_len)?;
            if buf.len() < total_len {
                return None;
            }
            let mut next_hdr = buf[6];
            let ttl = buf[7];
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&buf[8..24]);
            dst.copy_from_slice(&buf[24..40]);

            let mut offset = 40usize;
            // Bounded walk over standard IPv6 extension headers (Hop-by-Hop=0, Routing=43, DestOpts=60)
            for _ in 0..8 {
                if !matches!(next_hdr, 0 | 43 | 60) {
                    break;
                }
                if offset + 2 > total_len {
                    return None;
                }
                let ext_next = buf[offset];
                let ext_len = ((buf[offset + 1] as usize) + 1) * 8;
                if offset + ext_len > total_len {
                    return None;
                }
                next_hdr = ext_next;
                offset += ext_len;
            }

            Some(ParsedIpPacket {
                version: 6,
                src_ip: IpAddr::V6(Ipv6Addr::from(src)),
                dst_ip: IpAddr::V6(Ipv6Addr::from(dst)),
                protocol: IpProtocol::from(next_hdr),
                ttl,
                ip_id: 0,
                df: true,
                ip_header_len: offset,
                total_len,
                payload: &buf[offset..total_len],
            })
        }
        _ => None,
    }
}

pub fn parse_tcp(payload: &[u8]) -> Option<ParsedTcp<'_>> {
    if payload.len() < 20 {
        return None;
    }
    let data_offset = ((payload[12] >> 4) as usize) * 4;
    if data_offset < 20 || payload.len() < data_offset {
        return None;
    }
    Some(ParsedTcp {
        src_port: u16::from_be_bytes([payload[0], payload[1]]),
        dst_port: u16::from_be_bytes([payload[2], payload[3]]),
        seq: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        ack: u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]),
        flags: payload[13],
        window: u16::from_be_bytes([payload[14], payload[15]]),
        header_len: data_offset,
        payload: &payload[data_offset..],
    })
}

pub fn parse_udp(payload: &[u8]) -> Option<ParsedUdp<'_>> {
    if payload.len() < 8 {
        return None;
    }
    let udp_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if udp_len < 8 || payload.len() < udp_len {
        return None;
    }
    Some(ParsedUdp {
        src_port: u16::from_be_bytes([payload[0], payload[1]]),
        dst_port: u16::from_be_bytes([payload[2], payload[3]]),
        payload: &payload[8..udp_len],
    })
}

fn sum_words(mut sum: u64, data: &[u8]) -> u64 {
    let (chunks, rem) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u16::from_be_bytes(*chunk) as u64;
    }
    if let Some(&byte) = rem.first() {
        sum += (byte as u64) << 8;
    }
    sum
}

fn finalize_checksum(mut sum: u64) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u64;
    let (chunks, _) = header.as_chunks::<2>();
    for (i, chunk) in chunks.iter().enumerate() {
        if i == 5 {
            // Skip checksum field at bytes 10..12
            continue;
        }
        sum += u16::from_be_bytes(*chunk) as u64;
    }
    finalize_checksum(sum)
}

fn ipv4_pseudo_sum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4_len: u16) -> u64 {
    let mut sum = 0u64;
    sum = sum_words(sum, &src.octets());
    sum = sum_words(sum, &dst.octets());
    sum += proto as u64;
    sum += l4_len as u64;
    sum
}

fn ipv6_pseudo_sum(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, l4_len: u32) -> u64 {
    let mut sum = 0u64;
    sum = sum_words(sum, &src.octets());
    sum = sum_words(sum, &dst.octets());
    sum += ((l4_len >> 16) & 0xFFFF) as u64;
    sum += (l4_len & 0xFFFF) as u64;
    sum += proto as u64;
    sum
}

pub fn tcp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum = ipv4_pseudo_sum(src, dst, 6, tcp_segment.len().min(u16::MAX as usize) as u16);
    let (chunks, rem) = tcp_segment.as_chunks::<2>();
    for (i, chunk) in chunks.iter().enumerate() {
        if i == 8 {
            // Skip checksum field at bytes 16..18
            continue;
        }
        sum += u16::from_be_bytes(*chunk) as u64;
    }
    if let Some(&byte) = rem.first() {
        sum += (byte as u64) << 8;
    }
    finalize_checksum(sum)
}

pub fn tcp_checksum_ipv6(src: Ipv6Addr, dst: Ipv6Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum = ipv6_pseudo_sum(src, dst, 6, tcp_segment.len().min(u32::MAX as usize) as u32);
    let (chunks, rem) = tcp_segment.as_chunks::<2>();
    for (i, chunk) in chunks.iter().enumerate() {
        if i == 8 {
            continue;
        }
        sum += u16::from_be_bytes(*chunk) as u64;
    }
    if let Some(&byte) = rem.first() {
        sum += (byte as u64) << 8;
    }
    finalize_checksum(sum)
}

pub fn udp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, udp_packet: &[u8]) -> u16 {
    let mut sum = ipv4_pseudo_sum(src, dst, 17, udp_packet.len().min(u16::MAX as usize) as u16);
    let (chunks, rem) = udp_packet.as_chunks::<2>();
    for (i, chunk) in chunks.iter().enumerate() {
        if i == 3 {
            // Skip checksum field at bytes 6..8
            continue;
        }
        sum += u16::from_be_bytes(*chunk) as u64;
    }
    if let Some(&byte) = rem.first() {
        sum += (byte as u64) << 8;
    }
    let c = finalize_checksum(sum);
    if c == 0 { 0xFFFF } else { c }
}

pub fn udp_checksum_ipv6(src: Ipv6Addr, dst: Ipv6Addr, udp_packet: &[u8]) -> u16 {
    let mut sum = ipv6_pseudo_sum(src, dst, 17, udp_packet.len().min(u32::MAX as usize) as u32);
    let (chunks, rem) = udp_packet.as_chunks::<2>();
    for (i, chunk) in chunks.iter().enumerate() {
        if i == 3 {
            continue;
        }
        sum += u16::from_be_bytes(*chunk) as u64;
    }
    if let Some(&byte) = rem.first() {
        sum += (byte as u64) << 8;
    }
    let c = finalize_checksum(sum);
    if c == 0 { 0xFFFF } else { c }
}

/// Builds a complete IPv4 + UDP packet with valid header and UDP checksums.
pub fn build_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len];

    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    pkt[8] = ttl;
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_csum = ipv4_header_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    let udp_csum = udp_checksum_ipv4(src_ip, dst_ip, &pkt[20..]);
    pkt[26..28].copy_from_slice(&udp_csum.to_be_bytes());

    pkt
}

/// Builds a complete IPv6 + UDP packet with valid UDP checksum.
pub fn build_ipv6_udp_packet(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    hop_limit: u8,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut pkt = vec![0u8; 40 + udp_len];

    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = 17; // UDP
    pkt[7] = hop_limit;
    pkt[8..24].copy_from_slice(&src_ip.octets());
    pkt[24..40].copy_from_slice(&dst_ip.octets());

    pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
    pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[48..].copy_from_slice(payload);
    let udp_csum = udp_checksum_ipv6(src_ip, dst_ip, &pkt[40..]);
    pkt[46..48].copy_from_slice(&udp_csum.to_be_bytes());

    pkt
}

/// Builds a complete IPv4 + TCP packet (with optional original TCP options preserved).
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    ttl: u8,
    ip_id: u16,
    tcp_options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let opts = &tcp_options[..tcp_options.len().min(40)];
    let pad = (4 - (opts.len() % 4)) % 4;
    let tcp_hdr_len = 20 + opts.len() + pad;
    let max_payload = (u16::MAX as usize).saturating_sub(20 + tcp_hdr_len);
    let payload = &payload[..payload.len().min(max_payload)];
    let total_len = 20 + tcp_hdr_len + payload.len();
    let mut pkt = vec![0u8; total_len];

    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&ip_id.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = ttl;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_csum = ipv4_header_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    let tcp_start = 20;
    pkt[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[tcp_start + 8..tcp_start + 12].copy_from_slice(&ack.to_be_bytes());
    pkt[tcp_start + 12] = ((tcp_hdr_len / 4) as u8) << 4;
    pkt[tcp_start + 13] = flags;
    pkt[tcp_start + 14..tcp_start + 16].copy_from_slice(&window.to_be_bytes());
    if !opts.is_empty() {
        pkt[tcp_start + 20..tcp_start + 20 + opts.len()].copy_from_slice(opts);
    }
    pkt[tcp_start + tcp_hdr_len..].copy_from_slice(payload);

    let tcp_csum = tcp_checksum_ipv4(src_ip, dst_ip, &pkt[tcp_start..]);
    pkt[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    pkt
}

/// Builds a complete IPv6 + TCP packet (with optional TCP options preserved).
#[allow(clippy::too_many_arguments)]
pub fn build_ipv6_tcp_packet(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    hop_limit: u8,
    tcp_options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let opts = &tcp_options[..tcp_options.len().min(40)];
    let pad = (4 - (opts.len() % 4)) % 4;
    let tcp_hdr_len = 20 + opts.len() + pad;
    let max_payload = (u16::MAX as usize).saturating_sub(tcp_hdr_len);
    let payload = &payload[..payload.len().min(max_payload)];
    let l4_len = tcp_hdr_len + payload.len();
    let mut pkt = vec![0u8; 40 + l4_len];

    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(l4_len as u16).to_be_bytes());
    pkt[6] = 6;
    pkt[7] = hop_limit;
    pkt[8..24].copy_from_slice(&src_ip.octets());
    pkt[24..40].copy_from_slice(&dst_ip.octets());

    let tcp_start = 40;
    pkt[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[tcp_start + 8..tcp_start + 12].copy_from_slice(&ack.to_be_bytes());
    pkt[tcp_start + 12] = ((tcp_hdr_len / 4) as u8) << 4;
    pkt[tcp_start + 13] = flags;
    pkt[tcp_start + 14..tcp_start + 16].copy_from_slice(&window.to_be_bytes());
    if !opts.is_empty() {
        pkt[tcp_start + 20..tcp_start + 20 + opts.len()].copy_from_slice(opts);
    }
    pkt[tcp_start + tcp_hdr_len..].copy_from_slice(payload);

    let tcp_csum = tcp_checksum_ipv6(src_ip, dst_ip, &pkt[tcp_start..]);
    pkt[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    pkt
}
