//! TLS 1.2 / 1.3 ClientHello parser & TLS Record Fragmentation engine.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// Extracted SNI hostname (lowercase).
    pub sni: Option<String>,
    /// Start and end byte offsets of the SNI hostname string within the full input buffer.
    pub sni_range: Option<(usize, usize)>,
    /// Record-layer protocol version (e.g. [0x03, 0x01] or [0x03, 0x03]).
    pub record_version: [u8; 2],
    /// Total length of the first TLS record (including 5-byte record header).
    pub record_total_len: usize,
    /// Whether Encrypted Client Hello (ECH, 0xfe0d) extension was advertised.
    pub has_ech: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitStrategy {
    /// Split directly at the midpoint of the SNI hostname.
    SniMid,
    /// Split at an early fixed byte offset AND at the midpoint of SNI (ByeDPI `-r1+s`, 3 valid TLS records).
    OffsetAndSniMid(usize),
    /// Split at a fixed offset within the handshake payload (clamped cleanly).
    FixedOffset(usize),
    /// Split handshake payload into chunks of at most `chunk_size` bytes.
    MultiChunk(usize),
}

fn is_valid_tls_record_version(v: [u8; 2]) -> bool {
    v[0] == 0x03 && v[1] <= 0x04
}

/// Parses a complete TLS ClientHello from the beginning of a TCP payload stream.
/// Returns `None` if the data is not a complete TLS Handshake ClientHello or is truncated/malformed.
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHelloInfo> {
    parse_client_hello_inner(data, false)
}

/// Parses a TLS ClientHello even if only the first TCP segment arrived (e.g. Chrome 131+
/// post-quantum `X25519MLKEM768` ClientHello > 1460 bytes spanning multiple MSS segments).
/// Extracts SNI & offsets when present inside the available prefix; never panics on truncation.
pub fn parse_client_hello_prefix(data: &[u8]) -> Option<ClientHelloInfo> {
    parse_client_hello_inner(data, true)
}

fn parse_client_hello_inner(data: &[u8], allow_truncated: bool) -> Option<ClientHelloInfo> {
    // TLS record header: 1 byte type (0x16 Handshake), 2 bytes version, 2 bytes length
    if data.len() < 9 || data[0] != 0x16 {
        return None;
    }
    let record_version = [data[1], data[2]];
    if !is_valid_tls_record_version(record_version) {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    // RFC 8446 §5.1: TLSPlaintext fragment length MUST NOT exceed 2^14 (16384 bytes)
    if !(4..=16384).contains(&record_len) {
        return None;
    }
    let record_total_len = 5 + record_len;
    let is_truncated = data.len() < record_total_len;
    if !allow_truncated && is_truncated {
        return None;
    }
    let avail_record_end = record_total_len.min(data.len());
    let hs = &data[5..avail_record_end];

    // Handshake header: 1 byte type (0x01 ClientHello), 3 bytes length
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    // Minimum valid ClientHello body is 38 bytes (2 ver + 32 random + 1 sid + 2 ciphers + 1 comp)
    if hs_len < 38 {
        return None;
    }
    let body_truncated = is_truncated || hs.len() < 4 + hs_len;
    if !allow_truncated && body_truncated {
        return None;
    }
    let avail_body_end = (4 + hs_len).min(hs.len());
    let body = &hs[4..avail_body_end];
    if body.len() >= 2 && body[0] != 0x03 {
        return None;
    }

    // ClientHello body:
    // 2 bytes client_version + 32 bytes random = 34 bytes
    let mut pos = 34usize;
    if body.len() < pos + 1 {
        return if allow_truncated && body_truncated {
            Some(ClientHelloInfo {
                sni: None,
                sni_range: None,
                record_version,
                record_total_len,
                has_ech: false,
            })
        } else {
            None
        };
    }
    let session_id_len = body[pos] as usize;
    pos += 1 + session_id_len;

    if body.len() < pos + 2 {
        return if allow_truncated && body_truncated {
            Some(ClientHelloInfo {
                sni: None,
                sni_range: None,
                record_version,
                record_total_len,
                has_ech: false,
            })
        } else {
            None
        };
    }
    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if body.len() < pos + 1 {
        return if allow_truncated && body_truncated {
            Some(ClientHelloInfo {
                sni: None,
                sni_range: None,
                record_version,
                record_total_len,
                has_ech: false,
            })
        } else {
            None
        };
    }
    let comp_methods_len = body[pos] as usize;
    pos += 1 + comp_methods_len;

    // Extensions are optional in ancient TLS, required in TLS 1.2 SNI / TLS 1.3
    if body.len() == pos {
        return Some(ClientHelloInfo {
            sni: None,
            sni_range: None,
            record_version,
            record_total_len,
            has_ech: false,
        });
    }
    if body.len() < pos + 2 {
        return if allow_truncated && body_truncated {
            Some(ClientHelloInfo {
                sni: None,
                sni_range: None,
                record_version,
                record_total_len,
                has_ech: false,
            })
        } else {
            None
        };
    }
    let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if !allow_truncated && body.len() < pos + ext_total_len {
        return None;
    }
    let ext_end = (pos + ext_total_len).min(body.len());

    let mut sni: Option<String> = None;
    let mut sni_range: Option<(usize, usize)> = None;
    let mut has_ech = false;

    // Offset from start of `data` to start of `body` is 5 (record hdr) + 4 (handshake hdr) = 9
    const BODY_BASE: usize = 9;

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            if allow_truncated {
                // Chrome 131+ PQ extension permutation: if SNI straddles MSS boundary, extract partial
                // SNI byte range for splitting, and ONLY populate `sni` when the full hostname arrived.
                if ext_type == 0x0000 && pos + 5 < ext_end {
                    let avail = &body[pos..ext_end];
                    let name_type = avail[2];
                    let declared_name_len = u16::from_be_bytes([avail[3], avail[4]]) as usize;
                    let avail_name_len = declared_name_len.min(avail.len() - 5);
                    if name_type == 0 && avail_name_len > 0 {
                        let abs_start = BODY_BASE + pos + 5;
                        let abs_end = abs_start + avail_name_len;
                        sni_range = Some((abs_start, abs_end));
                        if avail_name_len == declared_name_len {
                            if let Ok(full_sni) = std::str::from_utf8(&avail[5..5 + avail_name_len]) {
                                sni = Some(full_sni.to_ascii_lowercase());
                            }
                        }
                    }
                }
                break;
            }
            return None;
        }
        let ext_data = &body[pos..pos + ext_len];

        if ext_type == 0xfe0d {
            has_ech = true;
        } else if ext_type == 0x0000 && ext_len >= 5 {
            // server_name extension: 2 bytes list_len, then entries: 1 byte name_type (0=host_name), 2 bytes name_len
            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            if 2 + list_len <= ext_len {
                let mut epos = 2usize;
                let list_end = 2 + list_len;
                while epos + 3 <= list_end {
                    let name_type = ext_data[epos];
                    let name_len = u16::from_be_bytes([ext_data[epos + 1], ext_data[epos + 2]]) as usize;
                    epos += 3;
                    if epos + name_len > list_end {
                        break;
                    }
                    if name_type == 0 && name_len > 0 {
                        if let Ok(host) = std::str::from_utf8(&ext_data[epos..epos + name_len]) {
                            let abs_start = BODY_BASE + pos + epos;
                            let abs_end = abs_start + name_len;
                            sni = Some(host.to_ascii_lowercase());
                            sni_range = Some((abs_start, abs_end));
                            break;
                        }
                    }
                    epos += name_len;
                }
            }
        }

        pos += ext_len;
    }

    Some(ClientHelloInfo {
        sni,
        sni_range,
        record_version,
        record_total_len,
        has_ech,
    })
}

/// Fragments a TLS ClientHello record into two or more valid TLS Handshake records.
///
/// Works over ordinary OS TCP sockets (including Android & iOS sandboxes) because TLS
/// explicitly permits a single handshake message to span multiple TLSPlaintext records.
/// Concatenating the payloads of the returned records reconstructs the original handshake bytes identically.
pub fn fragment_tls_client_hello(data: &[u8], strategy: SplitStrategy) -> Option<Vec<u8>> {
    let info = parse_client_hello(data)?;
    let record_payload = &data[5..info.record_total_len];
    if record_payload.len() < 8 {
        return None;
    }

    let split_points: Vec<usize> = match strategy {
        SplitStrategy::SniMid => {
            let point = if let Some((start, end)) = info.sni_range {
                // Convert absolute offset to offset inside `record_payload` (subtract 5-byte record header)
                let rel_start = start.saturating_sub(5);
                let rel_end = end.saturating_sub(5);
                let mid = rel_start + (rel_end.saturating_sub(rel_start)) / 2;
                mid.clamp(1, record_payload.len() - 1)
            } else {
                (record_payload.len() / 2).clamp(1, record_payload.len() - 1)
            };
            vec![point]
        }
        SplitStrategy::OffsetAndSniMid(early) => {
            let p1 = early.clamp(1, record_payload.len() - 1);
            let p2 = if let Some((start, end)) = info.sni_range {
                let rel_start = start.saturating_sub(5);
                let rel_end = end.saturating_sub(5);
                let mid = rel_start + (rel_end.saturating_sub(rel_start)) / 2;
                mid.clamp(1, record_payload.len() - 1)
            } else {
                (record_payload.len() / 2).clamp(1, record_payload.len() - 1)
            };
            let mut pts = vec![p1, p2];
            pts.sort_unstable();
            pts.dedup();
            pts
        }
        SplitStrategy::FixedOffset(off) => {
            let point = off.clamp(1, record_payload.len() - 1);
            vec![point]
        }
        SplitStrategy::MultiChunk(chunk_size) => {
            let step = chunk_size.max(5);
            let mut pts = Vec::new();
            let mut idx = step;
            while idx < record_payload.len() {
                pts.push(idx);
                idx += step;
            }
            // Guarantee SNI hostname itself is ALWAYS split across two TLS records
            if let Some((start, end)) = info.sni_range {
                let rel_start = start.saturating_sub(5);
                let rel_end = end.saturating_sub(5);
                let mid = (rel_start + (rel_end.saturating_sub(rel_start)) / 2)
                    .clamp(1, record_payload.len() - 1);
                pts.push(mid);
            }
            if pts.is_empty() {
                pts.push(record_payload.len() / 2);
            }
            pts.sort_unstable();
            pts.dedup();
            pts
        }
    };

    let mut out = Vec::with_capacity(data.len() + split_points.len() * 5);
    let mut prev = 0usize;
    for &pt in &split_points {
        if pt > prev && pt < record_payload.len() {
            append_tls_record(&mut out, info.record_version, &record_payload[prev..pt]);
            prev = pt;
        }
    }
    append_tls_record(&mut out, info.record_version, &record_payload[prev..]);

    // Append any trailing bytes that followed the first TLS record (e.g., CCS/early data)
    if data.len() > info.record_total_len {
        out.extend_from_slice(&data[info.record_total_len..]);
    }
    Some(out)
}

fn append_tls_record(out: &mut Vec<u8>, version: [u8; 2], fragment: &[u8]) {
    // TLSPlaintext max fragment is 16384; ClientHello is well below that.
    out.push(0x16);
    out.push(version[0]);
    out.push(version[1]);
    out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
    out.extend_from_slice(fragment);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn build_sample_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let name_entry_len = 1 + 2 + sni_bytes.len();
        let sni_ext_data_len = 2 + name_entry_len;
        let extensions_len = 4 + sni_ext_data_len;

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version
        body.extend_from_slice(&[0xAA; 32]); // Random
        body.push(0x00); // Session ID len = 0
        body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // Cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // Compression: null
        body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        // SNI extension (0x0000)
        body.extend_from_slice(&0x0000u16.to_be_bytes());
        body.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        body.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
        body.push(0x00); // host_name
        body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(sni_bytes);

        let hs_len = body.len();
        let mut hs = Vec::with_capacity(4 + hs_len);
        hs.push(0x01); // ClientHello
        hs.push(((hs_len >> 16) & 0xFF) as u8);
        hs.push(((hs_len >> 8) & 0xFF) as u8);
        hs.push((hs_len & 0xFF) as u8);
        hs.extend_from_slice(&body);

        let mut rec = Vec::with_capacity(5 + hs.len());
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parses_sni_and_fragments_cleanly() {
        let ch = build_sample_client_hello("blocked.example.org");
        let info = parse_client_hello(&ch).expect("valid ClientHello");
        assert_eq!(info.sni.as_deref(), Some("blocked.example.org"));
        let (s, e) = info.sni_range.unwrap();
        assert_eq!(&ch[s..e], b"blocked.example.org");

        let frag = fragment_tls_client_hello(&ch, SplitStrategy::SniMid).unwrap();
        assert_eq!(frag.len(), ch.len() + 5);

        // Reassemble fragmented TLS records and confirm byte-for-byte identity with original handshake
        let mut reassembled = Vec::new();
        let mut idx = 0;
        let mut record_count = 0;
        while idx < frag.len() {
            assert_eq!(frag[idx], 0x16);
            let len = u16::from_be_bytes([frag[idx + 3], frag[idx + 4]]) as usize;
            reassembled.extend_from_slice(&frag[idx + 5..idx + 5 + len]);
            idx += 5 + len;
            record_count += 1;
        }
        assert_eq!(record_count, 2);
        assert_eq!(reassembled, ch[5..]);
    }

    #[test]
    fn rejects_truncated_or_non_tls_gracefully() {
        assert!(parse_client_hello(&[]).is_none());
        assert!(parse_client_hello(b"GET / HTTP/1.1\r\n").is_none());
        let ch = build_sample_client_hello("example.com");
        assert!(parse_client_hello(&ch[..ch.len() - 1]).is_none());
    }

    #[test]
    fn detects_tls_ech_extension_alongside_sni() {
        let sni_bytes = b"cloudflare-ech.com";
        let name_entry_len = 1 + 2 + sni_bytes.len();
        let sni_ext_data_len = 2 + name_entry_len;
        let ech_ext_data = [0x00u8, 0x01, 0x00, 0x01, 0xAA, 0xBB];
        let extensions_len = (4 + sni_ext_data_len) + (4 + ech_ext_data.len());

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xCC; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        // SNI extension
        body.extend_from_slice(&0x0000u16.to_be_bytes());
        body.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        body.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(sni_bytes);
        // ECH extension (0xfe0d)
        body.extend_from_slice(&0xfe0du16.to_be_bytes());
        body.extend_from_slice(&(ech_ext_data.len() as u16).to_be_bytes());
        body.extend_from_slice(&ech_ext_data);

        let hs_len = body.len();
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&((4 + hs_len) as u16).to_be_bytes());
        rec.push(0x01);
        rec.push(0);
        rec.extend_from_slice(&(hs_len as u16).to_be_bytes());
        rec.extend_from_slice(&body);

        let info = parse_client_hello(&rec).expect("valid ECH ClientHello");
        assert_eq!(info.sni.as_deref(), Some("cloudflare-ech.com"));
        assert!(info.has_ech);
    }

    #[test]
    fn parses_post_quantum_client_hello_sni_from_first_1460_byte_tcp_segment() {
        // Simulate Chrome 131+ X25519MLKEM768 ClientHello (~1900 bytes total):
        // SNI extension appears before a 1216-byte post-quantum key_share extension,
        // so segment #1 (1460 bytes) is truncated relative to record_len.
        let sni_bytes = b"pq-censored.example.org";
        let name_entry_len = 1 + 2 + sni_bytes.len();
        let sni_ext_data_len = 2 + name_entry_len;
        let pq_key_share_len = 1700usize;
        let extensions_len = (4 + sni_ext_data_len) + (4 + pq_key_share_len);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xDD; 32]);
        body.push(32);
        body.extend_from_slice(&[0xEE; 32]);
        body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        // SNI extension
        body.extend_from_slice(&0x0000u16.to_be_bytes());
        body.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        body.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(sni_bytes);
        // Large post-quantum key_share extension (0x0033)
        body.extend_from_slice(&0x0033u16.to_be_bytes());
        body.extend_from_slice(&(pq_key_share_len as u16).to_be_bytes());
        body.resize(body.len() + pq_key_share_len, 0x42);

        let hs_len = body.len();
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&((4 + hs_len) as u16).to_be_bytes());
        rec.push(0x01);
        rec.push(((hs_len >> 16) & 0xFF) as u8);
        rec.push(((hs_len >> 8) & 0xFF) as u8);
        rec.push((hs_len & 0xFF) as u8);
        rec.extend_from_slice(&body);
        assert!(rec.len() > 1460);

        let first_mss_segment = &rec[..1460];
        // Strict full-record parser rejects incomplete segment (required for TLS record fragmentation)
        assert!(parse_client_hello(first_mss_segment).is_none());
        // Prefix parser extracts exact SNI & range so L3 TCP splitting works on Chrome 131+ PQ!
        let info = parse_client_hello_prefix(first_mss_segment).expect("prefix parser must find PQ SNI");
        assert_eq!(info.sni.as_deref(), Some("pq-censored.example.org"));
        let (s, e) = info.sni_range.unwrap();
        assert_eq!(&first_mss_segment[s..e], b"pq-censored.example.org");
    }
}
