//! Valid, RFC-compliant benign decoy TLS ClientHello and HTTP request builders.
//!
//! Real ISP DPI appliances (Sandvine, Procera, Huawei, Allot) validate TLS record/handshake
//! headers and extensions before updating per-flow state; malformed tiny dummy payloads are
//! ignored by stateful DPI. Sending a complete, valid benign ClientHello (`www.iana.org`)
//! with wrong-seq / bad-checksum / calibrated low-TTL genuinely desynchronizes the DPI
//! state machine while being silently discarded by the destination server.

/// Builds a complete, valid RFC 5246/8446 TLS ClientHello targeting a benign SNI (e.g. `www.iana.org`).
pub fn build_benign_fake_client_hello(benign_sni: &str) -> Vec<u8> {
    let sni_bytes = benign_sni.as_bytes();
    let name_entry_len = 1 + 2 + sni_bytes.len();
    let sni_ext_data_len = 2 + name_entry_len;

    // Build realistic TLS 1.3 + 1.2 extensions: SNI (0x0000), supported_groups (0x000a),
    // ec_point_formats (0x000b), signature_algorithms (0x000d), ALPN (0x0010),
    // supported_versions (0x002b), key_share (0x0033 with 32-byte x25519 dummy pubkey).
    let mut exts = Vec::with_capacity(160 + sni_bytes.len());

    // 1. server_name (0x0000)
    exts.extend_from_slice(&0x0000u16.to_be_bytes());
    exts.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    exts.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
    exts.push(0x00); // host_name
    exts.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    exts.extend_from_slice(sni_bytes);

    // 2. supported_groups (0x000a): x25519 (0x001d), secp256r1 (0x0017)
    exts.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);

    // 3. ec_point_formats (0x000b): uncompressed
    exts.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);

    // 4. signature_algorithms (0x000d)
    exts.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x0a, 0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
    ]);

    // 5. ALPN (0x0010): h2, http/1.1
    exts.extend_from_slice(&[
        0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/',
        b'1', b'.', b'1',
    ]);

    // 6. supported_versions (0x002b): TLS 1.3 (0x0304), TLS 1.2 (0x0303)
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);

    // 7. key_share (0x0033): x25519 (0x001d) 32-byte key
    exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    exts.extend_from_slice(&[0x37u8; 32]);

    // ClientHello body
    let mut body = Vec::with_capacity(96 + exts.len());
    body.extend_from_slice(&[0x03, 0x03]); // legacy TLS 1.2
    body.extend_from_slice(&[0x59u8; 32]); // Client Random
    body.push(32); // Session ID len = 32 (TLS 1.3 middlebox compatibility)
    body.extend_from_slice(&[0xA5u8; 32]); // Session ID
    // Standard Chrome/Firefox cipher suites
    let ciphers: &[u8] = &[
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    ];
    body.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    body.extend_from_slice(ciphers);
    body.extend_from_slice(&[0x01, 0x00]); // Compression: null
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let hs_len = body.len();
    let mut rec = Vec::with_capacity(9 + hs_len);
    rec.push(0x16); // Handshake
    rec.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record layer version
    rec.extend_from_slice(&((4 + hs_len) as u16).to_be_bytes());
    rec.push(0x01); // ClientHello
    rec.push(((hs_len >> 16) & 0xFF) as u8);
    rec.push(((hs_len >> 8) & 0xFF) as u8);
    rec.push((hs_len & 0xFF) as u8);
    rec.extend_from_slice(&body);
    rec
}

/// Builds a valid benign plaintext HTTP/1.1 GET request for HTTP DPI desync decoys.
pub fn build_benign_fake_http_request(benign_host: &str) -> Vec<u8> {
    format!(
        "GET / HTTP/1.1\r\nHost: {benign_host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::parse_http_host;
    use crate::tls::parse_client_hello;

    #[test]
    fn benign_fake_client_hello_parses_cleanly_as_valid_tls_with_sni() {
        let fake = build_benign_fake_client_hello("www.iana.org");
        assert!(fake.len() >= 180);
        let parsed = parse_client_hello(&fake).expect("fake ClientHello must be 100% valid TLS");
        assert_eq!(parsed.sni.as_deref(), Some("www.iana.org"));

        let fake_http = build_benign_fake_http_request("www.iana.org");
        let parsed_http = parse_http_host(&fake_http).expect("fake HTTP must be valid");
        assert_eq!(parsed_http.host, "www.iana.org");
    }
}
