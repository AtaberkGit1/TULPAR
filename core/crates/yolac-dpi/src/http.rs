//! Plaintext HTTP/1.x Host header detection and DPI evasion transforms.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHostInfo {
    pub host: String,
    /// Offset of the `Host:` header name start.
    pub header_name_start: usize,
    /// Offset range `(start, end)` of the host value inside the request buffer.
    pub host_range: (usize, usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpEvasionOptions {
    /// Mix casing of `Host:` -> `hOsT:` (RFC 9110 header names are case-insensitive).
    pub mix_host_case: bool,
    /// Remove optional single space after `Host:` if present (`Host:example.com`).
    pub remove_space_after_colon: bool,
}

impl Default for HttpEvasionOptions {
    fn default() -> Self {
        Self {
            mix_host_case: true,
            remove_space_after_colon: false,
        }
    }
}

const HTTP_METHODS: [&[u8]; 8] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
];

/// Parses an HTTP/1.x request's `Host` header offsets cleanly.
pub fn parse_http_host(data: &[u8]) -> Option<HttpHostInfo> {
    if !HTTP_METHODS.iter().any(|m| data.starts_with(m)) {
        return None;
    }

    let mut line_start = 0usize;
    while line_start < data.len() {
        let line_end = data[line_start..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| line_start + p)
            .unwrap_or(data.len());
        let line = &data[line_start..line_end];
        if line.is_empty() {
            break; // End of headers
        }

        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            let mut val_start = line_start + 5;
            while val_start < line_end && (data[val_start] == b' ' || data[val_start] == b'\t') {
                val_start += 1;
            }
            let mut val_end = line_end;
            while val_end > val_start && (data[val_end - 1] == b' ' || data[val_end - 1] == b'\t') {
                val_end -= 1;
            }
            if val_end > val_start {
                if let Ok(raw_host) = std::str::from_utf8(&data[val_start..val_end]) {
                    let (host_only, host_len) = if let Some(bracket_end) = raw_host.find(']') {
                        (&raw_host[..=bracket_end], bracket_end + 1)
                    } else if let Some(colon) = raw_host.rfind(':') {
                        (&raw_host[..colon], colon)
                    } else {
                        (raw_host, raw_host.len())
                    };
                    if host_len > 0 {
                        return Some(HttpHostInfo {
                            host: host_only.to_ascii_lowercase(),
                            header_name_start: line_start,
                            host_range: (val_start, val_start + host_len),
                        });
                    }
                }
            }
        }

        if line_end >= data.len() {
            break;
        }
        line_start = line_end + 2;
    }

    None
}

/// Applies RFC-compliant HTTP header evasion (e.g., `Host:` -> `hOsT:`) to defeat naive DPI matches.
pub fn evade_http_request(data: &[u8], opts: HttpEvasionOptions) -> Option<Vec<u8>> {
    let info = parse_http_host(data)?;
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..info.header_name_start]);
    if opts.mix_host_case {
        out.extend_from_slice(b"hOsT:");
    } else {
        out.extend_from_slice(&data[info.header_name_start..info.header_name_start + 5]);
    }

    let after_colon = info.header_name_start + 5;
    if opts.remove_space_after_colon && after_colon < info.host_range.0 {
        out.extend_from_slice(&data[info.host_range.0..]);
    } else {
        out.extend_from_slice(&data[after_colon..]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_evades_http_host() {
        let req = b"GET /news HTTP/1.1\r\nUser-Agent: test\r\nHost: blocked.example.com\r\n\r\n";
        let info = parse_http_host(req).unwrap();
        assert_eq!(info.host, "blocked.example.com");
        assert_eq!(&req[info.host_range.0..info.host_range.1], b"blocked.example.com");

        let evaded = evade_http_request(req, HttpEvasionOptions::default()).unwrap();
        assert!(evaded.windows(5).any(|w| w == b"hOsT:"));
        let re_parsed = parse_http_host(&evaded).unwrap();
        assert_eq!(re_parsed.host, "blocked.example.com");
    }
}
