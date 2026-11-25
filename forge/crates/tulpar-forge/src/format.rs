//! Portable, self-contained `.tulpar` binary package format (`TULPARF1`) with SHA-256 integrity seal.
//!
//! Layout:
//! - `[0..8]`   Magic `"TULPARF1"`
//! - `[8..10]`  Format version (`u16::to_be_bytes(1)`)
//! - `[10..12]` Flags (`u16` reserved, 0)
//! - `[12..]`   Canonical length-prefixed IR body (metadata + rollback policy + rules + lab_assert)
//! - `[end-32..]` SHA-256 digest of `data[..end - 32]`

use std::fmt;

use crate::ast::{
    DecoySpec, DecoyTtlMode, LabExpectations, MatchProtocol, MatchSpec, QuicMode, RawActionSpec,
    RawFallbackPolicy, RollbackPolicy, SocketActionSpec, SplitCutSpec, StrategyRule,
    StrategySpec, TlsRecordMode, MAX_DECOYS_PER_RULE, MAX_PACKAGE_BYTES, MAX_PORTS_PER_RULE,
    MAX_RULES, MAX_SNI_SUFFIXES_PER_RULE, MAX_SPLIT_CUTS,
};
use crate::sha256::{constant_time_eq_32, sha256_digest, sha256_hex};
use crate::verifier::{ForgeVerifier, VerifyError, VerifyReport};

pub const PACKAGE_MAGIC: &[u8; 8] = b"TULPARF1";
pub const PACKAGE_FORMAT_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgePackage {
    pub spec: StrategySpec,
    pub sha256: [u8; 32],
    pub sha256_hex: String,
    pub report: VerifyReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    TooLarge(usize),
    InvalidMagic,
    UnsupportedVersion(u16),
    Truncated,
    TrailingBytes,
    IntegrityCheckFailed,
    InvalidUtf8,
    InvalidTag(&'static str, u8),
    VerifyFailed(VerifyError),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(n) => write!(f, ".tulpar package size {n} exceeds {MAX_PACKAGE_BYTES}"),
            Self::InvalidMagic => write!(f, "invalid .tulpar package magic (expected TULPARF1)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported .tulpar format version {v}"),
            Self::Truncated => write!(f, "truncated .tulpar package"),
            Self::TrailingBytes => write!(f, "unexpected trailing bytes in .tulpar package"),
            Self::IntegrityCheckFailed => {
                write!(f, "SHA-256 integrity verification failed (corrupted or tampered .tulpar)")
            }
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 string in .tulpar package"),
            Self::InvalidTag(what, tag) => write!(f, "invalid {what} tag: 0x{tag:02x}"),
            Self::VerifyFailed(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FormatError {}

impl From<VerifyError> for FormatError {
    fn from(value: VerifyError) -> Self {
        Self::VerifyFailed(value)
    }
}

impl ForgePackage {
    /// Verifies `spec` statically and encodes a SHA-256 sealed portable `.tulpar` byte buffer.
    pub fn compile(spec: &StrategySpec) -> Result<(Self, Vec<u8>), FormatError> {
        let report = ForgeVerifier::verify(spec)?;

        let mut buf = Vec::with_capacity(1024);
        buf.extend_from_slice(PACKAGE_MAGIC);
        buf.extend_from_slice(&PACKAGE_FORMAT_VERSION.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        write_str(&mut buf, &spec.name);
        write_str(&mut buf, &spec.version);
        write_str(&mut buf, &spec.author);
        write_str(&mut buf, &spec.description);
        write_str(&mut buf, &spec.min_core_version);
        buf.push(spec.fallback_policy as u8);

        buf.push(spec.rollback.max_consecutive_failures);
        buf.extend_from_slice(&spec.rollback.min_samples.to_be_bytes());
        buf.push(spec.rollback.max_failure_pct);

        buf.extend_from_slice(&(spec.rules.len() as u16).to_be_bytes());
        for r in &spec.rules {
            write_str(&mut buf, &r.name);
            buf.extend_from_slice(&r.priority.to_be_bytes());
            buf.push(r.when_on_retry);

            buf.push(r.matcher.protocols.len() as u8);
            for p in &r.matcher.protocols {
                buf.push(*p as u8);
            }
            buf.push(r.matcher.ports.len() as u8);
            for port in &r.matcher.ports {
                buf.extend_from_slice(&port.to_be_bytes());
            }
            buf.push(r.matcher.sni_suffixes.len() as u8);
            for s in &r.matcher.sni_suffixes {
                write_str(&mut buf, s);
            }
            buf.extend_from_slice(&r.matcher.min_payload.to_be_bytes());
            buf.push(u8::from(r.matcher.exclude_sensitive));

            match &r.raw_actions {
                None => buf.push(0),
                Some(raw) => {
                    buf.push(1);
                    buf.push(u8::from(raw.passthrough));
                    write_cuts(&mut buf, &raw.tcp_splits);
                    buf.push(u8::from(raw.disorder));
                    write_str(&mut buf, &raw.decoy_sni);
                    buf.push(raw.decoys.len() as u8);
                    for d in &raw.decoys {
                        match d {
                            DecoySpec::BadChecksum => {
                                buf.push(1);
                                buf.push(0);
                            }
                            DecoySpec::WrongSeq => {
                                buf.push(2);
                                buf.push(0);
                            }
                            DecoySpec::BadChecksumWrongSeq => {
                                buf.push(3);
                                buf.push(0);
                            }
                            DecoySpec::LowTtl(DecoyTtlMode::AutoCalibrated) => {
                                buf.push(4);
                                buf.push(0);
                            }
                            DecoySpec::LowTtl(DecoyTtlMode::Fixed(t)) => {
                                buf.push(5);
                                buf.push(*t);
                            }
                            DecoySpec::LowTtlWrongSeq(DecoyTtlMode::AutoCalibrated) => {
                                buf.push(6);
                                buf.push(0);
                            }
                            DecoySpec::LowTtlWrongSeq(DecoyTtlMode::Fixed(t)) => {
                                buf.push(7);
                                buf.push(*t);
                            }
                        }
                    }
                    buf.push(u8::from(raw.http_split_host));
                    buf.push(u8::from(raw.http_host_case));
                    match raw.syn_mss_clamp {
                        None => {
                            buf.push(0);
                            buf.extend_from_slice(&0u16.to_be_bytes());
                        }
                        Some(m) => {
                            buf.push(1);
                            buf.extend_from_slice(&m.to_be_bytes());
                        }
                    }
                    buf.push(u8::from(raw.drop_forged_passive_rst));
                    buf.push(u8::from(raw.drop_forged_http_redirect));
                }
            }

            match &r.socket_actions {
                None => buf.push(0),
                Some(sock) => {
                    buf.push(1);
                    buf.push(u8::from(sock.passthrough));
                    match sock.tls_record {
                        None => {
                            buf.push(0);
                            buf.extend_from_slice(&0u16.to_be_bytes());
                        }
                        Some(TlsRecordMode::None) => {
                            buf.push(1);
                            buf.extend_from_slice(&0u16.to_be_bytes());
                        }
                        Some(TlsRecordMode::SniMid) => {
                            buf.push(2);
                            buf.extend_from_slice(&0u16.to_be_bytes());
                        }
                        Some(TlsRecordMode::OffsetAndSniMid(o)) => {
                            buf.push(3);
                            buf.extend_from_slice(&o.to_be_bytes());
                        }
                        Some(TlsRecordMode::SmallChunks(c)) => {
                            buf.push(4);
                            buf.extend_from_slice(&c.to_be_bytes());
                        }
                    }
                    write_cuts(&mut buf, &sock.tcp_splits);
                    buf.push(u8::from(sock.paced_flush));
                    buf.push(u8::from(sock.tcp_oob));
                    buf.push(u8::from(sock.http_split_host));
                    buf.push(u8::from(sock.http_host_case));
                }
            }

            match r.quic_mode {
                None => {
                    buf.push(0);
                    buf.push(0);
                }
                Some(QuicMode::Allow) => {
                    buf.push(1);
                    buf.push(0);
                }
                Some(QuicMode::BlockFallbackTcp) => {
                    buf.push(2);
                    buf.push(0);
                }
                Some(QuicMode::DesyncTtl(t)) => {
                    buf.push(3);
                    buf.push(t);
                }
            }

            match r.udp_desync_ttl {
                None => {
                    buf.push(0);
                    buf.push(0);
                }
                Some(t) => {
                    buf.push(1);
                    buf.push(t);
                }
            }
            buf.push(u8::from(r.udp_bad_checksum_decoy));
        }

        buf.push(spec.lab_assert.expect_pass.len().min(64) as u8);
        for s in spec.lab_assert.expect_pass.iter().take(64) {
            write_str(&mut buf, s);
        }
        buf.push(spec.lab_assert.expect_honest_unbypassable.len().min(64) as u8);
        for s in spec.lab_assert.expect_honest_unbypassable.iter().take(64) {
            write_str(&mut buf, s);
        }

        let sha256 = sha256_digest(&buf);
        let sha256_hex = sha256_hex(&buf);
        buf.extend_from_slice(&sha256);

        if buf.len() > MAX_PACKAGE_BYTES {
            return Err(FormatError::TooLarge(buf.len()));
        }

        Ok((
            Self {
                spec: spec.clone(),
                sha256,
                sha256_hex,
                report,
            },
            buf,
        ))
    }

    /// Decodes, verifies SHA-256 seal, and runs full `ForgeVerifier` audit before returning.
    pub fn decode_verified(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err(FormatError::TooLarge(bytes.len()));
        }
        if bytes.len() < 12 + 32 {
            return Err(FormatError::Truncated);
        }
        if &bytes[..8] != PACKAGE_MAGIC {
            return Err(FormatError::InvalidMagic);
        }
        let ver = u16::from_be_bytes([bytes[8], bytes[9]]);
        if ver != PACKAGE_FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(ver));
        }

        let split = bytes.len() - 32;
        let payload = &bytes[..split];
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&bytes[split..]);
        let actual = sha256_digest(payload);
        if !constant_time_eq_32(&actual, &expected) {
            return Err(FormatError::IntegrityCheckFailed);
        }

        let mut r = Reader {
            data: payload,
            pos: 12,
        };
        let name = r.read_str()?;
        let version = r.read_str()?;
        let author = r.read_str()?;
        let description = r.read_str()?;
        let min_core_version = r.read_str()?;
        let fallback_policy = match r.read_u8()? {
            0 => RawFallbackPolicy::Strict,
            1 => RawFallbackPolicy::AutoDegrade,
            other => return Err(FormatError::InvalidTag("fallback_policy", other)),
        };

        let max_consecutive_failures = r.read_u8()?;
        let min_samples = r.read_u16()?;
        let max_failure_pct = r.read_u8()?;

        let rule_count = r.read_u16()? as usize;
        if rule_count > MAX_RULES {
            return Err(FormatError::TooLarge(rule_count));
        }
        let mut rules = Vec::with_capacity(rule_count);
        for _ in 0..rule_count {
            let rname = r.read_str()?;
            let priority = r.read_u16()?;
            let when_on_retry = r.read_u8()?;

            let pcount = r.read_u8()? as usize;
            if pcount > 16 {
                return Err(FormatError::Truncated);
            }
            let mut protocols = Vec::with_capacity(pcount);
            for _ in 0..pcount {
                let p = match r.read_u8()? {
                    1 => MatchProtocol::Tls,
                    2 => MatchProtocol::Http,
                    3 => MatchProtocol::Quic,
                    4 => MatchProtocol::UdpStun,
                    5 => MatchProtocol::UdpRakNet,
                    6 => MatchProtocol::Any,
                    other => return Err(FormatError::InvalidTag("protocol", other)),
                };
                protocols.push(p);
            }
            let port_count = r.read_u8()? as usize;
            if port_count > MAX_PORTS_PER_RULE {
                return Err(FormatError::Truncated);
            }
            let mut ports = Vec::with_capacity(port_count);
            for _ in 0..port_count {
                ports.push(r.read_u16()?);
            }
            let suf_count = r.read_u8()? as usize;
            if suf_count > MAX_SNI_SUFFIXES_PER_RULE {
                return Err(FormatError::Truncated);
            }
            let mut sni_suffixes = Vec::with_capacity(suf_count);
            for _ in 0..suf_count {
                sni_suffixes.push(r.read_str()?);
            }
            let min_payload = r.read_u16()?;
            let exclude_sensitive = r.read_u8()? != 0;

            let raw_actions = match r.read_u8()? {
                0 => None,
                1 => {
                    let passthrough = r.read_u8()? != 0;
                    let tcp_splits = read_cuts(&mut r)?;
                    let disorder = r.read_u8()? != 0;
                    let decoy_sni = r.read_str()?;
                    let decoy_count = r.read_u8()? as usize;
                    if decoy_count > MAX_DECOYS_PER_RULE {
                        return Err(FormatError::Truncated);
                    }
                    let mut decoys = Vec::with_capacity(decoy_count);
                    for _ in 0..decoy_count {
                        let tag = r.read_u8()?;
                        let arg = r.read_u8()?;
                        let d = match tag {
                            1 => DecoySpec::BadChecksum,
                            2 => DecoySpec::WrongSeq,
                            3 => DecoySpec::BadChecksumWrongSeq,
                            4 => DecoySpec::LowTtl(DecoyTtlMode::AutoCalibrated),
                            5 => DecoySpec::LowTtl(DecoyTtlMode::Fixed(arg)),
                            6 => DecoySpec::LowTtlWrongSeq(DecoyTtlMode::AutoCalibrated),
                            7 => DecoySpec::LowTtlWrongSeq(DecoyTtlMode::Fixed(arg)),
                            other => return Err(FormatError::InvalidTag("decoy", other)),
                        };
                        decoys.push(d);
                    }
                    let http_split_host = r.read_u8()? != 0;
                    let http_host_case = r.read_u8()? != 0;
                    let has_mss = r.read_u8()? != 0;
                    let mss_val = r.read_u16()?;
                    let syn_mss_clamp = if has_mss { Some(mss_val) } else { None };
                    let drop_forged_passive_rst = r.read_u8()? != 0;
                    let drop_forged_http_redirect = r.read_u8()? != 0;
                    Some(RawActionSpec {
                        passthrough,
                        tcp_splits,
                        disorder,
                        decoy_sni,
                        decoys,
                        http_split_host,
                        http_host_case,
                        syn_mss_clamp,
                        drop_forged_passive_rst,
                        drop_forged_http_redirect,
                    })
                }
                other => return Err(FormatError::InvalidTag("raw_present", other)),
            };

            let socket_actions = match r.read_u8()? {
                0 => None,
                1 => {
                    let passthrough = r.read_u8()? != 0;
                    let tls_tag = r.read_u8()?;
                    let tls_arg = r.read_u16()?;
                    let tls_record = match tls_tag {
                        0 => None,
                        1 => Some(TlsRecordMode::None),
                        2 => Some(TlsRecordMode::SniMid),
                        3 => Some(TlsRecordMode::OffsetAndSniMid(tls_arg)),
                        4 => Some(TlsRecordMode::SmallChunks(tls_arg)),
                        other => return Err(FormatError::InvalidTag("tls_record", other)),
                    };
                    let tcp_splits = read_cuts(&mut r)?;
                    let paced_flush = r.read_u8()? != 0;
                    let tcp_oob = r.read_u8()? != 0;
                    let http_split_host = r.read_u8()? != 0;
                    let http_host_case = r.read_u8()? != 0;
                    Some(SocketActionSpec {
                        passthrough,
                        tls_record,
                        tcp_splits,
                        paced_flush,
                        tcp_oob,
                        http_split_host,
                        http_host_case,
                    })
                }
                other => return Err(FormatError::InvalidTag("socket_present", other)),
            };

            let qtag = r.read_u8()?;
            let qarg = r.read_u8()?;
            let quic_mode = match qtag {
                0 => None,
                1 => Some(QuicMode::Allow),
                2 => Some(QuicMode::BlockFallbackTcp),
                3 => Some(QuicMode::DesyncTtl(qarg)),
                other => return Err(FormatError::InvalidTag("quic_mode", other)),
            };

            let utag = r.read_u8()?;
            let uarg = r.read_u8()?;
            let udp_desync_ttl = match utag {
                0 => None,
                1 => Some(uarg),
                other => return Err(FormatError::InvalidTag("udp_desync", other)),
            };
            let udp_bad_checksum_decoy = r.read_u8()? != 0;

            rules.push(StrategyRule {
                name: rname,
                priority,
                when_on_retry,
                matcher: MatchSpec {
                    protocols,
                    ports,
                    sni_suffixes,
                    min_payload,
                    exclude_sensitive,
                },
                raw_actions,
                socket_actions,
                quic_mode,
                udp_desync_ttl,
                udp_bad_checksum_decoy,
            });
        }

        let ep_count = r.read_u8()? as usize;
        if ep_count > 64 {
            return Err(FormatError::Truncated);
        }
        let mut expect_pass = Vec::with_capacity(ep_count);
        for _ in 0..ep_count {
            expect_pass.push(r.read_str()?);
        }
        let eh_count = r.read_u8()? as usize;
        if eh_count > 64 {
            return Err(FormatError::Truncated);
        }
        let mut expect_honest_unbypassable = Vec::with_capacity(eh_count);
        for _ in 0..eh_count {
            expect_honest_unbypassable.push(r.read_str()?);
        }

        if r.pos != r.data.len() {
            return Err(FormatError::TrailingBytes);
        }

        let spec = StrategySpec {
            name,
            version,
            author,
            description,
            min_core_version,
            fallback_policy,
            rollback: RollbackPolicy {
                max_consecutive_failures,
                min_samples,
                max_failure_pct,
            },
            rules,
            lab_assert: LabExpectations {
                expect_pass,
                expect_honest_unbypassable,
            },
        };

        let report = ForgeVerifier::verify(&spec)?;
        Ok(Self {
            spec,
            sha256: actual,
            sha256_hex: sha256_hex(payload),
            report,
        })
    }
}

fn write_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let len = b.len().min(u16::MAX as usize) as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&b[..len as usize]);
}

fn write_cuts(out: &mut Vec<u8>, cuts: &[SplitCutSpec]) {
    out.push(cuts.len().min(MAX_SPLIT_CUTS) as u8);
    for c in cuts.iter().take(MAX_SPLIT_CUTS) {
        match c {
            SplitCutSpec::FixedOffset(o) => {
                out.push(1);
                out.extend_from_slice(&o.to_be_bytes());
            }
            SplitCutSpec::SniMid => {
                out.push(2);
                out.extend_from_slice(&0u16.to_be_bytes());
            }
            SplitCutSpec::HostMid => {
                out.push(3);
                out.extend_from_slice(&0u16.to_be_bytes());
            }
            SplitCutSpec::FirstRecordEnd => {
                out.push(4);
                out.extend_from_slice(&0u16.to_be_bytes());
            }
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        let end = self.pos.checked_add(n).ok_or(FormatError::Truncated)?;
        if end > self.data.len() {
            return Err(FormatError::Truncated);
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, FormatError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, FormatError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn read_str(&mut self) -> Result<String, FormatError> {
        let len = self.read_u16()? as usize;
        if len > 1024 {
            return Err(FormatError::TooLarge(len));
        }
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|_| FormatError::InvalidUtf8)
    }
}

fn read_cuts(r: &mut Reader<'_>) -> Result<Vec<SplitCutSpec>, FormatError> {
    let count = r.read_u8()? as usize;
    if count > MAX_SPLIT_CUTS {
        return Err(FormatError::Truncated);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let tag = r.read_u8()?;
        let arg = r.read_u16()?;
        let cut = match tag {
            1 => SplitCutSpec::FixedOffset(arg),
            2 => SplitCutSpec::SniMid,
            3 => SplitCutSpec::HostMid,
            4 => SplitCutSpec::FirstRecordEnd,
            other => return Err(FormatError::InvalidTag("split_cut", other)),
        };
        out.push(cut);
    }
    Ok(out)
}
