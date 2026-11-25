//! Declarative TULPAR Strategy Language (TSL v1) lexer, recursive-descent parser, and decompiler.

use std::fmt;

use crate::ast::{
    DecoySpec, DecoyTtlMode, LabExpectations, MatchProtocol, MatchSpec, QuicMode, RawActionSpec,
    RawFallbackPolicy, RollbackPolicy, SocketActionSpec, SplitCutSpec, StrategyRule,
    StrategySpec, TlsRecordMode,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DslError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for DslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TSL parse error on line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for DslError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokKind {
    Ident(String),
    Str(String),
    Num(u64),
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Eq,
    EqEq,
    GtEq,
    Comma,
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokKind,
    line: usize,
}

fn tokenize(src: &str) -> Result<Vec<Token>, DslError> {
    if src.len() > 128 * 1024 {
        return Err(DslError {
            line: 1,
            message: "strategy source exceeds 128 KiB limit".into(),
        });
    }
    let mut tokens = Vec::new();
    let mut chars = src.char_indices().peekable();
    let mut line = 1usize;

    while let Some(&(_, ch)) = chars.peek() {
        if ch == '\n' {
            line += 1;
            chars.next();
            continue;
        }
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch == '#' {
            for (_, c) in chars.by_ref() {
                if c == '\n' {
                    line += 1;
                    break;
                }
            }
            continue;
        }
        if ch == '/' {
            chars.next();
            if chars.peek().is_some_and(|&(_, c)| c == '/') {
                for (_, c) in chars.by_ref() {
                    if c == '\n' {
                        line += 1;
                        break;
                    }
                }
                continue;
            }
            return Err(DslError {
                line,
                message: "unexpected '/' (comments use '#' or '//')".into(),
            });
        }
        if ch == '"' {
            let start_line = line;
            chars.next();
            let mut s = String::new();
            let mut closed = false;
            while let Some((_, c)) = chars.next() {
                if c == '\n' {
                    return Err(DslError {
                        line: start_line,
                        message: "unterminated string literal".into(),
                    });
                }
                if c == '\\' {
                    let Some((_, esc)) = chars.next() else {
                        return Err(DslError {
                            line: start_line,
                            message: "unterminated escape in string".into(),
                        });
                    };
                    match esc {
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        other => {
                            return Err(DslError {
                                line: start_line,
                                message: format!("unsupported string escape '\\{other}'"),
                            });
                        }
                    }
                } else if c == '"' {
                    closed = true;
                    break;
                } else {
                    s.push(c);
                }
            }
            if !closed {
                return Err(DslError {
                    line: start_line,
                    message: "unterminated string literal".into(),
                });
            }
            tokens.push(Token {
                kind: TokKind::Str(s),
                line: start_line,
            });
            continue;
        }

        if ch.is_ascii_digit() {
            let mut n = 0u64;
            while let Some(&(_, d)) = chars.peek() {
                if !d.is_ascii_digit() {
                    break;
                }
                chars.next();
                n = n
                    .checked_mul(10)
                    .and_then(|v| v.checked_add((d as u8 - b'0') as u64))
                    .ok_or_else(|| DslError {
                        line,
                        message: "integer literal overflow".into(),
                    })?;
            }
            tokens.push(Token {
                kind: TokKind::Num(n),
                line,
            });
            continue;
        }

        if ch.is_ascii_alphabetic() || ch == '_' {
            let mut id = String::new();
            while let Some(&(_, c)) = chars.peek() {
                if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                    id.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(Token {
                kind: TokKind::Ident(id),
                line,
            });
            continue;
        }

        let tok = match ch {
            '{' => {
                chars.next();
                TokKind::LBrace
            }
            '}' => {
                chars.next();
                TokKind::RBrace
            }
            '[' => {
                chars.next();
                TokKind::LBracket
            }
            ']' => {
                chars.next();
                TokKind::RBracket
            }
            '(' => {
                chars.next();
                TokKind::LParen
            }
            ')' => {
                chars.next();
                TokKind::RParen
            }
            ',' => {
                chars.next();
                TokKind::Comma
            }
            '=' => {
                chars.next();
                if chars.peek().is_some_and(|&(_, c)| c == '=') {
                    chars.next();
                    TokKind::EqEq
                } else {
                    TokKind::Eq
                }
            }
            '>' => {
                chars.next();
                if chars.peek().is_some_and(|&(_, c)| c == '=') {
                    chars.next();
                    TokKind::GtEq
                } else {
                    return Err(DslError {
                        line,
                        message: "expected '>=' after '>'".into(),
                    });
                }
            }
            other => {
                return Err(DslError {
                    line,
                    message: format!("unexpected character '{other}'"),
                });
            }
        };
        tokens.push(Token { kind: tok, line });
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn cur_line(&self) -> usize {
        self.peek()
            .map(|t| t.line)
            .or_else(|| self.tokens.last().map(|t| t.line))
            .unwrap_or(1)
    }

    fn next(&mut self) -> Result<Token, DslError> {
        let line = self.cur_line();
        if self.pos >= self.tokens.len() {
            return Err(DslError {
                line,
                message: "unexpected end of strategy source".into(),
            });
        }
        let tok = self.tokens[self.pos].clone();
        self.pos += 1;
        Ok(tok)
    }

    fn expect_ident(&mut self, expected: Option<&str>) -> Result<(String, usize), DslError> {
        let tok = self.next()?;
        match tok.kind {
            TokKind::Ident(s) => {
                if let Some(exp) = expected {
                    if s != exp {
                        return Err(DslError {
                            line: tok.line,
                            message: format!("expected '{exp}', found '{s}'"),
                        });
                    }
                }
                Ok((s, tok.line))
            }
            other => Err(DslError {
                line: tok.line,
                message: format!("expected identifier, found {other:?}"),
            }),
        }
    }

    fn expect_str(&mut self) -> Result<(String, usize), DslError> {
        let tok = self.next()?;
        match tok.kind {
            TokKind::Str(s) => Ok((s, tok.line)),
            other => Err(DslError {
                line: tok.line,
                message: format!("expected string literal, found {other:?}"),
            }),
        }
    }

    fn expect_bool(&mut self) -> Result<bool, DslError> {
        let (id, line) = self.expect_ident(None)?;
        match id.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(DslError {
                line,
                message: format!("expected 'true' or 'false', found '{id}'"),
            }),
        }
    }

    fn expect_u64(&mut self) -> Result<(u64, usize), DslError> {
        let tok = self.next()?;
        match tok.kind {
            TokKind::Num(n) => Ok((n, tok.line)),
            other => Err(DslError {
                line: tok.line,
                message: format!("expected unsigned integer, found {other:?}"),
            }),
        }
    }

    fn expect_kind(&mut self, kind: &TokKind) -> Result<usize, DslError> {
        let tok = self.next()?;
        if &tok.kind == kind {
            Ok(tok.line)
        } else {
            Err(DslError {
                line: tok.line,
                message: format!("expected {kind:?}, found {:?}", tok.kind),
            })
        }
    }

    fn parse_strategy(&mut self) -> Result<StrategySpec, DslError> {
        self.expect_ident(Some("strategy"))?;
        let (name, _) = self.expect_str()?;
        self.expect_kind(&TokKind::LBrace)?;

        let mut spec = StrategySpec {
            name,
            version: "1.0.0".into(),
            author: "Unknown".into(),
            description: String::new(),
            min_core_version: "0.4.0".into(),
            fallback_policy: RawFallbackPolicy::AutoDegrade,
            rollback: RollbackPolicy::default(),
            rules: Vec::new(),
            lab_assert: LabExpectations::default(),
        };

        while let Some(tok) = self.peek() {
            if tok.kind == TokKind::RBrace {
                self.pos += 1;
                if self.peek().is_some() {
                    return Err(DslError {
                        line: self.cur_line(),
                        message: "unexpected tokens after strategy closing '}'".into(),
                    });
                }
                return Ok(spec);
            }
            let (kw, line) = self.expect_ident(None)?;
            match kw.as_str() {
                "version" => {
                    self.expect_kind(&TokKind::Eq)?;
                    spec.version = self.expect_str()?.0;
                }
                "author" => {
                    self.expect_kind(&TokKind::Eq)?;
                    spec.author = self.expect_str()?.0;
                }
                "description" => {
                    self.expect_kind(&TokKind::Eq)?;
                    spec.description = self.expect_str()?.0;
                }
                "min_core_version" => {
                    self.expect_kind(&TokKind::Eq)?;
                    spec.min_core_version = self.expect_str()?.0;
                }
                "requires_raw_fallback" => {
                    self.expect_kind(&TokKind::Eq)?;
                    let (val, vline) = self.expect_str()?;
                    spec.fallback_policy = match val.as_str() {
                        "strict" => RawFallbackPolicy::Strict,
                        "auto_degrade" => RawFallbackPolicy::AutoDegrade,
                        _ => {
                            return Err(DslError {
                                line: vline,
                                message: format!(
                                    "unknown requires_raw_fallback '{val}' (expected 'strict' or 'auto_degrade')"
                                ),
                            });
                        }
                    };
                }
                "rollback" => {
                    spec.rollback = self.parse_rollback()?;
                }
                "rule" => {
                    spec.rules.push(self.parse_rule()?);
                }
                "lab_assert" => {
                    spec.lab_assert = self.parse_lab_assert()?;
                }
                other => {
                    return Err(DslError {
                        line,
                        message: format!(
                            "unknown directive '{other}' in strategy block (disallowed or unsupported capability)"
                        ),
                    });
                }
            }
        }

        Err(DslError {
            line: self.cur_line(),
            message: "expected closing '}' for strategy block".into(),
        })
    }

    fn parse_rollback(&mut self) -> Result<RollbackPolicy, DslError> {
        self.expect_kind(&TokKind::LBrace)?;
        let mut pol = RollbackPolicy::default();
        while let Some(tok) = self.peek() {
            if tok.kind == TokKind::RBrace {
                self.pos += 1;
                return Ok(pol);
            }
            let (field, line) = self.expect_ident(None)?;
            self.expect_kind(&TokKind::Eq)?;
            let (val, vline) = self.expect_u64()?;
            match field.as_str() {
                "max_consecutive_failures" => {
                    pol.max_consecutive_failures = u8::try_from(val).map_err(|_| DslError {
                        line: vline,
                        message: "max_consecutive_failures out of u8 range".into(),
                    })?;
                }
                "min_samples" => {
                    pol.min_samples = u16::try_from(val).map_err(|_| DslError {
                        line: vline,
                        message: "min_samples out of u16 range".into(),
                    })?;
                }
                "max_failure_pct" => {
                    pol.max_failure_pct = u8::try_from(val).map_err(|_| DslError {
                        line: vline,
                        message: "max_failure_pct out of u8 range".into(),
                    })?;
                }
                other => {
                    return Err(DslError {
                        line,
                        message: format!("unknown rollback field '{other}'"),
                    });
                }
            }
        }
        Err(DslError {
            line: self.cur_line(),
            message: "unclosed rollback block".into(),
        })
    }

    fn parse_lab_assert(&mut self) -> Result<LabExpectations, DslError> {
        self.expect_kind(&TokKind::LBrace)?;
        let mut out = LabExpectations::default();
        while let Some(tok) = self.peek() {
            if tok.kind == TokKind::RBrace {
                self.pos += 1;
                return Ok(out);
            }
            let (field, line) = self.expect_ident(None)?;
            self.expect_kind(&TokKind::Eq)?;
            let items = self.parse_ident_list()?;
            match field.as_str() {
                "expect_pass" => out.expect_pass = items,
                "expect_honest_unbypassable" => out.expect_honest_unbypassable = items,
                other => {
                    return Err(DslError {
                        line,
                        message: format!("unknown lab_assert field '{other}'"),
                    });
                }
            }
        }
        Err(DslError {
            line: self.cur_line(),
            message: "unclosed lab_assert block".into(),
        })
    }

    fn parse_ident_list(&mut self) -> Result<Vec<String>, DslError> {
        self.expect_kind(&TokKind::LBracket)?;
        let mut items = Vec::new();
        while let Some(tok) = self.peek() {
            if tok.kind == TokKind::RBracket {
                self.pos += 1;
                return Ok(items);
            }
            let (id, _) = self.expect_ident(None)?;
            items.push(id);
            if self.peek().is_some_and(|t| t.kind == TokKind::Comma) {
                self.pos += 1;
            }
        }
        Err(DslError {
            line: self.cur_line(),
            message: "unclosed '[' list".into(),
        })
    }

    fn parse_rule(&mut self) -> Result<StrategyRule, DslError> {
        let (rule_name, _) = self.expect_ident(None)?;
        self.expect_kind(&TokKind::LBrace)?;

        let mut rule = StrategyRule {
            name: rule_name,
            priority: 50,
            when_on_retry: 0,
            matcher: MatchSpec::default(),
            raw_actions: None,
            socket_actions: None,
            quic_mode: None,
            udp_desync_ttl: None,
            udp_bad_checksum_decoy: false,
        };

        while let Some(tok) = self.peek() {
            if tok.kind == TokKind::RBrace {
                self.pos += 1;
                return Ok(rule);
            }
            let (kw, line) = self.expect_ident(None)?;
            match kw.as_str() {
                "priority" => {
                    self.expect_kind(&TokKind::Eq)?;
                    let (val, vline) = self.expect_u64()?;
                    rule.priority = u16::try_from(val).map_err(|_| DslError {
                        line: vline,
                        message: "priority out of u16 range".into(),
                    })?;
                }
                "when" => {
                    self.expect_ident(Some("on_retry"))?;
                    self.expect_kind(&TokKind::GtEq)?;
                    let (val, vline) = self.expect_u64()?;
                    rule.when_on_retry = u8::try_from(val).map_err(|_| DslError {
                        line: vline,
                        message: "on_retry out of u8 range".into(),
                    })?;
                }
                "match" => {
                    rule.matcher = self.parse_match_clause()?;
                }
                "raw_actions" => {
                    rule.raw_actions = Some(self.parse_raw_actions()?);
                }
                "socket_actions" => {
                    rule.socket_actions = Some(self.parse_socket_actions()?);
                }
                "quic_mode" => {
                    self.expect_kind(&TokKind::Eq)?;
                    rule.quic_mode = Some(self.parse_quic_mode()?);
                }
                "udp_desync_ttl" => {
                    self.expect_kind(&TokKind::Eq)?;
                    let (val, vline) = self.expect_u64()?;
                    rule.udp_desync_ttl = Some(u8::try_from(val).map_err(|_| DslError {
                        line: vline,
                        message: "udp_desync_ttl out of u8 range".into(),
                    })?);
                }
                "udp_bad_checksum_decoy" => {
                    self.expect_kind(&TokKind::Eq)?;
                    rule.udp_bad_checksum_decoy = self.expect_bool()?;
                }
                other => {
                    return Err(DslError {
                        line,
                        message: format!("unknown field '{other}' inside rule"),
                    });
                }
            }
        }

        Err(DslError {
            line: self.cur_line(),
            message: "unclosed rule block".into(),
        })
    }

    fn parse_match_clause(&mut self) -> Result<MatchSpec, DslError> {
        let mut m = MatchSpec::default();
        loop {
            let (pred, line) = self.expect_ident(None)?;
            match pred.as_str() {
                "proto" => {
                    let next_tok = self.next()?;
                    m.protocols.clear();
                    match next_tok.kind {
                        TokKind::EqEq => {
                            m.protocols.push(self.parse_proto()?);
                        }
                        TokKind::Ident(ref kw) if kw == "in" => {
                            self.expect_kind(&TokKind::LBracket)?;
                            while self.peek().is_some_and(|t| t.kind != TokKind::RBracket) {
                                m.protocols.push(self.parse_proto()?);
                                if self.peek().is_some_and(|t| t.kind == TokKind::Comma) {
                                    self.pos += 1;
                                }
                            }
                            self.expect_kind(&TokKind::RBracket)?;
                        }
                        other => {
                            return Err(DslError {
                                line: next_tok.line,
                                message: format!("expected '==' or 'in' after proto, found {other:?}"),
                            });
                        }
                    }
                }
                "port" => {
                    let next_tok = self.next()?;
                    match next_tok.kind {
                        TokKind::EqEq => {
                            let (p, pline) = self.expect_u64()?;
                            m.ports.push(u16::try_from(p).map_err(|_| DslError {
                                line: pline,
                                message: "port out of range".into(),
                            })?);
                        }
                        TokKind::Ident(ref kw) if kw == "in" => {
                            self.expect_kind(&TokKind::LBracket)?;
                            while self.peek().is_some_and(|t| t.kind != TokKind::RBracket) {
                                let (p, pline) = self.expect_u64()?;
                                m.ports.push(u16::try_from(p).map_err(|_| DslError {
                                    line: pline,
                                    message: "port out of range".into(),
                                })?);
                                if self.peek().is_some_and(|t| t.kind == TokKind::Comma) {
                                    self.pos += 1;
                                }
                            }
                            self.expect_kind(&TokKind::RBracket)?;
                        }
                        other => {
                            return Err(DslError {
                                line: next_tok.line,
                                message: format!("expected '==' or 'in' after port, found {other:?}"),
                            });
                        }
                    }
                }
                "sni_suffix" => {
                    let next_tok = self.next()?;
                    match next_tok.kind {
                        TokKind::EqEq => m.sni_suffixes.push(self.expect_str()?.0),
                        TokKind::Ident(ref kw) if kw == "in" => {
                            self.expect_kind(&TokKind::LBracket)?;
                            while self.peek().is_some_and(|t| t.kind != TokKind::RBracket) {
                                m.sni_suffixes.push(self.expect_str()?.0);
                                if self.peek().is_some_and(|t| t.kind == TokKind::Comma) {
                                    self.pos += 1;
                                }
                            }
                            self.expect_kind(&TokKind::RBracket)?;
                        }
                        other => {
                            return Err(DslError {
                                line: next_tok.line,
                                message: format!("expected '==' or 'in', found {other:?}"),
                            });
                        }
                    }
                }
                "min_payload" => {
                    self.expect_kind(&TokKind::Eq)?;
                    let (v, vline) = self.expect_u64()?;
                    m.min_payload = u16::try_from(v).map_err(|_| DslError {
                        line: vline,
                        message: "min_payload out of u16 range".into(),
                    })?;
                }
                "exclude_sensitive" => {
                    self.expect_kind(&TokKind::Eq)?;
                    m.exclude_sensitive = self.expect_bool()?;
                }
                other => {
                    return Err(DslError {
                        line,
                        message: format!("unknown match predicate '{other}'"),
                    });
                }
            }
            if self.peek().is_some_and(|t| t.kind == TokKind::Comma) {
                self.pos += 1;
                continue;
            }
            break;
        }
        Ok(m)
    }

    fn parse_proto(&mut self) -> Result<MatchProtocol, DslError> {
        let (id, line) = self.expect_ident(None)?;
        match id.as_str() {
            "tls" => Ok(MatchProtocol::Tls),
            "http" => Ok(MatchProtocol::Http),
            "quic" => Ok(MatchProtocol::Quic),
            "udp_stun" => Ok(MatchProtocol::UdpStun),
            "udp_raknet" => Ok(MatchProtocol::UdpRakNet),
            "any" => Ok(MatchProtocol::Any),
            _ => Err(DslError {
                line,
                message: format!("unknown protocol '{id}'"),
            }),
        }
    }

    fn parse_split_cuts(&mut self) -> Result<Vec<SplitCutSpec>, DslError> {
        self.expect_kind(&TokKind::LBracket)?;
        let mut cuts = Vec::new();
        while let Some(tok) = self.peek().cloned() {
            if tok.kind == TokKind::RBracket {
                self.pos += 1;
                return Ok(cuts);
            }
            match tok.kind {
                TokKind::Num(_) => {
                    let (off, oline) = self.expect_u64()?;
                    cuts.push(SplitCutSpec::FixedOffset(
                        u16::try_from(off).map_err(|_| DslError {
                            line: oline,
                            message: "split offset out of u16 range".into(),
                        })?,
                    ));
                }
                TokKind::Ident(_) => {
                    let (id, iline) = self.expect_ident(None)?;
                    let cut = match id.as_str() {
                        "sni_mid" => SplitCutSpec::SniMid,
                        "host_mid" => SplitCutSpec::HostMid,
                        "first_record_end" => SplitCutSpec::FirstRecordEnd,
                        _ => {
                            return Err(DslError {
                                line: iline,
                                message: format!("unknown symbolic cut point '{id}'"),
                            });
                        }
                    };
                    cuts.push(cut);
                }
                other => {
                    return Err(DslError {
                        line: tok.line,
                        message: format!("expected offset or cut symbol, found {other:?}"),
                    });
                }
            }
            if self.peek().is_some_and(|t| t.kind == TokKind::Comma) {
                self.pos += 1;
            }
        }
        Err(DslError {
            line: self.cur_line(),
            message: "unclosed tcp_split list".into(),
        })
    }

    fn parse_decoys(&mut self) -> Result<Vec<DecoySpec>, DslError> {
        self.expect_kind(&TokKind::LBracket)?;
        let mut list = Vec::new();
        while let Some(tok) = self.peek() {
            if tok.kind == TokKind::RBracket {
                self.pos += 1;
                return Ok(list);
            }
            let (id, line) = self.expect_ident(None)?;
            let decoy = match id.as_str() {
                "bad_checksum" => DecoySpec::BadChecksum,
                "wrong_seq" => DecoySpec::WrongSeq,
                "bad_checksum_wrong_seq" => DecoySpec::BadChecksumWrongSeq,
                "low_ttl" => DecoySpec::LowTtl(self.parse_ttl_arg()?),
                "low_ttl_wrong_seq" => DecoySpec::LowTtlWrongSeq(self.parse_ttl_arg()?),
                other => {
                    return Err(DslError {
                        line,
                        message: format!("unknown decoy action '{other}'"),
                    });
                }
            };
            list.push(decoy);
            if self.peek().is_some_and(|t| t.kind == TokKind::Comma) {
                self.pos += 1;
            }
        }
        Err(DslError {
            line: self.cur_line(),
            message: "unclosed decoys list".into(),
        })
    }

    fn parse_ttl_arg(&mut self) -> Result<DecoyTtlMode, DslError> {
        self.expect_kind(&TokKind::LParen)?;
        let tok = self.next()?;
        let mode = match tok.kind {
            TokKind::Ident(ref id) if id == "auto" => DecoyTtlMode::AutoCalibrated,
            TokKind::Num(v) => DecoyTtlMode::Fixed(u8::try_from(v).map_err(|_| DslError {
                line: tok.line,
                message: "TTL out of u8 range".into(),
            })?),
            other => {
                return Err(DslError {
                    line: tok.line,
                    message: format!("expected 'auto' or TTL integer, found {other:?}"),
                });
            }
        };
        self.expect_kind(&TokKind::RParen)?;
        Ok(mode)
    }

    fn parse_raw_actions(&mut self) -> Result<RawActionSpec, DslError> {
        self.expect_kind(&TokKind::LBrace)?;
        let mut act = RawActionSpec::default();
        while let Some(tok) = self.peek() {
            if tok.kind == TokKind::RBrace {
                self.pos += 1;
                return Ok(act);
            }
            let (field, line) = self.expect_ident(None)?;
            self.expect_kind(&TokKind::Eq)?;
            match field.as_str() {
                "passthrough" => act.passthrough = self.expect_bool()?,
                "tcp_split" => act.tcp_splits = self.parse_split_cuts()?,
                "disorder" => act.disorder = self.expect_bool()?,
                "decoy_sni" => act.decoy_sni = self.expect_str()?.0,
                "decoys" => act.decoys = self.parse_decoys()?,
                "http_split_host" => act.http_split_host = self.expect_bool()?,
                "http_host_case" => act.http_host_case = self.expect_bool()?,
                "syn_mss_clamp" => {
                    let (v, vline) = self.expect_u64()?;
                    act.syn_mss_clamp = Some(u16::try_from(v).map_err(|_| DslError {
                        line: vline,
                        message: "syn_mss_clamp out of u16 range".into(),
                    })?);
                }
                "drop_forged_passive_rst" => act.drop_forged_passive_rst = self.expect_bool()?,
                "drop_forged_http_redirect" => act.drop_forged_http_redirect = self.expect_bool()?,
                other => {
                    return Err(DslError {
                        line,
                        message: format!("unknown raw_actions field '{other}'"),
                    });
                }
            }
        }
        Err(DslError {
            line: self.cur_line(),
            message: "unclosed raw_actions block".into(),
        })
    }

    fn parse_socket_actions(&mut self) -> Result<SocketActionSpec, DslError> {
        self.expect_kind(&TokKind::LBrace)?;
        let mut act = SocketActionSpec::default();
        while let Some(tok) = self.peek() {
            if tok.kind == TokKind::RBrace {
                self.pos += 1;
                return Ok(act);
            }
            let (field, line) = self.expect_ident(None)?;
            self.expect_kind(&TokKind::Eq)?;
            match field.as_str() {
                "passthrough" => act.passthrough = self.expect_bool()?,
                "tls_record" => act.tls_record = Some(self.parse_tls_record_mode()?),
                "tcp_split" => act.tcp_splits = self.parse_split_cuts()?,
                "paced_flush" => act.paced_flush = self.expect_bool()?,
                "tcp_oob" => act.tcp_oob = self.expect_bool()?,
                "http_split_host" => act.http_split_host = self.expect_bool()?,
                "http_host_case" => act.http_host_case = self.expect_bool()?,
                other => {
                    return Err(DslError {
                        line,
                        message: format!("unknown socket_actions field '{other}'"),
                    });
                }
            }
        }
        Err(DslError {
            line: self.cur_line(),
            message: "unclosed socket_actions block".into(),
        })
    }

    fn parse_tls_record_mode(&mut self) -> Result<TlsRecordMode, DslError> {
        let (id, line) = self.expect_ident(None)?;
        match id.as_str() {
            "none" => Ok(TlsRecordMode::None),
            "sni_mid" => Ok(TlsRecordMode::SniMid),
            "offset_and_sni_mid" => {
                self.expect_kind(&TokKind::LParen)?;
                let (off, oline) = self.expect_u64()?;
                self.expect_kind(&TokKind::RParen)?;
                Ok(TlsRecordMode::OffsetAndSniMid(u16::try_from(off).map_err(
                    |_| DslError {
                        line: oline,
                        message: "offset_and_sni_mid out of range".into(),
                    },
                )?))
            }
            "small_chunks" => {
                self.expect_kind(&TokKind::LParen)?;
                let (sz, sline) = self.expect_u64()?;
                self.expect_kind(&TokKind::RParen)?;
                Ok(TlsRecordMode::SmallChunks(u16::try_from(sz).map_err(
                    |_| DslError {
                        line: sline,
                        message: "small_chunks size out of range".into(),
                    },
                )?))
            }
            _ => Err(DslError {
                line,
                message: format!("unknown tls_record mode '{id}'"),
            }),
        }
    }

    fn parse_quic_mode(&mut self) -> Result<QuicMode, DslError> {
        let (id, line) = self.expect_ident(None)?;
        match id.as_str() {
            "allow" => Ok(QuicMode::Allow),
            "block_fallback_tcp" => Ok(QuicMode::BlockFallbackTcp),
            "desync_ttl" => {
                self.expect_kind(&TokKind::LParen)?;
                let (ttl, tline) = self.expect_u64()?;
                self.expect_kind(&TokKind::RParen)?;
                Ok(QuicMode::DesyncTtl(u8::try_from(ttl).map_err(|_| DslError {
                    line: tline,
                    message: "quic_mode ttl out of range".into(),
                })?))
            }
            _ => Err(DslError {
                line,
                message: format!("unknown quic_mode '{id}'"),
            }),
        }
    }
}

/// Parses a declarative TSL v1 source string into a `StrategySpec`.
pub fn parse_tsl(src: &str) -> Result<StrategySpec, DslError> {
    let tokens = tokenize(src)?;
    let mut parser = Parser { tokens, pos: 0 };
    parser.parse_strategy()
}

/// Decompiles a `StrategySpec` into canonical TSL v1 source syntax.
pub fn format_tsl(spec: &StrategySpec) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "# Canonical TULPAR Strategy Language (TSL v1)");
    let _ = writeln!(out, "strategy \"{}\" {{", escape_tsl(&spec.name));
    let _ = writeln!(out, "  version = \"{}\"", escape_tsl(&spec.version));
    let _ = writeln!(out, "  author = \"{}\"", escape_tsl(&spec.author));
    let _ = writeln!(out, "  description = \"{}\"", escape_tsl(&spec.description));
    let _ = writeln!(
        out,
        "  min_core_version = \"{}\"",
        escape_tsl(&spec.min_core_version)
    );
    let fb = match spec.fallback_policy {
        RawFallbackPolicy::Strict => "strict",
        RawFallbackPolicy::AutoDegrade => "auto_degrade",
    };
    let _ = writeln!(out, "  requires_raw_fallback = \"{fb}\"");
    let _ = writeln!(out);
    let _ = writeln!(out, "  rollback {{");
    let _ = writeln!(
        out,
        "    max_consecutive_failures = {}",
        spec.rollback.max_consecutive_failures
    );
    let _ = writeln!(out, "    min_samples = {}", spec.rollback.min_samples);
    let _ = writeln!(out, "    max_failure_pct = {}", spec.rollback.max_failure_pct);
    let _ = writeln!(out, "  }}");

    for r in &spec.rules {
        let _ = writeln!(out);
        let _ = writeln!(out, "  rule {} {{", r.name);
        let _ = writeln!(out, "    priority = {}", r.priority);
        if r.when_on_retry > 0 {
            let _ = writeln!(out, "    when on_retry >= {}", r.when_on_retry);
        }
        let mut preds = Vec::new();
        if !r.matcher.protocols.is_empty() {
            let ps: Vec<&str> = r
                .matcher
                .protocols
                .iter()
                .map(|p| match p {
                    MatchProtocol::Tls => "tls",
                    MatchProtocol::Http => "http",
                    MatchProtocol::Quic => "quic",
                    MatchProtocol::UdpStun => "udp_stun",
                    MatchProtocol::UdpRakNet => "udp_raknet",
                    MatchProtocol::Any => "any",
                })
                .collect();
            if ps.len() == 1 {
                preds.push(format!("proto == {}", ps[0]));
            } else {
                preds.push(format!("proto in [{}]", ps.join(", ")));
            }
        }
        if !r.matcher.ports.is_empty() {
            let ports: Vec<String> = r.matcher.ports.iter().map(|p| p.to_string()).collect();
            if ports.len() == 1 {
                preds.push(format!("port == {}", ports[0]));
            } else {
                preds.push(format!("port in [{}]", ports.join(", ")));
            }
        }
        if !r.matcher.sni_suffixes.is_empty() {
            let quoted: Vec<String> = r
                .matcher
                .sni_suffixes
                .iter()
                .map(|s| format!("\"{}\"", escape_tsl(s)))
                .collect();
            if quoted.len() == 1 {
                preds.push(format!("sni_suffix == {}", quoted[0]));
            } else {
                preds.push(format!("sni_suffix in [{}]", quoted.join(", ")));
            }
        }
        if r.matcher.min_payload > 0 {
            preds.push(format!("min_payload = {}", r.matcher.min_payload));
        }
        if !r.matcher.exclude_sensitive {
            preds.push("exclude_sensitive = false".into());
        }
        if !preds.is_empty() {
            let _ = writeln!(out, "    match {}", preds.join(", "));
        }
        if let Some(raw) = &r.raw_actions {
            let _ = writeln!(out, "    raw_actions {{");
            if raw.passthrough {
                let _ = writeln!(out, "      passthrough = true");
            }
            if !raw.tcp_splits.is_empty() {
                let cuts = format_cuts(&raw.tcp_splits);
                let _ = writeln!(out, "      tcp_split = [{}]", cuts.join(", "));
            }
            if raw.disorder {
                let _ = writeln!(out, "      disorder = true");
            }
            let _ = writeln!(out, "      decoy_sni = \"{}\"", escape_tsl(&raw.decoy_sni));
            if !raw.decoys.is_empty() {
                let ds: Vec<String> = raw
                    .decoys
                    .iter()
                    .map(|d| match d {
                        DecoySpec::BadChecksum => "bad_checksum".into(),
                        DecoySpec::WrongSeq => "wrong_seq".into(),
                        DecoySpec::BadChecksumWrongSeq => "bad_checksum_wrong_seq".into(),
                        DecoySpec::LowTtl(DecoyTtlMode::AutoCalibrated) => "low_ttl(auto)".into(),
                        DecoySpec::LowTtl(DecoyTtlMode::Fixed(t)) => format!("low_ttl({t})"),
                        DecoySpec::LowTtlWrongSeq(DecoyTtlMode::AutoCalibrated) => {
                            "low_ttl_wrong_seq(auto)".into()
                        }
                        DecoySpec::LowTtlWrongSeq(DecoyTtlMode::Fixed(t)) => {
                            format!("low_ttl_wrong_seq({t})")
                        }
                    })
                    .collect();
                let _ = writeln!(out, "      decoys = [{}]", ds.join(", "));
            }
            if !raw.http_split_host {
                let _ = writeln!(out, "      http_split_host = false");
            }
            if raw.http_host_case {
                let _ = writeln!(out, "      http_host_case = true");
            }
            if let Some(mss) = raw.syn_mss_clamp {
                let _ = writeln!(out, "      syn_mss_clamp = {mss}");
            }
            let _ = writeln!(out, "    }}");
        }
        if let Some(sock) = &r.socket_actions {
            let _ = writeln!(out, "    socket_actions {{");
            if sock.passthrough {
                let _ = writeln!(out, "      passthrough = true");
            }
            if let Some(tr) = sock.tls_record {
                let s = match tr {
                    TlsRecordMode::None => "none".into(),
                    TlsRecordMode::SniMid => "sni_mid".into(),
                    TlsRecordMode::OffsetAndSniMid(o) => format!("offset_and_sni_mid({o})"),
                    TlsRecordMode::SmallChunks(c) => format!("small_chunks({c})"),
                };
                let _ = writeln!(out, "      tls_record = {s}");
            }
            if !sock.tcp_splits.is_empty() {
                let cuts = format_cuts(&sock.tcp_splits);
                let _ = writeln!(out, "      tcp_split = [{}]", cuts.join(", "));
            }
            if sock.paced_flush {
                let _ = writeln!(out, "      paced_flush = true");
            }
            if sock.tcp_oob {
                let _ = writeln!(out, "      tcp_oob = true");
            }
            if sock.http_split_host {
                let _ = writeln!(out, "      http_split_host = true");
            }
            if sock.http_host_case {
                let _ = writeln!(out, "      http_host_case = true");
            }
            let _ = writeln!(out, "    }}");
        }
        if let Some(qm) = r.quic_mode {
            let q = match qm {
                QuicMode::Allow => "allow".into(),
                QuicMode::BlockFallbackTcp => "block_fallback_tcp".into(),
                QuicMode::DesyncTtl(t) => format!("desync_ttl({t})"),
            };
            let _ = writeln!(out, "    quic_mode = {q}");
        }
        if let Some(ttl) = r.udp_desync_ttl {
            let _ = writeln!(out, "    udp_desync_ttl = {ttl}");
        }
        if r.udp_bad_checksum_decoy {
            let _ = writeln!(out, "    udp_bad_checksum_decoy = true");
        }
        let _ = writeln!(out, "  }}");
    }

    if !spec.lab_assert.expect_pass.is_empty()
        || !spec.lab_assert.expect_honest_unbypassable.is_empty()
    {
        let _ = writeln!(out);
        let _ = writeln!(out, "  lab_assert {{");
        if !spec.lab_assert.expect_pass.is_empty() {
            let _ = writeln!(
                out,
                "    expect_pass = [{}]",
                spec.lab_assert.expect_pass.join(", ")
            );
        }
        if !spec.lab_assert.expect_honest_unbypassable.is_empty() {
            let _ = writeln!(
                out,
                "    expect_honest_unbypassable = [{}]",
                spec.lab_assert.expect_honest_unbypassable.join(", ")
            );
        }
        let _ = writeln!(out, "  }}");
    }

    let _ = writeln!(out, "}}");
    out
}

fn format_cuts(cuts: &[SplitCutSpec]) -> Vec<String> {
    cuts.iter()
        .map(|c| match c {
            SplitCutSpec::FixedOffset(o) => o.to_string(),
            SplitCutSpec::SniMid => "sni_mid".into(),
            SplitCutSpec::HostMid => "host_mid".into(),
            SplitCutSpec::FirstRecordEnd => "first_record_end".into(),
        })
        .collect()
}

fn escape_tsl(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
