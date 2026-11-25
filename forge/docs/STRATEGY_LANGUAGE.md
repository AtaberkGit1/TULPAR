# TULPAR Strategy Language (TSL v1) & `.tulpar` Package Specification

## 1. Declarative Syntax Overview (`.tlp`)

TSL v1 uses typed blocks with strict finite iteration and zero general-purpose scripting:

```tulpar
strategy "<safe-ascii-name>" {
  version = "1.0.0"
  author = "Author Name"
  description = "Short human description (<= 256 chars)"
  min_core_version = "0.4.0"
  requires_raw_fallback = "auto_degrade" # "auto_degrade" | "strict"

  rollback {
    max_consecutive_failures = 4   # 1..=16 (mandatory)
    min_samples = 6                # 3..=64
    max_failure_pct = 65           # 20..=90
  }

  rule <rule_id> {
    priority = 100                 # higher wins within same retry tier
    when on_retry >= 1             # optional escalation threshold
    match proto == tls, port in [443, 8443], sni_suffix in [".example.org"], min_payload = 9, exclude_sensitive = true

    raw_actions {
      passthrough = false
      tcp_split = [2, sni_mid]     # fixed offsets (1..=512) | sni_mid | host_mid | first_record_end
      disorder = true              # send tail segments before leading bytes
      decoy_sni = "www.iana.org"   # MUST belong to RFC 2606 / IANA allowlist
      decoys = [bad_checksum, low_ttl_wrong_seq(auto), bad_checksum_wrong_seq]
      http_split_host = true
      http_host_case = false
      syn_mss_clamp = 536          # optional 536..=1460
    }

    socket_actions {
      passthrough = false
      tls_record = small_chunks(24) # none | sni_mid | offset_and_sni_mid(1..=64) | small_chunks(16..=512)
      tcp_split = [1, first_record_end]
      paced_flush = true
      tcp_oob = false               # Linux/Android MSG_OOB urgent byte
      http_split_host = true
      http_host_case = true
    }

    quic_mode = block_fallback_tcp  # allow | block_fallback_tcp | desync_ttl(1..=8)
    udp_desync_ttl = 3              # optional 1..=8 for udp_stun / udp_raknet
    udp_bad_checksum_decoy = true
  }

  lab_assert {
    expect_pass = [shallow_sni_reset, stateful_sni_reassembly]
    expect_honest_unbypassable = [hard_ip_blackhole]
  }
}
```

## 2. Portable `.tulpar` Binary Format (`TULPARF1`)

Compiling a verified `.tlp` source with `tulpar-forge build` emits a deterministic binary container:

1. **Magic**: `b"TULPARF1"` (8 bytes)
2. **Format Version**: `u16` big-endian (`1`)
3. **Reserved Flags**: `u16` big-endian (`0`)
4. **Metadata + Rollback Policy**: Bounded UTF-8 strings + `RawFallbackPolicy` + `RollbackPolicy`
5. **Typed Rule Table**: Big-endian TLV records encoding `MatchSpec`, `RawActionSpec`, `SocketActionSpec`, `QuicMode`, and UDP desync settings (no executable machine code or bytecode jumps)
6. **Lab Assertions**: Declared `expect_pass` and `expect_honest_unbypassable` identifiers
7. **Integrity Trailer**: 32-byte FIPS 180-4 SHA-256 digest over bytes `[0 .. end - 32]`

On load (`ForgePackage::decode_verified`), TULPAR:
1. Enforces `len <= 128 KiB`, valid magic, exact version, and zero trailing bytes.
2. Verifies the trailing SHA-256 digest using constant-time byte comparison.
3. Re-runs `ForgeVerifier::verify(&spec)` statically before allowing activation.

## 3. Verifier Limits & Security Rules

| Constraint | Bound | Rationale |
|---|---|---|
| Max package size | `128 KiB` | Prevents parser memory DoS on embedded mobile devices |
| Rules per package | `1..=32` | Bounds rule-evaluation latency to sub-microsecond per handshake |
| TCP split cuts | `<= 6` cuts, offsets `1..=512` | Prevents micro-packet flooding |
| TLS record small chunks | `16..=512` bytes | Disrupts SNI matchers without 1-byte flood |
| Decoy packets | `<= 4` per handshake | Strictly prevents amplification |
| Exact-seq `low_ttl(N)` | `N in 1..=5` | Prevents asymmetric Anycast server stream poisoning |
| `low_ttl_wrong_seq(N)` / UDP TTL | `N in 1..=8` | Keeps decoys mid-path while harmless to target endpoints |
| Decoy SNI/Host | IANA / RFC 2606 allowlist only | Prevents impersonating/attacking unrelated domains |
| Mandatory circuit breaker | `1..=16` consecutive failures; `20..=90%` rate | Guarantees broken packages cannot lock users offline |
