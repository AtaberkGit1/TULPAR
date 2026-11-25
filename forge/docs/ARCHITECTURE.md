# TULPAR Forge Architecture & Honest Technical Limitations

## 1. Crate Structure & Reusable TULPAR Components

Forge lives modularly under `forge/` and reuses TULPAR's existing audited core crates without duplicating DPI or DNS logic:

- **`forge/crates/tulpar-forge`** (`#![forbid(unsafe_code)]`, **zero third-party dependencies**):
  - `sha256`: Self-contained FIPS 180-4 SHA-256 digest & constant-time verification.
  - `ast`, `dsl`, `format`, `verifier`: Strategy AST, TSL v1 parser/decompiler, canonical `TULPARF1` binary encoder/decoder, and static capability/security verifier.
  - `runtime`: `ForgeRuntime` (lock-free `AtomicBool` fast path + `RwLock` hot-reload swap) and salted-hash `ForgeCircuitBreaker`.
- **`core/` Integration (`yolac-net`, `yolac-core`, `yolac-ffi`)**:
  - `yolac-net::DpiTcpRelay` queries `StrategyAdvisor::forge_socket_plan` and reuses `yolac-dpi::{fragment_tls_client_hello, evade_http_request, parse_client_hello_prefix, parse_http_host}`.
  - `yolac-core::AdaptiveController` hosts `Arc<ForgeRuntime>`, provides `execute_raw_forge_tcp(...)` shared by Windows `WinDivertEngine` and Linux `NFQUEUE` engine, and reports live `FlowOutcome` feedback back to `ForgeCircuitBreaker`.
  - `yolac-core::YolacEngine` exposes runtime hot-reload APIs (`load_forge_package_bytes`, `load_forge_package_file`, `unload_forge_package`, `forge_status`).
  - `yolac-ffi` exports C-ABI (`yolac_load_forge_package`, `yolac_unload_forge_package`, `yolac_get_forge_status_json`) and Android JNI (`nativeLoadForgePackage`, `nativeUnloadForgePackage`, `nativeGetForgeStatusJson`).
- **`forge/crates/tulpar-forge-lab`**:
  - Offline loopback middlebox simulators + L3 IPv4 packet/hop simulator using `yolac-dpi`, `yolac-dns`, `yolac-blocklist`, `yolac-net`, `yolac-core`, and `rcgen`/`rustls`.
- **`forge/crates/tulpar-forge-cli`**:
  - Developer workflow tool (`new`, `check`, `build`, `inspect`, `test`, `bench`, `verify-security`).

---

## 2. How Cross-Platform Execution & Capability Degradation Work

Operating systems enforce different security boundaries:
- **Windows (`WinDivert`) & Linux (`NFQUEUE` + `IPPROTO_RAW`)**: Can inject raw L3/L4 decoys (`LowTtl`, `BadChecksum`, `WrongSeq`), reorder TCP segments (`disorder = true`), and clamp `SYN` MSS. Both platforms execute `raw_actions`.
- **Android (`VpnService`)**: Unprivileged mobile VPN apps run behind a userspace L3 TUN interface (`smoltcp` + protected OS `TcpStream`). Arbitrary IP TTL spoofing and bad TCP checksum injection are blocked by the OS sandbox. On Android:
  - If `socket_actions` is defined, `DpiTcpRelay` executes those exact verified TLS record cuts, TCP splits, HTTP Host transforms, or POSIX `MSG_OOB` sends.
  - If only `raw_actions` is specified and `requires_raw_fallback = "auto_degrade"`, `ForgeRuntime` deterministically derives safe multi-record TLS/TCP splits.
  - If `requires_raw_fallback = "strict"`, Android cleanly refuses activation with an explicit incompatibility error.

---

## 3. Honest Technical Limitations of TULPAR Forge

1. **Loopback Lab ≠ Live Nationwide ISP Middleware Diversity**:
   `tulpar-forge test` validates strategies against deterministic middlebox models (shallow SNI resets, timed TCP/TLS stream reassembly, hop-threshold L3 decoy inspection, forged passive RSTs, HTTP Host inspection, QUIC Initial blocking, DNS poisoning, and hard IP blackholes). While these catch broken/malicious rules reliably, real ISP appliances can combine proprietary state timeouts or deep reassembly buffers not identical to lab constants.
2. **Protocol/SNI Throttling vs. Physical Line Limits**:
   Strategies in `.tulpar` can mitigate protocol- or SNI-based DPI blocking/throttling, **not** increase a user's physical ISP line rate or overcome hardware/cell congestion.
3. **Hard IP / ASN Blackholes Are Unbypassable On-Device**:
   No declarative `.tulpar` packet transform can bypass an ISP dropping all packets to a destination IP or terminating routes at BGP/ACL level; `hard_ip_blackhole` explicitly verifies and reports `UnbypassableOnDevice`.
4. **Integrity Seal vs. Asymmetric Publisher Trust**:
   `TULPARF1` enforces a FIPS 180-4 **SHA-256** integrity seal against accidental corruption or un-recomputed tampering, plus static `ForgeVerifier` capability bounds even if an attacker recomputes SHA-256. However, v1 does not yet include an Ed25519 publisher PKI keyring; users should obtain `.tulpar` packages only from trusted sources and verify SHA-256 hashes or inspect them via `tulpar-forge inspect`.
5. **Runtime Rollback Scope**:
   When `ForgeCircuitBreaker` trips, protection atomically switches back to TULPAR's verified built-in `SafeBaseline` in memory and preserves user safety without restarting apps or dropping protected DNS/IPv6 leak guards.
