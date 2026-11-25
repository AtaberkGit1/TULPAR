# TULPAR Forge

**TULPAR Forge** is a self-contained strategy language, capability-verified portable `.tulpar` package runtime, offline censorship simulation lab, and transactional rollback infrastructure integrated directly into **TULPAR**.

It enables researchers, operators, and community maintainers to author, test offline, verify, benchmark, and hot-load new DPI & protocol-throttling circumvention strategies on **Windows**, **Android**, and **Linux** **without recompiling the TULPAR application**—and without arbitrary code execution, data exfiltration, telemetry, or external servers.

---

## Why TULPAR Forge Exists (Prior-Art Comparison)

| System | Definition Format | Cross-Platform Raw + Mobile Sandbox | Security / Capability Sandbox | Built-in Offline Simulation Lab | Auto-Rollback Circuit Breaker |
|---|---|---|---|---|---|
| **Zapret (`nfqws` / `tpws`)** | CLI flags (`--dpi-desync=...`) | Split tools (no Android `VpnService` IR unification) | None (root flags directly drive engine) | External scripts | None |
| **GoodByeDPI** | Hardcoded CLI presets (`-5`, `-9`) | Windows WinDivert only | N/A | None | None |
| **ByeDPI (`ciadpi`)** | Socket proxy CLI flags | Userspace proxy only (no raw L3/TTL/chksum) | OS proxy process | None | None |
| **Geneva (CCS'19)** | Genetic action trees | Python `Scapy`/`nfqueue` (root only; no mobile sandbox) | Unbounded trees (can duplicate/tamper freely) | External harness / live evolution | Research prototype |
| **Marionette / Proteus** | Pluggable transport DSL (PSF) | Client + cooperative external server | Host-safety checks for proxy peers | Trace/model tests | Requires proxy pair |
| **TULPAR Forge** | **TSL v1 (`.tlp`) -> SHA-256 sealed `.tulpar` binary IR** | **Single portable strategy maps cleanly to Windows WinDivert, Linux NFQUEUE, and Android TUN sockets** | **eBPF-style static verifier + inert RFC 2606 decoy allowlist + 5-tuple immutability** | **9 deterministic loopback + L3 middlebox scenarios in `tulpar-forge test`** | **Mandatory runtime circuit breaker auto-disables broken `.tulpar` -> `SafeBaseline`** |

---

## Core Guarantees

1. **Zero Arbitrary Code Execution**: TSL v1 is strictly non-Turing-complete (no loops, no variables, no pointers, no shell/file/environment APIs).
2. **Zero Data Exfiltration & Zero Unauthorized Connections**: Packages can only inspect/segment handshake headers (`TLS ClientHello`, `HTTP Host`, `QUIC Initial`, `UDP STUN/RakNet`) and emit transformed segments strictly along the **original flow 5-tuple** (`src_ip`, `dst_ip`, `src_port`, `dst_port`).
3. **Abuse & Amplification Prevention**:
   - Decoy SNIs/Hosts are constrained by `ForgeVerifier` to inert RFC 2606 / IANA hosts (`www.iana.org`, `example.com`, `example.org`, `example.net`) so a malicious shared package can never forge traffic attributed to a third-party victim.
   - Strict ceilings: `<= 32` rules, `<= 6` TCP split points per rule, `<= 4` decoy packets, TTL `<= 8`, MSS clamp `>= 536`, TLS micro-chunks `>= 16` bytes, total `.tulpar` package `<= 128 KiB`.
   - Every `.tulpar` binary ends with a **FIPS 180-4 SHA-256 integrity seal** (`TULPARF1`), checked before parsing AST/IR, and re-verified statically before activation.
4. **Mandatory Transactional Rollback**: Authors cannot disable the circuit breaker (`max_consecutive_failures` capped `1..=16`). If live flows fail beyond threshold, `ForgeRuntime` atomically disables the package (`DisabledRollback`) and reverts in zero downtime to TULPAR's built-in `SafeBaseline`.
5. **Minimal Core Overhead**: `tulpar-forge` has **zero external crate dependencies** (`#![forbid(unsafe_code)]`) and adds a single `AtomicBool` load when inactive.

---

## Quick Start (`tulpar-forge`)

```bash
cd forge

# Run negative security & sandbox audit + unit/lab tests
cargo test --workspace

# Inspect CLI help
cargo run -p tulpar-forge-cli -- help

# Verify & test an example strategy in the local offline censorship lab
cargo run -p tulpar-forge-cli -- check examples/turkey_balanced.tlp
cargo run -p tulpar-forge-cli -- test examples/turkey_balanced.tlp
cargo run -p tulpar-forge-cli -- bench examples/turkey_balanced.tlp

# Build a portable SHA-256 sealed `.tulpar` package
cargo run -p tulpar-forge-cli -- build examples/turkey_balanced.tlp -o examples/turkey_balanced.tulpar

# Confirm unsafe strategies are blocked by ForgeVerifier
cargo run -p tulpar-forge-cli -- verify-security
```

## Loading `.tulpar` Packages Without Recompiling TULPAR

- **Linux (`platforms/linux`)**: `sudo tulpar start --strategy /path/to/turkey_balanced.tulpar` (or stage under `/etc/tulpar/active.tulpar`)
- **Windows (`platforms/windows`)**: `tulpar.exe --strategy C:\path\to\turkey_balanced.tulpar` (or `%ProgramData%\Tulpar\strategies\active.tulpar`)
- **Android (`platforms/android`)**: `YolacNative.nativeLoadForgePackage(bytes)` / `YolacNative.nativeUnloadForgePackage()` via JNI, or automatic verified load from app-private `filesDir/forge/active.tulpar` on VPN start.
- **Rust Core API (`yolac-core`)**: `engine.load_forge_package_file(path)` / `engine.load_forge_package_bytes(bytes)` / `engine.forge_status()`.

## Further Documentation
- [TULPAR Strategy Language Reference & Binary `.tulpar` Spec](docs/STRATEGY_LANGUAGE.md)
- [Forge Architecture, Safety Model & Honest Technical Limitations](docs/ARCHITECTURE.md)
