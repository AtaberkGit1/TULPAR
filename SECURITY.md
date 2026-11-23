# TULPAR Security & Privacy Model

## 1. Zero-Server & Zero-Telemetry Guarantee
- TULPAR operates **100% on-device**. There are no TULPAR-operated servers, relays, telemetry endpoints, crash-reporting SDKs, analytics libraries, or user accounts.
- No connection history, DNS queries, visited domains, SNI hostnames, or destination IP addresses are ever written to disk or transmitted to any third party.
- All ephemeral state (DNS LRU cache, per-destination adaptive DPI strategy map, SYN-ACK hop calibrator) lives strictly in RAM, uses salted ephemeral hashes where applicable, and is immediately zeroed/dropped when protection stops.

## 2. Memory Safety & Auditable Core
- The shared network core (`core/crates/*`) is written in safe Rust (`#![forbid(unsafe_code)]` in `yolac-dpi`, `yolac-blocklist`, `yolac-dns`, `yolac-core`).
- `unsafe` is strictly isolated to OS FFI/socket boundaries (`yolac-net` socket FD protection, `yolac-ffi` C-ABI/JNI boundary, `platforms/windows` Win32/WinDivert bindings) with explicit bounds checks and null-pointer guards.
- Pure-Rust TLS (`rustls` + `webpki-roots`) avoids C/C++ OpenSSL memory-corruption surfaces.

## 3. Leak Prevention & Binary Integrity
- **DNS Leak Prevention**: All IPv4 & IPv6 UDP/53 and TCP/53 traffic is captured and resolved locally through `yolac-dns` (local blocklist + persistent keep-alive encrypted DoH/DoT with hardcoded bootstrap IPs). Plaintext ISP fallback is strictly disabled (fail-closed).
- **Balanced Fail-Closed IPv6 Protection**: `probe_ipv6_leak_mode` checks protected IPv6 reachability; if IPv6 is broken or unguarded, YOLAÇ automatically switches to `BlockUnprotectedIpv6` + `AAAA` suppression so host IPv6 cannot leak.
- **Windows DLL Hijacking Protection**: Elevated `tulpar.exe` loads `WinDivert.dll` strictly from the executable directory (`LOAD_LIBRARY_SEARCH_APPLICATION_DIR`) ONLY after verifying official WinDivert 2.2.2 SHA-256 digests (`WinDivert.dll` + `WinDivert64.sys`) and Windows Authenticode signature (`WinVerifyTrust`).
- **Bounded Captive Portal Safety**: Temporary local-LAN portal allowance activates only on consecutive encrypted DNS failures alongside OS portal checks, is strictly capped at 90 seconds, and automatically closes the instant encrypted DNS succeeds again.
- **Release Checksums**: Tag-triggered releases (`v*`) publish `SHA256SUMS.txt` alongside all artifacts on `https://github.com/AtaberkGit1/TULPAR/releases`.
- **DoS / OOM Caps**: `TunEngine` enforces bounded concurrent DNS semaphores, strict max packet size (`<= 65535`), bounded TCP flow caps, and LRU UDP NAT eviction.

## 4. Reporting Vulnerabilities
Because TULPAR is open-source and runs locally, any security issue can be audited directly in the repository. Please avoid publishing exploit details before a fix is merged.
