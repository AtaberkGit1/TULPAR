//! Strict WinDivert binary cryptographic integrity (SHA-256) verification and
//! standalone embedded driver extraction to prevent DLL hijacking under elevated privileges.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use ring::digest::{Context, SHA256};
use yolac_core::ErrorCode;

/// Official WinDivert 2.2.2-A (x64) Microsoft-signed release SHA-256 digests.
pub const WINDIVERT_222_X64_DLL_SHA256: &str =
    "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2";
pub const WINDIVERT_222_X64_SYS_SHA256: &str =
    "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2";

#[cfg(has_embedded_windivert)]
const EMBEDDED_WINDIVERT_DLL: &[u8] = include_bytes!(env!("TULPAR_EMBED_DLL"));
#[cfg(has_embedded_windivert)]
const EMBEDDED_WINDIVERT_SYS: &[u8] = include_bytes!(env!("TULPAR_EMBED_SYS"));

pub fn sha256_file_hex(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut ctx = Context::new(&SHA256);
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let digest = ctx.finish();
    let mut hex = String::with_capacity(64);
    for b in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{b:02x}");
    }
    Ok(hex)
}

/// Verifies `WinDivert.dll` and `WinDivert64.sys` strictly inside `app_dir` against pinned
/// official 256-bit SHA-256 digests (Windows Kernel DSE additionally verifies the kernel driver
/// signature on load). Returns the path to `WinDivert.dll` ONLY if both SHA-256 digests match.
pub fn verify_windivert_in_dir(app_dir: &Path) -> Result<PathBuf, ErrorCode> {
    let dll_path = app_dir.join("WinDivert.dll");
    let sys_path = app_dir.join("WinDivert64.sys");

    if !dll_path.is_file() || !sys_path.is_file() {
        return Err(ErrorCode::DriverMissing);
    }

    let dll_hash = sha256_file_hex(&dll_path).map_err(|_| ErrorCode::DriverIntegrityFailed)?;
    let sys_hash = sha256_file_hex(&sys_path).map_err(|_| ErrorCode::DriverIntegrityFailed)?;

    if dll_hash != WINDIVERT_222_X64_DLL_SHA256 || sys_hash != WINDIVERT_222_X64_SYS_SHA256 {
        return Err(ErrorCode::DriverIntegrityFailed);
    }

    Ok(dll_path)
}

/// Resolves the directory containing `tulpar.exe` and runs strict WinDivert SHA-256 verification.
pub fn verify_windivert_next_to_exe() -> Result<PathBuf, ErrorCode> {
    let exe = std::env::current_exe().map_err(|_| ErrorCode::DriverMissing)?;
    let dir = exe.parent().ok_or(ErrorCode::DriverMissing)?;
    verify_windivert_in_dir(dir)
}

fn embedded_driver_dir() -> Option<PathBuf> {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return Some(PathBuf::from(local).join("Tulpar").join("driver").join("2.2.2"));
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("driver")))
}

/// Verifies WinDivert next to the executable first; if absent and embedded WinDivert bytes were
/// compiled into `tulpar.exe`, extracts them to `%LOCALAPPDATA%\Tulpar\driver\2.2.2` and verifies
/// both SHA-256 digests before returning the canonical path to `WinDivert.dll`.
#[allow(dead_code)]
pub fn ensure_verified_windivert() -> Result<PathBuf, ErrorCode> {
    match verify_windivert_next_to_exe() {
        Ok(p) => return Ok(p),
        Err(ErrorCode::DriverIntegrityFailed) => return Err(ErrorCode::DriverIntegrityFailed),
        Err(ErrorCode::DriverMissing) => {}
        Err(other) => return Err(other),
    }

    #[cfg(has_embedded_windivert)]
    {
        let dir = embedded_driver_dir().ok_or(ErrorCode::DriverMissing)?;
        if let Ok(existing) = verify_windivert_in_dir(&dir) {
            return Ok(existing);
        }
        std::fs::create_dir_all(&dir).map_err(|_| ErrorCode::DriverMissing)?;
        let dll_path = dir.join("WinDivert.dll");
        let sys_path = dir.join("WinDivert64.sys");
        // Ignore write error if an active driver already holds the file open; SHA-256 check below validates it.
        let _ = std::fs::write(&dll_path, EMBEDDED_WINDIVERT_DLL);
        let _ = std::fs::write(&sys_path, EMBEDDED_WINDIVERT_SYS);
        return verify_windivert_in_dir(&dir);
    }

    #[cfg(not(has_embedded_windivert))]
    {
        let _ = embedded_driver_dir();
        Err(ErrorCode::DriverMissing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_or_tampered_windivert_binaries() {
        let base = std::env::temp_dir().join(format!("tulpar_wd_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        // Missing files -> DriverMissing
        assert_eq!(verify_windivert_in_dir(&base), Err(ErrorCode::DriverMissing));

        // Trojanized / tampered dummy files -> DriverIntegrityFailed
        std::fs::write(base.join("WinDivert.dll"), b"fake trojan dll").unwrap();
        std::fs::write(base.join("WinDivert64.sys"), b"fake trojan sys").unwrap();
        assert_eq!(
            verify_windivert_in_dir(&base),
            Err(ErrorCode::DriverIntegrityFailed)
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
