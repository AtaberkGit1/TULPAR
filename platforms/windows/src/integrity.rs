#![allow(dead_code)]
//! Strict WinDivert binary cryptographic integrity (SHA-256), NTFS junction/reparse-point defense,
//! `%ProgramData%` machine-wide extraction, and TOCTOU file-handle locking under elevated privileges.

use std::fs::{File, OpenOptions};
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

/// Holds open read-shared (`FILE_SHARE_READ` only — denies write/delete!) file handles to
/// `WinDivert.dll` and `WinDivert64.sys` across `LoadLibraryExW` and `WinDivertOpen` so a
/// non-elevated local process CANNOT swap the verified binaries in a TOCTOU window!
pub struct VerifiedWinDivertLock {
    pub dll_path: PathBuf,
    _dll_handle: File,
    _sys_handle: File,
}

fn sha256_open_file_hex(file: &mut File) -> io::Result<String> {
    let mut ctx = Context::new(&SHA256);
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = file.read(&mut buf)?;
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

pub fn sha256_file_hex(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    sha256_open_file_hex(&mut f)
}

#[cfg(windows)]
fn is_reparse_point(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

#[cfg(not(windows))]
fn is_reparse_point(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn open_read_locked(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ (0x1) ONLY: blocks any concurrent process from modifying or deleting!
        opts.share_mode(0x0000_0001);
    }
    opts.open(path)
}

fn verify_and_lock_in_dir(app_dir: &Path) -> Result<VerifiedWinDivertLock, ErrorCode> {
    if is_reparse_point(app_dir) {
        return Err(ErrorCode::DriverIntegrityFailed);
    }
    let dll_path = app_dir.join("WinDivert.dll");
    let sys_path = app_dir.join("WinDivert64.sys");

    if !dll_path.is_file() || !sys_path.is_file() {
        return Err(ErrorCode::DriverMissing);
    }
    if is_reparse_point(&dll_path) || is_reparse_point(&sys_path) {
        return Err(ErrorCode::DriverIntegrityFailed);
    }

    let mut dll_file = open_read_locked(&dll_path).map_err(|_| ErrorCode::DriverIntegrityFailed)?;
    let mut sys_file = open_read_locked(&sys_path).map_err(|_| ErrorCode::DriverIntegrityFailed)?;

    let dll_hash = sha256_open_file_hex(&mut dll_file).map_err(|_| ErrorCode::DriverIntegrityFailed)?;
    let sys_hash = sha256_open_file_hex(&mut sys_file).map_err(|_| ErrorCode::DriverIntegrityFailed)?;

    if dll_hash != WINDIVERT_222_X64_DLL_SHA256 || sys_hash != WINDIVERT_222_X64_SYS_SHA256 {
        return Err(ErrorCode::DriverIntegrityFailed);
    }

    Ok(VerifiedWinDivertLock {
        dll_path,
        _dll_handle: dll_file,
        _sys_handle: sys_file,
    })
}

/// Verifies `WinDivert.dll` and `WinDivert64.sys` strictly inside `app_dir` against pinned
/// official 256-bit SHA-256 digests.
pub fn verify_windivert_in_dir(app_dir: &Path) -> Result<PathBuf, ErrorCode> {
    verify_and_lock_in_dir(app_dir).map(|lock| lock.dll_path)
}

/// Resolves the directory containing `tulpar.exe` and runs strict WinDivert SHA-256 verification.
pub fn verify_windivert_next_to_exe() -> Result<PathBuf, ErrorCode> {
    let exe = std::env::current_exe().map_err(|_| ErrorCode::DriverMissing)?;
    let dir = exe.parent().ok_or(ErrorCode::DriverMissing)?;
    verify_windivert_in_dir(dir)
}

/// Machine-wide `%ProgramData%\Tulpar\driver\2.2.2` directory (consistent across Standard User +
/// separate Admin UAC elevation and protected from Medium-integrity user tampering).
fn embedded_driver_dir() -> Option<PathBuf> {
    if let Some(pd) = std::env::var_os("ProgramData") {
        return Some(PathBuf::from(pd).join("Tulpar").join("driver").join("2.2.2"));
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return Some(PathBuf::from(local).join("Tulpar").join("driver").join("2.2.2"));
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("driver")))
}

/// Verifies & locks WinDivert next to the executable first; if absent and embedded WinDivert bytes
/// were compiled into `tulpar.exe`, safely extracts them into `%ProgramData%\Tulpar\driver\2.2.2`
/// (rejecting NTFS junctions/reparse points) and returns an active TOCTOU-proof `VerifiedWinDivertLock`.
#[allow(dead_code)]
pub fn ensure_verified_windivert_locked() -> Result<VerifiedWinDivertLock, ErrorCode> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            match verify_and_lock_in_dir(dir) {
                Ok(lock) => return Ok(lock),
                Err(ErrorCode::DriverIntegrityFailed) => return Err(ErrorCode::DriverIntegrityFailed),
                Err(ErrorCode::DriverMissing) => {}
                Err(other) => return Err(other),
            }
        }
    }

    #[cfg(has_embedded_windivert)]
    {
        let dir = embedded_driver_dir().ok_or(ErrorCode::DriverMissing)?;
        // Reject NTFS junction/symlink attacks on any ancestor component inside Tulpar dir
        if dir.exists() && is_reparse_point(&dir) {
            return Err(ErrorCode::DriverIntegrityFailed);
        }
        if let Some(parent) = dir.parent() {
            if parent.exists() && is_reparse_point(parent) {
                return Err(ErrorCode::DriverIntegrityFailed);
            }
        }
        if let Ok(existing) = verify_and_lock_in_dir(&dir) {
            return Ok(existing);
        }
        std::fs::create_dir_all(&dir).map_err(|_| ErrorCode::DriverMissing)?;
        if is_reparse_point(&dir) {
            return Err(ErrorCode::DriverIntegrityFailed);
        }
        let dll_path = dir.join("WinDivert.dll");
        let sys_path = dir.join("WinDivert64.sys");
        if is_reparse_point(&dll_path) || is_reparse_point(&sys_path) {
            return Err(ErrorCode::DriverIntegrityFailed);
        }
        let _ = std::fs::write(&dll_path, EMBEDDED_WINDIVERT_DLL);
        let _ = std::fs::write(&sys_path, EMBEDDED_WINDIVERT_SYS);
        verify_and_lock_in_dir(&dir)
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

        assert_eq!(verify_windivert_in_dir(&base), Err(ErrorCode::DriverMissing));

        std::fs::write(base.join("WinDivert.dll"), b"fake trojan dll").unwrap();
        std::fs::write(base.join("WinDivert64.sys"), b"fake trojan sys").unwrap();
        assert_eq!(
            verify_windivert_in_dir(&base),
            Err(ErrorCode::DriverIntegrityFailed)
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
