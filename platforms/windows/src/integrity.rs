//! Strict WinDivert binary integrity (SHA-256) and Windows Authenticode verification
//! to prevent DLL hijacking under elevated Administrator privileges.

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

/// Verifies `WinDivert.dll` and `WinDivert64.sys` strictly inside `app_dir` against known SHA-256 digests
/// (and on Windows, verifies Authenticode signature via `wintrust.dll::WinVerifyTrust`).
/// Returns the canonical absolute path to `WinDivert.dll` ONLY if all checks succeed.
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

    #[cfg(windows)]
    {
        if !verify_authenticode_signature(&sys_path) {
            return Err(ErrorCode::DriverIntegrityFailed);
        }
    }

    Ok(dll_path)
}

/// Resolves the directory containing `yolac.exe` and runs strict WinDivert integrity verification.
pub fn verify_windivert_next_to_exe() -> Result<PathBuf, ErrorCode> {
    let exe = std::env::current_exe().map_err(|_| ErrorCode::DriverMissing)?;
    let dir = exe.parent().ok_or(ErrorCode::DriverMissing)?;
    verify_windivert_in_dir(dir)
}

#[cfg(windows)]
fn verify_authenticode_signature(path: &Path) -> bool {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    struct WinTrustFileInfo {
        cb_struct: u32,
        pcwsz_file_path: *const u16,
        h_file: *mut c_void,
        pg_known_subject: *mut c_void,
    }

    #[repr(C)]
    struct WinTrustData {
        cb_struct: u32,
        p_policy_callback_data: *mut c_void,
        p_sip_client_data: *mut c_void,
        dw_ui_choice: u32,
        fdw_revocation_checks: u32,
        dw_union_choice: u32,
        p_file: *mut WinTrustFileInfo,
        dw_state_action: u32,
        h_wvt_state_data: *mut c_void,
        pwsz_url_reference: *mut u16,
        dw_prov_flags: u32,
        dw_ui_context: u32,
        p_signature_settings: *mut c_void,
    }

    // WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    let mut action_guid = Guid {
        data1: 0x00AA_C56B,
        data2: 0xCD44,
        data3: 0x11D0,
        data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };

    let path_w: Vec<u16> = path.to_string_lossy().encode_utf16().chain(Some(0)).collect();
    let mut file_info = WinTrustFileInfo {
        cb_struct: std::mem::size_of::<WinTrustFileInfo>() as u32,
        pcwsz_file_path: path_w.as_ptr(),
        h_file: std::ptr::null_mut(),
        pg_known_subject: std::ptr::null_mut(),
    };
    let mut trust_data = WinTrustData {
        cb_struct: std::mem::size_of::<WinTrustData>() as u32,
        p_policy_callback_data: std::ptr::null_mut(),
        p_sip_client_data: std::ptr::null_mut(),
        dw_ui_choice: 2, // WTD_UI_NONE
        fdw_revocation_checks: 0, // WTD_REVOKE_NONE (works offline without external server!)
        dw_union_choice: 1, // WTD_CHOICE_FILE
        p_file: &mut file_info,
        dw_state_action: 1, // WTD_STATEACTION_VERIFY
        h_wvt_state_data: std::ptr::null_mut(),
        pwsz_url_reference: std::ptr::null_mut(),
        dw_prov_flags: 0x0000_0040, // WTD_CACHE_ONLY_URL_RETRIEVAL
        dw_ui_context: 0,
        p_signature_settings: std::ptr::null_mut(),
    };

    unsafe {
        let mut dll: Vec<u16> = "wintrust.dll\0".encode_utf16().collect();
        let module = LoadLibraryExW(dll.as_mut_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if module.is_null() {
            return false;
        }
        let Some(sym) = GetProcAddress(module, b"WinVerifyTrust\0".as_ptr()) else {
            FreeLibrary(module);
            return false;
        };
        let win_verify_trust: unsafe extern "system" fn(
            *mut c_void,
            *mut Guid,
            *mut WinTrustData,
        ) -> i32 = std::mem::transmute(sym);

        let status = win_verify_trust((-1isize) as *mut c_void, &mut action_guid, &mut trust_data);
        // Clean up WVT state handle
        trust_data.dw_state_action = 2; // WTD_STATEACTION_CLOSE
        let _ = win_verify_trust((-1isize) as *mut c_void, &mut action_guid, &mut trust_data);
        FreeLibrary(module);
        status == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_or_tampered_windivert_binaries() {
        let base = std::env::temp_dir().join(format!("yolac_wd_test_{}", std::process::id()));
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
