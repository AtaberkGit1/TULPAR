//! Explicit Windows Administrator privilege check & UAC elevation trigger.

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

/// Requests explicit Windows UAC elevation by relaunching the current executable with `--elevated-start`,
/// preserving full UTF-16 path & working directory (never loops if elevation is suppressed).
#[cfg(all(windows, not(test)))]
pub fn request_uac_elevation() -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let mut exe_w: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut dir_w: Option<Vec<u16>> = exe
        .parent()
        .map(|d| d.as_os_str().encode_wide().chain(Some(0)).collect());
    let mut verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let mut args: Vec<u16> = "--elevated-start\0".encode_utf16().collect();

    let h = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_mut_ptr(),
            exe_w.as_mut_ptr(),
            args.as_mut_ptr(),
            dir_w.as_mut().map_or(std::ptr::null(), |v| v.as_ptr()),
            SW_SHOWNORMAL,
        )
    };
    (h as usize) > 32
}

#[cfg(any(not(windows), test))]
pub fn request_uac_elevation() -> bool {
    false
}
