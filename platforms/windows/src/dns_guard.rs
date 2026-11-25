//! Windows DNS cache flushing (System32-pinned against DLL hijacking) & MTU-safe L3 DNS reply builder.

use std::net::IpAddr;

use yolac_dpi::{build_ipv4_udp_packet, build_ipv6_udp_packet};

#[cfg(windows)]
pub fn flush_windows_dns_cache() {
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    unsafe {
        let mut name: Vec<u16> = "dnsapi.dll\0".encode_utf16().collect();
        // Strictly restrict search to System32 to eliminate DLL hijacking under Administrator privileges!
        let module = LoadLibraryExW(
            name.as_mut_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        );
        if module.is_null() {
            return;
        }
        if let Some(proc_addr) = GetProcAddress(module, c"DnsFlushResolverCache".as_ptr().cast()) {
            let func = std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn() -> i32,
            >(proc_addr);
            let _ = func();
        }
        FreeLibrary(module);
    }
}

#[cfg(not(windows))]
pub fn flush_windows_dns_cache() {}

pub fn build_dns_reply_l3(
    orig_src_ip: IpAddr,
    orig_dst_ip: IpAddr,
    orig_src_port: u16,
    orig_dst_port: u16,
    dns_payload: &[u8],
) -> Option<Vec<u8>> {
    // Never inject oversized unfragmented UDP DNS responses (> 1450B breaks DF=1 on 1500 MTU)
    if dns_payload.len() > 1450 {
        return None;
    }
    match (orig_dst_ip, orig_src_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => Some(build_ipv4_udp_packet(
            s,
            d,
            orig_dst_port,
            orig_src_port,
            64,
            dns_payload,
        )),
        (IpAddr::V6(s), IpAddr::V6(d)) => Some(build_ipv6_udp_packet(
            s,
            d,
            orig_dst_port,
            orig_src_port,
            64,
            dns_payload,
        )),
        _ => None,
    }
}
