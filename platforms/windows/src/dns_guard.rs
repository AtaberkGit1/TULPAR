//! Windows DNS cache flushing & L3 DNS reply packet builder.

use std::net::IpAddr;

use yolac_dpi::{build_ipv4_udp_packet, build_ipv6_udp_packet};

#[cfg(windows)]
pub fn flush_windows_dns_cache() {
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    unsafe {
        let mut name: Vec<u16> = "dnsapi.dll\0".encode_utf16().collect();
        let module = LoadLibraryW(name.as_mut_ptr());
        if module.is_null() {
            return;
        }
        if let Some(proc_addr) = GetProcAddress(module, b"DnsFlushResolverCache\0".as_ptr()) {
            let func: unsafe extern "system" fn() -> i32 = std::mem::transmute(proc_addr);
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
