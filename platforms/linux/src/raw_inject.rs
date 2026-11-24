//! Linux `IPPROTO_RAW` IPv4/IPv6 packet injector and `SO_MARK` socket protector.
//! Marks every injected DPI segment AND every upstream DoH/DoT socket with `TULPAR_FWMARK`
//! (`0x54554C50`) so nftables/iptables rules NEVER re-capture or loop TULPAR's own traffic!

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use yolac_net::SocketProtector;

/// Unique fwmark `"TULP"` (0x54554C50) used to bypass TULPAR netfilter/NAT/conntrack hooks cleanly.
pub const TULPAR_FWMARK: u32 = 0x5455_4C50;

pub struct LinuxMarkProtector;

impl SocketProtector for LinuxMarkProtector {
    fn protect_fd(&self, fd: i32) -> io::Result<()> {
        let mark = TULPAR_FWMARK as libc::c_uint;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&mark as *const libc::c_uint).cast(),
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }
}

pub struct RawPacketInjector {
    v4_fd: OwnedFd,
    v6_fd: Option<OwnedFd>,
}

impl RawPacketInjector {
    pub fn open() -> io::Result<Self> {
        let v4_raw = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            )
        };
        if v4_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let v4_fd = unsafe { OwnedFd::from_raw_fd(v4_raw) };
        let one: libc::c_int = 1;
        let mark = TULPAR_FWMARK as libc::c_uint;
        unsafe {
            if libc::setsockopt(
                v4_fd.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            // Must succeed so injected packets carry TULPAR_FWMARK and never loop back into NFQUEUE!
            if libc::setsockopt(
                v4_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&mark as *const libc::c_uint).cast(),
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
        }

        // Only enable IPv6 raw socket if BOTH IPV6_HDRINCL AND SO_MARK succeed cleanly;
        // otherwise return Err during IPv6 inject so NFQUEUE cleanly falls back to NF_ACCEPT!
        let v6_fd = unsafe {
            let raw = libc::socket(
                libc::AF_INET6,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            );
            if raw >= 0 {
                let fd = OwnedFd::from_raw_fd(raw);
                let ok_hdr = libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_HDRINCL,
                    (&one as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                ) == 0;
                let ok_mark = libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&mark as *const libc::c_uint).cast(),
                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                ) == 0;
                if ok_hdr && ok_mark {
                    Some(fd)
                } else {
                    None
                }
            } else {
                None
            }
        };

        Ok(Self { v4_fd, v6_fd })
    }

    pub fn inject(&self, raw_l3: &[u8]) -> io::Result<()> {
        if raw_l3.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty packet"));
        }
        let version = raw_l3[0] >> 4;
        match version {
            4 if raw_l3.len() >= 20 => {
                let mut dst: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                dst.sin_family = libc::AF_INET as libc::sa_family_t;
                dst.sin_port = 0;
                dst.sin_addr.s_addr = u32::from_ne_bytes(raw_l3[16..20].try_into().unwrap());
                let sent = unsafe {
                    libc::sendto(
                        self.v4_fd.as_raw_fd(),
                        raw_l3.as_ptr().cast(),
                        raw_l3.len(),
                        0,
                        (&dst as *const libc::sockaddr_in).cast(),
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };
                if sent < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }
            6 if raw_l3.len() >= 40 => {
                // Return Err when v6_fd is absent so run_nfqueue_loop issues NF_ACCEPT instead of blackholing!
                let v6 = self.v6_fd.as_ref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Unsupported, "IPv6 raw socket unavailable")
                })?;
                let mut dst: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                dst.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                dst.sin6_port = 0;
                dst.sin6_addr.s6_addr.copy_from_slice(&raw_l3[24..40]);
                let sent = unsafe {
                    libc::sendto(
                        v6.as_raw_fd(),
                        raw_l3.as_ptr().cast(),
                        raw_l3.len(),
                        0,
                        (&dst as *const libc::sockaddr_in6).cast(),
                        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                };
                if sent < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported L3 header")),
        }
    }
}
