//! Pure-Rust Linux Netlink `NFQUEUE` client (`AF_NETLINK` / `NETLINK_NETFILTER`).
//! Zero C library dependencies (`libnetfilter_queue.so` / `libmnl.so` are NOT required).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const AF_NETLINK_VAL: i32 = 16;
const NETLINK_NETFILTER_VAL: i32 = 12;
const SOL_NETLINK_VAL: i32 = 270;
const NETLINK_NO_ENOBUFS_VAL: i32 = 5;

const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFNETLINK_V0: u8 = 0;

// enum nfqnl_msg_types (linux/netfilter/nfnetlink_queue.h)
const NFQNL_MSG_PACKET: u8 = 0;
const NFQNL_MSG_VERDICT: u8 = 1;
const NFQNL_MSG_CONFIG: u8 = 2;

// enum nfqnl_msg_config_cmds
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_CFG_CMD_PF_UNBIND: u8 = 4;

// enum nfqnl_config_mode
const NFQNL_COPY_PACKET: u8 = 2;

// enum nfqnl_attr_config
const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;

// Fail-open ONLY (intentionally omit NFQA_CFG_F_GSO so Linux kernel segments GSO frames BEFORE
// NFQUEUE, ensuring every packet fits MTU for clean IPPROTO_RAW injection without EMSGSIZE!).
const NFQA_CFG_F_FAIL_OPEN: u32 = 1 << 0;

// enum nfqnl_attr_type
const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_PAYLOAD: u16 = 10;

pub const NF_DROP: u32 = 0;
pub const NF_ACCEPT: u32 = 1;

#[allow(dead_code)]
pub const NF_INET_LOCAL_IN: u8 = 1;
pub const NF_INET_LOCAL_OUT: u8 = 3;

const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_OVERRUN: u16 = 4;

#[inline]
fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

#[derive(Debug, Clone)]
pub struct NfqPacket {
    pub packet_id: u32,
    pub hook: u8,
    pub payload: Vec<u8>,
}

pub struct NfqSocket {
    fd: OwnedFd,
    queue_num: u16,
    seq: u32,
}

impl NfqSocket {
    pub fn open(queue_num: u16) -> io::Result<Self> {
        let raw = unsafe {
            libc::socket(
                AF_NETLINK_VAL,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER_VAL,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let rcvbuf: libc::c_int = 4 * 1024 * 1024;
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&rcvbuf as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            let one: libc::c_int = 1;
            libc::setsockopt(
                fd.as_raw_fd(),
                SOL_NETLINK_VAL,
                NETLINK_NO_ENOBUFS_VAL,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK_VAL as libc::sa_family_t;
        addr.nl_pid = 0;
        addr.nl_groups = 0;
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut sock = Self {
            fd,
            queue_num,
            seq: 1,
        };
        sock.set_recv_timeout_ms(1000);
        sock.configure()?;
        Ok(sock)
    }

    fn send_netlink(&self, buf: &[u8]) -> io::Result<()> {
        let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dst.nl_family = AF_NETLINK_VAL as libc::sa_family_t;
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                buf.as_ptr().cast(),
                buf.len(),
                0,
                (&dst as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn send_and_expect_ack(&self, msg: &[u8], label: &str) -> io::Result<()> {
        self.send_netlink(msg)?;
        let mut ack_buf = [0u8; 4096];
        let n = unsafe { libc::recv(self.fd.as_raw_fd(), ack_buf.as_mut_ptr().cast(), ack_buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let raw = &ack_buf[..n as usize];
        if raw.len() >= 20 {
            let nlmsg_type = u16::from_ne_bytes(raw[4..6].try_into().unwrap());
            if nlmsg_type == NLMSG_ERROR {
                let err_code = i32::from_ne_bytes(raw[16..20].try_into().unwrap());
                if err_code < 0 {
                    return Err(io::Error::from_raw_os_error(-err_code));
                }
                return Ok(());
            }
        }
        Err(io::Error::other(format!("{label}: kernel ACK alınamadı")))
    }

    fn configure(&mut self) -> io::Result<()> {
        for pf in [libc::AF_INET as u16, libc::AF_INET6 as u16] {
            let s = self.next_seq();
            let msg = build_config_cmd_msg(0, NFQNL_CFG_CMD_PF_UNBIND, pf, s, false);
            let _ = self.send_netlink(&msg);
        }

        let s = self.next_seq();
        let bind_msg = build_config_cmd_msg(self.queue_num, NFQNL_CFG_CMD_BIND, 0, s, true);
        self.send_and_expect_ack(&bind_msg, "NFQUEUE BIND (başka bir araç/zapret kuyruğu kullanıyor olabilir)")?;

        let s2 = self.next_seq();
        let params_msg = build_config_params_msg(self.queue_num, 65535, 4096, s2, true);
        self.send_and_expect_ack(&params_msg, "NFQUEUE PARAMS")?;
        Ok(())
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    pub fn recv_packets(&self, buf: &mut [u8]) -> io::Result<Vec<NfqPacket>> {
        let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(parse_nfq_messages(&buf[..n as usize]))
    }

    pub fn send_verdict(&self, packet_id: u32, verdict: u32) -> io::Result<()> {
        let msg = build_verdict_msg(self.queue_num, packet_id, verdict);
        self.send_netlink(&msg)
    }

    pub fn set_recv_timeout_ms(&self, ms: i64) {
        let tv = libc::timeval {
            tv_sec: ms / 1000,
            tv_usec: (ms % 1000) * 1000,
        };
        unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
    }
}

fn push_nl_header(buf: &mut Vec<u8>, msg_type: u8, seq: u32, family: u8, res_id: u16, ack: bool) {
    let nlmsg_type: u16 = (NFNL_SUBSYS_QUEUE << 8) | (msg_type as u16);
    let flags = if ack { NLM_F_REQUEST | NLM_F_ACK } else { NLM_F_REQUEST };
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&nlmsg_type.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.push(family);
    buf.push(NFNETLINK_V0);
    buf.extend_from_slice(&res_id.to_be_bytes());
}

fn push_nla(buf: &mut Vec<u8>, nla_type: u16, data: &[u8]) {
    let len = (4 + data.len()) as u16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&nla_type.to_ne_bytes());
    buf.extend_from_slice(data);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

fn finalize_nlmsg(buf: &mut [u8]) {
    let len = buf.len() as u32;
    buf[0..4].copy_from_slice(&len.to_ne_bytes());
}

pub fn build_config_cmd_msg(queue_num: u16, cmd: u8, pf: u16, seq: u32, ack: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    push_nl_header(&mut buf, NFQNL_MSG_CONFIG, seq, libc::AF_UNSPEC as u8, queue_num, ack);
    let mut cmd_data = [0u8; 4];
    cmd_data[0] = cmd;
    cmd_data[2..4].copy_from_slice(&pf.to_be_bytes());
    push_nla(&mut buf, NFQA_CFG_CMD, &cmd_data);
    finalize_nlmsg(&mut buf);
    buf
}

pub fn build_config_params_msg(queue_num: u16, copy_range: u32, maxlen: u32, seq: u32, ack: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96);
    push_nl_header(&mut buf, NFQNL_MSG_CONFIG, seq, libc::AF_UNSPEC as u8, queue_num, ack);

    let mut params = [0u8; 5];
    params[0..4].copy_from_slice(&copy_range.to_be_bytes());
    params[4] = NFQNL_COPY_PACKET;
    push_nla(&mut buf, NFQA_CFG_PARAMS, &params);

    push_nla(&mut buf, NFQA_CFG_QUEUE_MAXLEN, &maxlen.to_be_bytes());

    let flags = NFQA_CFG_F_FAIL_OPEN;
    push_nla(&mut buf, NFQA_CFG_MASK, &flags.to_be_bytes());
    push_nla(&mut buf, NFQA_CFG_FLAGS, &flags.to_be_bytes());

    finalize_nlmsg(&mut buf);
    buf
}

pub fn build_verdict_msg(queue_num: u16, packet_id: u32, verdict: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(48);
    push_nl_header(&mut buf, NFQNL_MSG_VERDICT, 0, libc::AF_UNSPEC as u8, queue_num, false);
    let mut hdr = [0u8; 8];
    hdr[0..4].copy_from_slice(&verdict.to_be_bytes());
    hdr[4..8].copy_from_slice(&packet_id.to_be_bytes());
    push_nla(&mut buf, NFQA_VERDICT_HDR, &hdr);
    finalize_nlmsg(&mut buf);
    buf
}

pub fn parse_nfq_messages(raw: &[u8]) -> Vec<NfqPacket> {
    let mut out = Vec::new();
    let mut offset = 0usize;

    while offset + 16 <= raw.len() {
        let nlmsg_len = u32::from_ne_bytes(raw[offset..offset + 4].try_into().unwrap()) as usize;
        if nlmsg_len < 16 || offset + nlmsg_len > raw.len() {
            break;
        }
        let nlmsg_type = u16::from_ne_bytes(raw[offset + 4..offset + 6].try_into().unwrap());
        let subsys = nlmsg_type >> 8;
        let msg_op = (nlmsg_type & 0x00FF) as u8;

        if (NLMSG_NOOP..=NLMSG_OVERRUN).contains(&nlmsg_type) {
            offset += nlmsg_align(nlmsg_len);
            continue;
        }

        if subsys == NFNL_SUBSYS_QUEUE && msg_op == NFQNL_MSG_PACKET && nlmsg_len >= 20 {
            let attrs = &raw[offset + 20..offset + nlmsg_len];
            let mut pkt_id = None;
            let mut hook = NF_INET_LOCAL_OUT;
            let mut payload = None;

            let mut aoff = 0usize;
            while aoff + 4 <= attrs.len() {
                let nla_len =
                    u16::from_ne_bytes(attrs[aoff..aoff + 2].try_into().unwrap()) as usize;
                let nla_type =
                    u16::from_ne_bytes(attrs[aoff + 2..aoff + 4].try_into().unwrap()) & 0x3FFF;
                if nla_len < 4 || aoff + nla_len > attrs.len() {
                    break;
                }
                let val = &attrs[aoff + 4..aoff + nla_len];
                match nla_type {
                    NFQA_PACKET_HDR if val.len() >= 7 => {
                        pkt_id = Some(u32::from_be_bytes(val[0..4].try_into().unwrap()));
                        hook = val[6];
                    }
                    NFQA_PAYLOAD if !val.is_empty() => {
                        payload = Some(val.to_vec());
                    }
                    _ => {}
                }
                aoff += nlmsg_align(nla_len);
            }

            if let (Some(id), Some(bytes)) = (pkt_id, payload) {
                out.push(NfqPacket {
                    packet_id: id,
                    hook,
                    payload: bytes,
                });
            }
        }

        offset += nlmsg_align(nlmsg_len);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_verdict_and_parses_synthetic_nfq_packet() {
        let v = build_verdict_msg(5455, 0x1122_3344, NF_ACCEPT);
        assert_eq!(u32::from_ne_bytes(v[0..4].try_into().unwrap()) as usize, v.len());
        let nlmsg_type = u16::from_ne_bytes(v[4..6].try_into().unwrap());
        assert_eq!(nlmsg_type, (NFNL_SUBSYS_QUEUE << 8) | (NFQNL_MSG_VERDICT as u16));
        assert_eq!(u16::from_be_bytes([v[18], v[19]]), 5455);

        let mut msg = Vec::new();
        push_nl_header(&mut msg, NFQNL_MSG_PACKET, 7, libc::AF_INET as u8, 5455, false);
        let mut hdr = [0u8; 7];
        hdr[0..4].copy_from_slice(&42u32.to_be_bytes());
        hdr[4..6].copy_from_slice(&0x0800u16.to_be_bytes());
        hdr[6] = NF_INET_LOCAL_IN;
        push_nla(&mut msg, NFQA_PACKET_HDR, &hdr);
        let sample_ip = vec![0x45, 0x00, 0x00, 0x28, 0xde, 0xad];
        push_nla(&mut msg, NFQA_PAYLOAD, &sample_ip);
        finalize_nlmsg(&mut msg);

        let parsed = parse_nfq_messages(&msg);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].packet_id, 42);
        assert_eq!(parsed[0].hook, NF_INET_LOCAL_IN);
        assert_eq!(parsed[0].payload, sample_ip);
    }
}
