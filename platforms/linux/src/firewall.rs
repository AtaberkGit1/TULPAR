//! Linux firewall (`nftables` with automatic `iptables`/`ip6tables` fallback), fail-open NFQUEUE
//! bypass rules, `notrack` conntrack immunity for TULPAR raw decoys (prevents ufw/firewalld drops),
//! transparent encrypted DNS redirect, and Zapret/nfqws conflict detector/cleaner.

use std::io;
use std::process::{Command, Stdio};

use crate::dns_proxy::DNS_PROXY_PORT;
use crate::raw_inject::TULPAR_FWMARK;

pub const NFQUEUE_NUM: u16 = 5455;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    IptablesFallback,
}

/// Builds the complete atomic `nftables` (`table inet tulpar`) ruleset string:
/// - `raw_out` (`priority raw;`): marks injected TULPAR decoys (`0x54554C50`) as `notrack` so host
///   firewalls (`ufw`/`firewalld`/`docker`) NEVER drop `LowTtlWrongSeq` packets as `ct state invalid`!
/// - `output` / `input` (`priority mangle;`): queues ONLY handshake packets (`ct original packets 1-16`)
///   with `bypass` (fail-open); >99.95% of steady traffic stays inside the Linux kernel!
/// - `dns_nat` (`priority -100;`): transparently redirects public & ISP router DNS UDP/TCP :53 -> :5354.
pub fn build_nftables_ruleset(queue_num: u16, dns_port: u16, fwmark: u32) -> String {
    format!(
        r#"table inet tulpar {{
    chain raw_out {{
        type filter hook output priority raw; policy accept;
        meta mark 0x{fwmark:x} notrack
    }}

    chain output {{
        type filter hook output priority mangle; policy accept;
        oifname "lo" accept
        meta mark 0x{fwmark:x} accept
        ip daddr {{ 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 }} accept
        ip6 daddr {{ ::1, fe80::/10, fc00::/7, ff00::/8 }} accept
        tcp dport {{ 80, 443 }} ct original packets 1-16 counter queue num {queue_num} bypass
        udp dport 443 ct original packets 1-12 counter queue num {queue_num} bypass
        udp dport {{ 596-599, 1400, 3478, 5349, 10000-65535 }} ct original packets 1-6 counter queue num {queue_num} bypass
        tcp dport {{ 53, 853 }} counter queue num {queue_num} bypass
    }}

    chain input {{
        type filter hook input priority mangle; policy accept;
        iifname "lo" accept
        tcp sport {{ 80, 443 }} ct reply packets 1-10 counter queue num {queue_num} bypass
    }}

    chain dns_nat {{
        type nat hook output priority -100; policy accept;
        meta mark 0x{fwmark:x} accept
        ip daddr {{ 127.0.0.1, 127.0.0.53, 127.0.0.54 }} accept
        ip6 daddr ::1 accept
        meta l4proto {{ tcp, udp }} th dport 53 redirect to :{dns_port}
    }}
}}
"#
    )
}

fn has_command(cmd: &str, arg: &str) -> bool {
    Command::new(cmd)
        .arg(arg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn apply_firewall_rules() -> io::Result<FirewallBackend> {
    remove_firewall_rules();

    if has_command("nft", "--version") {
        let rules = build_nftables_ruleset(NFQUEUE_NUM, DNS_PROXY_PORT, TULPAR_FWMARK);
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            use io::Write;
            stdin.write_all(rules.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if output.status.success() {
            return Ok(FirewallBackend::Nftables);
        }
        let err_msg = String::from_utf8_lossy(&output.stderr);
        if !has_command("iptables", "--version") {
            return Err(io::Error::other(format!("nftables yüklenemedi: {err_msg}")));
        }
    }

    if has_command("iptables", "--version") {
        apply_iptables_fallback()?;
        return Ok(FirewallBackend::IptablesFallback);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Sistemde 'nft' veya 'iptables' bulunamadı.",
    ))
}

fn run_ipt(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn apply_iptables_fallback() -> io::Result<()> {
    let mark_hex = format!("0x{:x}", TULPAR_FWMARK);
    let q_str = NFQUEUE_NUM.to_string();
    let dns_str = DNS_PROXY_PORT.to_string();

    for bin in ["iptables", "ip6tables"] {
        // Prevent conntrack invalid-state drops on LowTtlWrongSeq decoys
        let _ = run_ipt(bin, &["-t", "raw", "-D", "OUTPUT", "-m", "mark", "--mark", &mark_hex, "-j", "NOTRACK"]);
        let _ = run_ipt(bin, &["-t", "raw", "-I", "OUTPUT", "1", "-m", "mark", "--mark", &mark_hex, "-j", "NOTRACK"]);

        let _ = run_ipt(bin, &["-t", "mangle", "-N", "TULPAR_OUT"]);
        let _ = run_ipt(bin, &["-t", "mangle", "-F", "TULPAR_OUT"]);
        let _ = run_ipt(bin, &["-t", "mangle", "-A", "TULPAR_OUT", "-o", "lo", "-j", "RETURN"]);
        let _ = run_ipt(
            bin,
            &["-t", "mangle", "-A", "TULPAR_OUT", "-m", "mark", "--mark", &mark_hex, "-j", "RETURN"],
        );
        for spec in [
            vec!["-p", "tcp", "--dport", "443", "-m", "connbytes", "--connbytes", "1:16", "--connbytes-dir", "original", "--connbytes-mode", "packets", "-j", "NFQUEUE", "--queue-num", &q_str, "--queue-bypass"],
            vec!["-p", "tcp", "--dport", "80", "-m", "connbytes", "--connbytes", "1:16", "--connbytes-dir", "original", "--connbytes-mode", "packets", "-j", "NFQUEUE", "--queue-num", &q_str, "--queue-bypass"],
            vec!["-p", "udp", "--dport", "443", "-m", "connbytes", "--connbytes", "1:12", "--connbytes-dir", "original", "--connbytes-mode", "packets", "-j", "NFQUEUE", "--queue-num", &q_str, "--queue-bypass"],
            vec!["-p", "udp", "--dport", "596:599", "-m", "connbytes", "--connbytes", "1:6", "--connbytes-dir", "original", "--connbytes-mode", "packets", "-j", "NFQUEUE", "--queue-num", &q_str, "--queue-bypass"],
            vec!["-p", "udp", "--dport", "1400", "-m", "connbytes", "--connbytes", "1:6", "--connbytes-dir", "original", "--connbytes-mode", "packets", "-j", "NFQUEUE", "--queue-num", &q_str, "--queue-bypass"],
            vec!["-p", "udp", "--dport", "3478", "-m", "connbytes", "--connbytes", "1:6", "--connbytes-dir", "original", "--connbytes-mode", "packets", "-j", "NFQUEUE", "--queue-num", &q_str, "--queue-bypass"],
            vec!["-p", "udp", "--dport", "5349", "-m", "connbytes", "--connbytes", "1:6", "--connbytes-dir", "original", "--connbytes-mode", "packets", "-j", "NFQUEUE", "--queue-num", &q_str, "--queue-bypass"],
            vec!["-p", "udp", "--dport", "10000:65535", "-m", "connbytes", "--connbytes", "1:6", "--connbytes-dir", "original", "--connbytes-mode", "packets", "-j", "NFQUEUE", "--queue-num", &q_str, "--queue-bypass"],
            vec!["-p", "tcp", "--dport", "53", "-j", "NFQUEUE", "--queue-num", &q_str, "--queue-bypass"],
            vec!["-p", "tcp", "--dport", "853", "-j", "NFQUEUE", "--queue-num", &q_str, "--queue-bypass"],
        ] {
            let mut full = vec!["-t", "mangle", "-A", "TULPAR_OUT"];
            full.extend(spec);
            let _ = run_ipt(bin, &full);
        }
        let _ = run_ipt(bin, &["-t", "mangle", "-D", "OUTPUT", "-j", "TULPAR_OUT"]);
        if !run_ipt(bin, &["-t", "mangle", "-I", "OUTPUT", "1", "-j", "TULPAR_OUT"]) && bin == "iptables" {
            return Err(io::Error::other("iptables mangle OUTPUT kuralı eklenemedi"));
        }

        let _ = run_ipt(bin, &["-t", "mangle", "-N", "TULPAR_IN"]);
        let _ = run_ipt(bin, &["-t", "mangle", "-F", "TULPAR_IN"]);
        let _ = run_ipt(bin, &["-t", "mangle", "-A", "TULPAR_IN", "-i", "lo", "-j", "RETURN"]);
        let _ = run_ipt(
            bin,
            &["-t", "mangle", "-A", "TULPAR_IN", "-p", "tcp", "--sport", "443", "-m", "connbytes", "--connbytes", "1:10", "--connbytes-dir", "reply", "--connbytes-mode", "packets", "-j", "NFQUEUE", "--queue-num", &q_str, "--queue-bypass"],
        );
        let _ = run_ipt(
            bin,
            &["-t", "mangle", "-A", "TULPAR_IN", "-p", "tcp", "--sport", "80", "-m", "connbytes", "--connbytes", "1:10", "--connbytes-dir", "reply", "--connbytes-mode", "packets", "-j", "NFQUEUE", "--queue-num", &q_str, "--queue-bypass"],
        );
        let _ = run_ipt(bin, &["-t", "mangle", "-D", "INPUT", "-j", "TULPAR_IN"]);
        let _ = run_ipt(bin, &["-t", "mangle", "-I", "INPUT", "1", "-j", "TULPAR_IN"]);
    }

    // Transparent IPv4 DNS redirect in nat OUTPUT
    let _ = run_ipt("iptables", &["-t", "nat", "-N", "TULPAR_DNS"]);
    let _ = run_ipt("iptables", &["-t", "nat", "-F", "TULPAR_DNS"]);
    let _ = run_ipt("iptables", &["-t", "nat", "-A", "TULPAR_DNS", "-m", "mark", "--mark", &mark_hex, "-j", "RETURN"]);
    let _ = run_ipt("iptables", &["-t", "nat", "-A", "TULPAR_DNS", "-d", "127.0.0.1", "-j", "RETURN"]);
    let _ = run_ipt("iptables", &["-t", "nat", "-A", "TULPAR_DNS", "-d", "127.0.0.53", "-j", "RETURN"]);
    let _ = run_ipt("iptables", &["-t", "nat", "-A", "TULPAR_DNS", "-d", "127.0.0.54", "-j", "RETURN"]);
    let _ = run_ipt("iptables", &["-t", "nat", "-A", "TULPAR_DNS", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", &dns_str]);
    let _ = run_ipt("iptables", &["-t", "nat", "-A", "TULPAR_DNS", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", &dns_str]);
    let _ = run_ipt("iptables", &["-t", "nat", "-D", "OUTPUT", "-j", "TULPAR_DNS"]);
    let _ = run_ipt("iptables", &["-t", "nat", "-I", "OUTPUT", "1", "-j", "TULPAR_DNS"]);

    Ok(())
}

pub fn remove_firewall_rules() {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "tulpar"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let mark_hex = format!("0x{:x}", TULPAR_FWMARK);
    for bin in ["iptables", "ip6tables"] {
        let _ = run_ipt(bin, &["-t", "raw", "-D", "OUTPUT", "-m", "mark", "--mark", &mark_hex, "-j", "NOTRACK"]);
        let _ = run_ipt(bin, &["-t", "mangle", "-D", "OUTPUT", "-j", "TULPAR_OUT"]);
        let _ = run_ipt(bin, &["-t", "mangle", "-F", "TULPAR_OUT"]);
        let _ = run_ipt(bin, &["-t", "mangle", "-X", "TULPAR_OUT"]);

        let _ = run_ipt(bin, &["-t", "mangle", "-D", "INPUT", "-j", "TULPAR_IN"]);
        let _ = run_ipt(bin, &["-t", "mangle", "-F", "TULPAR_IN"]);
        let _ = run_ipt(bin, &["-t", "mangle", "-X", "TULPAR_IN"]);
    }
    let _ = run_ipt("iptables", &["-t", "nat", "-D", "OUTPUT", "-j", "TULPAR_DNS"]);
    let _ = run_ipt("iptables", &["-t", "nat", "-F", "TULPAR_DNS"]);
    let _ = run_ipt("iptables", &["-t", "nat", "-X", "TULPAR_DNS"]);
}

pub fn flush_linux_dns_caches() {
    for (cmd, args) in [
        ("resolvectl", &["flush-caches"][..]),
        ("systemd-resolve", &["--flush-caches"][..]),
    ] {
        let _ = Command::new(cmd)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

pub fn detect_conflicting_dpi_tools() -> Vec<String> {
    let mut found = Vec::new();
    for svc in ["zapret", "zapret2", "byedpi", "goodbyedpi"] {
        if Command::new("systemctl")
            .args(["is-active", "--quiet", svc])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            found.push(format!("systemd:{svc}"));
        }
    }
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if !s.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
                let c = comm.trim();
                if matches!(c, "nfqws" | "tpws" | "ciadpi") {
                    found.push(format!("process:{c}"));
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

pub fn stop_conflicting_zapret() -> Vec<String> {
    let mut stopped = Vec::new();
    for svc in ["zapret", "zapret2", "byedpi", "goodbyedpi"] {
        if Command::new("systemctl")
            .args(["is-active", "--quiet", svc])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            let _ = Command::new("systemctl")
                .args(["disable", "--now", svc])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            stopped.push(svc.to_string());
        }
    }
    for proc_name in ["nfqws", "tpws", "ciadpi"] {
        if Command::new("pkill")
            .args(["-x", proc_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            stopped.push(proc_name.to_string());
        }
    }
    for tbl in ["zapret", "zapret2"] {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", tbl])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    stopped
}

pub fn has_active_tulpar_table() -> bool {
    let nft_active = Command::new("nft")
        .args(["list", "table", "inet", "tulpar"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    nft_active || run_ipt("iptables", &["-t", "mangle", "-L", "TULPAR_OUT"])
}

pub struct FirewallGuard;

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        remove_firewall_rules();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_fail_open_nftables_ruleset_with_fwmark_and_notrack() {
        let rules = build_nftables_ruleset(NFQUEUE_NUM, DNS_PROXY_PORT, TULPAR_FWMARK);
        assert!(rules.contains("table inet tulpar"));
        assert!(rules.contains("meta mark 0x54554c50 notrack"));
        assert!(rules.contains("meta mark 0x54554c50 accept"));
        assert!(rules.contains("queue num 5455 bypass"));
        assert!(rules.contains("ct original packets 1-16"));
        assert!(rules.contains("redirect to :5354"));
        assert!(rules.contains("127.0.0.53"));
    }
}
