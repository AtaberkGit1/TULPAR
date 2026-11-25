//! Deterministic compile, load/verify, per-handshake dispatch, and RAM/wire benchmarks.

use std::time::Instant;

use tulpar_forge::{parse_tsl, ForgePackage, ForgePlatformCaps, ForgeRuntime, MatchProtocol};
use yolac_core::execute_raw_forge_tcp;
use yolac_dpi::{build_ipv4_tcp_packet, ParsedTcp, TtlCalibrator};

#[derive(Debug, Clone)]
pub struct BenchmarkReport {
    pub package_bytes: usize,
    pub estimated_ram_bytes: usize,
    pub compile_seal_us: u64,
    pub decode_verify_us: u64,
    pub per_handshake_eval_ns: u64,
    pub raw_transform_us: u64,
    pub wire_expansion_ratio: f64,
}

pub fn run_benchmark(tsl_source: &str) -> Result<BenchmarkReport, String> {
    let t_compile = Instant::now();
    let spec = parse_tsl(tsl_source).map_err(|e| e.to_string())?;
    let (pkg, bytes) = ForgePackage::compile(&spec).map_err(|e| e.to_string())?;
    let compile_seal_us = t_compile.elapsed().as_micros() as u64;

    let t_decode = Instant::now();
    let verified = ForgePackage::decode_verified(&bytes).map_err(|e| e.to_string())?;
    let decode_verify_us = t_decode.elapsed().as_micros() as u64;

    let rt = ForgeRuntime::new(ForgePlatformCaps::WINDOWS);
    rt.load_package_bytes(&bytes)?;

    const EVAL_ITERS: u32 = 2_000;
    let t_eval = Instant::now();
    let mut hits = 0usize;
    for _ in 0..EVAL_ITERS {
        if rt
            .select_raw_rule(MatchProtocol::Tls, 443, Some("bench.example.org"), 140, false, 0)
            .is_some()
        {
            hits += 1;
        }
    }
    let _ = hits;
    let per_handshake_eval_ns = (t_eval.elapsed().as_nanos() / EVAL_ITERS as u128) as u64;

    // Benchmark full L3 raw ClientHello transform latency + wire overhead
    let mut wire_ratio = 1.0;
    let mut raw_transform_us = 0u64;
    if let Some(raw_plan) =
        rt.select_raw_rule(MatchProtocol::Tls, 443, Some("bench.example.org"), 140, false, 0)
    {
        let payload = vec![0x16u8; 140];
        let pkt = build_ipv4_tcp_packet(
            std::net::Ipv4Addr::new(192, 168, 1, 10),
            std::net::Ipv4Addr::new(93, 184, 216, 34),
            55000,
            443,
            1000,
            2000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            1,
            &[],
            &payload,
        );
        let calibrator = TtlCalibrator::default();
        const RAW_ITERS: u32 = 200;
        let t_raw = Instant::now();
        let mut total_out_bytes = 0usize;
        for _ in 0..RAW_ITERS {
            if let Some(pkts) = execute_raw_forge_tcp(
                &pkt,
                70,
                None,
                false,
                &raw_plan,
                &calibrator,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            ) {
                total_out_bytes += pkts.iter().map(|p| p.bytes.len()).sum::<usize>();
            } else {
                total_out_bytes += pkt.len();
            }
        }
        raw_transform_us = (t_raw.elapsed().as_micros() / RAW_ITERS as u128) as u64;
        wire_ratio = (total_out_bytes as f64) / ((pkt.len() * RAW_ITERS as usize) as f64);
    }

    Ok(BenchmarkReport {
        package_bytes: bytes.len(),
        estimated_ram_bytes: verified.report.estimated_ram_bytes.max(pkg.report.estimated_ram_bytes),
        compile_seal_us,
        decode_verify_us,
        per_handshake_eval_ns,
        raw_transform_us,
        wire_expansion_ratio: wire_ratio,
    })
}
