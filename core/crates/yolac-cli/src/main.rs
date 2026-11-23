//! Minimal YOLAÇ diagnostic runner (on-device verification, zero telemetry).

use yolac_blocklist::Blocklist;
use yolac_core::{YolacConfig, YolacEngine};
use yolac_dpi::{fragment_tls_client_hello, parse_client_hello, SplitStrategy};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version") {
        println!("yolac-cli {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let bl = Blocklist::embedded_default();
    let engine = YolacEngine::new(YolacConfig::mobile_ios(), None);
    println!(
        "YOLAÇ Core Self-Check\n- Embedded blocklist rules: {} ({} bytes RAM)\n- Initial engine state: {:?}",
        bl.len(),
        bl.memory_bytes(),
        engine.state()
    );

    // Quick TLS ClientHello fragmentation sanity check
    let sample_sni = b"yolac.test";
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    let ext_len = 4 + 2 + 1 + 2 + sample_sni.len();
    body.extend_from_slice(&(ext_len as u16).to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&((2 + 1 + 2 + sample_sni.len()) as u16).to_be_bytes());
    body.extend_from_slice(&((1 + 2 + sample_sni.len()) as u16).to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(sample_sni.len() as u16).to_be_bytes());
    body.extend_from_slice(sample_sni);
    let mut pkt = vec![0x16, 0x03, 0x01];
    pkt.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
    pkt.push(0x01);
    pkt.push(0);
    pkt.extend_from_slice(&(body.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&body);

    let parsed = parse_client_hello(&pkt).expect("valid sample ClientHello");
    let frag = fragment_tls_client_hello(&pkt, SplitStrategy::SniMid).expect("fragmented");
    println!(
        "- DPI TLS ClientHello SNI={:?}, fragmented {} -> {} bytes",
        parsed.sni,
        pkt.len(),
        frag.len()
    );
    engine.stop().await;
}
