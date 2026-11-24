//! Zero-telemetry on-device live network, encrypted DNS latency, and IPv6 diagnostics
//! ("Swiss Army Knife" speed & censorship health check for Windows & Android).

use yolac_dns::UpstreamBenchmark;

use crate::updater::escape_json;

#[derive(Debug, Clone)]
pub struct DiagnosticReport {
    pub dns_benchmarks: Vec<UpstreamBenchmark>,
    pub fastest_dns_name: String,
    pub fastest_dns_rtt_ms: Option<u64>,
    pub ipv6_reachable: bool,
    pub blocked_ads_count: u64,
    pub total_dns_queries: u64,
    pub dns_cache_hit_pct: u8,
    pub summary_tr: String,
}

impl DiagnosticReport {
    pub fn build(
        dns_benchmarks: Vec<UpstreamBenchmark>,
        ipv6_reachable: bool,
        blocked_ads_count: u64,
        total_dns_queries: u64,
        cache_hits: u64,
    ) -> Self {
        let fastest = dns_benchmarks.iter().find(|b| b.ok);
        let fastest_dns_name = fastest
            .map(|b| b.name.to_string())
            .unwrap_or_else(|| "Erişilemedi".to_string());
        let fastest_dns_rtt_ms = fastest.and_then(|b| b.rtt_ms);
        let dns_cache_hit_pct = cache_hits
            .saturating_mul(100)
            .checked_div(total_dns_queries)
            .unwrap_or(0)
            .min(100) as u8;

        let mut lines = Vec::new();
        if let Some(ms) = fastest_dns_rtt_ms {
            lines.push(format!(
                "En Hızlı Şifreli DNS: {fastest_dns_name} ({ms} ms — otomatik seçildi)"
            ));
        } else {
            lines.push("Şifreli DNS sunucularına ulaşılamadı (internet bağlantınızı kontrol edin).".to_string());
        }

        let dns_row: Vec<String> = dns_benchmarks
            .iter()
            .filter(|b| !b.name.ends_with("-v6") || b.ok)
            .map(|b| match b.rtt_ms {
                Some(ms) if b.ok => format!("{}: {} ms", b.name, ms),
                _ => format!("{}: —", b.name),
            })
            .collect();
        if !dns_row.is_empty() {
            lines.push(dns_row.join(" · "));
        }

        let v6_str = if ipv6_reachable {
            "IPv6: Çift Yığın (Aktif)"
        } else {
            "IPv6: Yalnızca IPv4 (AAAA sızıntı/karadelik koruması aktif)"
        };
        lines.push(format!(
            "{v6_str} | Engellenen Reklam: {blocked_ads_count} | Önbellek İsabeti: %{dns_cache_hit_pct}"
        ));

        let summary_tr = lines.join("\n");
        Self {
            dns_benchmarks,
            fastest_dns_name,
            fastest_dns_rtt_ms,
            ipv6_reachable,
            blocked_ads_count,
            total_dns_queries,
            dns_cache_hit_pct,
            summary_tr,
        }
    }

    pub fn to_json(&self) -> String {
        let rtt_str = self
            .fastest_dns_rtt_ms
            .map(|m| m.to_string())
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"ok\":{},\"fastest_dns\":\"{}\",\"fastest_rtt_ms\":{},\"ipv6_reachable\":{},\"blocked_ads\":{},\"total_dns\":{},\"cache_hit_pct\":{},\"summary\":\"{}\"}}",
            self.fastest_dns_rtt_ms.is_some(),
            escape_json(&self.fastest_dns_name),
            rtt_str,
            self.ipv6_reachable,
            self.blocked_ads_count,
            self.total_dns_queries,
            self.dns_cache_hit_pct,
            escape_json(&self.summary_tr),
        )
    }
}
