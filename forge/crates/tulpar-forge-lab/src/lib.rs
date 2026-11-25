//! TULPAR Forge Local Censorship Lab, Security Audit, Rollback Simulator & Benchmarks.

pub mod benchmark;
pub mod scenarios;
pub mod security;

pub use benchmark::{run_benchmark, BenchmarkReport};
pub use scenarios::{
    run_lab_scenarios, run_rollback_circuit_breaker_simulation, ScenarioOutcome, ScenarioResult,
};
pub use security::{run_security_audit, SecurityCheckResult};

use tulpar_forge::StrategySpec;

/// Validates `spec`'s declared `lab_assert` expectations against actual lab outcomes.
pub fn evaluate_lab_assertions(
    spec: &StrategySpec,
    results: &[ScenarioResult],
) -> Result<(), Vec<String>> {
    let mut failures = Vec::new();
    for expected in &spec.lab_assert.expect_pass {
        match results.iter().find(|r| r.id == expected) {
            Some(r) if r.outcome == ScenarioOutcome::Pass => {}
            Some(r) => failures.push(format!(
                "lab_assert failed for '{}': expected Pass, got {:?} ({})",
                expected, r.outcome, r.detail
            )),
            None => failures.push(format!("lab_assert references unknown scenario '{expected}'")),
        }
    }
    for expected_unbypassable in &spec.lab_assert.expect_honest_unbypassable {
        match results.iter().find(|r| r.id == expected_unbypassable) {
            Some(r) if r.outcome == ScenarioOutcome::UnbypassableOnDevice => {}
            Some(r) => failures.push(format!(
                "lab_assert failed for '{}': expected UnbypassableOnDevice, got {:?}",
                expected_unbypassable, r.outcome
            )),
            None => failures.push(format!(
                "lab_assert references unknown negative control '{expected_unbypassable}'"
            )),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tulpar_forge::parse_tsl;

    #[tokio::test]
    async fn full_lab_security_benchmark_and_rollback_verify_builtin_examples() {
        let sec = run_security_audit();
        for item in &sec {
            assert!(item.passed, "Security check {} failed: {}", item.name, item.detail);
        }

        for example_src in [
            include_str!("../../../examples/turkey_balanced.tlp"),
            include_str!("../../../examples/mobile_conservative.tlp"),
            include_str!("../../../examples/strict_isp_desync.tlp"),
        ] {
            let spec = parse_tsl(example_src).expect("example strategy parses cleanly");
            let lab_res = run_lab_scenarios(&spec).await;
            assert!(
                evaluate_lab_assertions(&spec, &lab_res).is_ok(),
                "Lab assertions failed for {}: {:?}",
                spec.name,
                evaluate_lab_assertions(&spec, &lab_res)
            );
            let rb = run_rollback_circuit_breaker_simulation(&spec)
                .await
                .expect("rollback circuit breaker succeeds");
            assert!(rb.contains("Auto-disabled"));

            let bench = run_benchmark(example_src).expect("benchmark completes");
            assert!(bench.package_bytes < 4096);
            assert!(bench.estimated_ram_bytes < 32 * 1024);
        }
    }
}
