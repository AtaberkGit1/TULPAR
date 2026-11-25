#![forbid(unsafe_code)]
//! TULPAR Core Orchestrator (Windows & Android).

pub mod adaptive;
pub mod diagnostics;
pub mod engine;
pub mod health;
pub mod state;
pub mod updater;

pub use adaptive::{execute_raw_forge_tcp, AdaptiveController};
pub use diagnostics::DiagnosticReport;
pub use engine::{YolacConfig, YolacEngine};
pub use health::{
    forge_status_to_json, health_reports_to_json, HealthMonitor, ModuleHealthReport,
    ModuleHealthStatus, ModuleId,
};
pub use state::{EngineState, EphemeralMetrics, ErrorCode};
pub use tulpar_forge::{ForgeStatus, ForgeStatusSnapshot, PlatformSupport, VerifyReport};
pub use updater::{
    check_github_release, check_github_release_endpoint, check_github_release_with_protector,
    official_github_repo, SemVer, UpdateCheckResult, APP_VERSION, SECURITY_WARNING_TR,
};
