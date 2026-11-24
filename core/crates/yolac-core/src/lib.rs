#![forbid(unsafe_code)]
//! YOLAÇ Core Orchestrator.

pub mod adaptive;
pub mod engine;
pub mod health;
pub mod state;
pub mod updater;

pub use adaptive::AdaptiveController;
pub use engine::{YolacConfig, YolacEngine};
pub use health::{
    health_reports_to_json, HealthMonitor, ModuleHealthReport, ModuleHealthStatus, ModuleId,
};
pub use state::{EngineState, EphemeralMetrics, ErrorCode};
pub use updater::{
    check_github_release, check_github_release_endpoint, official_github_repo, SemVer,
    UpdateCheckResult, APP_VERSION, SECURITY_WARNING_TR,
};
