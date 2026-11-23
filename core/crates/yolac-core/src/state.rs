//! Engine lifecycle states & ephemeral anonymous atomic counters.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    None = 0,
    PermissionDenied = 1,
    TunSetupFailed = 2,
    DriverMissing = 3,
    AlreadyRunning = 4,
    InternalError = 5,
    DriverIntegrityFailed = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    Inactive,
    Activating,
    Active,
    Deactivating,
    Error(ErrorCode),
}

impl EngineState {
    /// Numeric representation shared across C-ABI, JNI, Swift, and Win32 UI.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Inactive => 0,
            Self::Activating => 1,
            Self::Active => 2,
            Self::Deactivating => 3,
            Self::Error(_) => 4,
        }
    }
}

/// Strictly ephemeral anonymous counters in RAM. Zero domains, IPs, or timestamps.
#[derive(Debug, Default)]
pub struct EphemeralMetrics {
    pub blocked_dns_queries: AtomicU64,
    pub dpi_evasions_applied: AtomicU64,
    pub adaptive_escalations: AtomicU64,
}

impl EphemeralMetrics {
    pub fn reset(&self) {
        self.blocked_dns_queries.store(0, Ordering::Relaxed);
        self.dpi_evasions_applied.store(0, Ordering::Relaxed);
        self.adaptive_escalations.store(0, Ordering::Relaxed);
    }
}
