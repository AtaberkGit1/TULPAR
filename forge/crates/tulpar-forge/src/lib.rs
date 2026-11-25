#![forbid(unsafe_code)]
//! TULPAR Forge: Safe declarative strategy DSL, portable `.tulpar` package format,
//! capability-safety verifier, and runtime hot-reload + transactional circuit-breaker rollback.

pub mod ast;
pub mod dsl;
pub mod format;
pub mod runtime;
pub mod sha256;
pub mod verifier;

pub use ast::{
    DecoySpec, DecoyTtlMode, ForgePlatformCaps, LabExpectations, MatchProtocol, MatchSpec,
    QuicMode, RawActionSpec, RawFallbackPolicy, RollbackPolicy, SocketActionSpec, SplitCutSpec,
    StrategyRule, StrategySpec, TlsRecordMode,
};
pub use dsl::{format_tsl, parse_tsl, DslError};
pub use format::{ForgePackage, FormatError, PACKAGE_FORMAT_VERSION, PACKAGE_MAGIC};
pub use runtime::{ForgeRuntime, ForgeStatus, ForgeStatusSnapshot};
pub use sha256::{sha256_digest, sha256_hex};
pub use verifier::{CompatibilityMatrix, ForgeVerifier, PlatformSupport, VerifyError, VerifyReport};
