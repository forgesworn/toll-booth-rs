pub mod types;
pub mod macaroon;
pub mod engine;
pub mod free_tier;

pub mod rails;
pub mod backends;
pub mod storage;

#[cfg(feature = "axum-middleware")]
pub mod middleware;

// Re-export key types
pub use types::*;
pub use engine::{FreeTierConfig, TollBoothConfig, TollBoothEngine};
pub use storage::{StorageBackend, MemoryStorage};
pub use backends::LightningBackend;
pub use rails::{PaymentRail, L402Rail, L402RailConfig, ChallengeFragment, RailVerifyResult, PaymentMode};
#[cfg(feature = "axum-middleware")]
pub use middleware::TollBoothLayer;
