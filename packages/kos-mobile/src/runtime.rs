//! Tokio runtime management for async operations

use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

/// Global Tokio runtime for handling asynchronous operations
///
/// This static runtime is created once and reused for all async operations to avoid
/// the overhead of creating a new runtime for each function call.
pub static RT: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime")
});

/// Helper function to access the runtime
pub fn rt() -> &'static Runtime {
    &RT
}
