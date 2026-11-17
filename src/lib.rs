//! # zentinel-modsec
//!
//! Rust ModSecurity rule engine, measured against the OWASP CRS
//! regression suite.
//!
//! The default build has no C/C++ dependency. The optional `libinjection-ffi`
//! feature compiles vendored upstream C libinjection for SQLi and XSS detection.
//!
//! CRS compatibility is reported as a number rather than asserted: the upstream
//! regression corpus runs in CI on every push, and the README carries the
//! current figure and the known gaps.
//!
//! ## Features
//!
//! - SecLang rule parsing and evaluation
//! - Loads the stock OWASP CRS rule set
//! - Rust heuristic or optional upstream C libinjection for @detectSQLi/@detectXSS
//! - Thread-safe, async-ready transaction processing
//! - Zero external C/C++ dependencies in the default build
//!
//! ## Quick Start
//!
//! ```ignore
//! use zentinel_modsec::ModSecurity;
//!
//! // Load rules from an inline string (or use ModSecurity::from_file(path)).
//! let modsec = ModSecurity::from_string(r#"
//!     SecRuleEngine On
//!     SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny,status:403"
//! "#)?;
//!
//! // Process a request
//! let mut tx = modsec.new_transaction();
//! tx.process_uri("/api/users?id=1", "GET", "HTTP/1.1")?;
//! tx.add_request_header("Host", "example.com")?;
//! tx.process_request_headers()?;
//!
//! // Check for intervention
//! if let Some(intervention) = tx.intervention() {
//!     println!("Blocked: status={}", intervention.status);
//! }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(unsafe_code)]

pub mod actions;
pub mod engine;
pub mod error;
pub mod libinjection;
pub mod operators;
pub mod parser;
pub mod transformations;
pub mod variables;

// Re-export main types at crate root
pub use engine::ruleset::{CompiledRuleset, Rules};
pub use engine::{
    BodyConfig, BodyLimitAction, BodyWriteResult, Intervention, ModSecurity, Transaction,
};
pub use error::{Error, Result};

/// Protocol version for compatibility tracking
pub const PROTOCOL_VERSION: u32 = 1;

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
