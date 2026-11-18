//! Body acquisition configuration and bounded write outcomes.

use crate::error::{Error, Result};
pub use crate::parser::BodyLimitAction;

/// Maximum supported configured body limit, matching pinned Coraza.
pub const MAX_BODY_LIMIT: usize = 1_073_741_824;

/// Immutable body policy compiled from SecLang directives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyConfig {
    /// Maximum parsed arguments per query, URL-encoded body, or JSON document.
    pub argument_limit: usize,
    /// Maximum JSON container nesting for requests.
    pub request_json_depth_limit: usize,
    /// Maximum JSON container nesting for responses.
    pub response_json_depth_limit: usize,
    /// Whether request bytes may be acquired for inspection.
    pub request_access: bool,
    /// Maximum retained request prefix length in bytes.
    pub request_limit: usize,
    /// Policy at the request limit.
    pub request_limit_action: BodyLimitAction,
    /// Whether response bytes may be acquired for inspection.
    pub response_access: bool,
    /// Maximum retained response prefix length in bytes.
    pub response_limit: usize,
    /// Policy at the response limit.
    pub response_limit_action: BodyLimitAction,
    /// Exact response media types made available to phase 4 body rules.
    pub response_mime_types: Vec<String>,
}

impl Default for BodyConfig {
    fn default() -> Self {
        Self {
            argument_limit: crate::variables::DEFAULT_ARGUMENT_LIMIT,
            request_json_depth_limit: crate::variables::json::DEFAULT_DEPTH_LIMIT,
            response_json_depth_limit: crate::variables::json::DEFAULT_DEPTH_LIMIT,
            request_access: false,
            request_limit: 134_217_728,
            request_limit_action: BodyLimitAction::Reject,
            response_access: false,
            response_limit: 524_288,
            response_limit_action: BodyLimitAction::ProcessPartial,
            response_mime_types: Vec::new(),
        }
    }
}

impl BodyConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        for (name, limit) in [
            ("request", self.request_limit),
            ("response", self.response_limit),
        ] {
            if !(1..=MAX_BODY_LIMIT).contains(&limit) {
                return Err(Error::Config {
                    message: format!("{name} body limit must be between 1 and {MAX_BODY_LIMIT}"),
                });
            }
        }
        Ok(())
    }
}

/// Result of writing a chunk to an inspection buffer, not to the origin/client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyWriteResult {
    /// Bytes copied from this chunk into the bounded inspection buffer.
    pub consumed: usize,
    /// The configured limit was reached, including an exact-limit chunk.
    pub limit_reached: bool,
    /// Header rules have not run yet; the buffered prefix is provisional.
    pub pending_headers: bool,
    /// The corresponding body phase has finished and will not run again.
    pub inspection_complete: bool,
}

/// State for one direction's bounded acquisition and phase progression.
#[derive(Debug, Default)]
pub(crate) struct BodyState {
    pub headers_processed: bool,
    pub processed: bool,
    /// Preserve a failed callback without executing its actions a second time.
    pub failure: Option<String>,
    pub limit_reached: bool,
    /// Previous complete-chunk length to restore if a deferred limit rejects.
    pub pending_reject_length: Option<usize>,
}
