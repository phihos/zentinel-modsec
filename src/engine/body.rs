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
    /// Spill acquired request bytes to a private file above this threshold.
    pub request_in_memory_limit: Option<usize>,
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
            request_in_memory_limit: None,
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
        if self
            .request_in_memory_limit
            .is_some_and(|v| v == 0 || v > self.request_limit)
        {
            return Err(Error::Config { message: "request body memory limit must be positive and no larger than the request body limit".into() });
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

/// A private file with a committed prefix. Reads stop at that length even if
/// a failed write or a provisional acquisition left more bytes in the file.
pub(crate) struct RequestSpool {
    file: std::fs::File,
    pub len: usize,
}

impl RequestSpool {
    pub fn new(prefix: &[u8]) -> std::io::Result<Self> {
        use std::io::Write;
        let mut file = tempfile::tempfile()?;
        file.write_all(prefix)?;
        Ok(Self {
            file,
            len: prefix.len(),
        })
    }

    pub fn append(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        self.file.seek(SeekFrom::Start(self.len as u64))?;
        self.file.write_all(bytes)?;
        self.len += bytes.len();
        Ok(())
    }

    pub fn read_prefix(&mut self) -> Result<Vec<u8>> {
        use std::io::{Read, Seek};
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.len)
            .map_err(|source| Error::BodyBufferAllocation { source })?;
        bytes.resize(self.len, 0);
        self.file
            .rewind()
            .and_then(|_| self.file.read_exact(&mut bytes))
            .map_err(Error::BodySpoolIo)?;
        Ok(bytes)
    }
}

/// Reserve amortized capacity within the inspection limit before committing a write.
pub(crate) fn append_memory(body: &mut Vec<u8>, data: &[u8], limit: usize) -> Result<()> {
    let current = body.len();
    let required = current + data.len();
    if required > body.capacity() {
        let capacity = required.max(body.capacity().saturating_mul(2).min(limit));
        body.try_reserve_exact(capacity - current)
            .or_else(|error| {
                if capacity > required {
                    body.try_reserve_exact(data.len())
                } else {
                    Err(error)
                }
            })
            .map_err(|source| Error::BodyBufferAllocation { source })?;
    }
    body.extend_from_slice(data);
    Ok(())
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
    /// The caller offered bytes after the provisional prefix was full.
    pub pending_discarded: bool,
}
