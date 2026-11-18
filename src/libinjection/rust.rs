//! Byte-oriented Rust implementation of the libinjection detectors.

use super::DetectionResult;
use libinjectionrs::{Fingerprint, SqliFlags, SqliState};

fn matching_sql_fingerprint(input: &[u8]) -> Option<Fingerprint> {
    let mut state = SqliState::new(input, SqliFlags::FLAG_NONE);
    // detect() leaves the matching parse context's fingerprint in state.
    state.detect().then(|| Fingerprint::new(state.fingerprint))
}

/// Detect SQL injection and return the matching SQL fingerprint.
pub fn detect_sqli_bytes(input: &[u8]) -> DetectionResult {
    if let Some(fingerprint) = matching_sql_fingerprint(input) {
        DetectionResult::detected(fingerprint.as_str().to_owned())
    } else {
        DetectionResult::safe()
    }
}

/// Detect XSS using the HTML tokenizer and libinjection parsing contexts.
pub fn detect_xss_bytes(input: &[u8]) -> DetectionResult {
    if is_xss_bytes(input) {
        DetectionResult::detected("XSS".to_owned())
    } else {
        DetectionResult::safe()
    }
}

#[cfg(not(feature = "libinjection-ffi"))]
pub(super) fn is_sqli_bytes(input: &[u8]) -> bool {
    matching_sql_fingerprint(input).is_some()
}

pub(super) fn is_xss_bytes(input: &[u8]) -> bool {
    libinjectionrs::detect_xss(input).is_injection()
}
