//! Byte-oriented Rust implementation of the libinjection detectors.

use super::DetectionResult;
use libinjectionrs::{Fingerprint, SqliFlags, SqliState};

/// Detect SQL injection and return the matching SQL fingerprint.
pub fn detect_sqli_bytes(input: &[u8]) -> DetectionResult {
    let mut state = SqliState::new(input, SqliFlags::FLAG_NONE);
    if state.detect() {
        // detect() leaves the fingerprint of the matching parse context in state.
        DetectionResult::detected(Fingerprint::new(state.fingerprint).as_str().to_owned())
    } else {
        DetectionResult::safe()
    }
}

/// Detect XSS using the HTML tokenizer and libinjection parsing contexts.
pub fn detect_xss_bytes(input: &[u8]) -> DetectionResult {
    if libinjectionrs::detect_xss(input).is_injection() {
        DetectionResult::detected("XSS".to_owned())
    } else {
        DetectionResult::safe()
    }
}
