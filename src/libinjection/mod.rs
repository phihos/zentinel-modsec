//! SQLi and XSS detection with selectable backends.
//!
//! The default backend uses the Rust libinjection port. The optional
//! `libinjection-ffi` feature selects vendored upstream C for the root API and
//! engine operators. The `sqli` and `xss` submodules expose the legacy heuristics.

pub mod rust;
pub mod sqli;
pub mod xss;

#[cfg(feature = "libinjection-ffi")]
#[allow(unsafe_code)] // Audited, length-aware C bridge.
mod ffi;
#[cfg(feature = "libinjection-ffi")]
use ffi as selected;
#[cfg(not(feature = "libinjection-ffi"))]
use rust as selected;

/// Detect SQL injection in a UTF-8 string.
pub fn detect_sqli(input: &str) -> DetectionResult {
    selected::detect_sqli_bytes(input.as_bytes())
}

/// Detect SQL injection in the original bytes, including embedded NULs.
pub fn detect_sqli_bytes(input: &[u8]) -> crate::Result<DetectionResult> {
    Ok(selected::detect_sqli_bytes(input))
}

/// Detect XSS in a UTF-8 string.
pub fn detect_xss(input: &str) -> DetectionResult {
    selected::detect_xss_bytes(input.as_bytes())
}

/// Detect XSS in the original bytes, including embedded NULs.
pub fn detect_xss_bytes(input: &[u8]) -> crate::Result<DetectionResult> {
    Ok(selected::detect_xss_bytes(input))
}

/// Check for SQL injection using the selected backend.
pub fn is_sqli(input: &str) -> bool {
    selected::is_sqli_bytes(input.as_bytes())
}

/// Return the selected SQLi backend's detection fingerprint.
pub fn sqli_fingerprint(input: &str) -> Option<String> {
    detect_sqli(input).fingerprint
}

/// Check for XSS using the selected backend.
pub fn is_xss(input: &str) -> bool {
    selected::is_xss_bytes(input.as_bytes())
}

/// Result of injection detection.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// Whether injection was detected.
    pub is_injection: bool,
    /// Fingerprint that matched (if any).
    pub fingerprint: Option<String>,
}

impl DetectionResult {
    /// Create a positive detection result.
    pub fn detected(fingerprint: String) -> Self {
        Self {
            is_injection: true,
            fingerprint: Some(fingerprint),
        }
    }

    /// Create a negative detection result.
    pub fn safe() -> Self {
        Self {
            is_injection: false,
            fingerprint: None,
        }
    }
}

#[cfg(test)]
mod tests {
    // These expectations document the original Rust heuristic backend.
    use super::{sqli::is_sqli, xss::is_xss};

    #[test]
    fn test_sqli_detection() {
        assert!(is_sqli("1' OR '1'='1"));
        assert!(is_sqli("1; DROP TABLE users--"));
        assert!(is_sqli("admin'--"));
        assert!(is_sqli("1 UNION SELECT * FROM users"));
        assert!(!is_sqli("hello world"));
        assert!(!is_sqli("normal query string"));
    }

    #[test]
    fn test_xss_detection() {
        assert!(is_xss("<script>alert(1)</script>"));
        assert!(is_xss("javascript:alert(1)"));
        assert!(is_xss("<img src=x onerror=alert(1)>"));
        assert!(is_xss("<svg onload=alert(1)>"));
        assert!(!is_xss("hello world"));
        assert!(!is_xss("<p>Normal paragraph</p>"));
    }
}
