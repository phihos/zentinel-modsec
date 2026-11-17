//! SQLi and XSS detection with selectable backends.
//!
//! The default backend is the original Rust heuristic implementation. Enabling
//! `libinjection-ffi` selects vendored upstream C libinjection for the root API
//! and the engine operators. The `sqli` and `xss` submodules always expose the
//! original Rust backend for explicit comparison or use.

pub mod sqli;
pub mod xss;

#[cfg(feature = "libinjection-ffi")]
#[allow(unsafe_code)] // Audited, length-aware C bridge; keep the rest of the crate safe.
mod ffi;
#[cfg(feature = "libinjection-ffi")]
pub use ffi::{detect_sqli, detect_xss};
#[cfg(not(feature = "libinjection-ffi"))]
pub use sqli::detect_sqli;
#[cfg(not(feature = "libinjection-ffi"))]
pub use xss::detect_xss;

/// Check for SQL injection using the selected backend.
pub fn is_sqli(input: &str) -> bool {
    detect_sqli(input).is_injection
}

/// Return the selected SQLi backend's detection fingerprint.
pub fn sqli_fingerprint(input: &str) -> Option<String> {
    detect_sqli(input).fingerprint
}

/// Check for XSS using the selected backend.
pub fn is_xss(input: &str) -> bool {
    detect_xss(input).is_injection
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
