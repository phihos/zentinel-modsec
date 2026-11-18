//! Small, allocation-free input bridge to upstream's length-aware API.

use super::DetectionResult;
use std::ffi::{c_char, c_int};

extern "C" {
    fn libinjection_sqli(input: *const c_char, len: usize, fingerprint: *mut c_char) -> c_int;
    fn libinjection_xss(input: *const c_char, len: usize) -> c_int;
}

fn checked_result(result: c_int, fingerprint: impl FnOnce() -> String) -> DetectionResult {
    match result {
        0 => DetectionResult::safe(),
        1 => DetectionResult::detected(fingerprint()),
        other => {
            // The public boolean API cannot represent an evaluation error.
            // Surface it and conservatively report a match, never a bypass.
            tracing::error!(result = other, "upstream libinjection parser error");
            DetectionResult::detected("LIBINJECTION_ERROR".into())
        }
    }
}

/// Detect SQLi in the original bytes, including invalid UTF-8 and embedded NULs.
pub fn detect_sqli_bytes(input: &[u8]) -> DetectionResult {
    // Upstream requires at least eight bytes and writes an ASCII C string.
    let mut fingerprint = [0 as c_char; 8];
    // SAFETY: input remains valid for len bytes throughout the synchronous
    // call. No NUL terminator is needed, and embedded NULs remain in the input.
    // The output buffer meets libinjection.h's eight-byte size requirement.
    // All parser state is local to the C call, so concurrent calls are safe.
    let result =
        unsafe { libinjection_sqli(input.as_ptr().cast(), input.len(), fingerprint.as_mut_ptr()) };
    checked_result(result, || {
        fingerprint
            .iter()
            .take_while(|&&byte| byte != 0)
            .map(|&byte| char::from(byte as u8))
            .collect()
    })
}

/// Detect XSS in the original bytes, including invalid UTF-8 and embedded NULs.
pub fn detect_xss_bytes(input: &[u8]) -> DetectionResult {
    // SAFETY: input is a valid immutable byte slice for the supplied length;
    // upstream neither retains nor mutates it. Embedded NULs are supported.
    let result = unsafe { libinjection_xss(input.as_ptr().cast(), input.len()) };
    checked_result(result, || "XSS".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_errors_are_visible_and_do_not_become_bypasses() {
        assert!(checked_result(-1, String::new).is_injection);
        assert_eq!(
            checked_result(-1, String::new).fingerprint.as_deref(),
            Some("LIBINJECTION_ERROR")
        );
    }
}
