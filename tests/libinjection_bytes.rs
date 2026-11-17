//! The native bridge accepts the original bytes without UTF-8 replacement.
use zentinel_modsec::libinjection;

#[cfg(feature = "libinjection-ffi")]
#[test]
fn native_backend_inspects_arbitrary_bytes_after_nul_and_invalid_utf8() {
    assert!(
        libinjection::detect_xss_bytes(b"\xff\x00<script>alert(1)</script>")
            .unwrap()
            .is_injection
    );
    assert!(
        libinjection::detect_sqli_bytes(b"-1839\" or \"1\"=\"2\xff")
            .unwrap()
            .is_injection
    );
    assert!(
        !libinjection::detect_sqli_bytes(b"/update-assets\xff\x00")
            .unwrap()
            .is_injection
    );
    assert!(
        !libinjection::detect_xss_bytes(b"plain\xff\x00text")
            .unwrap()
            .is_injection
    );
}

#[cfg(not(feature = "libinjection-ffi"))]
#[test]
fn rust_backend_reports_that_it_cannot_inspect_invalid_utf8() {
    let error = libinjection::detect_xss_bytes(b"\xff<script>").unwrap_err();
    assert!(error.to_string().contains("binary input"));
    assert!(
        libinjection::detect_xss_bytes(b"<script>")
            .unwrap()
            .is_injection
    );
}
