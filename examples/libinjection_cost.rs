//! Run with `cargo run --release --features libinjection-ffi --example libinjection_cost -- 1000000`.
//! Raw FFI measures no allocation; selected includes the public result conversion.
#![cfg(feature = "libinjection-ffi")]

use std::{
    ffi::{c_char, c_int},
    hint::black_box,
    time::Instant,
};
use zentinel_modsec::libinjection;

extern "C" {
    fn libinjection_sqli(input: *const c_char, len: usize, fingerprint: *mut c_char) -> c_int;
    fn libinjection_xss(input: *const c_char, len: usize) -> c_int;
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "1000000".into())
        .parse()
        .unwrap();
    for (name, input, sqli) in [
        ("sqli-safe", "/update-assets", true),
        ("sqli-attack", r#"-1839" or "1"="2"#, true),
        ("xss-safe", "hello world", false),
        ("xss-attack", "<img src=x onerror=alert(1)>", false),
    ] {
        for backend in ["raw-ffi", "selected", "pure-rust", "legacy-heuristic"] {
            let mut hits = 0;
            let start = Instant::now();
            for _ in 0..n {
                let input = black_box(input);
                let hit = match backend {
                    "raw-ffi" => {
                        let mut fp = [0 as c_char; 8];
                        // SAFETY: length-aware input and eight-byte output per libinjection.h.
                        unsafe {
                            if sqli {
                                libinjection_sqli(
                                    input.as_ptr().cast(),
                                    input.len(),
                                    fp.as_mut_ptr(),
                                ) != 0
                            } else {
                                libinjection_xss(input.as_ptr().cast(), input.len()) != 0
                            }
                        }
                    }
                    "selected" => {
                        if sqli {
                            libinjection::is_sqli(input)
                        } else {
                            libinjection::is_xss(input)
                        }
                    }
                    "pure-rust" => {
                        if sqli {
                            libinjection::rust::detect_sqli_bytes(input.as_bytes()).is_injection
                        } else {
                            libinjection::rust::detect_xss_bytes(input.as_bytes()).is_injection
                        }
                    }
                    _ => {
                        if sqli {
                            libinjection::sqli::is_sqli(input)
                        } else {
                            libinjection::xss::is_xss(input)
                        }
                    }
                };
                hits += usize::from(black_box(hit));
            }
            println!(
                "case={name} backend={backend} n={n} hits={hits} ns_per_eval={:.2}",
                start.elapsed().as_nanos() as f64 / n as f64
            );
        }
    }
}
