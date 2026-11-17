//! Expected bytes independently read back from pinned Coraza v3.8.1.
//! /tmp/zentinel-byte-transform-probe.go records native transform outputs.
use zentinel_modsec::transformations::create_transformation;
fn check(name: &str, cases: &[(&[u8], &[u8])]) {
    let transform = create_transformation(name).unwrap();
    for &(input, expected) in cases {
        assert_eq!(
            transform.transform_bytes(input).unwrap().as_ref(),
            expected,
            "{name}: {input:?}"
        );
    }
}
#[test]
fn base64_decoders_preserve_partial_and_forgiving_results() {
    check(
        "base64Decode",
        &[
            (b"YWJj??ZGVm", b"abc"),
            (b"YQ", b"a"),
            (b"YWI", b"ab"),
            (b"/wCA", b"\xff\0\x80"),
        ],
    );
    check(
        "base64DecodeExt",
        &[
            (b"YWJj??ZGVm", b"abcdef"),
            (b"/w.\xffCA", b"\xff\0\x80"),
            (b"_wCA", b"\xff\0\x80"),
        ],
    );
}
