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
fn css_escape_codepoints_use_utf8_and_keep_other_raw_bytes() {
    check(
        "cssDecode",
        &[
            (br"\ff", b"\xc3\xbf"),
            (br"\0", b"\xef\xbf\xbd"),
            (br"\1f37a", b"\xf0\x9f\x8d\xba"),
            (br"\ff1c", b"<"),
            (br"\q", b"q"),
            (b"a\\\n", b"a"),
            (b"\xff\\ff", b"\xff\xc3\xbf"),
        ],
    );
}
#[test]
fn javascript_extended_unicode_and_unknown_escapes_match_native_reference() {
    check(
        "jsDecode",
        &[
            (br"\u{ff1c}", b"<"),
            (br"\u{110000}", b"\0"),
            (br"\q", b"q"),
            (br"\777", b"?7"),
            (br"\xff", b"\xff"),
            (br"\a", b"\x07"),
        ],
    );
}
#[test]
fn c_escapes_are_distinct_from_javascript_unicode_escapes() {
    check(
        "escapeSeqDecode",
        &[
            (br"\777", b"\xff"),
            (br"\XFF", b"\xff"),
            (br"\uFF1C", b"uFF1C"),
            (br"\x1", b"x1"),
            (br"\q", b"q"),
        ],
    );
}
