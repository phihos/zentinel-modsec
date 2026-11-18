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
fn unicode_best_fit_mapping_is_applied_only_to_encoded_codepoints() {
    check(
        "urlDecodeUni",
        &[
            (b"%u2018", b"'"),
            (b"%u201C", b"\""),
            (b"%u00A0", b" "),
            (b"%uFF1C+%2B", b"< +"),
            ("‘".as_bytes(), "‘".as_bytes()),
        ],
    );
}

#[test]
fn every_pinned_codepage_20127_entry_matches_the_reference_table() {
    let transform = create_transformation("urlDecodeUni").unwrap();
    let mut tested = 0;
    for line in include_str!("fixtures/coraza-3.8.1-unicode-bestfit-20127.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (code, expected) = line.split_once('\t').unwrap();
        let code = u32::from_str_radix(code.trim_start_matches("0x"), 16).unwrap();
        let expected = u8::from_str_radix(expected.trim_start_matches("0x"), 16).unwrap();
        let encoded = format!("%u{code:04x}");
        assert_eq!(
            transform
                .transform_bytes(encoded.as_bytes())
                .unwrap()
                .as_ref(),
            [expected],
            "{encoded}"
        );
        tested += 1;
    }
    assert!(tested > 300);
    check(
        "urlDecodeUni",
        &[
            (b"%u4e00", b"\0"),
            (b"%u0000", b"\0"),
            (b"%uFF5F", b"_"),
            (b"%uZZZZ", b"%uZZZZ"),
        ],
    );
}
