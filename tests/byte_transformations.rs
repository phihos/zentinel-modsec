use std::borrow::Cow;
use zentinel_modsec::transformations::{create_transformation, Transformation};

#[test]
fn decoding_never_replaces_binary_intermediate_bytes() {
    for (name, input, expected) in [
        ("urlDecode", &b"%FF%00+%2B"[..], &b"\xff\0 +"[..]),
        ("urlDecodeUni", &b"%FF%uFF1C+%2B"[..], &b"\xff< +"[..]),
        ("hexDecode", &b"ff0080"[..], &b"\xff\0\x80"[..]),
        ("base64Decode", &b"/wCA"[..], &b"\xff\0\x80"[..]),
        ("base64DecodeExt", &b"_wCA"[..], &b"\xff\0\x80"[..]),
        ("jsDecode", &b"\\xff\\x00\\uFF1C"[..], &b"\xff\0<"[..]),
        ("cssDecode", &b"\\ff \\00 \\ff1c"[..], &b"\xff\0<"[..]),
        ("escapeSeqDecode", &b"\\xff\\000\\\""[..], &b"\xff\0\""[..]),
        ("sqlHexDecode", &b"0xff0080"[..], &b"\xff\0\x80"[..]),
        (
            "htmlEntityDecode",
            &b"\xff&lt;script&gt;\0"[..],
            &b"\xff<script>\0"[..],
        ),
    ] {
        assert_eq!(
            create_transformation(name)
                .unwrap()
                .transform_bytes(input)
                .unwrap()
                .as_ref(),
            expected,
            "{name}"
        );
    }
}

#[test]
fn binary_input_survives_normalization_and_hashes_are_raw() {
    assert_eq!(
        create_transformation("lowercase")
            .unwrap()
            .transform_bytes(b"A\xffZ")
            .unwrap()
            .as_ref(),
        b"a\xffz"
    );
    assert_eq!(
        create_transformation("md5")
            .unwrap()
            .transform_bytes(b"hello")
            .unwrap()
            .as_ref(),
        &hex::decode("5d41402abc4b2a76b9719d911017c592").unwrap()
    );
    assert_eq!(
        create_transformation("length")
            .unwrap()
            .transform_bytes(b"\xff\0")
            .unwrap()
            .as_ref(),
        b"2"
    );
}

#[test]
fn custom_text_only_transformations_reject_binary_input() {
    struct TextOnly;
    impl Transformation for TextOnly {
        fn transform<'a>(&self, value: &'a str) -> Cow<'a, str> {
            Cow::Borrowed(value)
        }
        fn name(&self) -> &'static str {
            "custom"
        }
    }
    assert!(TextOnly
        .transform_bytes(b"\xff")
        .unwrap_err()
        .to_string()
        .contains("binary input"));
}
