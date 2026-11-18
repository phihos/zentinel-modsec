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
        (
            "cssDecode",
            &b"\\ff \\00 \\ff1c"[..],
            &b"\xc3\xbf\xef\xbf\xbd<"[..],
        ),
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

#[test]
fn compress_whitespace_preserves_unicode_boundaries_and_latin1_separators() {
    let transform = create_transformation("compressWhitespace").unwrap();
    let text = "Å\u{85}\u{a0}你\u{2003}à";
    assert_eq!(transform.transform(text), "Å 你\u{2003}à");
    assert_eq!(
        transform.transform_bytes(text.as_bytes()).unwrap().as_ref(),
        "Å 你\u{2003}à".as_bytes(),
    );
    for (input, expected) in [
        (
            &b"a\xff\xc2\x85\xa0\t\xc2\xa0\xffb"[..],
            &b"a\xff \xffb"[..],
        ),
        (&b"\x85\xe0\xa0"[..], &b"\x85\xe0 "[..]),
    ] {
        assert_eq!(transform.transform_bytes(input).unwrap().as_ref(), expected);
    }
    for input in ["two words", "Åà你\u{2003}書"] {
        assert!(matches!(transform.transform(input), Cow::Borrowed(_)));
        assert!(matches!(
            transform.transform_bytes(input.as_bytes()).unwrap(),
            Cow::Borrowed(_)
        ));
    }
}
