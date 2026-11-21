//! `Transformation::leaves_unchanged` lets the pipeline skip a transformation
//! without running it. That is only sound when a `true` is a proof: whenever
//! it says an input is left alone, `transform` must return that input.
//!
//! The check is compared against `transform` itself, for every `t:` name the
//! engine knows and for inputs built from the bytes the transformations react
//! to. Nothing here changes what a transformation returns; the pipeline test
//! also passes without the check.

use std::borrow::Cow;
use zentinel_modsec::transformations::{create_transformation, TransformationPipeline};

/// Every name `create_transformation` accepts.
const NAMES: &[&str] = &[
    "urlDecode",
    "urlDecodeUni",
    "base64Decode",
    "base64DecodeExt",
    "hexDecode",
    "htmlEntityDecode",
    "jsDecode",
    "cssDecode",
    "base64Encode",
    "hexEncode",
    "urlEncode",
    "lowercase",
    "uppercase",
    "compressWhitespace",
    "removeWhitespace",
    "removeNulls",
    "replaceNulls",
    "trim",
    "trimLeft",
    "trimRight",
    "normalizePath",
    "normalizePathWin",
    "removeComments",
    "replaceComments",
    "cmdLine",
    "removeCommentsChar",
    "md5",
    "sha1",
    "length",
    "none",
    "sqlHexDecode",
    "utf8toUnicode",
    "escapeSeqDecode",
    "parityEven7bit",
    "sha256",
];

/// The transformations that have a check, with an input each must recognize.
const CHECKED: &[&str] = &[
    "urlDecode",
    "urlDecodeUni",
    "htmlEntityDecode",
    "jsDecode",
    "cssDecode",
    "urlEncode",
    "lowercase",
    "compressWhitespace",
    "removeWhitespace",
    "normalizePath",
    "normalizePathWin",
    "removeComments",
    "replaceComments",
    "cmdLine",
    "removeCommentsChar",
    "none",
    "sqlHexDecode",
    "escapeSeqDecode",
    "uppercase",
];

/// Characters a transformation treats specially, and a few it does not.
const ALPHABET: &[char] = &[
    'a', 'A', 'f', '0', '9', 'x', 'X', 'u', 'n', '%', '+', '&', ';', '#', '\\', '/', '*', '-', '.',
    ' ', '\t', '\n', '\0', '"', '\'', '^', ',', '(', '=', 'é', 'İ', '\u{a0}',
];

const HAND_PICKED: &[&str] = &[
    "",
    "hello",
    "Hello World",
    "index.html",
    "/a/b/c.php",
    "/a/./b",
    "/a/../b",
    "a/..",
    "../a",
    "./a",
    "a/.",
    "..",
    ".",
    "...",
    "a//b",
    "//",
    "a\\b",
    "a\\\\b",
    "%41",
    "%4",
    "%zz",
    "%u0041",
    "%uFF21",
    "%U0041",
    "%c3%a9",
    "%ff",
    "a+b",
    "&amp;",
    "&lt;script&gt;",
    "&#60;",
    "&#x3c;",
    "&amp",
    "& amp;",
    "\\n",
    "\\x41",
    "\\u0041",
    "\\41 ",
    "\\",
    "0x41",
    "0X41",
    "0x",
    "10x",
    "/* c */",
    "/*",
    "*/",
    "a/ *b",
    "--",
    "a-b",
    "#",
    "a b",
    "a  b",
    " a",
    "a ",
    "a /b",
    "a (b",
    "a\u{b}b",
    "a\u{c}b",
    "a\rb",
    "a\u{1c}b",
    "a\u{85}b",
    "a\u{a0}b",
    "a\u{1680}b",
    "a\u{2003}b",
    "a\u{2028}b",
    "a\u{3000}b",
    "a\u{200b}b",
    "a\0b",
    "École",
    "école",
    "straße",
    "ǅ",
    "ſ",
    "Σ",
    "ὈΔΥΣΣΕΎΣ",
    "Ａ",
    "ａ",
    "🍺",
    "aGVsbG8=",
    "aGVsbG8",
    "4142",
    "abc123",
    "ABC123",
    "\u{7f}",
];

fn corpus() -> Vec<String> {
    let mut inputs: Vec<String> = HAND_PICKED.iter().map(|s| s.to_string()).collect();
    // Every ASCII byte alone and every pair of them.
    for a in 0u8..=0x7f {
        inputs.push(char::from(a).to_string());
        for b in 0u8..=0x7f {
            inputs.push([char::from(a), char::from(b)].iter().collect());
        }
    }
    // Every triple of the special characters, bare and inside a word.
    for &a in ALPHABET {
        for &b in ALPHABET {
            for &c in ALPHABET {
                let triple: String = [a, b, c].iter().collect();
                inputs.push(format!("ab{triple}cd"));
                inputs.push(triple);
            }
        }
    }
    inputs
}

#[test]
fn leaves_unchanged_is_never_true_for_an_input_transform_changes() {
    let corpus = corpus();
    for name in NAMES {
        let t = create_transformation(name).unwrap();
        for input in &corpus {
            if t.leaves_unchanged(input) {
                assert_eq!(
                    t.transform(input),
                    input.as_str(),
                    "{name} claims to leave {input:?} unchanged"
                );
            }
        }
    }
}

#[test]
fn checked_transformations_recognize_plain_input() {
    for name in CHECKED {
        let t = create_transformation(name).unwrap();
        // Letters in the case the transformation keeps.
        let words: [&str; 3] = if *name == "uppercase" {
            ["ABC123", "ID", "EN"]
        } else {
            ["abc123", "id", "en"]
        };
        for input in [""].into_iter().chain(words) {
            assert!(t.leaves_unchanged(input), "{name} on {input:?}");
        }
    }
}

#[test]
fn pipeline_returns_what_the_transformations_return_in_sequence() {
    let pipelines: &[&[&str]] = &[
        &["urlDecodeUni"],
        &["lowercase"],
        &["urlDecodeUni", "lowercase"],
        &["lowercase", "urlDecodeUni"],
        &["urlDecodeUni", "htmlEntityDecode", "jsDecode", "cssDecode"],
        &["utf8toUnicode", "urlDecodeUni", "removeNulls", "cmdLine"],
        &["urlDecodeUni", "normalizePathWin", "lowercase"],
        &["urlDecode", "replaceComments", "compressWhitespace"],
        &["removeWhitespace", "removeCommentsChar", "sqlHexDecode"],
        &["escapeSeqDecode", "removeComments", "trim", "uppercase"],
        &["base64Decode", "lowercase", "length"],
        &["urlEncode", "normalizePath", "sha1", "hexEncode"],
    ];
    let corpus = corpus();
    for names in pipelines {
        let owned: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let pipeline = TransformationPipeline::from_names(&owned).unwrap();
        let stages: Vec<_> = names
            .iter()
            .map(|n| create_transformation(n).unwrap())
            .collect();
        for input in &corpus {
            let mut expected = input.clone();
            for stage in &stages {
                expected = stage.transform(&expected).into_owned();
            }
            assert_eq!(
                pipeline.apply(input),
                expected.as_str(),
                "{names:?} on {input:?}"
            );
        }
    }
}

#[test]
fn pipeline_borrows_an_input_no_transformation_changes() {
    // `none` would clear the pipeline rather than join it.
    let names: Vec<String> = CHECKED
        .iter()
        .filter(|n| **n != "none")
        .map(|n| n.to_string())
        .collect();
    let pipeline = TransformationPipeline::from_names(&names).unwrap();
    // Digits only: `lowercase` and `uppercase` are both in the pipeline.
    assert!(matches!(pipeline.apply("123"), Cow::Borrowed("123")));
}
