//! Decoding transformations.

use super::Transformation;
use std::borrow::Cow;

/// URL decode transformation.
pub struct UrlDecode;

impl Transformation for UrlDecode {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        Ok(super::bytes::url_decode_stage(input, false))
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        match super::bytes::url_decode_stage(input.as_bytes(), false) {
            Cow::Borrowed(_) => Cow::Borrowed(input),
            Cow::Owned(bytes) => String::from_utf8(bytes)
                .map(Cow::Owned)
                .unwrap_or(Cow::Borrowed(input)),
        }
    }

    fn name(&self) -> &'static str {
        "urlDecode"
    }
}

/// URL decode with Unicode support.
pub struct UrlDecodeUni;

impl Transformation for UrlDecodeUni {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        Ok(super::bytes::url_decode_stage(input, true))
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        // Decode original input positions exactly once. Invalid/truncated
        // escapes must not swallow the following character (which may itself
        // be a '+' or the start of a valid escape).
        let mut result = String::with_capacity(input.len());
        let mut modified = false;
        let mut offset = 0;
        while offset < input.len() {
            let tail = &input[offset..];
            if tail.starts_with('+') {
                result.push(' ');
                modified = true;
                offset += 1;
                continue;
            }
            if tail.starts_with('%') {
                if tail
                    .as_bytes()
                    .get(1)
                    .is_some_and(|c| *c == b'u' || *c == b'U')
                {
                    if let Some(code) = tail.get(2..6).and_then(|hex| {
                        hex.bytes()
                            .all(|b| b.is_ascii_hexdigit())
                            .then(|| u32::from_str_radix(hex, 16).ok())
                            .flatten()
                    }) {
                        let code = if (0xff01..=0xff5e).contains(&code) {
                            code - 0xfee0
                        } else {
                            code
                        };
                        if let Some(decoded) = char::from_u32(code) {
                            result.push(decoded);
                            modified = true;
                            offset += 6;
                            continue;
                        }
                    }
                } else if let Some(byte) = tail.get(1..3).and_then(|hex| {
                    hex.bytes()
                        .all(|b| b.is_ascii_hexdigit())
                        .then(|| u8::from_str_radix(hex, 16).ok())
                        .flatten()
                }) {
                    result.push(byte as char);
                    modified = true;
                    offset += 3;
                    continue;
                }
            }
            let literal = tail.chars().next().expect("nonempty tail");
            result.push(literal);
            offset += literal.len_utf8();
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(input)
        }
    }

    fn name(&self) -> &'static str {
        "urlDecodeUni"
    }
}

/// Base64 decode transformation.
pub struct Base64Decode;

impl Transformation for Base64Decode {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(input) {
            Ok(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
            Err(_) => Cow::Borrowed(input),
        }
    }

    fn name(&self) -> &'static str {
        "base64Decode"
    }
}

/// Extended base64 decode (handles URL-safe base64).
pub struct Base64DecodeExt;

impl Transformation for Base64DecodeExt {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use base64::Engine;
        // Try URL-safe first, then standard
        let result = base64::engine::general_purpose::URL_SAFE
            .decode(input)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input));

        match result {
            Ok(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
            Err(_) => Cow::Borrowed(input),
        }
    }

    fn name(&self) -> &'static str {
        "base64DecodeExt"
    }
}

/// Hex decode transformation.
pub struct HexDecode;

impl Transformation for HexDecode {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = Vec::new();
        let mut chars = input.chars().peekable();

        while let Some(c1) = chars.next() {
            if let Some(c2) = chars.next() {
                let hex = format!("{}{}", c1, c2);
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte);
                } else {
                    // Invalid hex, keep original
                    return Cow::Borrowed(input);
                }
            } else {
                // Odd number of chars
                return Cow::Borrowed(input);
            }
        }

        Cow::Owned(String::from_utf8_lossy(&result).into_owned())
    }

    fn name(&self) -> &'static str {
        "hexDecode"
    }
}

/// HTML entity decode transformation.
pub struct HtmlEntityDecode;

impl Transformation for HtmlEntityDecode {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        Ok(super::bytes::html_entity_stage(input))
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let decoded = html_escape::decode_html_entities(input);
        if decoded == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(decoded.into_owned())
        }
    }

    fn name(&self) -> &'static str {
        "htmlEntityDecode"
    }
}

/// JavaScript decode transformation.
pub struct JsDecode;

impl Transformation for JsDecode {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        Ok(super::bytes::escape_decode_stage(input, false, true))
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        let mut modified = false;

        while let Some(c) = chars.next() {
            if c == '\\' {
                modified = true;
                match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some('\\') => result.push('\\'),
                    Some('"') => result.push('"'),
                    Some('\'') => result.push('\''),
                    Some('x') => {
                        // \xHH
                        let mut hex = String::new();
                        for _ in 0..2 {
                            if let Some(h) = chars.next() {
                                hex.push(h);
                            }
                        }
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            result.push(byte as char);
                        } else {
                            result.push('\\');
                            result.push('x');
                            result.push_str(&hex);
                        }
                    }
                    Some('u') => {
                        // \uHHHH
                        let mut hex = String::new();
                        for _ in 0..4 {
                            if let Some(h) = chars.next() {
                                hex.push(h);
                            }
                        }
                        if let Ok(code) = u32::from_str_radix(&hex, 16) {
                            if let Some(decoded) = char::from_u32(code) {
                                result.push(decoded);
                            } else {
                                result.push('\\');
                                result.push('u');
                                result.push_str(&hex);
                            }
                        } else {
                            result.push('\\');
                            result.push('u');
                            result.push_str(&hex);
                        }
                    }
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(c);
            }
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(input)
        }
    }

    fn name(&self) -> &'static str {
        "jsDecode"
    }
}

/// CSS decode transformation.
pub struct CssDecode;

impl Transformation for CssDecode {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        Ok(super::bytes::escape_decode_stage(input, true, false))
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        let mut modified = false;

        while let Some(c) = chars.next() {
            if c == '\\' {
                modified = true;
                // CSS escape: \HH or \HHHHHH
                let mut hex = String::new();
                while hex.len() < 6 {
                    match chars.peek() {
                        Some(h) if h.is_ascii_hexdigit() => {
                            hex.push(chars.next().unwrap());
                        }
                        _ => break,
                    }
                }
                // Skip optional whitespace after hex
                if let Some(' ') | Some('\t') | Some('\n') = chars.peek() {
                    chars.next();
                }

                if !hex.is_empty() {
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(decoded) = char::from_u32(code) {
                            result.push(decoded);
                            continue;
                        }
                    }
                }
                result.push('\\');
                result.push_str(&hex);
            } else {
                result.push(c);
            }
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(input)
        }
    }

    fn name(&self) -> &'static str {
        "cssDecode"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        let t = UrlDecode;
        assert_eq!(t.transform("hello%20world"), "hello world");
        assert_eq!(t.transform("test%2Fpath"), "test/path");
    }

    #[test]
    fn test_base64_decode() {
        let t = Base64Decode;
        assert_eq!(t.transform("aGVsbG8="), "hello");
    }

    #[test]
    fn test_html_entity_decode() {
        let t = HtmlEntityDecode;
        assert_eq!(t.transform("&lt;script&gt;"), "<script>");
        assert_eq!(t.transform("&#60;"), "<");
    }

    #[test]
    fn test_js_decode() {
        let t = JsDecode;
        assert_eq!(t.transform(r"\x3cscript\x3e"), "<script>");
        assert_eq!(t.transform(r"\u003c"), "<");
    }
}

#[cfg(test)]
mod unicode_width_tests {
    use super::*;

    #[test]
    fn url_decode_uni_maps_full_width_ascii_for_crs_941110() {
        let t = UrlDecodeUni;
        assert_eq!(
            t.transform("%uFF1Cscript%uFF1Ealert(1)%uFF1C/script%uFF1E"),
            "<script>alert(1)</script>"
        );
        assert_eq!(t.transform("%UFF1cscript%uFF1e"), "<script>");
        for ascii in 0x21u32..=0x7e {
            let encoded = format!("%u{:04X}", ascii + 0xfee0);
            assert_eq!(
                t.transform(&encoded),
                char::from_u32(ascii).unwrap().to_string()
            );
        }
        // Only encoded full-width ASCII is folded; literal Unicode is left
        // for the explicit utf8toUnicode transformation in the CRS chain.
        assert_eq!(t.transform("＜script＞"), "＜script＞");
        assert_eq!(t.transform("%uFF00%uFF5F"), "＀｟");
    }
}
