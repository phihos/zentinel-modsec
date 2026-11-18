//! Built-in transformations on original bytes. Text adapters are never used to
//! represent binary intermediate results.
use super::Transformation;
use crate::{Error, Result};
use std::borrow::Cow;

fn hex(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0u32, |value, &b| {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(u32::from(digit))
    })
}
fn space(b: u8) -> bool {
    b.is_ascii_whitespace() || b == 0x0b
}
fn width(code: u32) -> u8 {
    if (0xff01..=0xff5e).contains(&code) {
        (code - 0xfee0) as u8
    } else {
        code as u8
    }
}

/// Decode one pass of URL bytes. A decoded percent-encoded plus is never
/// decoded a second time within this transformation.
pub(crate) fn url_decode(input: &[u8], unicode: bool, plus: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if plus && input[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        if input[i] == b'%' {
            if unicode && i + 5 < input.len() && matches!(input[i + 1], b'u' | b'U') {
                if let Some(code) = hex(&input[i + 2..i + 6]) {
                    out.push(super::unicode_bestfit::ascii(code).unwrap_or_else(|| width(code)));
                    i += 6;
                    continue;
                }
            }
            if i + 2 < input.len() {
                if let Some(code) = hex(&input[i + 1..i + 3]) {
                    out.push(code as u8);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

fn base64_decode(input: &[u8], forgiving: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut count = 0;
    let mut bits = 0u32;
    for &byte in input {
        if byte == b'=' {
            break;
        }
        if matches!(byte, b'\r' | b'\n') {
            continue;
        }
        let decoded = match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'-' if forgiving => Some(62),
            b'_' if forgiving => Some(63),
            _ => None,
        };
        let Some(decoded) = decoded else {
            if forgiving {
                continue;
            } else {
                break;
            }
        };
        bits = (bits << 6) | u32::from(decoded);
        count += 1;
        if count == 4 {
            out.extend_from_slice(&[(bits >> 16) as u8, (bits >> 8) as u8, bits as u8]);
            bits = 0;
            count = 0;
        }
    }
    match count {
        2 => out.push((bits >> 4) as u8),
        3 => out.extend_from_slice(&[(bits >> 10) as u8, (bits >> 2) as u8]),
        _ => {}
    }
    out
}

fn escape_decode(input: &[u8], css: bool, javascript: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        if i + 1 == input.len() {
            if !css {
                out.push(b'\\');
            }
            break;
        }
        let next = input[i + 1];
        if css {
            let mut end = i + 1;
            while end < input.len() && end < i + 7 && input[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end > i + 1 {
                let code = hex(&input[i + 1..end]).unwrap();
                let code = if (0xff01..=0xff5e).contains(&code) {
                    code - 0xfee0
                } else {
                    code
                };
                let character = if code == 0 {
                    '\u{fffd}'
                } else {
                    char::from_u32(code).unwrap_or('\u{fffd}')
                };
                let mut encoded = [0; 4];
                out.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                i = end;
                if i < input.len() && space(input[i]) {
                    i += 1;
                }
                continue;
            }
            if next != b'\n' {
                out.push(next);
            }
            i += 2;
            continue;
        }
        if javascript && next == b'u' && input.get(i + 2) == Some(&b'{') {
            if let Some(close) = input[i + 3..].iter().position(|&b| b == b'}') {
                let end = i + 3 + close;
                if (1..=6).contains(&close) {
                    if let Some(code) = hex(&input[i + 3..end]) {
                        out.push(width(code));
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        if (next == b'x' || !javascript && next == b'X') && i + 3 < input.len() {
            if let Some(code) = hex(&input[i + 2..i + 4]) {
                out.push(code as u8);
                i += 4;
                continue;
            }
        }
        if javascript && next == b'u' && i + 5 < input.len() {
            if let Some(code) = hex(&input[i + 2..i + 6]) {
                out.push(width(code));
                i += 6;
                continue;
            }
        }
        if (b'0'..=b'7').contains(&next) {
            let mut end = i + 1;
            let mut code = 0u32;
            let max = if javascript && next > b'3' { 2 } else { 3 };
            while end < input.len() && end < i + 1 + max && (b'0'..=b'7').contains(&input[end]) {
                code = code * 8 + u32::from(input[end] - b'0');
                end += 1;
            }
            out.push(code as u8);
            i = end;
            continue;
        }
        out.push(match next {
            b'a' => 7,
            b'b' => 8,
            b'f' => 12,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'v' => 11,
            _ => next,
        });
        i += 2;
    }
    out
}

/// The common unencoded case borrows the input without allocating a buffer.
pub(super) fn url_decode_stage(input: &[u8], unicode: bool) -> Cow<'_, [u8]> {
    if memchr::memchr2(b'%', b'+', input).is_none() {
        return Cow::Borrowed(input);
    }
    decoded_output(input, url_decode(input, unicode, true))
}

pub(super) fn escape_decode_stage(input: &[u8], css: bool, javascript: bool) -> Cow<'_, [u8]> {
    if memchr::memchr(b'\\', input).is_none() {
        return Cow::Borrowed(input);
    }
    decoded_output(input, escape_decode(input, css, javascript))
}

pub(super) fn html_entity_stage(input: &[u8]) -> Cow<'_, [u8]> {
    if memchr::memchr(b'&', input).is_none() {
        return Cow::Borrowed(input);
    }
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'&' {
            let mut end = i + 1;
            while end < input.len() && end < i + 64 && input[end].is_ascii_alphanumeric() {
                end += 1;
            }
            if i + 1 < input.len() && input[i + 1] == b'#' {
                end = i + 2;
                while end < input.len()
                    && end < i + 64
                    && (input[end].is_ascii_hexdigit() || matches!(input[end], b'x' | b'X'))
                {
                    end += 1;
                }
            }
            if end < input.len() && input[end] == b';' {
                end += 1;
            }
            if let Ok(entity) = std::str::from_utf8(&input[i..end]) {
                let decoded = html_escape::decode_html_entities(entity);
                if decoded.as_ref() != entity {
                    out.extend_from_slice(decoded.as_bytes());
                    i = end;
                    continue;
                }
            }
        }
        out.push(input[i]);
        i += 1;
    }
    decoded_output(input, out)
}

fn decoded_output(input: &[u8], output: Vec<u8>) -> Cow<'_, [u8]> {
    if output == input {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(output)
    }
}

pub(super) fn apply<'a>(
    transformation: &dyn Transformation,
    input: &'a [u8],
) -> Result<Cow<'a, [u8]>> {
    use base64::Engine;
    let name = transformation.name();
    let out = match name {
        "none" => return Ok(Cow::Borrowed(input)),
        "length" => input.len().to_string().into_bytes(),
        "hexDecode" => match ::hex::decode(input) {
            Ok(value) => value,
            Err(_) => return Ok(Cow::Borrowed(input)),
        },
        "base64Decode" => base64_decode(input, false),
        "base64DecodeExt" => base64_decode(input, true),
        "base64Encode" => base64::engine::general_purpose::STANDARD
            .encode(input)
            .into_bytes(),
        "hexEncode" => ::hex::encode(input).into_bytes(),
        "urlEncode" => percent_encoding::percent_encode(input, percent_encoding::NON_ALPHANUMERIC)
            .to_string()
            .into_bytes(),
        "md5" => {
            use md5::Digest;
            md5::Md5::digest(input).to_vec()
        }
        "sha1" => {
            use sha1::Digest;
            sha1::Sha1::digest(input).to_vec()
        }
        "sha256" => {
            use sha2::Digest;
            sha2::Sha256::digest(input).to_vec()
        }
        "sqlHexDecode" => {
            let mut out = Vec::with_capacity(input.len());
            let mut i = 0;
            while i < input.len() {
                if input[i..].starts_with(b"0x") {
                    let mut end = i + 2;
                    while end < input.len() && input[end].is_ascii_hexdigit() {
                        end += 1;
                    }
                    if end > i + 2 {
                        let mut p = i + 2;
                        while p + 1 < end {
                            out.push(hex(&input[p..p + 2]).unwrap() as u8);
                            p += 2;
                        }
                        i = end;
                        continue;
                    }
                }
                out.push(input[i]);
                i += 1;
            }
            out
        }
        _ => {
            // Existing Unicode-aware text semantics remain available for valid
            // text where the transform cannot create arbitrary output bytes.
            if let Ok(text) = std::str::from_utf8(input) {
                return Ok(match transformation.transform(text) {
                    Cow::Borrowed(value) => Cow::Borrowed(value.as_bytes()),
                    Cow::Owned(value) => Cow::Owned(value.into_bytes()),
                });
            }
            match name {
                "lowercase" => input.iter().map(u8::to_ascii_lowercase).collect(),
                "uppercase" => input.iter().map(u8::to_ascii_uppercase).collect(),
                "removeNulls" => input.iter().copied().filter(|&b| b != 0).collect(),
                "replaceNulls" => input
                    .iter()
                    .map(|&b| if b == 0 { b' ' } else { b })
                    .collect(),
                "removeWhitespace" => input.iter().copied().filter(|&b| !space(b)).collect(),
                "trim" | "trimLeft" | "trimRight" => {
                    let mut start = 0;
                    let mut end = input.len();
                    if name != "trimRight" {
                        while start < end && space(input[start]) {
                            start += 1;
                        }
                    }
                    if name != "trimLeft" {
                        while end > start && space(input[end - 1]) {
                            end -= 1;
                        }
                    }
                    input[start..end].to_vec()
                }
                "compressWhitespace" => {
                    let mut out = Vec::new();
                    let mut last = false;
                    for &b in input {
                        if space(b) {
                            if !last {
                                out.push(b' ');
                            }
                            last = true;
                        } else {
                            out.push(b);
                            last = false;
                        }
                    }
                    out
                }
                "cmdLine" => {
                    let mut out = Vec::with_capacity(input.len());
                    let mut pending = false;
                    for &b in input {
                        match b {
                            b'\\' | b'"' | b'\'' | b'^' => {}
                            b',' | b';' => {
                                if !pending {
                                    out.push(b' ');
                                    pending = true;
                                }
                            }
                            b if space(b) => {
                                if !pending {
                                    out.push(b' ');
                                    pending = true;
                                }
                            }
                            b'/' | b'(' => {
                                if pending {
                                    out.pop();
                                }
                                out.push(b);
                                pending = false;
                            }
                            _ => {
                                out.push(b.to_ascii_lowercase());
                                pending = false;
                            }
                        }
                    }
                    out
                }
                "normalizePath" | "normalizePathWin" => {
                    let normalized: Vec<u8> = input
                        .iter()
                        .map(|&b| if b == b'\\' { b'/' } else { b })
                        .collect();
                    let mut parts: Vec<&[u8]> = Vec::new();
                    for p in normalized.split(|&b| b == b'/') {
                        match p {
                            b"." => {}
                            b".." => {
                                parts.pop();
                            }
                            b"" if !parts.is_empty() => {}
                            _ => parts.push(p),
                        }
                    }
                    let mut out = Vec::new();
                    for (i, p) in parts.iter().enumerate() {
                        if i > 0 {
                            out.push(b'/');
                        }
                        out.extend_from_slice(p);
                    }
                    out
                }
                "removeComments" | "replaceComments" => {
                    let mut out = Vec::new();
                    let mut i = 0;
                    while i < input.len() {
                        if input[i..].starts_with(b"/*") {
                            i += 2;
                            while i < input.len() && !input[i..].starts_with(b"*/") {
                                i += 1;
                            }
                            if i < input.len() {
                                i += 2;
                                if name == "replaceComments" {
                                    out.push(b' ');
                                }
                            }
                        } else {
                            out.push(input[i]);
                            i += 1;
                        }
                    }
                    out
                }
                "removeCommentsChar" => {
                    let mut out = input.to_vec();
                    for marker in [&b"/*"[..], &b"*/"[..], &b"--"[..], &b"#"[..]] {
                        let mut next = Vec::new();
                        let mut i = 0;
                        while i < out.len() {
                            if out[i..].starts_with(marker) {
                                i += marker.len();
                            } else {
                                next.push(out[i]);
                                i += 1;
                            }
                        }
                        out = next;
                    }
                    out
                }
                "utf8ToUnicode" => {
                    let mut out = Vec::new();
                    let mut remaining = input;
                    while !remaining.is_empty() {
                        match std::str::from_utf8(remaining) {
                            Ok(text) => {
                                out.extend_from_slice(transformation.transform(text).as_bytes());
                                break;
                            }
                            Err(error) => {
                                let good = error.valid_up_to();
                                if good > 0 {
                                    let text = std::str::from_utf8(&remaining[..good])
                                        .expect("validated prefix");
                                    out.extend_from_slice(
                                        transformation.transform(text).as_bytes(),
                                    );
                                }
                                let bad = error.error_len().unwrap_or(remaining.len() - good);
                                out.extend_from_slice(&remaining[good..good + bad]);
                                remaining = &remaining[good + bad..];
                            }
                        }
                    }
                    out
                }
                _ => {
                    return Err(Error::UnsupportedBinaryInput {
                        component: format!("t:{}", transformation.name()),
                    })
                }
            }
        }
    };
    Ok(if out == input {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(out)
    })
}
