//! Normalization transformations.

use super::Transformation;
use std::borrow::Cow;

/// Lowercase transformation.
pub struct Lowercase;

impl Transformation for Lowercase {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let lower = input.to_lowercase();
        if lower == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(lower)
        }
    }

    fn name(&self) -> &'static str {
        "lowercase"
    }
}

/// Uppercase transformation.
pub struct Uppercase;

impl Transformation for Uppercase {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let upper = input.to_uppercase();
        if upper == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(upper)
        }
    }

    fn name(&self) -> &'static str {
        "uppercase"
    }
}

/// Compress whitespace transformation.
pub struct CompressWhitespace;

impl CompressWhitespace {
    fn compress(input: &[u8]) -> Cow<'_, [u8]> {
        let mut output = Vec::new();
        let mut copied = 0;
        let mut previous_space_end = None;
        let mut space_at = |start: usize, width: usize| {
            let adjacent = previous_space_end == Some(start);
            previous_space_end = Some(start + width);
            if adjacent || input[start] != b' ' {
                output.extend_from_slice(&input[copied..start]);
                if !adjacent {
                    output.push(b' ');
                }
                copied = start + width;
            }
        };

        let mut offset = 0;
        for chunk in input.utf8_chunks() {
            for (index, ch) in chunk.valid().char_indices() {
                // Coraza compresses the Latin-1 whitespace set.
                if matches!(ch, ' ' | '\t'..='\r' | '\u{85}' | '\u{a0}') {
                    space_at(offset + index, ch.len_utf8());
                }
            }
            offset += chunk.valid().len();
            for &byte in chunk.invalid() {
                // At an invalid UTF-8 boundary, 0xA0 is a bare Latin-1 NBSP.
                // Other malformed bytes pass through exactly as received.
                if byte == 0xa0 {
                    space_at(offset, 1);
                }
                offset += 1;
            }
        }

        if copied == 0 {
            return Cow::Borrowed(input);
        }
        output.extend_from_slice(&input[copied..]);
        Cow::Owned(output)
    }
}

impl Transformation for CompressWhitespace {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        Ok(Self::compress(input))
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        match Self::compress(input.as_bytes()) {
            Cow::Borrowed(_) => Cow::Borrowed(input),
            Cow::Owned(bytes) => Cow::Owned(
                String::from_utf8(bytes)
                    .expect("replacing whole whitespace characters preserves UTF-8"),
            ),
        }
    }

    fn name(&self) -> &'static str {
        "compressWhitespace"
    }
}

/// Remove whitespace transformation.
pub struct RemoveWhitespace;

impl Transformation for RemoveWhitespace {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let result: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        if result == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(result)
        }
    }

    fn name(&self) -> &'static str {
        "removeWhitespace"
    }
}

/// Remove null bytes transformation.
pub struct RemoveNulls;

impl Transformation for RemoveNulls {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if !input.contains('\0') {
            return Cow::Borrowed(input);
        }
        Cow::Owned(input.replace('\0', ""))
    }

    fn name(&self) -> &'static str {
        "removeNulls"
    }
}

/// Replace null bytes with spaces transformation.
pub struct ReplaceNulls;

impl Transformation for ReplaceNulls {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if !input.contains('\0') {
            return Cow::Borrowed(input);
        }
        Cow::Owned(input.replace('\0', " "))
    }

    fn name(&self) -> &'static str {
        "replaceNulls"
    }
}

/// Trim transformation.
pub struct Trim;

impl Transformation for Trim {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let trimmed = input.trim();
        if trimmed.len() == input.len() {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(trimmed.to_string())
        }
    }

    fn name(&self) -> &'static str {
        "trim"
    }
}

/// Trim left transformation.
pub struct TrimLeft;

impl Transformation for TrimLeft {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let trimmed = input.trim_start();
        if trimmed.len() == input.len() {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(trimmed.to_string())
        }
    }

    fn name(&self) -> &'static str {
        "trimLeft"
    }
}

/// Trim right transformation.
pub struct TrimRight;

impl Transformation for TrimRight {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let trimmed = input.trim_end();
        if trimmed.len() == input.len() {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(trimmed.to_string())
        }
    }

    fn name(&self) -> &'static str {
        "trimRight"
    }
}

// Pinned Coraza uses Linux filepath.Clean, maps a current-directory result
// to the empty string, and restores an input's trailing separator.
fn normalize_path(input: &[u8], windows: bool) -> Cow<'_, [u8]> {
    let separator = |byte: &u8| *byte == b'/' || (windows && *byte == b'\\');
    let needs_cleaning = input == b"/"
        || (windows && input.contains(&b'\\'))
        || input.windows(2).any(|pair| pair == b"//")
        || input
            .split(|b| *b == b'/')
            .any(|part| matches!(part, b"." | b".."));
    if !needs_cleaning {
        return Cow::Borrowed(input);
    }

    let absolute = separator(&input[0]);
    let mut components: Vec<&[u8]> = Vec::new();
    for part in input.split(separator) {
        match part {
            b"" | b"." => {}
            b".." if components.last().is_some_and(|last| *last != b"..") => {
                components.pop();
            }
            b".." if absolute => {}
            _ => components.push(part),
        }
    }
    let mut result = Vec::with_capacity(input.len());
    if absolute {
        result.push(b'/');
    }
    for (i, part) in components.iter().enumerate() {
        if i > 0 {
            result.push(b'/');
        }
        result.extend_from_slice(part);
    }
    if !result.is_empty() && input.last().is_some_and(separator) {
        result.push(b'/');
    }
    if result == input {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(result)
    }
}

fn normalize_text_path(input: &str, windows: bool) -> Cow<'_, str> {
    match normalize_path(input.as_bytes(), windows) {
        Cow::Borrowed(_) => Cow::Borrowed(input),
        Cow::Owned(path) => {
            Cow::Owned(String::from_utf8(path).expect("rearranged UTF-8 components"))
        }
    }
}

/// Normalize path transformation (Unix-style).
pub struct NormalizePath;

impl Transformation for NormalizePath {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        Ok(normalize_path(input, false))
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        normalize_text_path(input, false)
    }

    fn name(&self) -> &'static str {
        "normalizePath"
    }
}

/// Normalize path transformation (Windows-style).
pub struct NormalizePathWin;

impl Transformation for NormalizePathWin {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        Ok(normalize_path(input, true))
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        normalize_text_path(input, true)
    }

    fn name(&self) -> &'static str {
        "normalizePathWin"
    }
}

/// Remove comments transformation.
pub struct RemoveComments;

impl Transformation for RemoveComments {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut in_comment = false;
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if in_comment {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    in_comment = false;
                }
            } else if c == '/' && chars.peek() == Some(&'*') {
                chars.next();
                in_comment = true;
            } else {
                result.push(c);
            }
        }

        if result == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(result)
        }
    }

    fn name(&self) -> &'static str {
        "removeComments"
    }
}

/// Replace comments transformation (replaces /* ... */ with space).
pub struct ReplaceComments;

impl Transformation for ReplaceComments {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut in_comment = false;
        let mut chars = input.chars().peekable();
        let mut modified = false;

        while let Some(c) = chars.next() {
            if in_comment {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    in_comment = false;
                    result.push(' '); // Replace comment with space
                }
            } else if c == '/' && chars.peek() == Some(&'*') {
                chars.next();
                in_comment = true;
                modified = true;
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
        "replaceComments"
    }
}

/// Remove comment characters transformation.
pub struct RemoveCommentsChar;

impl Transformation for RemoveCommentsChar {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        // Remove /*, */, --, and #
        let mut result = input.to_string();
        result = result.replace("/*", "");
        result = result.replace("*/", "");
        result = result.replace("--", "");
        result = result.replace('#', "");

        if result == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(result)
        }
    }

    fn name(&self) -> &'static str {
        "removeCommentsChar"
    }
}

/// SQL hex decode transformation.
pub struct SqlHexDecode;

impl Transformation for SqlHexDecode {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        // Decode SQL hex strings like 0x41424344 to ABCD
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        let mut modified = false;

        while let Some(c) = chars.next() {
            if c == '0' && chars.peek() == Some(&'x') {
                chars.next(); // consume 'x'
                let mut hex = String::new();
                while let Some(&next) = chars.peek() {
                    if next.is_ascii_hexdigit() {
                        hex.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                // Decode hex pairs
                let mut i = 0;
                while i + 1 < hex.len() {
                    if let Ok(byte) = u8::from_str_radix(&hex[i..i + 2], 16) {
                        result.push(byte as char);
                    }
                    i += 2;
                }
                modified = true;
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
        "sqlHexDecode"
    }
}

/// UTF-8 to Unicode transformation (pass-through for now).
pub struct Utf8ToUnicode;

impl Transformation for Utf8ToUnicode {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        // SecLang's transformation serializes non-ASCII code points as
        // IIS-style %u escapes; valid Rust UTF-8 is still subject to this
        // normalization. The following urlDecodeUni can then fold width.
        if input.is_ascii() {
            return Cow::Borrowed(input);
        }
        use std::fmt::Write;
        let mut result = String::with_capacity(input.len());
        for c in input.chars() {
            if c.is_ascii() {
                result.push(c);
            } else {
                write!(&mut result, "%u{:04x}", c as u32).expect("writing to a String");
            }
        }
        Cow::Owned(result)
    }

    fn name(&self) -> &'static str {
        "utf8ToUnicode"
    }
}

/// Command line normalization transformation.
pub struct CmdLine;

impl Transformation for CmdLine {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    /// Normalise a Windows/Unix command line the way ModSecurity does.
    ///
    /// The steps, and the order, are ModSecurity's:
    ///
    /// 1. delete backslashes, double quotes, single quotes and carets, which
    ///    a shell treats as noise but which break naive pattern matching;
    /// 2. turn commas, semicolons and any run of whitespace into a single
    ///    space;
    /// 3. delete a space that immediately precedes `/` or `(`;
    /// 4. lowercase everything else.
    ///
    /// Step 3 is the one that matters most and was previously missing: CRS
    /// regexes are written against the collapsed form. Rule 932140 looks for
    /// `in\(`, with no space, so `for %v in (set) do cmd` only matches once
    /// `in (set)` has become `in(set)`.
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::with_capacity(input.len());
        // Whether the last character written was a space we introduced, and so
        // may still be removed by a following `/` or `(`.
        let mut pending_space = false;

        for c in input.chars() {
            match c {
                // Deleted outright.
                '\\' | '"' | '\'' | '^' => {}
                // Separators and whitespace collapse to one space.
                ',' | ';' => {
                    if !pending_space {
                        result.push(' ');
                        pending_space = true;
                    }
                }
                c if c.is_whitespace() => {
                    if !pending_space {
                        result.push(' ');
                        pending_space = true;
                    }
                }
                // A space before either of these is dropped.
                '/' | '(' => {
                    if pending_space {
                        result.pop();
                    }
                    pending_space = false;
                    result.push(c);
                }
                _ => {
                    pending_space = false;
                    result.extend(c.to_lowercase());
                }
            }
        }

        if result == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(result)
        }
    }

    fn name(&self) -> &'static str {
        "cmdLine"
    }
}

/// Escape sequence decode transformation.
pub struct EscapeSeqDecode;

impl Transformation for EscapeSeqDecode {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        Ok(super::bytes::escape_decode_stage(input, false, false))
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        // ModSecurity's ANSI C escape decoding: fixed controls, quotes,
        // two-digit hex, up to three octal digits, and unknown-escape slash
        // removal. Unicode escapes belong to jsDecode, not this transform.
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        let mut modified = false;
        while let Some(character) = chars.next() {
            if character != '\\' {
                result.push(character);
                continue;
            }
            let Some(escaped) = chars.next() else {
                result.push('\\');
                break;
            };
            modified = true;
            match escaped {
                'a' => result.push('\x07'),
                'b' => result.push('\x08'),
                'f' => result.push('\x0c'),
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                'v' => result.push('\x0b'),
                '\\' | '\'' | '"' | '?' => result.push(escaped),
                'x' | 'X' => {
                    let mut candidate = chars.clone();
                    match (candidate.next(), candidate.next()) {
                        (Some(high), Some(low))
                            if high.is_ascii_hexdigit() && low.is_ascii_hexdigit() =>
                        {
                            let byte = high.to_digit(16).unwrap() * 16 + low.to_digit(16).unwrap();
                            result.push(byte as u8 as char);
                            chars = candidate;
                        }
                        _ => result.push(escaped),
                    }
                }
                '0'..='7' => {
                    let mut value = escaped as u16 - '0' as u16;
                    for _ in 0..2 {
                        match chars.peek().copied() {
                            Some(digit @ '0'..='7') => {
                                chars.next();
                                value = value * 8 + digit as u16 - '0' as u16;
                            }
                            _ => break,
                        }
                    }
                    result.push((value & 0xff) as u8 as char);
                }
                other => result.push(other),
            }
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(input)
        }
    }

    fn name(&self) -> &'static str {
        "escapeSeqDecode"
    }
}

/// SHA-256 hash transformation.
pub struct Sha256;

impl Transformation for Sha256 {
    fn transform_bytes<'a>(&self, input: &'a [u8]) -> crate::Result<Cow<'a, [u8]>> {
        super::bytes::apply(self, input)
    }

    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use sha2::{Digest, Sha256 as Sha256Hasher};
        let mut hasher = Sha256Hasher::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        Cow::Owned(hex::encode(result))
    }

    fn name(&self) -> &'static str {
        "sha256"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lowercase() {
        let t = Lowercase;
        assert_eq!(t.transform("Hello World"), "hello world");
        assert_eq!(t.transform("already lower"), "already lower");
    }

    #[test]
    fn test_compress_whitespace() {
        let t = CompressWhitespace;
        assert_eq!(t.transform("hello   world"), "hello world");
        assert_eq!(t.transform("a\t\nb"), "a b");
    }

    #[test]
    fn test_remove_whitespace() {
        let t = RemoveWhitespace;
        assert_eq!(t.transform("hello world"), "helloworld");
    }

    #[test]
    fn test_normalize_path() {
        let t = NormalizePath;
        assert_eq!(t.transform("/a/b/../c"), "/a/c");
        assert_eq!(t.transform("/a//b/./c"), "/a/b/c");
        assert_eq!(t.transform(r"a\b\c"), r"a\b\c");
    }

    #[test]
    fn path_cleaning_preserves_relative_parents_and_trailing_separators() {
        for (input, expected) in [
            ("../blue", "../blue"),
            ("../../a/../blue/", "../../blue/"),
            ("/../blue", "/blue"),
            ("a/../", ""),
            ("/", "//"),
        ] {
            for transform in [&NormalizePath as &dyn Transformation, &NormalizePathWin] {
                assert_eq!(transform.transform(input), expected);
                assert_eq!(
                    transform
                        .transform_bytes(input.as_bytes())
                        .unwrap()
                        .as_ref(),
                    expected.as_bytes()
                );
            }
        }
        assert_eq!(
            NormalizePathWin
                .transform_bytes(b"..\\a\\..\\b\xff")
                .unwrap()
                .as_ref(),
            b"../b\xff"
        );
    }

    #[test]
    fn normalize_path_win_uses_forward_slashes_for_crs_lfi_targets() {
        let t = NormalizePathWin;
        for (input, expected) in [
            ("/.git/config", "/.git/config"),
            ("/sys/class/net", "/sys/class/net"),
            ("/etc/subuid", "/etc/subuid"),
            (r"C:\temp\..\Windows\win.ini", "C:/Windows/win.ini"),
            (r"a\b/c", "a/b/c"),
        ] {
            assert_eq!(t.transform(input), expected, "input: {input}");
        }
    }

    #[test]
    fn utf8_to_unicode_encodes_non_ascii_for_crs_xss_chain() {
        let t = Utf8ToUnicode;
        assert_eq!(t.transform("＜script＞"), "%uff1cscript%uff1e");
        assert_eq!(t.transform("ĤéllŌ"), "%u0124%u00e9ll%u014c");
        assert_eq!(t.transform("hello 🍺"), "hello %u1f37a");
        assert!(matches!(t.transform("plain ASCII%20\0"), Cow::Borrowed(_)));
    }

    #[test]
    fn test_cmdline() {
        let t = CmdLine;
        // Caret is the Windows escape character - it is simply removed.
        assert_eq!(t.transform("echo^hello"), "echohello");
        // Backslashes and quotes are deleted, not replaced.
        assert_eq!(t.transform(r"c:\\windows\\system32"), "c:windowssystem32");
        assert_eq!(t.transform("\"cat\" '/etc/passwd'"), "cat/etc/passwd");
        // Commas and semicolons become a space; runs collapse to one.
        assert_eq!(t.transform("DIR,,,X"), "dir x");
        assert_eq!(t.transform("a \t\n b"), "a b");
        // A space before `/` or `(` is deleted -- this is what CRS regexes are
        // written against, e.g. 932140 matching `in\(`.
        assert_eq!(t.transform("CMD;/C"), "cmd/c");
        assert_eq!(t.transform("CMD,/C;DIR"), "cmd/c dir");
        assert_eq!(
            t.transform("for %v in (set) do cmd"),
            "for %v in(set) do cmd"
        );
        assert_eq!(t.transform("cat /etc/passwd"), "cat/etc/passwd");
        // Nothing to change: borrowed, not reallocated.
        assert!(matches!(t.transform("already normal"), Cow::Borrowed(_)));
    }
}
