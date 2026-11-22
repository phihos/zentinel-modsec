//! Normalization transformations.

use super::Transformation;
use std::borrow::Cow;

/// Whether an ASCII byte is whitespace for `char::is_whitespace`, which the
/// whitespace transformations use: tab, LF, VT, FF, CR and space.
fn is_ascii_whitespace_char(b: u8) -> bool {
    matches!(b, b'\t'..=b'\r' | b' ')
}

/// Whether two adjacent bytes of `input` are `pair`. A plain scan: the values
/// are short, and `str::contains` first builds a searcher for the pattern.
fn contains_pair(input: &str, pair: &[u8; 2]) -> bool {
    input.as_bytes().windows(2).any(|w| w == pair)
}

/// Lowercase transformation.
pub struct Lowercase;

impl Transformation for Lowercase {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let lower = input.to_lowercase();
        if lower == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(lower)
        }
    }

    // ASCII lowercases byte for byte, and only `A-Z` change. Text with
    // anything else in it goes through `to_lowercase`.
    fn leaves_unchanged(&self, input: &str) -> bool {
        input
            .bytes()
            .all(|b| b.is_ascii() && !b.is_ascii_uppercase())
    }

    fn name(&self) -> &'static str {
        "lowercase"
    }
}

/// Uppercase transformation.
pub struct Uppercase;

impl Transformation for Uppercase {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let upper = input.to_uppercase();
        if upper == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(upper)
        }
    }

    // As for `lowercase`: in ASCII text only `a-z` change.
    fn leaves_unchanged(&self, input: &str) -> bool {
        input
            .bytes()
            .all(|b| b.is_ascii() && !b.is_ascii_lowercase())
    }

    fn name(&self) -> &'static str {
        "uppercase"
    }
}

/// Compress whitespace transformation.
pub struct CompressWhitespace;

impl Transformation for CompressWhitespace {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut last_was_space = false;
        let mut modified = false;

        for c in input.chars() {
            if c.is_whitespace() {
                if !last_was_space {
                    result.push(' ');
                } else {
                    modified = true;
                }
                last_was_space = true;
            } else {
                result.push(c);
                last_was_space = false;
            }
        }

        if modified || result.chars().any(|c| c.is_whitespace() && c != ' ') {
            Cow::Owned(result)
        } else if result == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(result)
        }
    }

    // In ASCII text the result differs only where there is whitespace other
    // than a space, or a space after a space.
    fn leaves_unchanged(&self, input: &str) -> bool {
        let mut after_space = false;
        input.bytes().all(|b| {
            let keeps =
                (b.is_ascii() && !is_ascii_whitespace_char(b)) || (b == b' ' && !after_space);
            after_space = b == b' ';
            keeps
        })
    }

    fn name(&self) -> &'static str {
        "compressWhitespace"
    }
}

/// Remove whitespace transformation.
pub struct RemoveWhitespace;

impl Transformation for RemoveWhitespace {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let result: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        if result == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(result)
        }
    }

    // ASCII text without whitespace has nothing to remove.
    fn leaves_unchanged(&self, input: &str) -> bool {
        input
            .bytes()
            .all(|b| b.is_ascii() && !is_ascii_whitespace_char(b))
    }

    fn name(&self) -> &'static str {
        "removeWhitespace"
    }
}

/// Remove null bytes transformation.
pub struct RemoveNulls;

impl Transformation for RemoveNulls {
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

/// libmodsecurity v3's `normalize_path_inplace` (`normalise_path.cc`,
/// Apache-2.0, Copyright (c) 2015 - 2021 Trustwave Holdings, Inc.), ported
/// step for step on bytes: empty segments and self-references dropped, a
/// back-reference removes the segment before it, a relative path keeps the
/// back-references it cannot resolve (`../.history` stays), and with `win`
/// a backslash is a separator. Returns v3's `changed`, which a path ending on
/// a back-reference leaves unset though the value changed (`/a/b/..` is
/// `/a`): v3 resizes the value whatever it says, as [`normalize_path`] does.
fn normalize_path_inplace(val: &mut Vec<u8>, win: bool) -> bool {
    enum Step {
        Normalize,
        Copy,
        SkipCopy,
    }
    if val.is_empty() {
        return false;
    }
    let mut changed = false;
    let end = val.len() - 1;
    let relative = !(val[0] == b'/' || (win && val[0] == b'\\'));
    let trailing = val[end] == b'/' || (win && val[end] == b'\\');
    let (mut src, mut dst) = (0usize, 0usize);
    let (mut hitroot, mut done) = (false, false);

    while !done && src <= end && dst <= end {
        // Convert backslash to forward slash on Windows only
        if win {
            if val[src] == b'\\' {
                val[src] = b'/';
                changed = true;
            }
            if src < end && val[src + 1] == b'\\' {
                val[src + 1] = b'/';
                changed = true;
            }
        }
        // Always normalize at the end of the input; skip normalization if
        // this is not the end of the path segment
        let mut step = Step::Normalize;
        if src == end {
            done = true;
        } else if val[src + 1] != b'/' {
            step = Step::Copy;
        }
        if let Step::Normalize = step {
            step = Step::Copy;
            if src != end && val[src] == b'/' {
                // An empty path segment: the copy takes care of it
                changed = true;
            } else if val[src] == b'.' {
                if dst > 0 && val[dst - 1] == b'.' {
                    // A back-reference. In a relative path that has hit the
                    // root, or with no segment before it, it is kept.
                    if relative && (hitroot || dst <= 2) {
                        hitroot = true;
                    } else {
                        // Remove it and the segment before, not above the root
                        let mut d = dst as isize - 3;
                        while d > 0 && val[d as usize] != b'/' {
                            d -= 1;
                        }
                        if d <= 0 {
                            hitroot = true;
                            d = 0;
                            // Leave the root slash of an absolute path that
                            // ended on a back-reference
                            if !relative && src == end {
                                d += 1;
                            }
                        }
                        dst = d as usize;
                        if done {
                            step = Step::SkipCopy;
                        } else {
                            src += 1;
                            changed = true;
                        }
                    }
                } else if dst == 0 {
                    // A relative self-reference: ignored
                    changed = true;
                    if done {
                        step = Step::SkipCopy;
                    } else {
                        src += 1;
                    }
                } else if val[dst - 1] == b'/' {
                    // A self-reference: ignored
                    changed = true;
                    if done {
                        step = Step::SkipCopy;
                    } else {
                        dst -= 1;
                        src += 1;
                    }
                }
            } else if dst > 0 {
                // A regular path segment
                hitroot = false;
            }
        }
        if let Step::Copy = step {
            // Skip to the last of several separators
            if val[src] == b'/' {
                let old = src;
                while src < end && (val[src + 1] == b'/' || (win && val[src + 1] == b'\\')) {
                    src += 1;
                }
                if old != src {
                    changed = true;
                }
                // A relative path does not gain a root slash
                if relative && dst == 0 {
                    src += 1;
                    continue;
                }
            }
            val[dst] = val[src];
            dst += 1;
            src += 1;
        }
    }
    // No trailing slash the original did not have
    if !trailing && dst > 0 && val[dst - 1] == b'/' {
        dst -= 1;
    }
    val.truncate(dst);
    changed
}

fn normalize_path(input: &str, win: bool) -> Cow<'_, str> {
    let mut bytes = input.as_bytes().to_vec();
    // The value as v3 leaves it, whatever its `changed` says: a path ending
    // on a back-reference is normalized without setting it
    normalize_path_inplace(&mut bytes, win);
    if bytes == input.as_bytes() {
        Cow::Borrowed(input)
    } else {
        // Whole segments and ASCII separators are removed, never part of a
        // character, so the bytes stay the text they were
        Cow::Owned(
            String::from_utf8(bytes)
                .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
        )
    }
}

/// Normalize path transformation (Unix-style): `t:normalizePath`.
pub struct NormalizePath;

impl Transformation for NormalizePath {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        normalize_path(input, false)
    }

    // `normalize_path_inplace` changes a value only at a repeated separator
    // or at a `.` that ends a segment: a self-reference (`.`, `/./`), or a
    // back-reference, which v3 recognizes by the `.` before it alone, so
    // `ab../cd` is `cd` as surely as `a/../cd`. A backslash is a separator
    // for `normalizePathWin`. Without those, nothing can change.
    fn leaves_unchanged(&self, input: &str) -> bool {
        !input.as_bytes().contains(&b'\\')
            && !contains_pair(input, b"//")
            && input.split('/').all(|part| !part.ends_with('.'))
    }

    fn name(&self) -> &'static str {
        "normalizePath"
    }
}

/// Normalize path transformation (Windows-style, a backslash is a
/// separator): `t:normalizePathWin`.
pub struct NormalizePathWin;

impl Transformation for NormalizePathWin {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        normalize_path(input, true)
    }

    fn leaves_unchanged(&self, input: &str) -> bool {
        NormalizePath.leaves_unchanged(input)
    }

    fn name(&self) -> &'static str {
        "normalizePathWin"
    }
}

/// Remove comments transformation.
pub struct RemoveComments;

impl Transformation for RemoveComments {
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

    // A comment opens with `/*`; without one every character is copied.
    fn leaves_unchanged(&self, input: &str) -> bool {
        !contains_pair(input, b"/*")
    }

    fn name(&self) -> &'static str {
        "removeComments"
    }
}

/// Replace comments transformation (replaces /* ... */ with space).
pub struct ReplaceComments;

impl Transformation for ReplaceComments {
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

    // A comment opens with `/*`; without one every character is copied.
    fn leaves_unchanged(&self, input: &str) -> bool {
        !contains_pair(input, b"/*")
    }

    fn name(&self) -> &'static str {
        "replaceComments"
    }
}

/// Remove comment characters transformation.
pub struct RemoveCommentsChar;

impl Transformation for RemoveCommentsChar {
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

    // None of the four replaced patterns occurs.
    fn leaves_unchanged(&self, input: &str) -> bool {
        !input.as_bytes().contains(&b'#')
            && !contains_pair(input, b"/*")
            && !contains_pair(input, b"*/")
            && !contains_pair(input, b"--")
    }

    fn name(&self) -> &'static str {
        "removeCommentsChar"
    }
}

/// SQL hex decode transformation.
pub struct SqlHexDecode;

impl Transformation for SqlHexDecode {
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

    // Decoding starts at `0x`; without one every character is copied.
    fn leaves_unchanged(&self, input: &str) -> bool {
        !contains_pair(input, b"0x")
    }

    fn name(&self) -> &'static str {
        "sqlHexDecode"
    }
}

/// Serialize non-ASCII code points as IIS-style %u escapes.
pub struct Utf8ToUnicode;

impl Transformation for Utf8ToUnicode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
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

    // The four steps of `transform`, as a test for ASCII text that none of
    // them touches: no deleted character, no separator or whitespace other
    // than a single space, no space before `/` or `(`, no uppercase letter.
    fn leaves_unchanged(&self, input: &str) -> bool {
        let mut after_space = false;
        input.bytes().all(|b| {
            let keeps = match b {
                b'\\' | b'"' | b'\'' | b'^' | b',' | b';' => false,
                b' ' | b'/' | b'(' => !after_space,
                _ => b.is_ascii() && !is_ascii_whitespace_char(b) && !b.is_ascii_uppercase(),
            };
            after_space = b == b' ';
            keeps
        })
    }

    fn name(&self) -> &'static str {
        "cmdLine"
    }
}

/// Escape sequence decode transformation.
pub struct EscapeSeqDecode;

/// libmodsecurity v3's `ansi_c_sequences_decode_inplace`
/// (`escape_seq_decode.cc`, Apache-2.0, Copyright (c) 2015 - 2021 Trustwave
/// Holdings, Inc.), ported on bytes: `\\a \\b \\f \\n \\r \\t \\v \\\\ \\? \\' \\"`,
/// `\\xHH` and up to three octal digits; any other escaped byte is that byte,
/// its backslash dropped; a lone trailing backslash stays.
impl Transformation for EscapeSeqDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if !input.contains('\\') {
            return Cow::Borrowed(input);
        }
        let b = input.as_bytes();
        let len = b.len();
        let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
        let oct = |c: u8| (b'0'..=b'7').contains(&c);
        let mut out = Vec::with_capacity(len);
        let mut i = 0;
        while i < len {
            if b[i] != b'\\' || i + 1 >= len {
                out.push(b[i]);
                i += 1;
                continue;
            }
            let simple = match b[i + 1] {
                b'a' => Some(0x07),
                b'b' => Some(0x08),
                b'f' => Some(0x0c),
                b'n' => Some(b'\n'),
                b'r' => Some(b'\r'),
                b't' => Some(b'\t'),
                b'v' => Some(0x0b),
                b'\\' => Some(b'\\'),
                b'?' => Some(b'?'),
                b'\'' => Some(b'\''),
                b'"' => Some(b'"'),
                _ => None,
            };
            if let Some(c) = simple {
                out.push(c);
                i += 2;
                continue;
            }
            if b[i + 1] == b'x' || b[i + 1] == b'X' {
                if i + 3 < len {
                    if let (Some(h), Some(l)) = (hex(b[i + 2]), hex(b[i + 3])) {
                        out.push(h * 16 + l);
                        i += 4;
                        continue;
                    }
                }
            } else if oct(b[i + 1]) {
                let mut j = 0;
                let mut value: u32 = 0;
                while i + 1 + j < len && j < 3 {
                    value = value * 8 + u32::from(b[i + 1 + j] - b'0');
                    j += 1;
                    if i + 1 + j >= len || !oct(b[i + 1 + j]) {
                        break;
                    }
                }
                out.push(value as u8);
                i += 1 + j;
                continue;
            }
            // Not an encoding: the byte, without its backslash
            out.push(b[i + 1]);
            i += 2;
        }
        // A decoded byte that is not UTF-8 (`\xff`) is U+FFFD, as this crate's
        // other decoders write it
        Cow::Owned(String::from_utf8_lossy(&out).into_owned())
    }

    // Every character but `\` is copied.
    fn leaves_unchanged(&self, input: &str) -> bool {
        !input.as_bytes().contains(&b'\\')
    }

    fn name(&self) -> &'static str {
        "escapeSeqDecode"
    }
}

/// SHA-256 hash transformation.
pub struct Sha256;

impl Transformation for Sha256 {
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

    /// libmodsecurity v3's normalize_path_inplace, as ported
    #[test]
    fn paths_normalize_as_modsecurity() {
        let n = |s| NormalizePath.transform(s).into_owned();
        let w = |s| NormalizePathWin.transform(s).into_owned();
        assert_eq!(n("/a/b/../c"), "/a/c");
        assert_eq!(n("/a/./b"), "/a/b");
        assert_eq!(n("/a//b"), "/a/b");
        assert_eq!(n("/../x"), "/x", "not above the root");
        assert_eq!(
            n("../.history"),
            "../.history",
            "a relative back-reference stays"
        );
        assert_eq!(n("a\\..\\b"), "a\\..\\b", "a backslash is not a separator");
        assert_eq!(w("a\\..\\b"), "b");
        assert_eq!(w("..\\pineapple"), "../pineapple");
        assert_eq!(n("/a/b/"), "/a/b/", "a trailing slash kept");
        // Ending on a back-reference: v3 leaves `changed` unset but resizes
        // the value, so the segment before is removed all the same. Its root
        // slash is kept and then trimmed as a trailing slash the input did
        // not have, so `/foo/..` is empty (v3's own function gives the same)
        assert_eq!(n("/a/b/.."), "/a");
        assert_eq!(n("/foo/.."), "");
        assert_eq!(n("a/.."), "");
        // v3 recognizes a back-reference by the `.` before it alone
        assert_eq!(n("ab../cd"), "cd");
        assert_eq!(n("/x/ab../cd"), "/x/cd");
        assert!(!NormalizePath.leaves_unchanged("ab../cd"));
        assert!(NormalizePath.leaves_unchanged("/a/file.txt/b"));
        let mut ends_on_back_reference = b"/a/b/..".to_vec();
        assert!(!normalize_path_inplace(&mut ends_on_back_reference, false));
        assert_eq!(ends_on_back_reference, b"/a");
    }

    /// libmodsecurity v3's ansi_c_sequences_decode_inplace, as ported
    #[test]
    fn escape_sequences_decode_as_modsecurity() {
        let d = |s| EscapeSeqDecode.transform(s).into_owned();
        assert_eq!(d(r#"1;.\"shell"#), r#"1;."shell"#);
        assert_eq!(d(r"1;.\'shell"), "1;.'shell");
        assert_eq!(d(r"\a\b\f\n\r\t\v\\\?"), "\u{7}\u{8}\u{c}\n\r\t\u{b}\\?");
        assert_eq!(d(r"\x41\101\0"), "AA\0");
        assert_eq!(
            d(r"\q\xZZ"),
            "qxZZ",
            "not an encoding: the byte, no backslash"
        );
        assert_eq!(d("tail\\"), "tail\\", "a lone trailing backslash stays");
    }
    use super::*;

    #[test]
    fn utf8_to_unicode_encodes_non_ascii_code_points() {
        let t = Utf8ToUnicode;
        assert_eq!(t.transform("École Ａ 🍺"), "%u00c9cole %uff21 %u1f37a");
        assert!(matches!(t.transform("ASCII%20\0"), Cow::Borrowed(_)));
    }

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
        // A backslash is a separator for normalizePathWin alone, as in
        // ModSecurity
        assert_eq!(t.transform("a\\b\\c"), "a\\b\\c");
        assert_eq!(NormalizePathWin.transform("a\\b\\c"), "a/b/c");
    }

    #[test]
    fn normalize_path_win_uses_forward_slashes() {
        let t = NormalizePathWin;
        assert_eq!(t.transform("/var/log"), "/var/log");
        assert_eq!(t.transform(r"C:\temp\..\docs/file"), "C:/docs/file");
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
