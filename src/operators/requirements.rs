//! What every match of a regular expression needs, read off its syntax.
//!
//! Most values a rule tests cannot match its pattern, and many of them show
//! it at a glance: `abc` is too short for `^[a-z]{8,}$`, `user42` holds no
//! `<` for `<script`, and no run of letters satisfies `\.\./`. Checking that
//! first costs a length comparison or one pass over a short value and saves
//! the regex search.
//!
//! Every requirement is a necessary condition: it may fail to rule a value
//! out, but a value it rules out has no match. Where the syntax gives no
//! clear answer the requirement is left empty.

use regex_syntax::hir::{Class, Hir, HirKind};

/// Values longer than this are not scanned for their alphabet.
const ALPHABET_SCAN_LIMIT: usize = 64;

/// Values longer than this are not searched for the required byte.
const BYTE_SEARCH_LIMIT: usize = 128;

/// How deep the analysis follows nested groups before it settles for what
/// the parser already knows about the rest.
const DEPTH_LIMIT: usize = 32;

/// A letter, a digit, or the punctuation of names and paths: `-./:_`.
pub(crate) fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'/' | b':' | b'_')
}

fn is_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

/// Necessary conditions for a value to match a pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MatchRequirements {
    /// The shortest match, in bytes.
    len: usize,
    /// The shortest match made only of token bytes; `usize::MAX` if none is.
    token_len: usize,
    /// The shortest match made only of letters and digits.
    alphanumeric_len: usize,
    /// A byte every match contains.
    byte: Option<u8>,
}

impl MatchRequirements {
    /// The shortest match made only of token bytes, and only of letters and
    /// digits: what a value of such bytes has to be as long as.
    pub(crate) fn widths(&self) -> (usize, usize) {
        (self.token_len, self.alphanumeric_len)
    }

    pub(super) fn of(pattern: &Hir) -> Self {
        Self {
            len: pattern.properties().minimum_len().unwrap_or(0),
            token_len: shortest_within(pattern, is_token, DEPTH_LIMIT).unwrap_or(usize::MAX),
            alphanumeric_len: shortest_within(pattern, is_alphanumeric, DEPTH_LIMIT)
                .unwrap_or(usize::MAX),
            byte: required_byte(pattern, DEPTH_LIMIT),
        }
    }

    /// Whether `value` cannot match.
    ///
    /// A match is a piece of the value, so it is no longer than the value and
    /// made of the value's bytes: a value of token bytes only matches with a
    /// match of token bytes, and holds every byte its match does.
    #[inline]
    pub(super) fn rule_out(&self, value: &[u8]) -> bool {
        let len = value.len();
        if len < self.len {
            return true;
        }
        if len <= ALPHABET_SCAN_LIMIT
            && (len < self.token_len && value.iter().copied().all(is_token)
                || len < self.alphanumeric_len && value.iter().copied().all(is_alphanumeric))
        {
            return true;
        }
        len <= BYTE_SEARCH_LIMIT
            && self
                .byte
                .is_some_and(|byte| memchr::memchr(byte, value).is_none())
    }
}

/// Whether a class with the code points `first..=last` admits a byte of the
/// alphabet. Alphabets are ASCII, where a code point is its own byte.
fn admits(alphabet: fn(u8) -> bool, first: u32, last: u32) -> bool {
    (first..=last.min(0x7F)).any(|point| alphabet(point as u8))
}

/// The length of the shortest match made only of bytes of `alphabet`, or
/// `None` if no match is. Assertions are taken to hold, which can only make
/// the answer shorter.
fn shortest_within(hir: &Hir, alphabet: fn(u8) -> bool, depth: usize) -> Option<usize> {
    if depth == 0 {
        // The shortest match of all is no longer than the shortest of these.
        return Some(hir.properties().minimum_len().unwrap_or(0));
    }
    let shortest = |part: &Hir| shortest_within(part, alphabet, depth - 1);
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(0),
        HirKind::Literal(literal) => literal
            .0
            .iter()
            .copied()
            .all(alphabet)
            .then_some(literal.0.len()),
        HirKind::Class(Class::Unicode(class)) => class
            .iter()
            .any(|range| admits(alphabet, range.start().into(), range.end().into()))
            .then_some(1),
        HirKind::Class(Class::Bytes(class)) => class
            .iter()
            .any(|range| admits(alphabet, range.start().into(), range.end().into()))
            .then_some(1),
        HirKind::Capture(capture) => shortest(&capture.sub),
        HirKind::Repetition(repetition) if repetition.min == 0 => Some(0),
        HirKind::Repetition(repetition) => {
            let count = usize::try_from(repetition.min).unwrap_or(usize::MAX);
            shortest(&repetition.sub).map(|len| len.saturating_mul(count))
        }
        HirKind::Concat(parts) => parts.iter().try_fold(0usize, |total, part| {
            shortest(part).map(|len| total.saturating_add(len))
        }),
        HirKind::Alternation(branches) => branches.iter().filter_map(shortest).min(),
    }
}

/// A byte every match contains, preferring one that is no letter or digit
/// because fewer values hold it.
///
/// A literal needs each of its bytes, a concatenation what any part needs, a
/// repetition what its content needs if it runs at least once, and an
/// alternation only a byte all of its branches need.
fn required_byte(hir: &Hir, depth: usize) -> Option<u8> {
    if depth == 0 {
        return None;
    }
    let required = |part: &Hir| required_byte(part, depth - 1);
    let rarest = |bytes: &mut dyn Iterator<Item = u8>| bytes.min_by_key(u8::is_ascii_alphanumeric);
    match hir.kind() {
        HirKind::Literal(literal) => rarest(&mut literal.0.iter().copied()),
        HirKind::Capture(capture) => required(&capture.sub),
        HirKind::Repetition(repetition) if repetition.min > 0 => required(&repetition.sub),
        HirKind::Concat(parts) => rarest(&mut parts.iter().filter_map(required)),
        HirKind::Alternation(branches) => {
            let mut needs = branches.iter().map(required);
            let first = needs.next()??;
            needs.all(|next| next == Some(first)).then_some(first)
        }
        HirKind::Empty | HirKind::Look(_) | HirKind::Class(_) | HirKind::Repetition(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(pattern: &str) -> MatchRequirements {
        let hir = regex_syntax::Parser::new()
            .parse(pattern)
            .expect("pattern parses");
        MatchRequirements::of(&hir)
    }

    fn requirements(
        len: usize,
        token_len: usize,
        alphanumeric_len: usize,
        byte: Option<u8>,
    ) -> MatchRequirements {
        MatchRequirements {
            len,
            token_len,
            alphanumeric_len,
            byte,
        }
    }

    const NEVER: usize = usize::MAX;

    #[test]
    fn a_literal_needs_its_length_and_its_bytes() {
        assert_eq!(of("select"), requirements(6, 6, 6, Some(b's')));
        assert_eq!(of("<script"), requirements(7, NEVER, NEVER, Some(b'<')));
        assert_eq!(of(r"\.\./"), requirements(3, 3, NEVER, Some(b'.')));
        assert_eq!(of("a b"), requirements(3, NEVER, NEVER, Some(b' ')));
    }

    #[test]
    fn a_pattern_that_matches_the_empty_string_needs_nothing() {
        for pattern in ["(?:)", "a*", "^$", "(?:a|)", r"\b", "(a)?(b)?", "x{0,3}"] {
            assert_eq!(of(pattern), requirements(0, 0, 0, None), "{pattern}");
        }
    }

    #[test]
    fn an_alternation_needs_what_its_shortest_branch_does() {
        assert_eq!(of("GET|HEAD"), requirements(3, 3, 3, None));
        assert_eq!(of("a-b|<"), requirements(1, 3, NEVER, None));
        // Each branch needs the same byte.
        assert_eq!(of("a=1|b=22"), requirements(3, NEVER, NEVER, Some(b'=')));
        // The branches share no byte, and the parser may factor a common
        // prefix out of them.
        assert_eq!(of("foo:x|foo:y").byte, Some(b':'));
        assert_eq!(of("x:|y;").byte, None);
    }

    #[test]
    fn an_optional_part_adds_nothing() {
        assert_eq!(of("ab(?:<c)?"), requirements(2, 2, 2, Some(b'a')));
        assert_eq!(of("ab(?:<c)*d"), requirements(3, 3, 3, Some(b'a')));
        assert_eq!(of("(?:<c)+"), requirements(2, NEVER, NEVER, Some(b'<')));
        assert_eq!(of("a{3}-{2,}"), requirements(5, 5, NEVER, Some(b'-')));
    }

    #[test]
    fn a_class_counts_one_byte_of_any_alphabet_it_admits() {
        assert_eq!(of("[a-z]{8,}"), requirements(8, 8, 8, None));
        assert_eq!(of(r"\d+"), requirements(1, 1, 1, None));
        assert_eq!(of("[<>]x"), requirements(2, NEVER, NEVER, Some(b'x')));
        assert_eq!(of("[/.]x"), requirements(2, 2, NEVER, Some(b'x')));
        assert_eq!(of("[^a-z]"), requirements(1, 1, 1, None));
        assert_eq!(of("[^!-~]"), requirements(1, NEVER, NEVER, None));
        assert_eq!(of("."), requirements(1, 1, 1, None));
        assert_eq!(of(r"\s"), requirements(1, NEVER, NEVER, None));
        assert_eq!(of(r"(?-u:\w)"), requirements(1, 1, 1, None));
    }

    #[test]
    fn a_case_insensitive_literal_is_a_class_and_needs_no_byte() {
        assert_eq!(of("(?i)select"), requirements(6, 6, 6, None));
        assert_eq!(of("(?i)<script"), requirements(7, NEVER, NEVER, Some(b'<')));
        // `k` also matches the Kelvin sign, three bytes that are no token.
        assert_eq!(of("(?i)k"), requirements(1, 1, 1, None));
    }

    #[test]
    fn text_outside_ascii_is_in_no_alphabet() {
        assert_eq!(of("é"), requirements(2, NEVER, NEVER, Some(0xC3)));
        assert_eq!(of(r"\p{Greek}+"), requirements(2, NEVER, NEVER, None));
        assert_eq!(of("[a-zé]"), requirements(1, 1, 1, None));
    }

    #[test]
    fn assertions_are_taken_to_hold() {
        assert_eq!(of(r"^\d+$"), requirements(1, 1, 1, None));
        assert_eq!(of(r"\bor\b"), requirements(2, 2, 2, Some(b'o')));
        assert_eq!(of(r"(?m)^end$"), requirements(3, 3, 3, Some(b'e')));
    }

    #[test]
    fn nesting_past_the_limit_falls_back_to_the_shortest_match() {
        let nested = format!("{}deep<{}", "(?:".repeat(40), ")+".repeat(40));
        assert_eq!(of(&nested), requirements(5, 5, 5, None));
    }

    #[test]
    fn a_value_is_ruled_out_only_within_the_limits() {
        let script = of("<script");
        assert!(script.rule_out(b"<scrip"), "shorter than any match");
        assert!(script.rule_out(b"user42"), "shorter than any match");
        assert!(script.rule_out(b"a/b.c-d_e:f"), "token bytes only");
        assert!(script.rule_out(b"hello world"), "no `<`");
        assert!(!script.rule_out(b"<script"));
        assert!(!script.rule_out(b"hello <b>"));

        let tokens = "a".repeat(ALPHABET_SCAN_LIMIT + 1);
        assert!(script.rule_out(tokens.as_bytes()), "no `<`");
        let long = "a".repeat(BYTE_SEARCH_LIMIT + 1);
        assert!(!script.rule_out(long.as_bytes()), "past both limits");

        let traversal = of(r"\.\./");
        assert!(traversal.rule_out(b"abc"), "letters only");
        assert!(traversal.rule_out(b"a-b"), "no `.`");
        assert!(!traversal.rule_out(b"a.b"));

        let nothing = of("a*");
        assert!(!nothing.rule_out(b""));
        assert!(!nothing.rule_out(b"<"));
    }
}
