//! Regular expressions that select collection keys: `ARGS:/^user/` in a rule's
//! targets, `!REQUEST_COOKIES:/__utm/` in its exclusions, and the targets of
//! `ctl:ruleRemoveTargetById` / `ctl:ruleRemoveTargetByTag`.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};

/// A compiled expression, or `None` for one that does not compile.
type Compiled = Option<Arc<regex::bytes::Regex>>;

/// A key selection's regular expression, compiled when the rule text is read.
///
/// ModSecurity v3 compiles these with PCRE's caseless flag and without its UTF
/// flag (`VariableRegex`, `KeyExclusionRegex`): a key is matched as bytes, and
/// only ASCII letters fold. So `!ARGS:/^session/` leaves `SESSION` and not
/// `ſession` (U+017F, which Unicode folds to `s`), and `.` is one byte of a
/// key's UTF-8, as in PCRE without UTF.
///
/// It is compiled once, and one compiled program serves every rule and every
/// thread that names the same expression: clones share it through an `Arc`.
/// Cloning a `regex` `Regex` itself would not do: a clone shares the program
/// but starts an empty cache pool, so the first match on each clone allocates
/// the matcher's scratch space afresh. Looked up and cloned once per resolved
/// value, as `cached_regex` did, that was paid for every cookie by each CRS rule
/// excluding `!REQUEST_COOKIES:/__utm/`, and for every argument a regex
/// exclusion was checked against.
#[derive(Clone)]
pub struct KeyRegex {
    source: Arc<str>,
    /// `None` when the expression does not compile: it then matches nothing,
    /// which is how an invalid selection has always behaved.
    compiled: Compiled,
}

impl KeyRegex {
    /// The expression `source` (without its slashes), compiled, or the copy
    /// already compiled for an earlier rule naming the same one.
    pub fn new(source: &str) -> Self {
        static COMPILED: LazyLock<RwLock<HashMap<Arc<str>, Compiled>>> =
            LazyLock::new(Default::default);
        if let Some((source, compiled)) = COMPILED
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get_key_value(source)
        {
            return Self {
                source: source.clone(),
                compiled: compiled.clone(),
            };
        }
        let compiled = regex::bytes::RegexBuilder::new(source)
            .case_insensitive(true)
            .unicode(false)
            .build()
            .ok()
            .map(Arc::new);
        let source: Arc<str> = Arc::from(source);
        COMPILED
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .entry(source.clone())
            .or_insert_with(|| compiled.clone());
        Self { source, compiled }
    }

    /// The expression as the rule wrote it, without its slashes.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Whether the expression finds `key`, read as its UTF-8 bytes.
    pub fn is_match(&self, key: &str) -> bool {
        self.compiled
            .as_ref()
            .is_some_and(|re| re.is_match(key.as_bytes()))
    }
}

impl std::fmt::Debug for KeyRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "/{}/", self.source)
    }
}

impl PartialEq for KeyRegex {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

#[cfg(test)]
mod tests {
    use super::KeyRegex;

    #[test]
    fn ascii_letters_fold_and_nothing_else_does() {
        let re = KeyRegex::new("^session");
        assert!(re.is_match("session_id"));
        assert!(re.is_match("SESSION_ID"));
        // U+017F folds to `s` under Unicode rules; PCRE without UTF does not fold it
        assert!(!re.is_match("\u{17f}ession_id"));
        let re = KeyRegex::new("^STRASSE$");
        assert!(!re.is_match("stra\u{df}e"));
    }

    #[test]
    fn keys_are_matched_as_bytes() {
        // A UTF-8 character is the bytes that encode it, as PCRE without UTF reads it
        assert!(KeyRegex::new("^.{2}$").is_match("\u{e9}"));
        assert!(
            !KeyRegex::new(r"^\w+$").is_match("caf\u{e9}"),
            "\\w is ASCII"
        );
        assert!(KeyRegex::new(r"^caf\xc3\xa9$").is_match("caf\u{e9}"));
    }

    #[test]
    fn one_expression_is_compiled_once_and_an_invalid_one_matches_nothing() {
        let a = KeyRegex::new(r"^user_\d+$");
        let b = KeyRegex::new(r"^user_\d+$");
        assert!(a.is_match("user_42") && b.is_match("USER_42"));
        assert!(std::sync::Arc::ptr_eq(
            a.compiled.as_ref().unwrap(),
            b.compiled.as_ref().unwrap()
        ));
        let bad = KeyRegex::new("(unclosed");
        assert!(!bad.is_match("(unclosed") && !bad.is_match(""));
        assert_eq!(bad.as_str(), "(unclosed");
    }
}
