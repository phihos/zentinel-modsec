//! TX (transaction) collection.

use super::collection::{Collection, HashMapCollection, MutableCollection};
use super::KeyRegex;
use std::borrow::Cow;

/// Transaction collection for storing intermediate values.
///
/// Keys are **case-insensitive**, as they are in ModSecurity. The OWASP CRS
/// depends on this: it writes `setvar:'tx.blocking_paranoia_level=1'` and reads
/// `TX:BLOCKING_PARANOIA_LEVEL`, and its anomaly scoring never accumulates if
/// those are treated as two different keys. Normalising here rather than at the
/// call sites keeps the guarantee in one place -- every read and write in the
/// engine goes through this type -- and leaves case-sensitive collections such
/// as `ARGS` untouched.
#[derive(Debug, Clone, Default)]
pub struct TxCollection {
    data: HashMapCollection,
}

/// Lowercase a key only when it actually contains uppercase, so the common path
/// (CRS writes and reads lowercase) does not allocate.
fn normalize(key: &str) -> Cow<'_, str> {
    if key.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(key.to_ascii_lowercase())
    } else {
        Cow::Borrowed(key)
    }
}

impl TxCollection {
    /// Create a new TX collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Every `(key, value)` pair in insertion order, read in place. Keys are
    /// the stored, lowercased ones.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.data.iter()
    }

    /// The values stored under `key`, matched case-insensitively. Empty when
    /// the variable is not set.
    pub fn values(&self, key: &str) -> &[String] {
        self.data.values(&normalize(key))
    }

    /// The `(key, value)` pairs whose stored, lowercased key matches
    /// `pattern`, read in place.
    pub fn iter_regex<'a, 'r>(
        &'a self,
        pattern: &'r KeyRegex,
    ) -> impl Iterator<Item = (&'a str, &'a str)> + 'r
    where
        'a: 'r,
    {
        self.data.iter_regex(pattern)
    }
}

impl Collection for TxCollection {
    fn all(&self) -> Vec<(&str, &str)> {
        self.data.all()
    }

    fn get(&self, key: &str) -> Option<Vec<&str>> {
        self.data.get(&normalize(key))
    }

    /// Regex selection (`TX:/^foo/`) matches against the stored, lowercased
    /// key, so a pattern anchored on uppercase will not match.
    fn get_regex(&self, pattern: &KeyRegex) -> Vec<(&str, &str)> {
        self.data.get_regex(pattern)
    }

    fn count(&self) -> usize {
        self.data.count()
    }

    fn count_key(&self, key: &str) -> usize {
        self.data.count_key(&normalize(key))
    }
}

impl MutableCollection for TxCollection {
    fn set(&mut self, key: String, value: String) {
        match normalize(&key) {
            Cow::Borrowed(_) => self.data.set(key, value),
            Cow::Owned(lower) => self.data.set(lower, value),
        }
    }

    fn delete(&mut self, key: &str) {
        self.data.delete(&normalize(key));
    }

    fn increment(&mut self, key: &str, amount: i64) {
        self.data.increment(&normalize(key), amount);
    }

    fn decrement(&mut self, key: &str, amount: i64) {
        self.data.decrement(&normalize(key), amount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TxCollection {
        let mut tx = TxCollection::new();
        tx.set("Score".to_string(), "5".to_string());
        tx.set("blocking_paranoia_level".to_string(), "1".to_string());
        tx
    }

    #[test]
    fn values_match_the_key_case_insensitively_like_get() {
        let tx = sample();
        for key in ["score", "SCORE", "Score"] {
            assert_eq!(tx.values(key), ["5"]);
            assert_eq!(tx.get(key), Some(vec!["5"]));
        }
        assert!(tx.values("missing").is_empty());
        assert_eq!(tx.get("missing"), None);
    }

    #[test]
    fn iter_and_iter_regex_read_the_stored_lowercased_keys() {
        let tx = sample();
        let pairs: Vec<_> = tx.iter().collect();
        assert_eq!(pairs, [("score", "5"), ("blocking_paranoia_level", "1")]);
        assert_eq!(pairs, tx.all());

        let lower = KeyRegex::new("^score$");
        assert_eq!(tx.iter_regex(&lower).collect::<Vec<_>>(), [("score", "5")]);
        assert_eq!(tx.get_regex(&lower), [("score", "5")]);
        // A selection's expression is caseless, as ModSecurity builds it
        let upper = KeyRegex::new("^Score$");
        assert_eq!(tx.iter_regex(&upper).collect::<Vec<_>>(), [("score", "5")]);
        assert_eq!(tx.iter_regex(&KeyRegex::new("^scores$")).count(), 0);
    }
}
