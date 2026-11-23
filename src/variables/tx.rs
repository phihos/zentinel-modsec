//! TX (transaction) collection.

use super::collection::{Collection, HashMapCollection, MutableCollection};
use super::KeyRegex;
use std::borrow::Cow;
use std::sync::Arc;

/// Transaction collection for storing intermediate values.
///
/// Keys are **case-insensitive**, as they are in ModSecurity. The OWASP CRS
/// depends on this: it writes `setvar:'tx.blocking_paranoia_level=1'` and reads
/// `TX:BLOCKING_PARANOIA_LEVEL`, and its anomaly scoring never accumulates if
/// those are treated as two different keys. Normalising here rather than at the
/// call sites keeps the guarantee in one place -- every read and write in the
/// engine goes through this type -- and leaves case-sensitive collections such
/// as `ARGS` untouched.
///
/// A transaction that starts from variables prepared with the ruleset shares
/// them (`shared`) and keeps only what it changes: a variable of its own goes
/// to `data`, a shared one it sets or deletes is noted in `changes`. The
/// shared variables were set first, so they come first in order.
#[derive(Debug, Clone, Default)]
pub struct TxCollection {
    shared: Option<Arc<HashMapCollection>>,
    /// What became of each shared variable, by its position. Shorter than
    /// `shared` while the later ones are unchanged.
    changes: Vec<Change>,
    data: HashMapCollection,
}

/// What a transaction did to a variable it shares.
#[derive(Debug, Clone, Default)]
enum Change {
    #[default]
    Kept,
    Set(Vec<String>),
    /// Deleted. Set again, it is a variable of the transaction's own, at the
    /// end of the order, where a deleted and re-added key goes.
    Deleted,
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
        self.shared = None;
        self.changes.clear();
        self.data.clear();
    }

    /// The variables of this collection, which shares none, for other
    /// collections to share.
    pub(crate) fn into_shared(self) -> Arc<HashMapCollection> {
        debug_assert!(self.shared.is_none());
        Arc::new(self.data)
    }

    /// Start this collection, which is empty, from `shared`.
    pub(crate) fn share(&mut self, shared: &Arc<HashMapCollection>) {
        debug_assert!(self.shared.is_none() && self.data.keys() == 0);
        self.shared = Some(Arc::clone(shared));
    }

    /// The values of the shared variable at `position`, unless it was deleted.
    fn shared_at<'a>(&'a self, position: usize, values: &'a [String]) -> Option<&'a [String]> {
        match self.changes.get(position) {
            None | Some(Change::Kept) => Some(values),
            Some(Change::Set(values)) => Some(values),
            Some(Change::Deleted) => None,
        }
    }

    /// The position of the shared variable `key`, a lowercased key.
    fn shared_position(&self, key: &str) -> Option<usize> {
        self.shared.as_ref()?.position(key)
    }

    /// Every variable with its values, in order.
    fn entries(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.shared
            .iter()
            .flat_map(|shared| shared.entries())
            .enumerate()
            .filter_map(|(position, (key, values))| {
                Some((key, self.shared_at(position, values)?))
            })
            .chain(self.data.entries())
    }

    /// The values of the lowercased `key`.
    fn lowered_values(&self, key: &str) -> &[String] {
        if let Some(shared) = &self.shared {
            if let Some(position) = shared.position(key) {
                let (_, values) = shared.entry_at(position).expect("a position of this map");
                if let Some(values) = self.shared_at(position, values) {
                    return values;
                }
            }
        }
        self.data.values(key)
    }

    /// Every `(key, value)` pair in insertion order, read in place. Keys are
    /// the stored, lowercased ones.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries()
            .flat_map(|(key, values)| values.iter().map(move |v| (key, v.as_str())))
    }

    /// The values stored under `key`, matched case-insensitively. Empty when
    /// the variable is not set.
    pub fn values(&self, key: &str) -> &[String] {
        self.lowered_values(&normalize(key))
    }

    /// The values stored under `key`, which is already lowercased, when the
    /// shared variables hold it at `position` or, for `None`, not at all.
    ///
    /// Only for a collection that shares the variables the position was
    /// taken from, or none.
    pub(crate) fn values_at(&self, key: &str, position: Option<usize>) -> &[String] {
        let Some(shared) = &self.shared else {
            return self.data.values(key);
        };
        if let Some(position) = position {
            match shared.entry_at(position) {
                Some((stored, values)) if stored == key => {
                    if let Some(values) = self.shared_at(position, values) {
                        return values;
                    }
                }
                _ => return self.lowered_values(key),
            }
        }
        self.data.values(key)
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
        self.entries()
            .filter(move |(key, _)| pattern.is_match(key))
            .flat_map(|(key, values)| values.iter().map(move |v| (key, v.as_str())))
    }

    /// Note what became of the shared variable at `position`.
    fn change(&mut self, position: usize, change: Change) {
        if self.changes.len() <= position {
            let all = self.shared.as_ref().map_or(0, |shared| shared.keys());
            self.changes.resize_with(all, Change::default);
        }
        self.changes[position] = change;
    }

    /// Set the lowercased `key`.
    fn set_lowered(&mut self, key: Cow<'_, str>, value: String) {
        if let Some(position) = self.shared_position(&key) {
            if !matches!(self.changes.get(position), Some(Change::Deleted)) {
                self.change(position, Change::Set(vec![value]));
                return;
            }
        }
        self.data.set(key.into_owned(), value);
    }

    /// The first value of a lowercased key as a number, or 0 when it is
    /// missing or not numeric.
    fn numeric(&self, key: &str) -> i64 {
        self.lowered_values(key)
            .first()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }
}

impl Collection for TxCollection {
    fn all(&self) -> Vec<(&str, &str)> {
        self.iter().collect()
    }

    fn get(&self, key: &str) -> Option<Vec<&str>> {
        let values = self.values(key);
        (!values.is_empty()).then(|| values.iter().map(String::as_str).collect())
    }

    /// Regex selection (`TX:/^foo/`) matches against the stored, lowercased
    /// key, so a pattern anchored on uppercase will not match.
    fn get_regex(&self, pattern: &KeyRegex) -> Vec<(&str, &str)> {
        self.iter_regex(pattern).collect()
    }

    fn count(&self) -> usize {
        self.entries().map(|(_, values)| values.len()).sum()
    }

    fn count_key(&self, key: &str) -> usize {
        self.values(key).len()
    }
}

impl MutableCollection for TxCollection {
    fn set(&mut self, key: String, value: String) {
        match normalize(&key) {
            Cow::Borrowed(_) => self.set_lowered(Cow::Owned(key), value),
            Cow::Owned(lower) => self.set_lowered(Cow::Owned(lower), value),
        }
    }

    fn delete(&mut self, key: &str) {
        let key = normalize(key);
        if let Some(position) = self.shared_position(&key) {
            self.change(position, Change::Deleted);
        }
        self.data.delete(&key);
    }

    fn increment(&mut self, key: &str, amount: i64) {
        // Saturating, as in `HashMapCollection`.
        let key = normalize(key);
        let sum = self.numeric(&key).saturating_add(amount);
        self.set_lowered(key, sum.to_string());
    }

    fn decrement(&mut self, key: &str, amount: i64) {
        let key = normalize(key);
        let difference = self.numeric(&key).saturating_sub(amount);
        self.set_lowered(key, difference.to_string());
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
