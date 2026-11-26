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
    /// What became of the shared variables this transaction changed, with
    /// their positions. A transaction changes few of them.
    changes: Vec<(usize, Change)>,
    data: HashMapCollection,
}

/// What a transaction did to a variable it shares.
#[derive(Debug, Clone)]
enum Change {
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

    pub(crate) fn uses_default(&self, defaults: &HashMapCollection, position: usize) -> bool {
        self.shared
            .as_deref()
            .is_some_and(|shared| std::ptr::eq(shared, defaults))
            && self.changed(position).is_none()
    }

    /// The values of the shared variable at `position`, unless it was deleted.
    fn shared_at<'a>(&'a self, position: usize, values: &'a [String]) -> Option<&'a [String]> {
        match self.changed(position) {
            None => Some(values),
            Some(Change::Set(values)) => Some(values),
            Some(Change::Deleted) => None,
        }
    }

    /// What became of the shared variable at `position`, if it changed.
    fn changed(&self, position: usize) -> Option<&Change> {
        self.changes
            .iter()
            .find(|(changed, _)| *changed == position)
            .map(|(_, change)| change)
    }

    /// The position of the shared variable `key`, a lowercased key.
    fn shared_position(&self, key: &str) -> Option<usize> {
        let (position, _) = self.shared.as_ref()?.find(key)?;
        Some(position)
    }

    /// Every variable with its values, in order.
    fn entries(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.shared
            .iter()
            .flat_map(|shared| shared.entries())
            .enumerate()
            .filter_map(|(position, (key, values))| Some((key, self.shared_at(position, values)?)))
            .chain(self.data.entries())
    }

    /// The values of the lowercased `key`.
    fn lowered_values(&self, key: &str) -> &[String] {
        self.shared
            .as_ref()
            .and_then(|shared| shared.find(key))
            .and_then(|(position, values)| self.shared_at(position, values))
            .unwrap_or_else(|| self.data.values(key))
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

    /// The values stored under `key`, which is already lowercased, for a
    /// caller that looked the key up in the shared variables beforehand:
    /// `position` is where they hold it, `None` when they do not.
    ///
    /// Only for a collection that shares those variables or none, which is
    /// every transaction of the ruleset they were prepared with.
    pub(crate) fn values_at(&self, key: &str, position: Option<usize>) -> &[String] {
        let Some(shared) = &self.shared else {
            return self.data.values(key);
        };
        debug_assert_eq!(shared.find(key).map(|(found, _)| found), position);
        position
            .and_then(|position| shared.entry_at(position))
            .and_then(|(_, values)| self.shared_at(position?, values))
            .unwrap_or_else(|| self.data.values(key))
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
        match self
            .changes
            .iter_mut()
            .find(|(changed, _)| *changed == position)
        {
            Some((_, slot)) => *slot = change,
            None => self.changes.push((position, change)),
        }
    }

    /// Set the lowercased `key`.
    fn set_lowered(&mut self, key: Cow<'_, str>, value: String) {
        if let Some(position) = self.shared_position(&key) {
            if !matches!(self.changed(position), Some(Change::Deleted)) {
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

    /// The reads of a collection, for comparing two of them.
    fn reads(tx: &TxCollection) -> impl PartialEq + std::fmt::Debug + '_ {
        let keys = ["a", "B", "c", "d", "missing", "0"];
        (
            tx.all(),
            tx.count(),
            keys.map(|key| (tx.values(key), tx.get(key), tx.count_key(key))),
            tx.get_regex(&KeyRegex::new("^[a-c]$")),
            tx.iter_regex(&KeyRegex::new("^[a-c]$")).collect::<Vec<_>>(),
        )
    }

    /// A collection that shares `a`, `b` and `c`, and one that holds them itself.
    fn shared_and_own() -> (TxCollection, TxCollection) {
        let mut own = TxCollection::new();
        for (key, value) in [("a", "1"), ("B", "2"), ("c", "x")] {
            own.set(key.to_string(), value.to_string());
        }
        let mut shared = TxCollection::new();
        shared.share(&own.clone().into_shared());
        (shared, own)
    }

    #[test]
    fn a_collection_that_shares_its_variables_reads_like_one_that_holds_them() {
        let (shared, own) = shared_and_own();
        assert_eq!(
            format!("{:?}", reads(&shared)),
            format!("{:?}", reads(&own))
        );
        assert_eq!(shared.all(), [("a", "1"), ("b", "2"), ("c", "x")]);
    }

    #[test]
    fn changes_to_shared_variables_read_like_changes_to_held_ones() {
        type Step = fn(&mut TxCollection);
        let steps: [Step; 12] = [
            |tx| tx.set("d".to_string(), "new".to_string()),
            |tx| tx.set("B".to_string(), "20".to_string()),
            |tx| tx.increment("a", 5),
            |tx| tx.decrement("A", 2),
            |tx| tx.increment("c", 1),
            |tx| tx.delete("b"),
            |tx| tx.delete("missing"),
            |tx| tx.set("b".to_string(), "back".to_string()),
            |tx| tx.increment("b", 1),
            |tx| tx.delete("B"),
            |tx| tx.set("0".to_string(), "capture".to_string()),
            |tx| tx.delete("d"),
        ];
        let (mut shared, mut own) = shared_and_own();
        for (number, step) in steps.iter().enumerate() {
            step(&mut shared);
            step(&mut own);
            assert_eq!(
                format!("{:?}", reads(&shared)),
                format!("{:?}", reads(&own)),
                "after step {number}"
            );
        }
        // A deleted variable that is set again goes to the end.
        let (mut shared, _) = shared_and_own();
        shared.delete("a");
        shared.set("a".to_string(), "again".to_string());
        assert_eq!(shared.all(), [("b", "2"), ("c", "x"), ("a", "again")]);
    }

    #[test]
    fn a_change_stays_with_the_collection_that_made_it() {
        let (mut first, _) = shared_and_own();
        let mut second = first.clone();
        first.set("a".to_string(), "changed".to_string());
        first.delete("c");
        assert_eq!(second.all(), [("a", "1"), ("b", "2"), ("c", "x")]);
        second.clear();
        assert!(second.all().is_empty());
        assert_eq!(first.all(), [("a", "changed"), ("b", "2")]);
    }
}
