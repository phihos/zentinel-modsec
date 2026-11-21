//! Collection trait and implementations.

use super::KeyRegex;
use indexmap::IndexMap;

/// A collection of key-value pairs.
pub trait Collection: Send + Sync {
    /// Get all key-value pairs.
    fn all(&self) -> Vec<(&str, &str)>;

    /// Get values by key.
    fn get(&self, key: &str) -> Option<Vec<&str>>;

    /// Get values matching a regex pattern.
    fn get_regex(&self, pattern: &KeyRegex) -> Vec<(&str, &str)>;

    /// Count items.
    fn count(&self) -> usize;

    /// Count items with specific key.
    fn count_key(&self, key: &str) -> usize;
}

/// A mutable collection (TX, SESSION, etc.).
pub trait MutableCollection: Collection {
    /// Set a value.
    fn set(&mut self, key: String, value: String);

    /// Delete a key.
    fn delete(&mut self, key: &str);

    /// Increment a numeric value.
    fn increment(&mut self, key: &str, amount: i64);

    /// Decrement a numeric value.
    fn decrement(&mut self, key: &str, amount: i64);
}

/// A keyed collection that iterates in insertion order.
///
/// Order is part of the result, not an implementation detail: a rule over a
/// collection reports the first variable that matched, which becomes
/// `MATCHED_VAR`, the captures and the audit log's matched data. A
/// `std::collections::HashMap` iterates in an order seeded per map, so the
/// same rules and the same request gave different answers from run to run
/// (zentinelproxy/zentinel-modsec#53). Insertion order is the order the
/// request carried its headers and arguments in, and the order `setvar`
/// created TX variables in.
///
/// The name is kept for API compatibility.
#[derive(Debug, Clone, Default)]
pub struct HashMapCollection {
    data: IndexMap<String, Vec<String>>,
}

impl HashMapCollection {
    /// Create a new empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a value to a key.
    pub fn add(&mut self, key: String, value: String) {
        self.data.entry(key).or_default().push(value);
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Every `(key, value)` pair in insertion order, read in place.
    ///
    /// What [`Collection::all`] returns, without collecting it.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.data
            .iter()
            .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str())))
    }

    /// The values stored under `key`, in the order they were added. Empty
    /// when the key is absent, where [`Collection::get`] returns `None`.
    pub fn values(&self, key: &str) -> &[String] {
        self.data.get(key).map_or(&[], Vec::as_slice)
    }

    /// The `(key, value)` pairs whose key matches `pattern`, in insertion
    /// order, read in place.
    ///
    /// What [`Collection::get_regex`] returns, without collecting it.
    pub fn iter_regex<'a, 'r>(
        &'a self,
        pattern: &'r KeyRegex,
    ) -> impl Iterator<Item = (&'a str, &'a str)> + 'r
    where
        'a: 'r,
    {
        self.data
            .iter()
            .filter(move |(k, _)| pattern.is_match(k))
            .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str())))
    }

    /// The first value of a key as a number, or 0 when it is missing or not
    /// numeric.
    fn numeric(&self, key: &str) -> i64 {
        self.data
            .get(key)
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }
}

impl Collection for HashMapCollection {
    fn all(&self) -> Vec<(&str, &str)> {
        self.iter().collect()
    }

    fn get(&self, key: &str) -> Option<Vec<&str>> {
        self.data
            .get(key)
            .map(|vs| vs.iter().map(|s| s.as_str()).collect())
    }

    fn get_regex(&self, pattern: &KeyRegex) -> Vec<(&str, &str)> {
        self.iter_regex(pattern).collect()
    }

    fn count(&self) -> usize {
        self.data.values().map(|v| v.len()).sum()
    }

    fn count_key(&self, key: &str) -> usize {
        self.data.get(key).map(|v| v.len()).unwrap_or(0)
    }
}

impl MutableCollection for HashMapCollection {
    fn set(&mut self, key: String, value: String) {
        self.data.insert(key, vec![value]);
    }

    fn delete(&mut self, key: &str) {
        // `shift_remove`, not `swap_remove`: the latter moves the last key
        // into the gap and so reorders what is left.
        self.data.shift_remove(key);
    }

    fn increment(&mut self, key: &str, amount: i64) {
        // Saturating, so that an operand a request supplies (`=+%{tx.1}`) can
        // neither overflow nor carry a score round to the other end of the
        // range, where a threshold comparison would stop matching.
        let sum = self.numeric(key).saturating_add(amount);
        self.set(key.to_string(), sum.to_string());
    }

    fn decrement(&mut self, key: &str, amount: i64) {
        // Subtracted directly rather than added negated: `i64::MIN` has no
        // negation.
        let difference = self.numeric(key).saturating_sub(amount);
        self.set(key.to_string(), difference.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> HashMapCollection {
        let mut c = HashMapCollection::new();
        c.add("b".to_string(), "1".to_string());
        c.add("a".to_string(), "2".to_string());
        c.add("b".to_string(), "3".to_string());
        c.add("ab".to_string(), "".to_string());
        c
    }

    #[test]
    fn iter_reads_what_all_collects_in_insertion_order() {
        let c = sample();
        let pairs: Vec<_> = c.iter().collect();
        assert_eq!(pairs, [("b", "1"), ("b", "3"), ("a", "2"), ("ab", "")]);
        assert_eq!(pairs, c.all());
        assert_eq!(HashMapCollection::new().iter().count(), 0);
    }

    #[test]
    fn values_reads_what_get_collects() {
        let c = sample();
        assert_eq!(c.values("b"), ["1", "3"]);
        assert_eq!(c.get("b"), Some(vec!["1", "3"]));
        assert_eq!(c.values("ab"), [""]);
        // Keys are case-sensitive, and a missing key has no values.
        assert!(c.values("B").is_empty());
        assert_eq!(c.get("B"), None);
    }

    #[test]
    fn iter_regex_reads_what_get_regex_collects() {
        let c = sample();
        let pattern = KeyRegex::new("^a");
        let pairs: Vec<_> = c.iter_regex(&pattern).collect();
        assert_eq!(pairs, [("a", "2"), ("ab", "")]);
        assert_eq!(pairs, c.get_regex(&pattern));
        let none = KeyRegex::new("^z");
        assert_eq!(c.iter_regex(&none).count(), 0);
    }
}
