//! Collection trait and implementations.

use super::ByteValue;
use indexmap::{map::Entry, IndexMap};
use regex::Regex;

/// A collection of key-value pairs.
pub trait Collection: Send + Sync {
    /// Get all key-value pairs.
    fn all(&self) -> Vec<(&str, &str)>;

    /// Get values by key.
    fn get(&self, key: &str) -> Option<Vec<&str>>;

    /// Get values matching a regex pattern.
    fn get_regex(&self, pattern: &Regex) -> Vec<(&str, &str)>;

    /// Count items.
    fn count(&self) -> usize;

    /// Count items with specific key.
    fn count_key(&self, key: &str) -> usize;
}

/// Lossless byte access to a collection.
///
/// Engine evaluation uses this API. Legacy text accessors present escaped binary
/// values for display and must not feed those presentations back into detection.
pub trait ByteCollection: Collection {
    /// Every original key and value in insertion order.
    fn all_bytes(&self) -> Vec<(&[u8], &[u8])>;
    /// Stored lookup key, original observed name, and value for every member.
    /// Ordinary collections use the lookup key as their observed name.
    fn all_bytes_with_names(&self) -> Vec<(&[u8], &[u8], &[u8])> {
        self.all_bytes()
            .into_iter()
            .map(|(key, value)| (key, key, value))
            .collect()
    }
    /// Values under the exact original key bytes.
    fn get_bytes(&self, key: &[u8]) -> Option<Vec<&[u8]>>;
    /// Values selected by a regex over original key bytes.
    fn get_regex_bytes(&self, pattern: &regex::bytes::Regex) -> Vec<(&[u8], &[u8])>;
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
    data: IndexMap<ByteValue, CollectionValues>,
    fold_keys: bool,
}

#[derive(Debug, Clone, Default)]
struct CollectionValues {
    values: Vec<ByteValue>,
    // Allocated only when the observed name differs from the lookup key.
    // Every slot then aligns with exactly one value, including duplicates.
    original_names: Option<Vec<ByteValue>>,
}
impl std::ops::Deref for CollectionValues {
    type Target = Vec<ByteValue>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl CollectionValues {
    fn name<'a>(&'a self, key: &'a ByteValue, index: usize) -> &'a ByteValue {
        self.original_names
            .as_ref()
            .and_then(|names| names.get(index))
            .unwrap_or(key)
    }
}

/// Lowercase lookup keys without passing opaque bytes through a text rendering.
/// Use simple Unicode lowercase, as Go strings.ToLower does for named maps.
pub(crate) fn folded_key(key: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    use std::borrow::Cow;
    if key.is_ascii() {
        return if key.iter().any(u8::is_ascii_uppercase) {
            Cow::Owned(key.to_ascii_lowercase())
        } else {
            Cow::Borrowed(key)
        };
    }
    let mut folded = Vec::with_capacity(key.len());
    for chunk in key.utf8_chunks() {
        for ch in chunk.valid().chars() {
            let lower = ch.to_lowercase().next().unwrap_or(ch);
            folded.extend_from_slice(lower.encode_utf8(&mut [0; 4]).as_bytes());
        }
        folded.extend_from_slice(chunk.invalid());
    }
    Cow::Owned(folded)
}

impl HashMapCollection {
    /// Create a new empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// A named map with folded lookup keys and original per-value spellings.
    pub(crate) fn named() -> Self {
        Self {
            fold_keys: true,
            ..Self::default()
        }
    }

    fn lookup_key<'a>(&self, key: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
        if self.fold_keys {
            folded_key(key)
        } else {
            key.into()
        }
    }

    /// Visit one indexed bucket or all buckets. The callback sees the lookup
    /// key, observed name, and original value without allocating a result list.
    pub(crate) fn visit(&self, literal: Option<&[u8]>, mut f: impl FnMut(&[u8], &[u8], &[u8])) {
        let mut bucket = |key: &ByteValue, values: &CollectionValues| {
            for (i, value) in values.iter().enumerate() {
                f(
                    key.as_bytes(),
                    values.name(key, i).as_bytes(),
                    value.as_bytes(),
                );
            }
        };
        if let Some(key) = literal {
            if let Some((key, values)) = self.data.get_key_value(key) {
                bucket(key, values);
            }
        } else {
            for (key, values) in &self.data {
                bucket(key, values);
            }
        }
    }

    /// Add a value to a key.
    pub fn add(&mut self, key: String, value: String) {
        self.add_bytes(key, value);
    }

    pub(super) fn last_value_bytes(&self, key: &[u8]) -> Option<&[u8]> {
        self.data.get(key)?.last().map(ByteValue::as_bytes)
    }

    /// Append original bytes, keeping invalid UTF-8 and binary keys distinct.
    pub fn add_bytes(&mut self, key: impl Into<ByteValue>, value: impl Into<ByteValue>) {
        let key = key.into();
        if let std::borrow::Cow::Owned(folded) = self.lookup_key(key.as_bytes()) {
            return self.add_named_bytes(folded, key, value);
        }
        let value = value.into();
        match self.data.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(CollectionValues {
                    values: vec![value],
                    original_names: None,
                });
            }
            Entry::Occupied(mut entry) => {
                if entry.get().original_names.is_some() {
                    let key = entry.key().clone();
                    entry.get_mut().original_names.as_mut().unwrap().push(key);
                }
                entry.get_mut().values.push(value);
            }
        }
    }

    /// Append a value with an observed name distinct from its lookup key.
    /// Headers use normalized lookup keys while preserving each received name.
    pub fn add_named_bytes(
        &mut self,
        key: impl Into<ByteValue>,
        original_name: impl Into<ByteValue>,
        value: impl Into<ByteValue>,
    ) {
        let key = key.into();
        let original_name = original_name.into();
        let value = value.into();
        let differs = key != original_name;
        match self.data.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(CollectionValues {
                    values: vec![value],
                    original_names: differs.then(|| vec![original_name]),
                });
            }
            Entry::Occupied(mut entry) => {
                if differs && entry.get().original_names.is_none() {
                    let canonical = entry.key().clone();
                    let count = entry.get().len();
                    entry.get_mut().original_names = Some(vec![canonical; count]);
                }
                if let Some(names) = &mut entry.get_mut().original_names {
                    names.push(original_name);
                }
                entry.get_mut().values.push(value);
            }
        }
    }

    /// Replace values under an original byte key.
    pub fn set_bytes(&mut self, key: impl Into<ByteValue>, value: impl Into<ByteValue>) {
        let original = key.into();
        let (key, original_names) = match self.lookup_key(original.as_bytes()) {
            std::borrow::Cow::Borrowed(_) => (original, None),
            std::borrow::Cow::Owned(key) => (key.into(), Some(vec![original])),
        };
        self.data.insert(
            key,
            CollectionValues {
                values: vec![value.into()],
                original_names,
            },
        );
    }

    /// Delete an original byte key without rendering or decoding it.
    pub fn delete_bytes(&mut self, key: &[u8]) {
        self.data.shift_remove(self.lookup_key(key).as_ref());
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

impl Collection for HashMapCollection {
    fn all(&self) -> Vec<(&str, &str)> {
        self.data
            .iter()
            .flat_map(|(k, vs)| {
                vs.iter()
                    .enumerate()
                    .map(move |(i, v)| (vs.name(k, i).display_text(), v.display_text()))
            })
            .collect()
    }

    fn get(&self, key: &str) -> Option<Vec<&str>> {
        self.data
            .get(self.lookup_key(key.as_bytes()).as_ref())
            .map(|vs| vs.iter().map(ByteValue::display_text).collect())
    }

    fn get_regex(&self, pattern: &Regex) -> Vec<(&str, &str)> {
        self.data
            .iter()
            .filter(|(k, _)| pattern.is_match(k.display_text()))
            .flat_map(|(k, vs)| {
                vs.iter()
                    .enumerate()
                    .map(move |(i, v)| (vs.name(k, i).display_text(), v.display_text()))
            })
            .collect()
    }

    fn count(&self) -> usize {
        self.data.values().map(|v| v.len()).sum()
    }

    fn count_key(&self, key: &str) -> usize {
        self.data
            .get(self.lookup_key(key.as_bytes()).as_ref())
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

impl MutableCollection for HashMapCollection {
    fn set(&mut self, key: String, value: String) {
        self.set_bytes(key, value);
    }

    fn delete(&mut self, key: &str) {
        // `shift_remove`, not `swap_remove`: the latter moves the last key
        // into the gap and so reorders what is left.
        self.delete_bytes(key.as_bytes());
    }

    fn increment(&mut self, key: &str, amount: i64) {
        let current: i64 = self
            .data
            .get(self.lookup_key(key.as_bytes()).as_ref())
            .and_then(|v| v.first())
            .and_then(|s| s.as_utf8().ok()?.parse().ok())
            .unwrap_or(0);
        self.set(key.to_string(), current.wrapping_add(amount).to_string());
    }

    fn decrement(&mut self, key: &str, amount: i64) {
        self.increment(key, amount.wrapping_neg());
    }
}

impl ByteCollection for HashMapCollection {
    fn all_bytes(&self) -> Vec<(&[u8], &[u8])> {
        self.data
            .iter()
            .flat_map(|(key, values)| {
                values.iter().enumerate().map(move |(index, value)| {
                    (values.name(key, index).as_bytes(), value.as_bytes())
                })
            })
            .collect()
    }
    fn all_bytes_with_names(&self) -> Vec<(&[u8], &[u8], &[u8])> {
        self.data
            .iter()
            .flat_map(|(key, values)| {
                values.iter().enumerate().map(move |(index, value)| {
                    (
                        key.as_bytes(),
                        values.name(key, index).as_bytes(),
                        value.as_bytes(),
                    )
                })
            })
            .collect()
    }
    fn get_bytes(&self, key: &[u8]) -> Option<Vec<&[u8]>> {
        self.data
            .get(self.lookup_key(key).as_ref())
            .map(|values| values.iter().map(ByteValue::as_bytes).collect())
    }
    fn get_regex_bytes(&self, pattern: &regex::bytes::Regex) -> Vec<(&[u8], &[u8])> {
        self.data
            .iter()
            .filter(|(key, _)| pattern.is_match(key.as_bytes()))
            .flat_map(|(key, values)| {
                values.iter().enumerate().map(move |(index, value)| {
                    (values.name(key, index).as_bytes(), value.as_bytes())
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod byte_tests {
    use super::*;

    #[test]
    fn binary_keys_never_alias_escaped_text_and_mutation_preserves_order() {
        let mut collection = HashMapCollection::new();
        collection.add_bytes(&b"\xff"[..], &b"\x80\0"[..]);
        collection.add("\\xff".into(), "literal".into());
        collection.add_bytes(&b"\xff"[..], &b"second"[..]);
        assert_eq!(collection.count(), 3);
        assert_eq!(
            collection.get_bytes(b"\xff"),
            Some(vec![&b"\x80\0"[..], &b"second"[..]])
        );
        assert_eq!(collection.get_bytes(b"\\xff"), Some(vec![&b"literal"[..]]));
        collection.set_bytes(&b"\xff"[..], &b"replacement\xff"[..]);
        assert_eq!(
            collection.all_bytes()[0],
            (&b"\xff"[..], &b"replacement\xff"[..])
        );
        collection.delete_bytes(b"\xff");
        assert_eq!(
            collection.all_bytes(),
            vec![(&b"\\xff"[..], &b"literal"[..])]
        );
        collection.increment("\\xff", 2);
        assert_eq!(collection.get_bytes(b"\\xff"), Some(vec![&b"2"[..]]));
    }
}
