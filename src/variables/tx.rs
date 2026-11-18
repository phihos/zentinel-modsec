//! TX (transaction) collection.

use super::collection::{ByteCollection, Collection, HashMapCollection, MutableCollection};
use super::{folded_key, ByteValue};
use regex::Regex;
use std::borrow::Cow;

/// Transaction collection for storing intermediate values.
///
/// Keys are **case-insensitive**, as they are in ModSecurity. The OWASP CRS
/// depends on this: it writes `setvar:'tx.blocking_paranoia_level=1'` and reads
/// `TX:BLOCKING_PARANOIA_LEVEL`, and its anomaly scoring never accumulates if
/// those are treated as two different keys. Normalising here rather than at the
/// call sites keeps the guarantee in one place -- every read and write in the
/// engine goes through this type.
#[derive(Debug, Clone, Default)]
pub struct TxCollection {
    data: HashMapCollection,
}

/// Lowercase a key only when it actually contains uppercase, so the common path
/// (CRS writes and reads lowercase) does not allocate.
fn normalize(key: &str) -> Cow<'_, str> {
    match folded_key(key.as_bytes()) {
        Cow::Borrowed(_) => Cow::Borrowed(key),
        Cow::Owned(bytes) => {
            Cow::Owned(String::from_utf8(bytes).expect("lowercased text is UTF-8"))
        }
    }
}

impl TxCollection {
    pub(crate) fn members(&self) -> &HashMapCollection {
        &self.data
    }

    pub(crate) fn first_value_bytes(&self, key: &[u8]) -> Option<&[u8]> {
        self.data.first_value_bytes(&folded_key(key))
    }

    /// Create a new TX collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store original value bytes under a case-insensitive original byte key.
    pub fn set_bytes(&mut self, key: impl Into<ByteValue>, value: impl Into<ByteValue>) {
        let key = key.into();
        match folded_key(key.as_bytes()) {
            Cow::Borrowed(_) => self.data.set_bytes(key, value),
            Cow::Owned(folded) => self.data.set_bytes(folded, value),
        }
    }

    /// Delete a case-insensitive original byte key.
    pub fn delete_bytes(&mut self, key: &[u8]) {
        self.data.delete_bytes(&folded_key(key));
    }

    /// Increment a numeric byte value with signed 64-bit wrapping, matching
    /// Coraza on 64-bit targets. A nonnumeric value starts at zero.
    pub fn increment_bytes(&mut self, key: &[u8], amount: i64) {
        let current = self
            .first_value_bytes(key)
            .and_then(|v| std::str::from_utf8(v).ok()?.parse::<i64>().ok())
            .unwrap_or(0);
        self.set_bytes(key.to_vec(), current.wrapping_add(amount).to_string());
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

impl Collection for TxCollection {
    fn all(&self) -> Vec<(&str, &str)> {
        self.data.all()
    }

    fn get(&self, key: &str) -> Option<Vec<&str>> {
        self.data.get(&normalize(key))
    }

    /// Match a selector compiled by the resolver with TX's case-insensitive
    /// default; explicit inline flags in the regex may override that default.
    fn get_regex(&self, pattern: &Regex) -> Vec<(&str, &str)> {
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

impl ByteCollection for TxCollection {
    fn all_bytes(&self) -> Vec<(&[u8], &[u8])> {
        self.data.all_bytes()
    }
    fn get_bytes(&self, key: &[u8]) -> Option<Vec<&[u8]>> {
        self.data.get_bytes(&folded_key(key))
    }
    fn get_regex_bytes(&self, pattern: &regex::bytes::Regex) -> Vec<(&[u8], &[u8])> {
        self.data.get_regex_bytes(pattern)
    }
}
