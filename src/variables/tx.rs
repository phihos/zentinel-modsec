//! TX (transaction) collection.

use super::collection::{ByteCollection, Collection, MutableCollection};
use super::{folded_key, ByteValue, MemberSelector};
use indexmap::IndexMap;
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
    data: IndexMap<ByteValue, ByteValue>,
    // Upper bound on occupied single-digit keys, including values written by callers.
    capture_limit: u8,
}

impl TxCollection {
    pub(crate) fn visit(&self, selector: &MemberSelector, mut emit: impl FnMut(&[u8], &[u8])) {
        match selector {
            MemberSelector::Key(key) => {
                if let Some(value) = self.data.get(key.as_ref()) {
                    emit(key, value.as_bytes());
                }
            }
            MemberSelector::All => {
                for (key, value) in &self.data {
                    emit(key.as_bytes(), value.as_bytes());
                }
            }
            MemberSelector::Regex(Some(pattern)) => {
                for (key, value) in &self.data {
                    if pattern.is_match(key.as_bytes()) {
                        emit(key.as_bytes(), value.as_bytes());
                    }
                }
            }
            MemberSelector::Regex(None) => (),
        }
    }

    fn lookup(&self, key: &[u8]) -> Option<&ByteValue> {
        self.data.get(folded_key(key).as_ref())
    }

    pub(crate) fn first_value_bytes(&self, key: &[u8]) -> Option<&[u8]> {
        self.lookup(key).map(ByteValue::as_bytes)
    }

    /// Create a new TX collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store original value bytes under a case-insensitive original byte key.
    pub fn set_bytes(&mut self, key: impl Into<ByteValue>, value: impl Into<ByteValue>) {
        let key = key.into();

        let key = match folded_key(key.as_bytes()) {
            Cow::Borrowed(_) => key,
            Cow::Owned(folded) => folded.into(),
        };
        self.set_canonical(key, value.into());
    }

    pub(crate) fn set_canonical(&mut self, key: ByteValue, value: ByteValue) {
        self.observe_capture_key(key.as_bytes());
        self.data.insert(key, value);
    }

    /// Delete a case-insensitive original byte key.
    pub fn delete_bytes(&mut self, key: &[u8]) {
        self.delete_canonical(&folded_key(key));
    }

    pub(crate) fn delete_canonical(&mut self, key: &[u8]) {
        self.data.shift_remove(key);
    }

    /// Increment a numeric byte value with signed 64-bit wrapping, matching
    /// Coraza on 64-bit targets. A nonnumeric value starts at zero.
    pub fn increment_bytes(&mut self, key: &[u8], amount: i64) {
        self.increment_canonical(ByteValue::from(folded_key(key)), amount);
    }

    pub(crate) fn increment_canonical(&mut self, key: ByteValue, amount: i64) {
        self.observe_capture_key(key.as_bytes());
        self.data
            .entry(key)
            .and_modify(|value| {
                let current = value
                    .as_utf8()
                    .ok()
                    .and_then(|v| v.parse::<i64>().ok())
                    .unwrap_or(0);
                *value = ByteValue::decimal(current.wrapping_add(amount));
            })
            .or_insert_with(|| ByteValue::decimal(amount));
    }

    fn observe_capture_key(&mut self, key: &[u8]) {
        if let [digit @ b'0'..=b'9'] = key {
            self.capture_limit = self.capture_limit.max(digit - b'0' + 1);
        }
    }

    pub(crate) fn clear_capture_slots(&mut self) {
        for slot in 0..std::mem::take(&mut self.capture_limit) {
            self.data.shift_remove(&[b'0' + slot][..]);
        }
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.data.clear();
        self.capture_limit = 0;
    }
}

impl Collection for TxCollection {
    fn all(&self) -> Vec<(&str, &str)> {
        self.data
            .iter()
            .map(|(key, value)| (key.display_text(), value.display_text()))
            .collect()
    }

    fn get(&self, key: &str) -> Option<Vec<&str>> {
        self.lookup(key.as_bytes()).map(|v| vec![v.display_text()])
    }

    fn get_regex(&self, pattern: &Regex) -> Vec<(&str, &str)> {
        self.data
            .iter()
            .filter(|(key, _)| pattern.is_match(key.display_text()))
            .map(|(key, value)| (key.display_text(), value.display_text()))
            .collect()
    }

    fn count(&self) -> usize {
        self.data.len()
    }

    fn count_key(&self, key: &str) -> usize {
        usize::from(self.lookup(key.as_bytes()).is_some())
    }
}

impl MutableCollection for TxCollection {
    fn set(&mut self, key: String, value: String) {
        self.set_bytes(key, value);
    }

    fn delete(&mut self, key: &str) {
        self.delete_bytes(key.as_bytes());
    }

    fn increment(&mut self, key: &str, amount: i64) {
        self.increment_bytes(key.as_bytes(), amount);
    }

    fn decrement(&mut self, key: &str, amount: i64) {
        self.increment(key, amount.wrapping_neg());
    }
}

impl ByteCollection for TxCollection {
    fn all_bytes(&self) -> Vec<(&[u8], &[u8])> {
        self.data
            .iter()
            .map(|(key, value)| (key.as_bytes(), value.as_bytes()))
            .collect()
    }

    fn get_bytes(&self, key: &[u8]) -> Option<Vec<&[u8]>> {
        self.first_value_bytes(key).map(|v| vec![v])
    }

    fn get_regex_bytes(&self, pattern: &regex::bytes::Regex) -> Vec<(&[u8], &[u8])> {
        self.data
            .iter()
            .filter(|(key, _)| pattern.is_match(key.as_bytes()))
            .map(|(key, value)| (key.as_bytes(), value.as_bytes()))
            .collect()
    }
}
