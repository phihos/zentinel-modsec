//! Lossless runtime bytes with a separate, escaped text presentation.

use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A request value, collection key, capture, or expanded macro.
///
/// Valid UTF-8 keeps the existing compact `String` representation. Other bytes
/// have an escaped display string for legacy text getters and logs. Equality,
/// hashing and byte access always use the original bytes, never that display.
#[derive(Clone, Debug)]
pub struct ByteValue {
    storage: Storage,
}

#[derive(Clone, Debug)]
enum Storage {
    Text(String),
    Binary { bytes: Vec<u8>, display: String },
}

impl ByteValue {
    /// The original bytes; use this accessor for every engine operation.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.storage {
            Storage::Text(value) => value.as_bytes(),
            Storage::Binary { bytes, .. } => bytes,
        }
    }

    /// The value as UTF-8, or an error when it contains invalid UTF-8.
    pub fn as_utf8(&self) -> std::result::Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self.as_bytes())
    }

    /// Human-readable presentation for legacy text accessors and logs.
    ///
    /// Binary bytes are escaped. This is never an engine input or lookup key.
    pub fn display_text(&self) -> &str {
        match &self.storage {
            Storage::Text(value) => value,
            Storage::Binary { display, .. } => display,
        }
    }

    /// Move both audit representations out, reusing the escaped binary display.
    pub(crate) fn into_display_and_bytes(self) -> (String, Vec<u8>) {
        match self.storage {
            Storage::Text(text) => (text.clone(), text.into_bytes()),
            Storage::Binary { bytes, display } => (display, bytes),
        }
    }

    /// Move out the original bytes without replacing invalid UTF-8.
    pub fn into_bytes(self) -> Vec<u8> {
        match self.storage {
            Storage::Text(value) => value.into_bytes(),
            Storage::Binary { bytes, .. } => bytes,
        }
    }
}

impl Default for ByteValue {
    fn default() -> Self {
        Self::from(String::new())
    }
}

impl From<String> for ByteValue {
    fn from(value: String) -> Self {
        Self {
            storage: Storage::Text(value),
        }
    }
}

impl From<&str> for ByteValue {
    fn from(value: &str) -> Self {
        Self::from(value.to_owned())
    }
}

impl From<&[u8]> for ByteValue {
    fn from(value: &[u8]) -> Self {
        Self::from(value.to_vec())
    }
}

impl From<Vec<u8>> for ByteValue {
    fn from(bytes: Vec<u8>) -> Self {
        let storage = match String::from_utf8(bytes) {
            Ok(value) => Storage::Text(value),
            Err(error) => {
                let bytes = error.into_bytes();
                let display = bytes
                    .iter()
                    .flat_map(|&b| std::ascii::escape_default(b))
                    .map(char::from)
                    .collect();
                Storage::Binary { bytes, display }
            }
        };
        Self { storage }
    }
}

impl Borrow<[u8]> for ByteValue {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl PartialEq for ByteValue {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}
impl Eq for ByteValue {}
impl Hash for ByteValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}
impl fmt::Display for ByteValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;

    #[test]
    fn every_byte_roundtrips_without_display_collisions() {
        let original: Vec<u8> = (0..=255).collect();
        let value = ByteValue::from(original.clone());
        assert_eq!(value.as_bytes(), original);
        assert!(value.as_utf8().is_err());
        assert_eq!(value.into_bytes(), original);
        let mut map = IndexMap::new();
        map.insert(ByteValue::from(&b"\xff"[..]), 1);
        map.insert(ByteValue::from("\\xff"), 2);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&b"\xff"[..]), Some(&1));
        assert_eq!(map.get(&b"\\xff"[..]), Some(&2));
    }
}
