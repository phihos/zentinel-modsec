//! Lossless runtime bytes with a separate, escaped text presentation.

use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, OnceLock};

/// A request value, collection key, capture, or expanded macro.
///
/// Short text can be stored inline. Invalid UTF-8 values
/// have an escaped display string for legacy text getters and logs. Equality,
/// hashing and byte access always use the original bytes, never that display.
#[derive(Clone, Debug)]
pub struct ByteValue {
    storage: Storage,
}

#[derive(Clone)]
enum Storage {
    Short(ShortText),
    Text(String),
    Binary(Arc<BinaryValue>),
}

// Leave room for the length and enum tag. Five machine words cover most
// qualified TX names without growing the collection buckets.
const INLINE_CAPACITY: usize = 5 * std::mem::size_of::<usize>() - 2;

#[derive(Clone)]
struct ShortText {
    bytes: [u8; INLINE_CAPACITY],
    len: u8,
}

impl ShortText {
    fn new(text: &str) -> Self {
        let mut bytes = [0; INLINE_CAPACITY];
        bytes[..text.len()].copy_from_slice(text.as_bytes());
        Self {
            bytes,
            len: text.len() as u8,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).expect("short text contains UTF-8")
    }
}

impl fmt::Debug for Storage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short(text) => f.debug_tuple("Text").field(&text.as_str()).finish(),
            Self::Text(text) => f.debug_tuple("Text").field(text).finish(),
            Self::Binary(value) => f
                .debug_struct("Binary")
                .field("bytes", &value.bytes)
                .field("display", &value.display_text())
                .finish(),
        }
    }
}

struct BinaryValue {
    bytes: Vec<u8>,
    display: OnceLock<String>,
}

impl BinaryValue {
    fn escaped(bytes: &[u8]) -> String {
        bytes
            .iter()
            .flat_map(|&b| std::ascii::escape_default(b))
            .map(char::from)
            .collect()
    }

    fn display_text(&self) -> &str {
        self.display.get_or_init(|| Self::escaped(&self.bytes))
    }
}

impl ByteValue {
    fn binary(bytes: Vec<u8>) -> Self {
        Self {
            storage: Storage::Binary(Arc::new(BinaryValue {
                bytes,
                display: OnceLock::new(),
            })),
        }
    }

    /// The original bytes; use this accessor for every engine operation.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.storage {
            Storage::Short(text) => text.as_bytes(),
            Storage::Text(value) => value.as_bytes(),
            Storage::Binary(value) => &value.bytes,
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
            Storage::Short(text) => text.as_str(),
            Storage::Text(value) => value,
            Storage::Binary(value) => value.display_text(),
        }
    }

    /// Move both audit representations out, reusing the escaped binary display.
    pub(crate) fn into_display_and_bytes(self) -> (String, Vec<u8>) {
        match self.storage {
            Storage::Short(text) => (text.as_str().to_owned(), text.as_bytes().to_vec()),
            Storage::Text(text) => (text.clone(), text.into_bytes()),
            Storage::Binary(value) => match Arc::try_unwrap(value) {
                Ok(value) => {
                    let display = value
                        .display
                        .into_inner()
                        .unwrap_or_else(|| BinaryValue::escaped(&value.bytes));
                    (display, value.bytes)
                }
                Err(value) => (value.display_text().to_owned(), value.bytes.clone()),
            },
        }
    }

    /// Move out the original bytes without replacing invalid UTF-8.
    pub fn into_bytes(self) -> Vec<u8> {
        match self.storage {
            Storage::Short(text) => text.as_bytes().to_vec(),
            Storage::Text(value) => value.into_bytes(),
            Storage::Binary(value) => {
                Arc::try_unwrap(value).map_or_else(|value| value.bytes.clone(), |value| value.bytes)
            }
        }
    }
}

pub(crate) fn qualified_name(prefix: &str, member: Option<&[u8]>) -> ByteValue {
    let Some(key) = member.filter(|k| !k.is_empty()) else {
        return prefix.into();
    };
    let length = prefix.len() + 1 + key.len();
    if length <= INLINE_CAPACITY {
        let mut bytes = [0; INLINE_CAPACITY];
        bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
        bytes[prefix.len()] = b':';
        bytes[prefix.len() + 1..length].copy_from_slice(key);
        return ByteValue::from(&bytes[..length]);
    }
    let mut name = Vec::with_capacity(length);
    name.extend_from_slice(prefix.as_bytes());
    name.push(b':');
    name.extend_from_slice(key);
    name.into()
}

impl Default for ByteValue {
    fn default() -> Self {
        Self::from(String::new())
    }
}

impl From<String> for ByteValue {
    fn from(value: String) -> Self {
        let storage = if value.len() <= INLINE_CAPACITY {
            Storage::Short(ShortText::new(&value))
        } else {
            Storage::Text(value)
        };
        Self { storage }
    }
}

impl From<&str> for ByteValue {
    fn from(value: &str) -> Self {
        if value.len() <= INLINE_CAPACITY {
            Self {
                storage: Storage::Short(ShortText::new(value)),
            }
        } else {
            Self::from(value.to_owned())
        }
    }
}

impl From<&[u8]> for ByteValue {
    fn from(value: &[u8]) -> Self {
        if value.len() <= INLINE_CAPACITY {
            return match std::str::from_utf8(value) {
                Ok(text) => text.into(),
                Err(_) => Self::binary(value.to_vec()),
            };
        }
        Self::from(value.to_vec())
    }
}

impl From<Vec<u8>> for ByteValue {
    fn from(bytes: Vec<u8>) -> Self {
        match String::from_utf8(bytes) {
            Ok(value) => value.into(),
            Err(error) => Self::binary(error.into_bytes()),
        }
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
    fn short_text_boundaries_preserve_borrowed_and_owned_representations() {
        for size in [2, INLINE_CAPACITY - 1, INLINE_CAPACITY, INLINE_CAPACITY + 1] {
            let text = format!("{}é", "x".repeat(size - 2));
            for value in [
                ByteValue::from(text.clone()),
                ByteValue::from(text.as_str()),
                ByteValue::from(text.as_bytes()),
                ByteValue::from(text.clone().into_bytes()),
            ] {
                assert_eq!(value.as_utf8().unwrap(), text);
                assert_eq!(value.display_text(), text);
                assert_eq!(value.clone().into_bytes(), text.as_bytes());
                assert_eq!(
                    value.into_display_and_bytes(),
                    (text.clone(), text.clone().into_bytes())
                );
            }
        }
    }

    #[test]
    fn binary_audit_can_consume_shared_or_unique_storage() {
        let bytes = b"x\\\xff\n";
        let expected = r"x\\\xff\n";
        let value = ByteValue::from(bytes.as_slice());
        assert_eq!(value.clone().into_bytes(), bytes);
        assert_eq!(
            value.clone().into_display_and_bytes(),
            (expected.into(), bytes.to_vec())
        );
        assert_eq!(value.display_text(), expected);
        assert_eq!(
            value.into_display_and_bytes(),
            (expected.into(), bytes.to_vec())
        );
        assert_eq!(
            ByteValue::from(bytes.to_vec()).into_display_and_bytes(),
            (expected.into(), bytes.to_vec())
        );
    }

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
