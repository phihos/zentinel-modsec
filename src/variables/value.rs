//! Lossless runtime bytes with a separate, escaped text presentation.

use std::borrow::{Borrow, Cow};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, LazyLock, OnceLock};

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
    Shared(Arc<SharedValue>),
}

// Leave room for the length and enum tag. Four machine words cover most
// qualified TX names without growing the collection buckets.
const INLINE_CAPACITY: usize = 4 * std::mem::size_of::<usize>() - 2;
// Keep ordinary owned strings movable. A match can retain a large header or
// body field in several snapshots, where copying its buffer costs more.
const SHARED_TEXT_MIN: usize = 1024;

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
            Self::Shared(value) => match value.as_ref() {
                SharedValue::Text(text) => f.debug_tuple("Text").field(text).finish(),
                SharedValue::Binary(value) => f
                    .debug_struct("Binary")
                    .field("bytes", &value.bytes)
                    .field("display", &value.display_text())
                    .finish(),
            },
        }
    }
}

// Large text and binary matches can occur in several transaction snapshots.
enum SharedValue {
    Text(String),
    Binary(BinaryValue),
}

impl SharedValue {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(text) => text.as_bytes(),
            Self::Binary(value) => &value.bytes,
        }
    }

    fn display_text(&self) -> &str {
        match self {
            Self::Text(text) => text,
            Self::Binary(value) => value.display_text(),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Text(text) => text.into_bytes(),
            Self::Binary(value) => value.bytes,
        }
    }
}

struct BinaryValue {
    bytes: Vec<u8>,
    display: OnceLock<String>,
}

/// A byte's standard ASCII escape takes at most four bytes (for example, `\xff`).
struct AsciiEscape {
    bytes: [u8; 4],
    len: u8,
}

static ASCII_ESCAPES: LazyLock<[AsciiEscape; 256]> = LazyLock::new(|| {
    std::array::from_fn(|i| {
        let escape = std::ascii::escape_default(i as u8);
        let len = escape.len() as u8;
        let mut bytes = [0; 4];
        for (dst, byte) in bytes.iter_mut().zip(escape) {
            *dst = byte;
        }
        AsciiEscape { bytes, len }
    })
});

fn needs_ascii_escape(byte: u8) -> bool {
    !matches!(byte, b' '..=b'~') || matches!(byte, b'\'' | b'"' | b'\\')
}

impl BinaryValue {
    fn escaped(bytes: &[u8]) -> String {
        const BLOCK: usize = 256;
        let escapes = &*ASCII_ESCAPES;
        let mut output = Vec::with_capacity(bytes.len());
        let mut buffer = [0; BLOCK * 4];
        for block in bytes.chunks(BLOCK) {
            // Reject a non-ASCII block cheaply. For printable text a bitwise
            // reduction lets the compiler check multiple bytes at a time.
            if !needs_ascii_escape(block[0])
                && block.is_ascii()
                && !block
                    .iter()
                    .fold(false, |any, &byte| any | needs_ascii_escape(byte))
            {
                output.extend_from_slice(block);
                continue;
            }
            let mut written = 0;
            for &byte in block {
                let escape = &escapes[usize::from(byte)];
                // Write the padded entry. The next write starts at the end of
                // the actual escape, and each input byte has four bytes of room.
                buffer[written..written + 4].copy_from_slice(&escape.bytes);
                written += usize::from(escape.len);
            }
            output.extend_from_slice(&buffer[..written]);
        }
        String::from_utf8(output).expect("ASCII escape table contains only ASCII")
    }

    fn display_text(&self) -> &str {
        self.display.get_or_init(|| Self::escaped(&self.bytes))
    }
}

impl ByteValue {
    pub(crate) fn decimal(value: i64) -> Self {
        match value {
            0..=9 => Self::from(&[b'0' + value as u8][..]),
            _ => Self::from(value.to_string()),
        }
    }

    fn binary(bytes: Vec<u8>) -> Self {
        Self {
            storage: Storage::Shared(Arc::new(SharedValue::Binary(BinaryValue {
                bytes,
                display: OnceLock::new(),
            }))),
        }
    }

    /// The original bytes; use this accessor for every engine operation.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.storage {
            Storage::Short(text) => text.as_bytes(),
            Storage::Text(value) => value.as_bytes(),
            Storage::Shared(value) => value.as_bytes(),
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
            Storage::Shared(value) => value.display_text(),
        }
    }

    /// Move both audit representations out, reusing the escaped binary display.
    pub(crate) fn into_display_and_bytes(self) -> (String, Vec<u8>) {
        match self.storage {
            Storage::Short(text) => (text.as_str().to_owned(), text.as_bytes().to_vec()),
            Storage::Text(text) => (text.clone(), text.into_bytes()),
            Storage::Shared(value) => match Arc::try_unwrap(value) {
                Ok(SharedValue::Text(text)) => (text.clone(), text.into_bytes()),
                Ok(SharedValue::Binary(value)) => {
                    let display = value
                        .display
                        .into_inner()
                        .unwrap_or_else(|| BinaryValue::escaped(&value.bytes));
                    (display, value.bytes)
                }
                Err(value) => {
                    // A single remaining owner often holds MATCHED_VAR until
                    // the transaction ends. Produce the audit string directly
                    // unless other readers already use the cached presentation.
                    let display = match value.as_ref() {
                        SharedValue::Binary(binary)
                            if Arc::strong_count(&value) == 2 && binary.display.get().is_none() =>
                        {
                            BinaryValue::escaped(&binary.bytes)
                        }
                        _ => value.display_text().to_owned(),
                    };
                    (display, value.as_bytes().to_vec())
                }
            },
        }
    }

    /// Move out the original bytes without replacing invalid UTF-8.
    pub fn into_bytes(self) -> Vec<u8> {
        match self.storage {
            Storage::Short(text) => text.as_bytes().to_vec(),
            Storage::Text(value) => value.into_bytes(),
            Storage::Shared(value) => Arc::try_unwrap(value)
                .map_or_else(|value| value.as_bytes().to_vec(), SharedValue::into_bytes),
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
        } else if value.len() >= SHARED_TEXT_MIN {
            Storage::Shared(Arc::new(SharedValue::Text(value)))
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

impl From<Cow<'_, [u8]>> for ByteValue {
    fn from(value: Cow<'_, [u8]>) -> Self {
        match value {
            Cow::Borrowed(bytes) => bytes.into(),
            Cow::Owned(bytes) => bytes.into(),
        }
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
    fn text_storage_boundaries_preserve_borrowed_and_owned_representations() {
        for size in [
            2,
            INLINE_CAPACITY - 1,
            INLINE_CAPACITY,
            INLINE_CAPACITY + 1,
            SHARED_TEXT_MIN - 1,
            SHARED_TEXT_MIN,
            SHARED_TEXT_MIN + 1,
        ] {
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
                    value.clone().into_display_and_bytes(),
                    (text.clone(), text.as_bytes().to_vec())
                );
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
    fn binary_audit_populates_the_shared_display_only_with_multiple_remaining_owners() {
        let bytes = b"x\xff";
        let value = ByteValue::from(bytes.as_slice());
        let Storage::Shared(shared) = &value.storage else {
            panic!("binary storage expected");
        };
        let SharedValue::Binary(binary) = shared.as_ref() else {
            panic!("binary storage expected");
        };
        let expected = (r"x\xff".to_owned(), bytes.to_vec());
        assert_eq!(value.clone().into_display_and_bytes(), expected);
        assert!(binary.display.get().is_none());

        let reader = value.clone();
        assert_eq!(value.clone().into_display_and_bytes(), expected);
        assert_eq!(binary.display.get(), Some(&expected.0));
        assert_eq!(reader.into_display_and_bytes(), expected);
        assert_eq!(value.display_text(), expected.0);
    }

    #[test]
    fn binary_display_matches_standard_escaping_across_blocks() {
        let mut bytes: Vec<u8> = (0..=255).collect();
        bytes.extend([b'a'; 512]);
        bytes.extend([b'\\', b'"', b'\'', b'\t', b'\r', b'\n', 0x7f, 0xff]);
        bytes.extend([0xff; 257]);
        for len in [0, 1, 15, 16, 17, 255, 256, 257, 511, 512, 769, bytes.len()] {
            let input = &bytes[..len];
            assert_eq!(
                BinaryValue::escaped(input),
                input.escape_ascii().to_string()
            );
        }
    }

    #[test]
    fn printable_block_keeps_standard_escaping_for_each_byte() {
        let mut bytes = [b'a'; 256];
        for index in [0, 1, 15, 16, 127, 255] {
            for byte in 0..=255 {
                bytes[index] = byte;
                assert_eq!(
                    BinaryValue::escaped(&bytes),
                    bytes.escape_ascii().to_string()
                );
            }
            bytes[index] = b'a';
        }
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
