// This module includes the auto-generated SQL data from build.rs

// Include the generated data at compile time
#[cfg(build_generated)]
include!(concat!(env!("OUT_DIR"), "/sqli_data.rs"));

// Fallback to committed data when submodule is not available (e.g., on crates.io)
#[cfg(not(build_generated))]
include!("generated_data.rs");

// Fingerprints share the '0' prefix. Ordinary tokenizer lookups only search
// entries with the same initial byte, retaining the original sorted table.
const WORD_START: [usize; 257] = {
    let mut starts = [0; 257];
    let mut pos = 0;
    let mut byte = 0;
    while byte < 256 {
        starts[byte] = pos;
        while pos < SQL_KEYWORDS.len() && SQL_KEYWORDS[pos].word.as_bytes()[0] == byte as u8 {
            pos += 1;
        }
        byte += 1;
    }
    starts[256] = pos;
    starts
};

use crate::sqli::TokenType;

/// Look up a word in the keyword table, distinguishing "not present" (`None`)
/// from "present, typed as bareword" (`Some(Bareword)`).
///
/// The C library's `lookup` returns `CHAR_NULL` only when the word is absent,
/// and multi-word keywords such as `LOCK IN` and `LOCK IN SHARE` are stored in
/// the table with the bareword type `n`. Word merging keys off presence, not
/// type, so this distinction is what lets a multi-word keyword fold one word at
/// a time.
pub fn lookup_word_type(word: &str) -> Option<TokenType> {
    let mut buffer = [0u8; 32];
    let upper = buffer.get_mut(..word.len())?;
    upper.copy_from_slice(word.as_bytes());
    upper.make_ascii_uppercase();
    let first = usize::from(*upper.first()?);
    let words = &SQL_KEYWORDS[WORD_START[first]..WORD_START[first + 1]];
    let idx = words
        .binary_search_by(|k| k.word.as_bytes().cmp(upper))
        .ok()?;
    Some(match words[idx].token_type {
        b'k' => TokenType::Keyword,
        b'f' => TokenType::Function,
        b'U' => TokenType::Union,
        b'E' => TokenType::Expression,
        b'T' => TokenType::Tsql,
        b't' => TokenType::SqlType,
        b'o' => TokenType::Operator,
        b'&' => TokenType::LogicOperator,
        b'v' => TokenType::Variable,
        b'1' => TokenType::Number,
        b'A' => TokenType::Collate,
        b'B' => TokenType::Group,
        b'F' => TokenType::Fingerprint,
        _ => TokenType::Bareword,
    })
}

pub fn lookup_word(word: &str) -> TokenType {
    lookup_word_type(word).unwrap_or(TokenType::Bareword)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_ranges_cover_every_keyword_and_fingerprint() {
        assert_eq!(WORD_START[256], SQL_KEYWORDS.len());
        for keyword in SQL_KEYWORDS {
            let first = usize::from(keyword.word.as_bytes()[0]);
            assert!(SQL_KEYWORDS[WORD_START[first]..WORD_START[first + 1]]
                .binary_search_by_key(&keyword.word, |entry| entry.word)
                .is_ok());
            assert!(lookup_word_type(keyword.word).is_some());
        }
        assert!(lookup_word_type("").is_none());
    }
}
impl CharType {
    pub fn is_white(&self) -> bool {
        matches!(self, CharType::White)
    }
    
    pub fn is_word(&self) -> bool {
        matches!(self, CharType::Word | CharType::BWord)
    }
    
    pub fn is_string_start(&self) -> bool {
        matches!(self, CharType::String | CharType::BString | CharType::EString | 
                      CharType::NQString | CharType::QString | 
                      CharType::UString | CharType::XString)
    }
    
    pub fn is_operator(&self) -> bool {
        matches!(self, CharType::Op1 | CharType::Op2 | CharType::Unary)
    }
    
    pub fn is_number(&self) -> bool {
        matches!(self, CharType::Number)
    }
}

// Helper for getting character type
pub fn get_char_type(ch: u8) -> CharType {
    CHAR_MAP[ch as usize]
}