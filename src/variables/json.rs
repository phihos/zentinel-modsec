//! Duplicate-preserving, bounded JSON flattening for request arguments.
//!
//! Process containers one member at a time. Serde validates each scalar and
//! decodes JSON strings. Numbers use their original token, including trailing
//! zeros and exponent spelling. Completed members remain visible on error.

use super::HashMapCollection;
use serde::Deserialize;
use serde_json::{value::RawValue, Deserializer};
use std::borrow::Cow;

// Existing request processor limits. Array metadata has a separate entry cap
// and shares the byte budget with scalar arguments, as in Coraza 3.8.1.
const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 64;

struct Parser<'a, 'out> {
    remaining: &'a [u8],
    path: String,
    args: &'out mut HashMapCollection,
    remaining_bytes: usize,
    leaves: usize,
    lengths: usize,
}

pub(super) fn parse(body: &[u8], args: &mut HashMapCollection) -> Result<(), String> {
    if body.is_empty() {
        return Ok(());
    }
    let mut parser = Parser {
        remaining: body,
        path: "json".into(),
        args,
        remaining_bytes: body.len().saturating_mul(8).max(4096),
        leaves: 0,
        lengths: 0,
    };
    match parser.peek() {
        Some(b'{' | b'[') => parser.value(0)?,
        // The reference represents a top-level scalar as a one-member array.
        Some(_) => {
            parser.path.push_str(".0");
            parser.value(0)?;
            parser.path.truncate(4);
            parser.array_length(1)?;
        }
        None => return Err(syntax("expected a JSON value")),
    }
    if parser.peek().is_some() {
        return Err(syntax("trailing characters"));
    }
    Ok(())
}

fn syntax(message: impl std::fmt::Display) -> String {
    format!("JSON parsing error: {message}")
}

impl<'a> Parser<'a, '_> {
    fn peek(&mut self) -> Option<u8> {
        while matches!(self.remaining.first(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.remaining = &self.remaining[1..];
        }
        self.remaining.first().copied()
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.remaining = &self.remaining[1..];
            return true;
        }
        false
    }

    fn token<T: Deserialize<'a>>(&mut self) -> Result<T, String> {
        let mut tokens = Deserializer::from_slice(self.remaining).into_iter::<T>();
        let token = tokens
            .next()
            .ok_or_else(|| syntax("unexpected end"))?
            .map_err(syntax)?;
        self.remaining = &self.remaining[tokens.byte_offset()..];
        Ok(token)
    }

    fn value(&mut self, depth: usize) -> Result<(), String> {
        match self.peek() {
            Some(b'{' | b'[') => {
                if depth >= MAX_DEPTH {
                    return Err(syntax("maximum container depth reached"));
                }
                self.container(depth + 1)
            }
            Some(_) => {
                if self.leaves >= MAX_ENTRIES {
                    return Err(syntax("argument count limit reached"));
                }
                let value = if self.peek() == Some(b'"') {
                    Cow::Owned(self.token::<String>()?)
                } else {
                    let raw: &RawValue = self.token()?;
                    Cow::Borrowed(if raw.get() == "null" { "" } else { raw.get() })
                };
                self.store(value)?;
                self.leaves += 1;
                Ok(())
            }
            None => Err(syntax("expected a JSON value")),
        }
    }

    fn container(&mut self, depth: usize) -> Result<(), String> {
        let array = self.remaining[0] == b'[';
        let close = if array { b']' } else { b'}' };
        self.remaining = &self.remaining[1..];
        if self.consume(close) {
            return Ok(());
        }
        let mut count = 0;
        let parent_len = self.path.len();
        loop {
            self.path.push('.');
            if array {
                use std::fmt::Write;
                write!(&mut self.path, "{count}").expect("writing a string is infallible");
            } else {
                self.peek();
                let key: String = self.token()?;
                self.path.push_str(&key);
                if !self.consume(b':') {
                    return Err(syntax("expected colon"));
                }
            }
            self.value(depth)?;
            self.path.truncate(parent_len);
            count += 1;
            if self.consume(close) {
                break;
            }
            if !self.consume(b',') {
                // A truncated array still exposes its completed elements and
                // their observed count, matching the pinned processor.
                if array && self.peek().is_none() {
                    self.array_length(count)?;
                }
                return Err(syntax("expected a comma or closing delimiter"));
            }
        }
        if array {
            self.array_length(count)?;
        }
        Ok(())
    }

    fn array_length(&mut self, count: usize) -> Result<(), String> {
        if self.lengths >= MAX_ENTRIES {
            return Err(syntax("array metadata count limit reached"));
        }
        self.store(Cow::Owned(count.to_string()))?;
        self.lengths += 1;
        Ok(())
    }

    fn store(&mut self, value: Cow<'_, str>) -> Result<(), String> {
        let cost = self.path.len().saturating_add(value.len());
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(cost)
            .ok_or_else(|| syntax("flattened form exceeds its byte budget"))?;
        self.args.add(self.path.clone(), value.into_owned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variables::Collection;

    fn flattened(input: &str) -> HashMapCollection {
        let mut args = HashMapCollection::new();
        parse(input.as_bytes(), &mut args).unwrap();
        args
    }

    #[test]
    fn duplicate_keys_keep_both_values() {
        assert_eq!(
            flattened(r#"{"a":"first","a":"second"}"#)
                .get("json.a")
                .unwrap(),
            ["first", "second"]
        );
    }

    #[test]
    fn object_keys_retain_input_order() {
        assert_eq!(
            flattened(r#"{"z":1,"a":2}"#).all(),
            [("json.z", "1"), ("json.a", "2")]
        );
    }

    #[test]
    fn top_level_scalars_keep_their_values() {
        for (input, value) in [
            ("null", ""),
            ("true", "true"),
            (r#""s""#, "s"),
            ("42", "42"),
        ] {
            assert_eq!(flattened(input).get("json.0").unwrap(), [value]);
        }
    }

    #[test]
    fn number_tokens_keep_precision_and_spelling() {
        for input in ["9007199254740993", "1.500", "1e+009", "1e900"] {
            assert_eq!(flattened(input).get("json.0").unwrap(), [input]);
        }
    }

    #[test]
    fn nested_structures_emit_scalar_values_and_array_length() {
        assert_eq!(
            flattened(r#"{"a":[1,{"b":null}]}"#).all(),
            [("json.a.0", "1"), ("json.a.1.b", ""), ("json.a", "2")]
        );
    }

    #[test]
    fn store_accepts_exact_byte_budget_and_preserves_previous_entries_on_error() {
        let mut args = HashMapCollection::new();
        let mut parser = Parser {
            remaining: &[],
            path: "json.x".into(),
            args: &mut args,
            remaining_bytes: 7,
            leaves: 0,
            lengths: 0,
        };
        parser.store(Cow::Borrowed("a")).unwrap();
        assert!(parser.store(Cow::Borrowed("b")).is_err());
        assert_eq!(args.all(), [("json.x", "a")]);
    }
}
