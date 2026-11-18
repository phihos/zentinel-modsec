//! Duplicate-preserving, bounded JSON flattening for request arguments.
//!
//! Process containers one member at a time. Serde validates each scalar and
//! decodes JSON strings. Numbers use their original token, including trailing
//! zeros and exponent spelling. Completed members remain visible on error.

use super::HashMapCollection;
use serde::Deserialize;
use serde_json::{value::RawValue, Deserializer};
use std::borrow::Cow;

pub(crate) const DEFAULT_DEPTH_LIMIT: usize = 1024;

// Keep the traversal on the heap even when a ruleset permits very deep JSON.
struct Container {
    array: bool,
    path_len: usize,
    count: usize,
    collect: bool,
    truncated: bool,
}

struct Parser<'a, 'out> {
    remaining: &'a [u8],
    path: String,
    args: &'out mut HashMapCollection,
    remaining_bytes: usize,
    argument_limit: usize,
    depth_limit: usize,
    truncated: &'out mut bool,
    leaves: usize,
    lengths: usize,
}

pub(crate) fn parse(
    body: &[u8],
    args: &mut HashMapCollection,
    argument_limit: usize,
    depth_limit: usize,
    truncated: &mut bool,
) -> Result<(), String> {
    if body.is_empty() {
        return Ok(());
    }
    let mut parser = Parser {
        remaining: body,
        path: "json".into(),
        args,
        remaining_bytes: body.len().saturating_mul(8).max(4096),
        argument_limit,
        depth_limit,
        truncated,
        leaves: 0,
        lengths: 0,
    };
    match parser.peek() {
        Some(b'{' | b'[') => parser.containers()?,
        // The reference represents a top-level scalar as a one-member array.
        Some(_) => {
            parser.path.push_str(".0");
            parser.scalar(true)?;
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

    fn scalar(&mut self, collect: bool) -> Result<(), String> {
        let value = if self.peek() == Some(b'"') {
            Cow::Owned(self.token::<String>()?)
        } else {
            let raw: &RawValue = self.token()?;
            Cow::Borrowed(if raw.get() == "null" { "" } else { raw.get() })
        };
        if collect {
            self.store(value)?;
            self.leaves += 1;
        }
        Ok(())
    }

    fn start_container(&mut self, collect: bool, stack: &mut Vec<Container>) -> Result<(), String> {
        if stack.len() >= self.depth_limit {
            return Err(syntax("maximum container depth reached"));
        }
        stack.push(Container {
            array: self.remaining[0] == b'[',
            path_len: self.path.len(),
            count: 0,
            collect,
            truncated: false,
        });
        self.remaining = &self.remaining[1..];
        Ok(())
    }

    fn containers(&mut self) -> Result<(), String> {
        let mut stack = Vec::new();
        self.start_container(true, &mut stack)?;
        while let Some(frame) = stack.last_mut() {
            self.path.truncate(frame.path_len);
            let close = if frame.array { b']' } else { b'}' };
            if self.consume(close) {
                if frame.array && frame.count != 0 && frame.collect && !frame.truncated {
                    frame.truncated = self.array_length(frame.count)?;
                }
                let truncated = frame.truncated;
                stack.pop();
                if let Some(parent) = stack.last_mut() {
                    parent.truncated |= truncated;
                }
                continue;
            }
            if frame.count != 0 && !self.consume(b',') {
                // The reference retains the observed count of an incomplete array.
                if frame.array && self.peek().is_none() && frame.collect && !frame.truncated {
                    self.array_length(frame.count)?;
                }
                return Err(syntax("expected a comma or closing delimiter"));
            }
            // Validate the entire document, including entries beyond the limit.
            // Dropped entries neither grow the flattened path nor consume its budget.
            let collect = frame.collect && self.leaves < self.argument_limit;
            if !collect {
                frame.truncated = true;
                *self.truncated = true;
            }
            if collect {
                self.path.push('.');
            }
            if frame.array {
                if collect {
                    use std::fmt::Write;
                    write!(&mut self.path, "{}", frame.count)
                        .expect("writing a string is infallible");
                }
            } else {
                self.peek();
                let key: String = self.token()?;
                if collect {
                    self.path.push_str(&key);
                }
                if !self.consume(b':') {
                    return Err(syntax("expected colon"));
                }
            }
            frame.count += 1;
            match self.peek() {
                Some(b'{' | b'[') => self.start_container(collect, &mut stack)?,
                Some(_) => self.scalar(collect)?,
                None => return Err(syntax("expected a JSON value")),
            }
        }
        Ok(())
    }

    // Array metadata has its own entry count and shares the flattening byte budget.
    fn array_length(&mut self, count: usize) -> Result<bool, String> {
        if self.lengths >= self.argument_limit {
            *self.truncated = true;
            return Ok(true);
        }
        self.store(Cow::Owned(count.to_string()))?;
        self.lengths += 1;
        Ok(false)
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
        parse(
            input.as_bytes(),
            &mut args,
            1000,
            DEFAULT_DEPTH_LIMIT,
            &mut false,
        )
        .unwrap();
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
            argument_limit: 1000,
            depth_limit: DEFAULT_DEPTH_LIMIT,
            truncated: &mut false,
            leaves: 0,
            lengths: 0,
        };
        parser.store(Cow::Borrowed("a")).unwrap();
        assert!(parser.store(Cow::Borrowed("b")).is_err());
        assert_eq!(args.all(), [("json.x", "a")]);
    }
}
