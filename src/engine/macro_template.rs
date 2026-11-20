//! Immutable SecLang operands. Values are resolved at the original action's execution point.
use super::{split_operator_macro, transaction::Transaction};
use crate::{parser::VariableName, variables::folded_key};
use std::borrow::Cow;

pub(super) struct MacroTemplate(Box<[Part]>);

enum Part {
    Literal(Box<[u8]>),
    Tx {
        key: Box<[u8]>,
        missing: Box<[u8]>,
    },
    Variable {
        name: VariableName,
        key: Box<[u8]>,
        token: Box<[u8]>,
    },
}

impl MacroTemplate {
    pub fn compile(mut text: &str) -> Self {
        let mut parts = Vec::new();
        while let Some((prefix, token, suffix)) = split_operator_macro(text) {
            if !prefix.is_empty() {
                parts.push(Part::Literal(prefix.as_bytes().into()));
            }
            let (collection, key) = token.split_once('.').unwrap_or((token, ""));
            let part = if collection.eq_ignore_ascii_case("tx") {
                Part::Tx {
                    key: folded_key(key.as_bytes()).into_owned().into(),
                    missing: token.as_bytes().into(),
                }
            } else if let Some(name) = VariableName::from_str(collection) {
                Part::Variable {
                    name,
                    key: key.as_bytes().into(),
                    token: token.as_bytes().into(),
                }
            } else if collection == token {
                Part::Tx {
                    key: folded_key(token.as_bytes()).into_owned().into(),
                    missing: Box::default(),
                }
            } else {
                Part::Literal(Box::default())
            };
            parts.push(part);
            text = suffix;
        }
        if !text.is_empty() {
            parts.push(Part::Literal(text.as_bytes().into()));
        }
        Self(parts.into())
    }

    pub fn expand<'a>(&'a self, tx: &'a Transaction) -> Cow<'a, [u8]> {
        let value = |part: &'a Part| match part {
            Part::Literal(bytes) => Cow::Borrowed(bytes.as_ref()),
            Part::Tx { key, missing } => {
                Cow::Borrowed(tx.tx().canonical_value(key).unwrap_or(missing))
            }
            Part::Variable { name, key, token } => {
                tx.variable_resolver().macro_value(*name, key, token)
            }
        };
        match &*self.0 {
            [] => Cow::Borrowed(b""),
            [single] => value(single),
            parts => {
                // Read each transaction variable once (some produce owned bytes or time values).
                let pieces: smallvec::SmallVec<[_; 4]> = parts.iter().map(value).collect();
                let mut bytes = Vec::with_capacity(pieces.iter().map(|piece| piece.len()).sum());
                for piece in pieces {
                    bytes.extend_from_slice(&piece);
                }
                Cow::Owned(bytes)
            }
        }
    }
}
