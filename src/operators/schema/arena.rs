//! Instance containers store child IDs. Parsing, traversal and destruction never
//! require one Rust call frame per input container.
use serde_json::Value;
use std::collections::HashMap;

pub(super) const MAX_DOCUMENT_DEPTH: usize = 10_000;

pub(super) struct Arena {
    nodes: Vec<Value>,
    pub(super) root: usize,
    names: HashMap<String, usize>,
}

impl Arena {
    pub(super) fn parse(input: &[u8], store_names: bool) -> Option<Self> {
        let raw = serde_json::from_slice::<&serde_json::value::RawValue>(input).ok()?;
        let mut ids = HashMap::new();
        let mut names = HashMap::new();
        let root = intern_subtree(
            raw.get().as_bytes(),
            &mut ids,
            store_names.then_some(&mut names),
        )?;
        let mut nodes = vec![Value::Null; ids.len()];
        for (node, index) in ids {
            nodes[index] = node;
        }
        Some(Self { nodes, root, names })
    }

    pub(super) fn name(&self, key: &str) -> usize {
        self.names[key]
    }

    pub(super) fn nodes(&self) -> &[Value] {
        &self.nodes
    }
}

pub(super) fn child(id: &Value) -> usize {
    id.as_u64().expect("arena containers store child IDs") as usize
}

// Intern exact scalar values and containers of child IDs. Keys in this map
// are at most one container deep, including during hashing, equality and drop.
pub(super) fn intern_subtree(
    mut bytes: &[u8],
    ids: &mut HashMap<Value, usize>,
    mut names: Option<&mut HashMap<String, usize>>,
) -> Option<usize> {
    let mut frames = Vec::<(Value, Option<String>)>::new();
    while let Some((&byte, rest)) = bytes.split_first() {
        let mut node = match byte {
            b'{' | b'[' => {
                if frames.len() >= MAX_DOCUMENT_DEPTH {
                    return None;
                }
                let container = if byte == b'{' {
                    Value::Object(Default::default())
                } else {
                    Value::Array(Vec::new())
                };
                frames.push((container, None));
                bytes = rest;
                continue;
            }
            b'}' | b']' => {
                bytes = rest;
                frames.pop()?.0
            }
            b':' | b',' | b' ' | b'\t' | b'\n' | b'\r' => {
                bytes = rest;
                continue;
            }
            _ => {
                // The outer RawValue check already validated the grammar. Only
                // scalar tokens reach this decoder, so it never recurses.
                let mut tokens = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
                let value = tokens.next()?.ok()?;
                bytes = &bytes[tokens.byte_offset()..];
                if let Some((Value::Object(_), key @ None)) = frames.last_mut() {
                    *key = Some(value.as_str()?.to_owned());
                    if let Some(names) = names.as_deref_mut() {
                        let next = ids.len();
                        let id = *ids.entry(value).or_insert(next);
                        names.entry(key.as_ref()?.clone()).or_insert(id);
                    }
                    continue;
                }
                value
            }
        };
        // JSON Schema compares numeric values, so 1 and 1.0 are equal.
        if let Value::Number(n) = &node {
            if n.is_f64() {
                let f = n.as_f64()?;
                if f.fract() == 0.0 && f.to_bits() != (-0.0f64).to_bits() {
                    if (0.0..u64::MAX as f64).contains(&f) {
                        node = Value::from(f as u64);
                    } else if (i64::MIN as f64..0.0).contains(&f) {
                        node = Value::from(f as i64);
                    }
                }
            }
        }
        let next = ids.len();
        let id = *ids.entry(node).or_insert(next);
        match frames.last_mut() {
            Some((Value::Array(items), _)) => items.push(Value::from(id)),
            Some((Value::Object(fields), key)) => {
                fields.insert(key.take()?, Value::from(id));
            }
            None => return Some(id),
            _ => unreachable!("frames hold containers"),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interns_only_shallow_nodes_and_preserves_equivalent_subtrees() {
        let a = Arena::parse(
            br#"[[{"a":1,"b":0}],[{"b":0,"a":1.0}],[{"a":1,"b":-0.0}]]"#,
            false,
        )
        .unwrap();
        let children = a.nodes()[a.root].as_array().unwrap();
        assert_eq!(children[0], children[1]);
        assert_ne!(children[0], children[2]);
        assert!(Arena::parse(
            format!("{}1{}", "[".repeat(10_000), "]".repeat(10_000)).as_bytes(),
            false
        )
        .is_some());
        assert!(Arena::parse(
            format!("{}1{}", "[".repeat(10_001), "]".repeat(10_001)).as_bytes(),
            false
        )
        .is_none());
        assert!(Arena::parse(b"[1e400]", false).is_none());
    }
}
