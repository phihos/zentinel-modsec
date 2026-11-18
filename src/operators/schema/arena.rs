//! Instance containers store child IDs. Parsing, traversal and destruction never
//! require one Rust call frame per input container.
use super::{intern_subtree, Value};
use std::collections::HashMap;

pub(super) struct Arena {
    nodes: Vec<Value>,
    pub(super) root: usize,
    names: HashMap<String, usize>,
}

impl Arena {
    pub(super) fn parse(input: &[u8], store_names: bool) -> Option<Self> {
        let raw = serde_json::from_slice::<&serde_json::value::RawValue>(input).ok()?;
        let mut ids = HashMap::new();
        let root = intern_subtree(raw.get().as_bytes(), &mut ids, store_names)?;
        let mut nodes = vec![Value::Null; ids.len()];
        for (node, index) in ids {
            nodes[index] = node;
        }
        let names = if store_names {
            nodes
                .iter()
                .enumerate()
                .filter_map(|(id, v)| Some((v.as_str()?.to_owned(), id)))
                .collect()
        } else {
            HashMap::new()
        };
        Some(Self { nodes, root, names })
    }

    pub(super) fn name(&self, key: &str) -> usize {
        self.names[key]
    }

    pub(super) fn nodes(&self) -> &[Value] {
        &self.nodes
    }

    // Only build the prefix proved sufficient for the particular validator.
    // The schema compiler bounds this recursion independently of input nesting.
    pub(super) fn project(&self, id: usize, depth: usize, unique: bool) -> Value {
        let node = &self.nodes[id];
        match node {
            Value::Array(items) if depth > 0 => Value::Array(
                items
                    .iter()
                    .map(|v| self.project(child(v), depth - 1, unique))
                    .collect(),
            ),
            Value::Object(fields) if depth > 0 => Value::Object(
                fields
                    .iter()
                    .map(|(key, v)| (key.clone(), self.project(child(v), depth - 1, unique)))
                    .collect(),
            ),
            Value::Array(_) => Value::Array(if unique { vec![id.into()] } else { vec![] }),
            Value::Object(_) => {
                let mut object = serde_json::Map::new();
                if unique {
                    object.insert(String::new(), id.into());
                }
                Value::Object(object)
            }
            scalar => scalar.clone(),
        }
    }
}

pub(super) fn child(id: &Value) -> usize {
    id.as_u64().expect("arena containers store child IDs") as usize
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
