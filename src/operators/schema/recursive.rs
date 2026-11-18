//! Evaluate recursive applicators bottom-up. An instruction that stays on the
//! same instance runs after its dependencies. One that selects a child reads
//! the already completed row for that child. Neither traversal grows the stack.
use super::arena::{child, Arena};
use super::projection::Projection;
use jsonschema::Validator;
use serde_json::{Map, Value};
use std::collections::HashMap;

mod compile;

type Id = usize;

pub(super) struct Program {
    states: Vec<State>,
    order: Vec<Id>,
    annotations: bool,
    names: bool,
}

#[derive(Default)]
struct State {
    leaf: Option<(Validator, Projection)>,
    same: Vec<Op>,
    object: Object,
    array: Array,
}

enum Op {
    All(Vec<Id>),
    Any(Vec<Id>),
    One(Vec<Id>),
    Not(Id),
    If(Id, Option<Id>, Option<Id>),
    Dependent(String, Id),
}

#[derive(Default)]
struct Object {
    properties: HashMap<String, Id>,
    patterns: Vec<(Validator, Id)>,
    additional: Option<Id>,
    names: Option<Id>,
    unevaluated: Option<Id>,
}

#[derive(Default)]
struct Array {
    prefix: Vec<Id>,
    rest: Option<Id>,
    contains: Option<(Id, u64, u64)>,
    unevaluated: Option<Id>,
}

#[derive(Default)]
struct Coverage {
    all: bool,
    positions: Vec<usize>,
}

impl Coverage {
    fn push(&mut self, pos: usize) {
        if !self.all {
            self.positions.push(pos);
        }
    }
    fn mark_all(&mut self) {
        self.all = true;
        self.positions = Vec::new();
    }
}

struct Results {
    count: usize,
    truths: Vec<u64>,
    marks: HashMap<usize, Coverage>,
}

impl Results {
    fn valid(&self, node: Id, state: Id) -> bool {
        let index = node * self.count + state;
        self.truths[index / 64] & (1u64 << (index % 64)) != 0
    }
    fn inherit(&self, node: Id, state: Id, seen: &mut Coverage) -> bool {
        let index = node * self.count + state;
        if !self.valid(node, state) {
            return false;
        }
        if let Some(fields) = self.marks.get(&index) {
            if fields.all {
                seen.mark_all();
            } else if !seen.all {
                seen.positions.extend_from_slice(&fields.positions);
            }
        }
        true
    }
}

impl Object {
    fn active(&self) -> bool {
        !(self.properties.is_empty()
            && self.patterns.is_empty()
            && self.additional.is_none()
            && self.names.is_none()
            && self.unevaluated.is_none())
    }
}

impl Array {
    fn active(&self) -> bool {
        !(self.prefix.is_empty()
            && self.rest.is_none()
            && self.contains.is_none()
            && self.unevaluated.is_none())
    }
}

impl State {
    fn evaluate(
        &self,
        arena: &Arena,
        node: Id,
        results: &Results,
        track: bool,
        seen: &mut Coverage,
    ) -> bool {
        let value = &arena.nodes()[node];
        if let Some((validator, projection)) = &self.leaf {
            let valid = if value.is_array() || value.is_object() {
                validator.is_valid(&projection.project_node(arena, node))
            } else {
                validator.is_valid(value)
            };
            if !valid {
                return false;
            }
        }
        for op in &self.same {
            let ok = match op {
                Op::All(ids) => ids.iter().all(|&s| results.inherit(node, s, seen)),
                Op::Any(ids) => {
                    if track {
                        let mut valid = false;
                        for &s in ids {
                            valid |= results.inherit(node, s, seen);
                        }
                        valid
                    } else {
                        ids.iter().any(|&s| results.valid(node, s))
                    }
                }
                Op::One(ids) => {
                    ids.iter()
                        .filter(|&&s| results.inherit(node, s, seen))
                        .count()
                        == 1
                }
                Op::Not(s) => !results.valid(node, *s),
                Op::If(condition, yes, no) => {
                    let branch = if results.inherit(node, *condition, seen) {
                        yes
                    } else {
                        no
                    };
                    branch.is_none_or(|s| results.inherit(node, s, seen))
                }
                Op::Dependent(key, s) => {
                    value.get(key).is_none() || results.inherit(node, *s, seen)
                }
            };
            if !ok {
                return false;
            }
        }

        if let Some(fields) = value.as_object().filter(|_| self.object.active()) {
            for (pos, (key, id)) in fields.iter().enumerate() {
                if self
                    .object
                    .names
                    .is_some_and(|s| !results.valid(arena.name(key), s))
                {
                    return false;
                }
                let mut applied = false;
                let id = child(id);
                if let Some(&s) = self.object.properties.get(key) {
                    if !results.valid(id, s) {
                        return false;
                    }
                    applied = true;
                }
                if !self.object.patterns.is_empty() {
                    let key = Value::String(key.clone());
                    for (pattern, s) in &self.object.patterns {
                        if pattern.is_valid(&key) {
                            if !results.valid(id, *s) {
                                return false;
                            }
                            applied = true;
                        }
                    }
                }
                if !applied {
                    if let Some(s) = self.object.additional {
                        if !results.valid(id, s) {
                            return false;
                        }
                        applied = true;
                    }
                }
                if track && applied {
                    seen.push(pos);
                }
            }
            if let Some(s) = self.object.unevaluated {
                return check_remaining(fields.values(), s, results, seen);
            }
        }
        if let Some(items) = value.as_array().filter(|_| self.array.active()) {
            let mut count = 0;
            for (pos, id) in items.iter().enumerate() {
                let id = child(id);
                let mut applied = false;
                if let Some(s) = self.array.prefix.get(pos).copied().or(self.array.rest) {
                    if !results.valid(id, s) {
                        return false;
                    }
                    applied = true;
                }
                if let Some((s, _, _)) = self.array.contains {
                    if results.valid(id, s) {
                        count += 1;
                        applied = true;
                    }
                }
                if track && applied {
                    seen.push(pos);
                }
            }
            if let Some((_, min, max)) = self.array.contains {
                if count < min || count > max {
                    return false;
                }
            }
            if let Some(s) = self.array.unevaluated {
                return check_remaining(items.iter(), s, results, seen);
            }
        }
        true
    }
}

fn check_remaining<'a>(
    children: impl ExactSizeIterator<Item = &'a Value>,
    state: Id,
    results: &Results,
    seen: &mut Coverage,
) -> bool {
    if seen.all {
        return true;
    }
    seen.positions.sort_unstable();
    if children.enumerate().any(|(pos, id)| {
        seen.positions.binary_search(&pos).is_err() && !results.valid(child(id), state)
    }) {
        return false;
    }
    seen.mark_all();
    true
}

impl Program {
    pub(super) fn is_valid(&self, input: &[u8]) -> bool {
        let Some(arena) = Arena::parse(input, self.names) else {
            return false;
        };
        let n = self.states.len();
        let Some(size) = arena.nodes().len().checked_mul(n) else {
            return false;
        };
        let mut results = Results {
            count: n,
            truths: vec![0; size.div_ceil(64)],
            marks: HashMap::new(),
        };
        for (node, value) in arena.nodes().iter().enumerate() {
            let width = value
                .as_array()
                .map(Vec::len)
                .or_else(|| value.as_object().map(Map::len))
                .unwrap_or(0);
            for &state in &self.order {
                let mut seen = Coverage::default();
                if self.states[state].evaluate(&arena, node, &results, self.annotations, &mut seen)
                {
                    let index = node * n + state;
                    results.truths[index / 64] |= 1u64 << (index % 64);
                    if !seen.positions.is_empty() {
                        seen.positions.sort_unstable();
                        seen.positions.dedup();
                        if seen.positions.len() == width {
                            seen.mark_all();
                        }
                    }
                    if width != 0 && (seen.all || !seen.positions.is_empty()) {
                        results.marks.insert(index, seen);
                    }
                }
            }
        }
        results.valid(arena.root, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::schema::documents::SchemaDocuments;
    use jsonschema::Draft;
    use serde_json::json;

    fn program(schema: &Value) -> Program {
        let base = url::Url::parse("file:///policy/schema.json").unwrap();
        let draft = Draft::default().detect(schema);
        Program::compile(schema, &base, &SchemaDocuments::new(), draft)
            .unwrap_or_else(|| panic!("no program for {schema}"))
    }

    #[test]
    fn heap_results_match_the_compiled_validator_on_shallow_inputs() {
        let mut values = vec![
            json!(null),
            json!(true),
            json!(0),
            json!(2),
            json!("hi"),
            json!([]),
            json!({}),
        ];
        for _ in 0..3 {
            for v in values.clone() {
                values.extend([
                    json!([v]),
                    json!([v, 2]),
                    json!({"p":v}),
                    json!({"q":v,"p":[2]}),
                ]);
            }
        }
        let schemas = [
            json!({"$ref":"#/$defs/n","$defs":{"n":{"anyOf":[{"type":"integer"},{"type":"array","items":{"$ref":"#/$defs/n"}}]}}}),
            json!({"if":{"type":"object"},"then":{"allOf":[{"properties":{"p":{"$ref":"#"}}}],"unevaluatedProperties":false},"else":{"type":["integer","boolean"]}}),
            json!({"properties":{"p":true},"patternProperties":{"^p":{"type":"array"}},"additionalProperties":{"type":"integer"}}),
            json!({"anyOf":[{"properties":{"p":true}},{"properties":{"q":true}}],"unevaluatedProperties":false}),
            json!({"oneOf":[{"required":["p"],"properties":{"p":true}},{"required":["q"],"properties":{"q":true}}],"unevaluatedProperties":false}),
            json!({"not":{"properties":{"q":{"type":"string"}}},"unevaluatedProperties":false}),
            json!({"if":{"required":["p"],"properties":{"p":true}},"then":{"properties":{"q":{"type":"array"}}},"unevaluatedProperties":false}),
            json!({"dependentSchemas":{"q":{"properties":{"p":true}}},"unevaluatedProperties":false}),
            json!({"contains":{"type":"integer"},"minContains":0,"maxContains":1,"unevaluatedItems":{"type":"array"}}),
            json!({"prefixItems":[true],"items":{"enum":[0,2]},"uniqueItems":true}),
            json!({"allOf":[{"contains":{"const":2}},{"prefixItems":[true]}],"unevaluatedItems":false}),
            json!({"propertyNames":{"not":{"const":"q"}},"required":["p"],"minProperties":1}),
            json!({"$schema":"http://json-schema.org/draft-07/schema#","contentMediaType":"application/json"}),
            json!({"dependencies":{"p":["q"],"q":{"properties":{"p":{"type":"array"}}}}}),
            json!({"$schema":"http://json-schema.org/draft-07/schema#","$ref":"#/definitions/n","not":{},"definitions":{"n":{"items":[{"type":"integer"}],"additionalItems":false}}}),
            json!({"$schema":"http://json-schema.org/draft-07/schema#","dependencies":{"p":["q"],"q":{"properties":{"p":{"type":"array"}}}}}),
            json!({"$schema":"https://json-schema.org/draft/2019-09/schema","items":[true],"additionalItems":{"type":"integer"},"unevaluatedItems":false}),
            json!({"$schema":"http://json-schema.org/draft-04/schema#","properties":{"p":{"type":"array"}},"additionalProperties":false}),
        ];
        for schema in schemas {
            let native = jsonschema::validator_for(&schema).unwrap();
            let heap = program(&schema);
            for v in &values {
                assert_eq!(
                    heap.is_valid(&serde_json::to_vec(v).unwrap()),
                    native.is_valid(v),
                    "{schema} {v}"
                );
            }
        }
    }

    #[test]
    fn recursive_graph_runs_on_a_small_stack_and_observes_every_wide_member() {
        std::thread::Builder::new().stack_size(1024*1024).spawn(||{
            let schema=json!({"anyOf":[{"type":"integer"},{"type":"array","items":{"$ref":"#"}},{"type":"object","propertyNames":{"minLength":1},"additionalProperties":{"$ref":"#"}}]});
            let heap=program(&schema);
            for (levels,tail,ok) in [(10_000,"2",true),(10_000,"false",false),(10_001,"2",false)] {
                let doc=format!("{}{tail}{}", "[".repeat(levels), "]".repeat(levels));
                assert_eq!(heap.is_valid(doc.as_bytes()),ok);
            }
            let prefix=(0..4096).map(|i|format!(r#""k{i}":[2]"#)).collect::<Vec<_>>().join(",");
            for (last,ok) in [("2",true),("false",false)] {
                let doc=format!(r#"{{{prefix},"last":[{last}]}}"#);
                assert_eq!(heap.is_valid(doc.as_bytes()),ok);
            }
        }).unwrap().join().unwrap();
    }
}
