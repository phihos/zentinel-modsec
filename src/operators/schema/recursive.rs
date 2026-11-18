//! Evaluate recursive applicators bottom-up. An instruction that stays on the
//! same instance runs after its dependencies. One that selects a child reads
//! the already completed row for that child. Neither traversal grows the stack.
use super::arena::{child, Arena};
use super::documents::SchemaDocuments;
use super::reference::{DynamicScope, LocalRefs};
use super::{projection::Projection, validation::validator_options};
use jsonschema::{Draft, Validator};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};

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

impl Op {
    fn inputs(&self) -> Vec<Id> {
        match self {
            Self::All(v) | Self::Any(v) | Self::One(v) => v.clone(),
            Self::If(i, t, e) => [Some(*i), *t, *e].into_iter().flatten().collect(),
            Self::Not(id) | Self::Dependent(_, id) => vec![*id],
        }
    }
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

struct Compiler<'a> {
    refs: LocalRefs<'a>,
    draft: Draft,
    scope: DynamicScope,
    queued: Vec<(&'a Value, DynamicScope)>,
    indices: HashMap<(*const Value, DynamicScope), Id>,
    incomplete: bool,
    unique_schemas: HashSet<*const Value>,
}

impl<'a> Compiler<'a> {
    fn id(&mut self, schema: &'a Value) -> Id {
        let Some(scope) = self.refs.enter_scope(&self.scope, schema) else {
            self.incomplete = true;
            return 0;
        };
        let key = (std::ptr::from_ref(schema), scope.clone());
        if let Some(&id) = self.indices.get(&key) {
            return id;
        }
        let id = self.queued.len();
        // Configuration can compose independent dynamic bindings combinatorially.
        // Bound the compiled graph before allocating any per-instance result rows.
        if !self.unique_schemas.insert(key.0) && id - self.unique_schemas.len() >= 16_384 {
            self.incomplete = true;
            return 0;
        }
        self.queued.push((schema, scope));
        self.indices.insert(key, id);
        id
    }

    fn list(&mut self, list: &'a Value) -> Option<Vec<Id>> {
        Some(list.as_array()?.iter().map(|s| self.id(s)).collect())
    }

    fn state(&mut self, schema: &'a Value) -> Option<State> {
        self.draft = self.refs.draft_for(schema)?;
        let mut state = State::default();
        let Some(map) = schema.as_object() else {
            state.leaf = Some((
                jsonschema::validator_for(schema).ok()?,
                Projection::default(),
            ));
            return Some(state);
        };
        if let Some(reference) = map.get("$ref") {
            let target = self.refs.resolve(schema, reference.as_str()?)?;
            state.same.push(Op::All(vec![self.id(target)]));
            if self.draft < Draft::Draft201909 {
                return Some(state);
            }
        }
        let modern = self.draft >= Draft::Draft201909;
        let prefix = self.draft >= Draft::Draft202012;
        let mut leaf = Map::new();
        for (key, value) in map {
            match key.as_str() {
                "$ref" | "$schema" | "$id" | "id" | "$anchor" | "$dynamicAnchor"
                | "$recursiveAnchor" | "$defs" | "definitions" | "$comment" => {}
                "$recursiveRef" if self.draft == Draft::Draft201909 => {
                    let target =
                        self.refs
                            .resolve_recursive_in(schema, value.as_str()?, &self.scope)?;
                    state.same.push(Op::All(vec![self.id(target)]));
                }
                "$dynamicRef" if prefix => {
                    let target =
                        self.refs
                            .resolve_dynamic_in(schema, value.as_str()?, &self.scope)?;
                    state.same.push(Op::All(vec![self.id(target)]));
                }
                // A declaration documents a meta-schema's vocabularies. The
                // active validation dialect comes from the schema's $schema.
                "$vocabulary" if !modern || standard_vocabularies(value, self.draft) => {}
                "$vocabulary" => return None,
                "allOf" => state.same.push(Op::All(self.list(value)?)),
                "anyOf" => state.same.push(Op::Any(self.list(value)?)),
                "oneOf" => state.same.push(Op::One(self.list(value)?)),
                "not" => state.same.push(Op::Not(self.id(value))),
                "if" if self.draft >= Draft::Draft7 => state.same.push(Op::If(
                    self.id(value),
                    map.get("then").map(|v| self.id(v)),
                    map.get("else").map(|v| self.id(v)),
                )),
                "then" | "else" => {}
                "dependentSchemas" if modern => {
                    for (name, s) in value.as_object()? {
                        state.same.push(Op::Dependent(name.clone(), self.id(s)));
                    }
                }
                "dependencies" => {
                    let mut required = Map::new();
                    for (name, s) in value.as_object()? {
                        if s.is_array() {
                            required.insert(name.clone(), s.clone());
                        } else {
                            state.same.push(Op::Dependent(name.clone(), self.id(s)));
                        }
                    }
                    if !required.is_empty() {
                        leaf.insert(key.clone(), Value::Object(required));
                    }
                }
                "properties" => {
                    state.object.properties = value
                        .as_object()?
                        .iter()
                        .map(|(k, v)| (k.clone(), self.id(v)))
                        .collect();
                }
                "patternProperties" => {
                    for (pattern, s) in value.as_object()? {
                        let check = jsonschema::options()
                            .with_draft(self.draft)
                            .build(&serde_json::json!({"pattern":pattern}))
                            .ok()?;
                        state.object.patterns.push((check, self.id(s)));
                    }
                }
                "additionalProperties" => state.object.additional = Some(self.id(value)),
                "propertyNames" if self.draft >= Draft::Draft6 => {
                    state.object.names = Some(self.id(value))
                }
                "unevaluatedProperties" if modern => {
                    state.object.unevaluated = Some(self.id(value))
                }
                "unevaluatedItems" if modern => state.array.unevaluated = Some(self.id(value)),
                "prefixItems" if prefix => state.array.prefix = self.list(value)?,
                "items" if !prefix && value.is_array() => {
                    state.array.prefix = self.list(value)?;
                    state.array.rest = map.get("additionalItems").map(|s| self.id(s));
                }
                "items" => state.array.rest = Some(self.id(value)),
                "additionalItems" => {}
                "contains" if self.draft >= Draft::Draft6 => {
                    let bound = |key, default| {
                        if modern {
                            map.get(key).and_then(Value::as_u64).unwrap_or(default)
                        } else {
                            default
                        }
                    };
                    state.array.contains = Some((
                        self.id(value),
                        bound("minContains", 1),
                        bound("maxContains", u64::MAX),
                    ));
                }
                "minContains" | "maxContains" => {}
                "contentMediaType" | "contentEncoding"
                    if matches!(self.draft, Draft::Draft6 | Draft::Draft7) =>
                {
                    leaf.insert(key.clone(), value.clone());
                }
                "type" | "format" | "pattern" | "minLength" | "maxLength" | "minimum"
                | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" | "multipleOf"
                | "minProperties" | "maxProperties" | "required" | "dependentRequired"
                | "minItems" | "maxItems" | "uniqueItems" | "const" | "enum" => {
                    leaf.insert(key.clone(), value.clone());
                }
                // Unknown and metadata keywords are annotations in the configured validator.
                _ => {}
            }
        }
        if !leaf.is_empty() {
            // Only property-name lists remain from legacy dependencies. They
            // observe the object's keys without inspecting any property value.
            let dependencies = leaf.remove("dependencies");
            let mut finite = Value::Object(leaf);
            let mut projection = Projection::for_schema(&finite)?;
            if let Some(dependencies) = dependencies {
                finite["dependencies"] = dependencies;
                projection.depth = projection.depth.max(1);
            }
            let validator = validator_options()
                .with_draft(self.draft)
                .build(&finite)
                .ok()?;
            state.leaf = Some((validator, projection));
        }
        Some(state)
    }
}

fn standard_vocabularies(declaration: &Value, draft: Draft) -> bool {
    let prefix = match draft {
        Draft::Draft201909 => "https://json-schema.org/draft/2019-09/vocab/",
        Draft::Draft202012 => "https://json-schema.org/draft/2020-12/vocab/",
        _ => return false,
    };
    declaration.as_object().is_some_and(|vocabularies| {
        vocabularies.iter().all(|(uri, required)| {
            required.is_boolean()
                && match uri.strip_prefix(prefix) {
                    Some("core" | "applicator" | "validation" | "meta-data" | "content") => true,
                    Some("format") => draft == Draft::Draft201909,
                    Some("unevaluated" | "format-assertion" | "format-annotation") => {
                        draft == Draft::Draft202012
                    }
                    _ => false,
                }
        })
    })
}

impl Program {
    pub(super) fn compile(
        root: &Value,
        base: &url::Url,
        documents: &SchemaDocuments,
        draft: Draft,
    ) -> Option<Self> {
        if draft == Draft::Unknown {
            return None;
        }
        let mut refs = LocalRefs::new(root, base)?;
        for (retrieval, document) in documents {
            refs.add_document(document, retrieval)?;
        }
        let mut compiler = Compiler {
            refs,
            draft,
            scope: DynamicScope::default(),
            incomplete: false,
            unique_schemas: HashSet::new(),
            queued: vec![],
            indices: HashMap::new(),
        };
        compiler.id(root);
        let mut states = Vec::new();
        while states.len() < compiler.queued.len() {
            let (schema, scope) = compiler.queued[states.len()].clone();
            compiler.scope = scope;
            states.push(compiler.state(schema)?);
            if compiler.incomplete {
                return None;
            }
        }

        // Only same-instance edges constrain the order. A cycle among these
        // never consumes an instance node and cannot use a structural fixpoint.
        let mut incoming = vec![0; states.len()];
        let mut users = vec![vec![]; states.len()];
        for (i, state) in states.iter().enumerate() {
            for dep in state
                .same
                .iter()
                .flat_map(Op::inputs)
                .collect::<HashSet<_>>()
            {
                incoming[i] += 1;
                users[dep].push(i);
            }
        }
        let mut ready: VecDeque<_> = incoming
            .iter()
            .enumerate()
            .filter(|(_, n)| **n == 0)
            .map(|(i, _)| i)
            .collect();
        let mut order = Vec::new();
        while let Some(i) = ready.pop_front() {
            order.push(i);
            for &user in &users[i] {
                incoming[user] -= 1;
                if incoming[user] == 0 {
                    ready.push_back(user);
                }
            }
        }
        if order.len() != states.len() {
            return None;
        }
        let annotations = states
            .iter()
            .any(|s| s.object.unevaluated.is_some() || s.array.unevaluated.is_some());
        let names = states.iter().any(|s| s.object.names.is_some());
        Some(Self {
            states,
            order,
            annotations,
            names,
        })
    }
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
