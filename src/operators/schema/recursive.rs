//! Evaluate recursive applicators bottom-up. An instruction that stays on the
//! same instance runs after its dependencies. One that selects a child reads
//! the already completed row for that child. Neither traversal grows the stack.
use super::arena::{child, Arena};
use super::reference::LocalRefs;
use super::{inspection_depth, UniqueItems};
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
    leaf: Option<(Validator, usize, bool)>,
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
    queued: Vec<&'a Value>,
    indices: HashMap<*const Value, Id>,
}

impl<'a> Compiler<'a> {
    fn id(&mut self, schema: &'a Value) -> Id {
        let key = std::ptr::from_ref(schema);
        if let Some(&id) = self.indices.get(&key) {
            return id;
        }
        let id = self.queued.len();
        self.queued.push(schema);
        self.indices.insert(key, id);
        id
    }

    fn list(&mut self, list: &'a Value) -> Option<Vec<Id>> {
        Some(list.as_array()?.iter().map(|s| self.id(s)).collect())
    }

    fn state(&mut self, schema: &'a Value) -> Option<State> {
        let mut state = State::default();
        let Some(map) = schema.as_object() else {
            state.leaf = Some((
                jsonschema::options()
                    .with_draft(self.draft)
                    .build(schema)
                    .ok()?,
                0,
                false,
            ));
            return Some(state);
        };
        if map
            .get("$schema")
            .and_then(Value::as_str)
            .is_some_and(|uri| Draft::from_schema_uri(uri) != self.draft)
        {
            return None;
        }
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
                "$recursiveRef" if self.draft == Draft::Draft201909 => return None,
                "$dynamicRef" if prefix => return None,
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
                "dependencies" if !modern => {
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
            let finite = Value::Object(leaf);
            let (depth, unique) = if finite.get("dependencies").is_some() {
                let mut rest = finite.clone();
                rest.as_object_mut()?.remove("dependencies");
                let (depth, unique) = inspection_depth(&rest)?;
                (depth.max(1), unique)
            } else {
                inspection_depth(&finite)?
            };
            let validator = jsonschema::options()
                .with_draft(self.draft)
                .should_validate_formats(false)
                .with_keyword("uniqueItems", |_, value, _| {
                    Ok(Box::new(UniqueItems(value.as_bool() == Some(true))))
                })
                .build(&finite)
                .ok()?;
            state.leaf = Some((validator, depth, unique));
        }
        Some(state)
    }
}

impl Program {
    pub(super) fn compile(root: &Value, base: &url::Url, draft: Draft) -> Option<Self> {
        if draft == Draft::Unknown {
            return None;
        }
        let mut compiler = Compiler {
            refs: LocalRefs::new(root, base)?,
            draft,
            queued: vec![],
            indices: HashMap::new(),
        };
        compiler.id(root);
        let mut states = Vec::new();
        while states.len() < compiler.queued.len() {
            let schema = compiler.queued[states.len()];
            states.push(compiler.state(schema)?);
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

struct Results {
    count: usize,
    truths: Vec<bool>,
    marks: HashMap<usize, Box<[usize]>>,
}

impl Results {
    fn valid(&self, node: Id, state: Id) -> bool {
        self.truths[node * self.count + state]
    }
    fn inherit(&self, node: Id, state: Id, seen: &mut Vec<usize>) -> bool {
        let index = node * self.count + state;
        if !self.truths[index] {
            return false;
        }
        if let Some(fields) = self.marks.get(&index) {
            seen.extend_from_slice(fields);
        }
        true
    }
}

impl State {
    fn evaluate(
        &self,
        arena: &Arena,
        node: Id,
        results: &Results,
        track: bool,
        seen: &mut Vec<usize>,
    ) -> bool {
        let value = &arena.nodes()[node];
        if let Some((validator, depth, unique)) = &self.leaf {
            let valid = if value.is_array() || value.is_object() {
                validator.is_valid(&arena.project(node, *depth, *unique))
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
                        ids.iter()
                            .fold(false, |found, &s| results.inherit(node, s, seen) || found)
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

        if let Some(fields) = value.as_object() {
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
        if let Some(items) = value.as_array() {
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
    seen: &mut Vec<usize>,
) -> bool {
    seen.sort_unstable();
    let len = children.len();
    if children
        .enumerate()
        .any(|(pos, id)| seen.binary_search(&pos).is_err() && !results.valid(child(id), state))
    {
        return false;
    }
    seen.clear();
    seen.extend(0..len);
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
            truths: vec![false; size],
            marks: HashMap::new(),
        };
        for node in 0..arena.nodes().len() {
            for &state in &self.order {
                let mut seen = Vec::new();
                if self.states[state].evaluate(&arena, node, &results, self.annotations, &mut seen)
                {
                    let index = node * n + state;
                    results.truths[index] = true;
                    if !seen.is_empty() {
                        seen.sort_unstable();
                        seen.dedup();
                        results.marks.insert(index, seen.into_boxed_slice());
                    }
                }
            }
        }
        results.valid(arena.root, 0)
    }
}
