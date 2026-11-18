//! Compile schema applicators and order their same-instance dependencies.
use super::{Id, Op, Program, State};
use crate::operators::schema::{
    documents::SchemaDocuments,
    projection::Projection,
    reference::{DynamicScope, LocalRefs},
    validation::validator_options,
};
use jsonschema::Draft;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};

impl Op {
    fn inputs(&self) -> Vec<Id> {
        match self {
            Self::All(v) | Self::Any(v) | Self::One(v) => v.clone(),
            Self::If(i, t, e) => [Some(*i), *t, *e].into_iter().flatten().collect(),
            Self::Not(id) | Self::Dependent(_, id) => vec![*id],
        }
    }
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
    pub(in crate::operators::schema) fn compile(
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
