//! Compiled ruleset for efficient rule matching.

use crate::error::{Error, Result};
use crate::operators::{compile_operator, Operator};
use crate::parser::{
    Action, DataAction, Directive, DisruptiveAction, FlowAction, MetadataAction, OperatorName,
    OperatorSpec, Parser, RuleEngineMode as ParserRuleEngineMode, Selection, SetVarValue,
    UpdateTargetById, VariableSpec,
};
use crate::transformations::TransformationPipeline;

use super::phase::Phase;
use crate::variables::{folded_key, ByteValue};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// A parsed SecRule ready for execution.
#[derive(Clone)]
pub struct CompiledRule {
    /// Rule ID.
    pub id: Option<String>,
    /// Rule phase.
    pub phase: Phase,
    /// Variable specifications.
    pub variables: Vec<VariableSpec>,
    /// Compiled operator.
    pub operator: Arc<dyn Operator>,
    /// Original operator specification (retained for runtime macro expansion).
    pub operator_spec: OperatorSpec,
    /// Whether operator is negated.
    pub operator_negated: bool,
    /// Transformation pipeline.
    pub transformations: TransformationPipeline,
    /// Actions to execute on match.
    pub actions: Vec<Action>,
    /// Whether this rule is part of a chain.
    pub is_chain: bool,
    /// Index of next rule in chain (if any).
    pub chain_next: Option<usize>,
}

impl std::fmt::Debug for CompiledRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRule")
            .field("id", &self.id)
            .field("phase", &self.phase)
            .field("variables", &self.variables)
            .field("operator_negated", &self.operator_negated)
            .field("is_chain", &self.is_chain)
            .finish()
    }
}

/// Rules grouped by phase for efficient processing.
pub struct Rules {
    /// Rules organized by phase.
    by_phase: [Vec<CompiledRule>; 5],
    /// Markers for skipAfter, as the index the marker occupies in *each*
    /// phase's rule list. A marker separates rules in every phase, not only in
    /// the phase of the rules written around it, so a phase-2 `skipAfter` must
    /// be able to resume at the phase-2 position of the same marker.
    markers: HashMap<String, HashMap<Phase, usize>>,
}

impl Rules {
    /// Create empty rules.
    pub fn new() -> Self {
        Self {
            by_phase: Default::default(),
            markers: HashMap::new(),
        }
    }

    /// Add a rule to a specific phase.
    pub fn add(&mut self, phase: Phase, rule: CompiledRule) {
        self.by_phase[phase.index()].push(rule);
    }

    /// Record a marker at the current end of every phase's rule list.
    pub fn add_marker(&mut self, name: String) {
        let positions = Phase::ALL
            .iter()
            .map(|&phase| (phase, self.for_phase(phase).len()))
            .collect();
        self.markers.insert(name, positions);
    }

    /// Get rules for a phase.
    pub fn for_phase(&self, phase: Phase) -> &[CompiledRule] {
        &self.by_phase[phase.index()]
    }

    /// Get a marker's position within one phase.
    pub fn marker(&self, name: &str, phase: Phase) -> Option<usize> {
        self.markers.get(name).and_then(|p| p.get(&phase)).copied()
    }

    /// Get total rule count.
    pub fn count(&self) -> usize {
        self.by_phase.iter().map(|v| v.len()).sum()
    }
}

impl Default for Rules {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-transaction positions reserved for frequent numeric TX lookups.
pub(super) const NUMERIC_TX_SLOTS: usize = 4;

pub(super) struct CompiledSetVar {
    pub action_index: usize,
    /// Literal TX keys can be folded once, when configuration updates are final.
    pub key: Option<ByteValue>,
    pub value: Option<ByteValue>,
}

/// Execution metadata for a finalized rule. The public parsed rule and its ordered
/// actions remain the source for captures, control arguments and audit messages.
#[derive(Default)]
pub(super) struct RuleDispatch {
    pub targets: super::target_indices::TargetIndices,
    /// First logical rule for which a miss on this target plan proves nothing.
    pub after_empty_targets: usize,
    pub selections: Box<[crate::variables::TargetSelection]>,
    /// Immutable numeric predicates match the full input without capture groups.
    pub numeric: Option<crate::operators::NumericComparison>,
    /// A static comparison of one literal TX member or its count, without transforms or exclusions.
    pub single_tx_numeric: bool,
    pub numeric_tx_slot: Option<u8>,
    pub dynamic: bool,
    pub within_tx_key: Option<Box<[u8]>>,
    pub capture: bool,
    pub multi_match: bool,
    /// Start of the suffix containing every control, or the action count.
    pub controls_from: usize,
    pub setvars: Box<[CompiledSetVar]>,
    pub removable_by_tag: bool,
    pub target_removable_by_tag: bool,
    pub flow: CompiledFlow,
    /// Last effective disruptive action, or the action count for pass.
    disruptive: usize,
}

#[derive(Default, Clone, Copy)]
pub(super) enum CompiledFlow {
    #[default]
    Next,
    Chain,
    Skip(u32),
    SkipAfter(usize),
}

impl RuleDispatch {
    fn compile(
        rule: &CompiledRule,
        rules: &Rules,
        programs: &crate::variables::SelectorPrograms,
        removed_tags: &HashSet<&str>,
        target_tags: &HashSet<&str>,
    ) -> Self {
        let dynamic = rule.operator_spec.argument.contains("%{")
            && !rule.operator_spec.name.uses_data_file()
            && rule.operator_spec.name != OperatorName::ValidateNid;
        let minimum = if !dynamic
            && !rule.operator_negated
            && rule.transformations.preserves_alphanumeric_width_bounds()
        {
            let [word, path] = rule.operator.short_token_minimums();
            [
                word,
                rule.operator.dotted_token_minimum(),
                if rule.transformations.preserves_token_width_bounds() {
                    path
                } else {
                    0
                },
            ]
        } else {
            [0; 3]
        };
        let mut dispatch = Self {
            targets: super::target_indices::TargetIndices::compile(&rule.variables, minimum),
            selections: rule
                .variables
                .iter()
                .map(|spec| crate::variables::TargetSelection::compile(spec, programs))
                .collect(),
            numeric: if dynamic {
                None
            } else {
                rule.operator.numeric_comparison()
            },
            controls_from: rule.actions.len(),
            disruptive: rule.actions.len(),
            dynamic,
            within_tx_key: if dynamic && rule.operator_spec.name == OperatorName::Within {
                super::split_operator_macro(&rule.operator_spec.argument).and_then(
                    |(prefix, name, suffix)| {
                        let (collection, key) = name.split_once('.')?;
                        (prefix.is_empty()
                            && suffix.is_empty()
                            && collection.eq_ignore_ascii_case("tx"))
                        .then(|| folded_key(key.as_bytes()).into_owned().into_boxed_slice())
                    },
                )
            } else {
                None
            },
            ..Self::default()
        };
        dispatch.single_tx_numeric = dispatch.numeric.is_some()
            && rule.transformations.is_empty()
            && matches!(rule.variables.as_slice(), [spec] if spec.name == crate::parser::VariableName::Tx && spec.exclusions.is_empty())
            && matches!(
                dispatch.selections[0].member,
                crate::variables::MemberSelector::Key(_)
            );
        let mut setvars = Vec::new();
        for (index, action) in rule.actions.iter().enumerate() {
            match action {
                Action::Data(DataAction::Capture) => {
                    dispatch.capture = !matches!(
                        rule.operator_spec.name,
                        OperatorName::GeoLookup | OperatorName::StrMatch
                    );
                }
                Action::Data(DataAction::SetVar(op)) => {
                    setvars.push(CompiledSetVar {
                        action_index: index,
                        value: match &op.value {
                            SetVarValue::Int(n) => Some(ByteValue::decimal(*n)),
                            SetVarValue::String(text) => Some(text.as_str().into()),
                            _ => None,
                        },
                        key: (!op.key.contains("%{"))
                            .then(|| ByteValue::from(folded_key(op.key.as_bytes()))),
                    });
                }
                Action::Control(_) => {
                    dispatch.controls_from = dispatch.controls_from.min(index);
                }
                Action::Metadata(MetadataAction::Tag(tag)) => {
                    dispatch.removable_by_tag |= removed_tags.contains(tag.as_str());
                    dispatch.target_removable_by_tag |= target_tags.contains(tag.as_str());
                }
                Action::Flow(FlowAction::MultiMatch) => dispatch.multi_match = true,
                Action::Flow(FlowAction::Chain) => dispatch.flow = CompiledFlow::Chain,
                Action::Flow(FlowAction::Skip(n)) => dispatch.flow = CompiledFlow::Skip(*n),
                Action::Flow(FlowAction::SkipAfter(marker)) => {
                    let destination = rules
                        .marker(marker, rule.phase)
                        .unwrap_or(rules.for_phase(rule.phase).len());
                    dispatch.flow = CompiledFlow::SkipAfter(destination);
                }
                Action::Disruptive(DisruptiveAction::Pass) => {
                    dispatch.disruptive = rule.actions.len()
                }
                Action::Disruptive(_) => dispatch.disruptive = index,
                _ => {}
            }
        }
        dispatch.setvars = setvars.into_boxed_slice();
        dispatch
    }

    fn numeric_tx_key(&self) -> Option<&[u8]> {
        if self.single_tx_numeric {
            if let crate::variables::MemberSelector::Key(key) = &self.selections[0].member {
                return Some(key);
            }
        }
        None
    }

    fn header_members<'a>(
        rule: &'a CompiledRule,
        selections: &'a [crate::variables::TargetSelection],
    ) -> impl Iterator<Item = (usize, &'a [u8])> {
        rule.variables
            .iter()
            .zip(selections)
            .take(super::target_indices::PREFIX)
            .enumerate()
            .filter_map(|(index, (spec, selection))| {
                if let crate::variables::MemberSelector::Key(key) = &selection.member {
                    if spec.name == crate::parser::VariableName::RequestHeaders && !spec.count_mode
                    {
                        return Some((index, key.as_ref()));
                    }
                }
                None
            })
    }

    /// Compile masks for the most frequently selected literal request headers.
    fn assign_header_slots(rules: &[CompiledRule], dispatch: &mut [Self]) -> Vec<Box<[u8]>> {
        let members = rules.iter().zip(dispatch.iter()).flat_map(|(rule, plan)| {
            Self::header_members(rule, &plan.selections).map(|(_, key)| key)
        });
        let keys = Self::frequent_keys(members, 4, super::target_indices::HEADER_SLOTS);
        for (rule, plan) in rules.iter().zip(dispatch) {
            for (index, key) in Self::header_members(rule, &plan.selections) {
                if let Some(slot) = keys.iter().position(|k| k.as_ref() == key) {
                    plan.targets.header_targets[slot] |= 1 << index;
                } else {
                    plan.targets.add_optional_header(index, key);
                }
            }
        }
        keys
    }

    fn frequent_keys<'a>(
        keys: impl Iterator<Item = &'a [u8]>,
        min_count: usize,
        limit: usize,
    ) -> Vec<Box<[u8]>> {
        let mut counts = HashMap::new();
        for key in keys {
            *counts.entry(key).or_insert(0) += 1;
        }
        let mut repeated: Vec<_> = counts
            .into_iter()
            .filter(|(_, count)| *count >= min_count)
            .collect();
        repeated.sort_unstable_by(|(a, n), (b, m)| m.cmp(n).then_with(|| a.cmp(b)));
        repeated
            .into_iter()
            .take(limit)
            .map(|(key, _)| key.into())
            .collect()
    }

    // Rank keys per phase so one-off guards cannot evict the positions used
    // by repeated comparisons. The transaction verifies a position on each hit.
    fn assign_numeric_tx_slots(dispatch: &mut [Self]) {
        let keys = Self::frequent_keys(
            dispatch.iter().filter_map(Self::numeric_tx_key),
            2,
            NUMERIC_TX_SLOTS,
        );
        for rule in dispatch {
            rule.numeric_tx_slot = rule
                .numeric_tx_key()
                .and_then(|key| keys.iter().position(|entry| key == entry.as_ref()))
                .map(|index| index as u8);
        }
    }

    pub(super) fn disruptive<'a>(&self, rule: &'a CompiledRule) -> Option<&'a DisruptiveAction> {
        match rule.actions.get(self.disruptive) {
            Some(Action::Disruptive(action)) => Some(action),
            _ => None,
        }
    }
}

/// A fully compiled ruleset ready for transaction processing.
pub struct CompiledRuleset {
    /// Compiled rules.
    rules: Rules,
    dispatch: [Vec<RuleDispatch>; 5],
    pub(super) header_slots: [Vec<Box<[u8]>>; 5],
    pub(super) width_sources: [super::target_indices::WidthSources; 5],
    pub(super) tx_defaults: Option<Box<super::initialization::TxDefaults>>,
    /// Rule engine mode.
    engine_mode: RuleEngineMode,
    body_config: super::body::BodyConfig,
    pub(crate) controls: HashMap<crate::parser::ControlAction, super::control::CtlDirective>,
    pub(crate) selectors: crate::variables::SelectorPrograms,
}

/// Rule engine operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleEngineMode {
    /// Rules are enabled and will block.
    #[default]
    On,
    /// Rules are enabled but will only detect.
    DetectionOnly,
    /// Rules are disabled.
    Off,
}

impl CompiledRuleset {
    /// Create an empty ruleset.
    pub fn new() -> Self {
        Self {
            rules: Rules::new(),
            dispatch: Default::default(),
            tx_defaults: None,
            width_sources: Default::default(),
            header_slots: Default::default(),
            selectors: Default::default(),
            controls: Default::default(),
            engine_mode: RuleEngineMode::default(),
            body_config: super::body::BodyConfig::default(),
        }
    }

    /// Load and compile rules from a file.
    pub fn from_file(path: &str) -> Result<Self> {
        let mut parser = Parser::new();
        parser.parse_file(std::path::Path::new(path))?;
        Self::compile(parser.into_directives())
    }

    /// Load and compile rules from a string.
    pub fn from_string(rules: &str) -> Result<Self> {
        let mut parser = Parser::new();
        parser.parse(rules)?;
        Self::compile(parser.into_directives())
    }

    /// Compile parsed directives into a ruleset.
    pub fn compile(mut directives: Vec<Directive>) -> Result<Self> {
        apply_rule_edits(&mut directives)?;
        let mut ruleset = Self::new();
        let mut pending_chain: Option<(Phase, usize)> = None;

        // Report ctl: directives this engine cannot honour, once, at load time.
        //
        // This is a warning rather than an error on purpose: CRS ships
        // ctl:requestBodyProcessor=JSON and ctl:auditLogParts, so rejecting
        // them would make CRS unloadable. But an operator has to be told at
        // startup, because the alternative -- finding out from a rule that
        // never fired -- is the failure this reporting exists to prevent.
        report_unsupported_controls(&directives);
        super::diagnostics::report(&directives, &mut ruleset.selectors)?;

        let mut target_updates: Vec<(Option<String>, UpdateTargetById)> = Vec::new();

        for directive in directives {
            match directive {
                Directive::SecRuleEngine(mode) => {
                    ruleset.engine_mode = match mode {
                        ParserRuleEngineMode::On => RuleEngineMode::On,
                        ParserRuleEngineMode::Off => RuleEngineMode::Off,
                        ParserRuleEngineMode::DetectionOnly => RuleEngineMode::DetectionOnly,
                    };
                }
                Directive::SecRule(rule) => {
                    // A chained rule inherits the phase of its chain starter.
                    // ModSecurity does not allow a `phase` action on
                    // continuation rules, so deriving it from the rule's own
                    // actions would drop every continuation into the default
                    // phase and split the chain across two phases.
                    let phase = match pending_chain {
                        Some((chain_phase, _)) => chain_phase,
                        None => extract_phase(&rule.actions),
                    };
                    let id = extract_id(&rule.actions);
                    let is_chain = has_chain(&rule.actions);

                    let transformations = extract_transformations(&rule.actions)?;

                    let operator_spec = rule.operator.clone();
                    let (operator, operator_negated) = compile_operator_reporting(
                        &rule.operator,
                        &id,
                        rule.location.file.as_deref(),
                    )?;

                    let compiled = CompiledRule {
                        id,
                        phase,
                        variables: rule.variables,
                        operator,
                        operator_negated,
                        operator_spec,
                        transformations,
                        actions: rule.actions,
                        is_chain,
                        chain_next: None,
                    };

                    let rules_for_phase = &mut ruleset.rules.by_phase[phase.index()];
                    let idx = rules_for_phase.len();
                    rules_for_phase.push(compiled);

                    // Handle chaining
                    if let Some((chain_phase, chain_idx)) = pending_chain.take() {
                        if chain_phase == phase {
                            if let Some(prev_rule) =
                                ruleset.rules.by_phase[chain_phase.index()].get_mut(chain_idx)
                            {
                                prev_rule.chain_next = Some(idx);
                            }
                        }
                    }

                    if is_chain {
                        pending_chain = Some((phase, idx));
                    }
                }
                Directive::SecAction(sec_action) => {
                    // SecAction is like a rule that always matches
                    let phase = extract_phase(&sec_action.actions);
                    let id = extract_id(&sec_action.actions);
                    let transformations = extract_transformations(&sec_action.actions)?;

                    // Create a rule with unconditional match operator
                    let operator_spec = OperatorSpec {
                        negated: false,
                        name: OperatorName::UnconditionalMatch,
                        argument: String::new(),
                    };
                    let operator = compile_operator(&operator_spec)?;

                    let compiled = CompiledRule {
                        id,
                        phase,
                        variables: vec![],
                        operator,
                        operator_negated: false,
                        operator_spec,
                        transformations,
                        actions: sec_action.actions,
                        is_chain: false,
                        chain_next: None,
                    };

                    ruleset.rules.add(phase, compiled);
                }
                Directive::SecRuleUpdateTargetById(update) => {
                    // Applied after every rule is compiled: the directive may
                    // appear before or after the rule it targets, and CRS
                    // exclusion files are conventionally included last.
                    target_updates.push((None, update));
                }
                Directive::SecRuleUpdateTargetByTag(update) => {
                    target_updates.push((Some(update.tag), update.targets));
                }
                Directive::SecMarker(marker) => {
                    ruleset.rules.add_marker(marker.name);
                }
                Directive::SecRequestBodyAccess(value) => {
                    ruleset.body_config.request_access = value
                }
                Directive::SecResponseBodyAccess(value) => {
                    ruleset.body_config.response_access = value
                }
                Directive::SecArgumentsLimit(value) => ruleset.body_config.argument_limit = value,
                Directive::SecRequestBodyJsonDepthLimit(value) => {
                    ruleset.body_config.request_json_depth_limit = value
                }
                Directive::SecResponseBodyJsonDepthLimit(value) => {
                    ruleset.body_config.response_json_depth_limit = value
                }
                Directive::SecRequestBodyInMemoryLimit(value) => {
                    ruleset.body_config.request_in_memory_limit = Some(value);
                }
                Directive::SecRequestBodyLimit(value) => ruleset.body_config.request_limit = value,
                Directive::SecResponseBodyLimit(value) => {
                    ruleset.body_config.response_limit = value
                }
                Directive::SecRequestBodyLimitAction(value) => {
                    ruleset.body_config.request_limit_action = value
                }
                Directive::SecResponseBodyLimitAction(value) => {
                    ruleset.body_config.response_limit_action = value
                }
                Directive::SecResponseBodyMimeType(value) => {
                    ruleset.body_config.response_mime_types = value
                }
                Directive::SecResponseBodyMimeTypesClear => {
                    ruleset.body_config.response_mime_types.clear()
                }
                _ => {
                    // Other directives (SecDefaultAction, etc.) handled elsewhere
                }
            }
        }

        apply_target_updates(&mut ruleset, &target_updates);
        for rule in ruleset.rules.by_phase.iter().flatten() {
            for action in &rule.actions {
                if let Action::Control(ctl) = action {
                    ruleset.controls.entry(ctl.clone()).or_insert_with(|| {
                        let directive = super::control::CtlDirective::parse(ctl);
                        if let super::control::CtlDirective::RuleRemoveTargetByTag {
                            target, ..
                        } = &directive
                        {
                            if let Ok(spec) = crate::parser::parse_single_variable(target) {
                                if let Some(Selection::Regex(pattern)) = spec.selection {
                                    ruleset.selectors.add(&pattern, spec.name);
                                }
                            }
                        }
                        directive
                    });
                }
            }
        }
        // All updates, markers and possible transaction controls are known now.
        let mut removed_tags = HashSet::new();
        let mut target_tags = HashSet::new();
        for ctl in ruleset.controls.values() {
            match ctl {
                super::control::CtlDirective::RuleRemoveByTag(tag) => {
                    removed_tags.insert(tag.as_str());
                }
                super::control::CtlDirective::RuleRemoveTargetByTag { tag, .. } => {
                    target_tags.insert(tag.as_str());
                }
                _ => {}
            }
        }
        ruleset.dispatch = Phase::ALL.map(|phase| {
            ruleset
                .rules
                .for_phase(phase)
                .iter()
                .map(|rule| {
                    RuleDispatch::compile(
                        rule,
                        &ruleset.rules,
                        &ruleset.selectors,
                        &removed_tags,
                        &target_tags,
                    )
                })
                .collect()
        });
        for phase in &mut ruleset.dispatch {
            RuleDispatch::assign_numeric_tx_slots(phase);
        }
        ruleset.header_slots = Phase::ALL.map(|phase| {
            RuleDispatch::assign_header_slots(
                ruleset.rules.for_phase(phase),
                &mut ruleset.dispatch[phase.index()],
            )
        });
        ruleset.width_sources = Phase::ALL.map(|phase| {
            let mut sources = super::target_indices::WidthSources::default();
            for (rule, plan) in ruleset
                .rules
                .for_phase(phase)
                .iter()
                .zip(&mut ruleset.dispatch[phase.index()])
            {
                plan.targets.finalize();
                plan.targets
                    .add_width_sources(&mut sources, &rule.variables);
            }
            sources
        });
        for phase in Phase::ALL {
            let rules = ruleset.rules.for_phase(phase);
            let dispatch = &mut ruleset.dispatch[phase.index()];
            let mut next = rules.len();
            for index in (0..rules.len()).rev() {
                if !rules[index].is_chain {
                    next = index + 1;
                }
                dispatch[index].after_empty_targets = match rules.get(next) {
                    Some(rule)
                        if !rule.variables.is_empty()
                            && rule.variables.len() <= super::target_indices::PREFIX
                            && dispatch[index].targets == dispatch[next].targets =>
                    {
                        dispatch[next].after_empty_targets
                    }
                    _ => next,
                };
            }
        }
        ruleset.tx_defaults = super::initialization::TxDefaults::compile(
            ruleset.rules_for_phase(Phase::RequestHeaders),
            ruleset.dispatch_for_phase(Phase::RequestHeaders),
        );
        ruleset.body_config.validate()?;
        if ruleset.engine_mode == RuleEngineMode::DetectionOnly {
            ruleset.body_config.request_limit_action =
                crate::parser::BodyLimitAction::ProcessPartial;
            ruleset.body_config.response_limit_action =
                crate::parser::BodyLimitAction::ProcessPartial;
        }

        Ok(ruleset)
    }

    /// Get the compiled immutable body acquisition policy.
    pub fn body_config(&self) -> &super::body::BodyConfig {
        &self.body_config
    }

    /// Get rules for a phase.
    pub fn rules_for_phase(&self, phase: Phase) -> &[CompiledRule] {
        self.rules.for_phase(phase)
    }

    pub(super) fn dispatch_for_phase(&self, phase: Phase) -> &[RuleDispatch] {
        &self.dispatch[phase.index()]
    }

    /// Get total rule count.
    pub fn rule_count(&self) -> usize {
        self.rules.count()
    }

    /// Get engine mode.
    pub fn engine_mode(&self) -> RuleEngineMode {
        self.engine_mode
    }

    /// Get a marker's position within one phase.
    pub fn marker(&self, name: &str, phase: Phase) -> Option<usize> {
        self.rules.marker(name, phase)
    }
}

impl Default for CompiledRuleset {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract phase from actions, defaulting to Phase 2.
fn extract_phase(actions: &[Action]) -> Phase {
    for action in actions {
        if let Action::Metadata(MetadataAction::Phase(p)) = action {
            return Phase::from_number(*p).unwrap_or(Phase::RequestBody);
        }
    }
    Phase::RequestBody // ModSecurity default
}

/// Resolve removals and action updates against the logical rules declared so far.
fn apply_rule_edits(directives: &mut Vec<Directive>) -> Result<()> {
    let mut targets: HashMap<u64, Option<usize>> = directives
        .iter()
        .filter_map(|directive| {
            if let Directive::SecRuleUpdateActionById { id, .. } = directive {
                Some((*id, None))
            } else {
                None
            }
        })
        .collect();
    let is_removal = |d: &Directive| {
        matches!(
            d,
            Directive::SecRuleRemoveById(_)
                | Directive::SecRuleRemoveByTag(_)
                | Directive::SecRuleRemoveByMsg(_)
        )
    };
    if targets.is_empty() && !directives.iter().any(is_removal) {
        return Ok(());
    }
    let mut removed = vec![false; directives.len()];
    let mut in_chain = false;
    let mut chain_id = None;
    for index in 0..directives.len() {
        let (earlier, current) = directives.split_at_mut(index);
        let (actions, unconditional) = match &current[0] {
            Directive::SecRule(rule) => (&rule.actions, false),
            Directive::SecAction(rule) => (&rule.actions, true),
            removal if is_removal(removal) => {
                let mut child = false;
                let mut remove = false;
                for (declaration, deleted) in earlier.iter().zip(&mut removed) {
                    let actions = match declaration {
                        Directive::SecRule(r) => &r.actions,
                        Directive::SecAction(r) => &r.actions,
                        _ => continue,
                    };
                    if *deleted {
                        continue;
                    }
                    if !child {
                        remove = match removal {
                            Directive::SecRuleRemoveById(ids) => numeric_id(actions)
                                .is_some_and(|id| ids.iter().any(|r| r.matches(id))),
                            Directive::SecRuleRemoveByTag(tag) => has_tag(actions, tag),
                            Directive::SecRuleRemoveByMsg(msg) => {
                                actions.iter().rev().find_map(|a| match a {
                                    Action::Metadata(MetadataAction::Msg(m)) => Some(m),
                                    _ => None,
                                }) == Some(msg)
                            }
                            _ => unreachable!(),
                        };
                    }
                    *deleted = remove;
                    child = has_chain(actions);
                }
                if child && remove {
                    in_chain = false;
                    chain_id = None;
                }
                for slot in targets.values_mut() {
                    if slot.is_some_and(|index| removed[index]) {
                        *slot = None;
                    }
                }
                continue;
            }
            Directive::SecRuleUpdateActionById { id, actions } => {
                let slot = targets
                    .get(id)
                    .copied()
                    .flatten()
                    .ok_or_else(|| Error::Config {
                        message: format!(
                            "SecRuleUpdateActionById: rule {id} not found before this directive"
                        ),
                    })?;
                let original = match &mut earlier[slot] {
                    Directive::SecRule(rule) => &mut rule.actions,
                    Directive::SecAction(rule) => &mut rule.actions,
                    _ => unreachable!("only logical rule declarations are indexed"),
                };
                update_disruption(*id, original, actions)?;
                continue;
            }
            _ => continue,
        };
        let child = in_chain;
        in_chain = has_chain(actions);
        if !child {
            chain_id = numeric_id(actions);
        }
        if let Some(id) = chain_id {
            if let Some(slot) = targets.get_mut(&id) {
                if unconditional && (child || in_chain) {
                    return Err(Error::Config {
                        message: format!("SecRuleUpdateActionById {id} does not support a chain containing SecAction"),
                    });
                }
                if !child && slot.replace(index).is_some() {
                    return Err(Error::DuplicateRuleId { id });
                }
            }
        }
    }
    if in_chain && chain_id.is_some_and(|id| targets.contains_key(&id)) {
        return Err(Error::IncompleteChain);
    }
    let mut deleted = removed.into_iter();
    directives.retain(|_| !deleted.next().unwrap());
    Ok(())
}

/// An update can replace either field independently. Resolve the entire list
/// first so an unsupported action cannot partially change the target.
fn update_disruption(id: u64, original: &mut Vec<Action>, actions: &[Action]) -> Result<()> {
    let invalid = || {
        Error::Config {
        message: format!("SecRuleUpdateActionById {id} supports only deny, pass and status on a positive rule ID"),
    }
    };
    if id == 0 || actions.is_empty() {
        return Err(invalid());
    }
    let mut disruptive = None;
    let mut status = None;
    for action in actions {
        match action {
            Action::Disruptive(DisruptiveAction::Pass | DisruptiveAction::Deny) => {
                disruptive = Some(action)
            }
            Action::Metadata(MetadataAction::Status(_)) => status = Some(action),
            _ => return Err(invalid()),
        }
    }
    original.retain(|action| match action {
        Action::Disruptive(_) => disruptive.is_none(),
        Action::Metadata(MetadataAction::Status(_)) => status.is_none(),
        _ => true,
    });
    original.extend(disruptive.cloned());
    original.extend(status.cloned());
    Ok(())
}

/// Apply `SecRuleUpdateTargetById` directives to the compiled rules.
///
/// ModSecurity semantics, as CRS exclusion files rely on them:
///
/// - `SecRuleUpdateTargetById 942100 "!ARGS:password"` adds a target exclusion,
///   so the rule stops inspecting that target. The exclusion is pushed onto
///   every variable of the rule, because the resolver applies exclusions
///   per-variable when expanding collections.
/// - `SecRuleUpdateTargetById 942100 "ARGS:foo"` appends a target.
/// - `SecRuleUpdateTargetById 942100 "ARGS:foo" "ARGS:bar"` replaces the
///   `ARGS:bar` target with `ARGS:foo`.
///
/// The update applies to the rule carrying the ID. For a chained rule that is
/// the chain starter, matching ModSecurity, which identifies a chain by the
/// starter's ID.
fn apply_target_updates(
    ruleset: &mut CompiledRuleset,
    updates: &[(Option<String>, UpdateTargetById)],
) {
    if updates.is_empty() {
        return;
    }
    for rules in &mut ruleset.rules.by_phase {
        for rule in rules.iter_mut() {
            for (tag, update) in updates {
                let selected = match tag {
                    Some(tag) => has_tag(&rule.actions, tag),
                    None => rule
                        .id
                        .as_ref()
                        .and_then(|id| id.parse::<u64>().ok())
                        .is_some_and(|id| update.ids.iter().any(|selector| selector.matches(id))),
                };
                if !selected {
                    continue;
                }
                if let Some(replaced) = &update.replaced {
                    rule.variables
                        .retain(|var| !variable_matches_target(var, replaced));
                }
                for exclusion in &update.exclusions {
                    for var in rule.variables.iter_mut() {
                        if !var.exclusions.iter().any(|e| e == exclusion) {
                            if let Some((name, pattern)) =
                                crate::variables::regex_exclusion(exclusion)
                            {
                                ruleset.selectors.add(pattern, name);
                            }
                            var.exclusions.push(exclusion.clone());
                        }
                    }
                }
                super::diagnostics::report_added_targets(
                    &update.additions,
                    rule.id.as_deref(),
                    &mut ruleset.selectors,
                );
                rule.variables.extend(update.additions.iter().cloned());
            }
        }
    }
}

/// Tags are exact and case-sensitive, as in Coraza's tag exclusions.
pub(crate) fn has_tag(actions: &[Action], tag: &str) -> bool {
    actions.iter().any(|action| {
        matches!(action,
        Action::Metadata(MetadataAction::Tag(value)) if value == tag)
    })
}

/// Whether a rule variable refers to the target named by a directive argument
/// such as `ARGS:bar` or `REQUEST_HEADERS`.
fn variable_matches_target(var: &VariableSpec, target: &str) -> bool {
    // Parse the directive's target with the same parser used for rule
    // variables, so collection names round-trip correctly. Comparing the
    // enum's Debug output instead would work only for single-word names:
    // SecLang writes REQUEST_HEADERS where the variant renders as
    // "RequestHeaders".
    let Ok(parsed) = crate::parser::parse_single_variable(target) else {
        return false;
    };
    if var.name != parsed.name {
        return false;
    }
    match (&var.selection, &parsed.selection) {
        (None, None) => true,
        (Some(Selection::Regex(existing)), Some(Selection::Regex(wanted))) => existing == wanted,
        (Some(Selection::Key(existing)), Some(Selection::Key(wanted))) => {
            crate::variables::folded_key(existing.as_bytes())
                == crate::variables::folded_key(wanted.as_bytes())
        }
        _ => false,
    }
}

/// Compile a rule's operator, reporting an unusable `@rx` pattern rather than
/// failing the whole load.
///
/// An invalid regex used to be discovered lazily at match time and swallowed
/// into a no-match, so the rule was dead and nothing said so. Rejecting the
/// pattern outright would fix the silence but introduce a worse failure: a
/// single pattern this engine cannot parse — a PCRE construct the `regex`
/// crate does not implement, say — would stop the entire ruleset from
/// loading, and with it the WAF.
///
/// So the rule is kept and can never match, exactly as before, but the
/// operator is told at load time which rule is dead and why. Every other
/// operator keeps failing the load, as it did before: those arguments come
/// from the same config the operator is editing, not from a third-party
/// ruleset.
fn compile_operator_reporting(
    spec: &OperatorSpec,
    rule_id: &Option<String>,
    rule_file: Option<&std::path::Path>,
) -> Result<(Arc<dyn Operator>, bool)> {
    if spec.name == OperatorName::ValidateSchema {
        let root = rule_file
            .and_then(std::path::Path::parent)
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let schema = crate::operators::schema::SchemaOperator::load(&spec.argument, root)?;
        return Ok((Arc::new(schema), spec.negated));
    }
    // A byte range supplied by a transaction macro is validated after expansion.
    if spec.name == OperatorName::ValidateByteRange
        && super::split_operator_macro(&spec.argument).is_some()
    {
        return Ok((
            Arc::new(crate::operators::ValidateByteRangeOperator::new(
                &spec.argument,
            )),
            spec.negated,
        ));
    }
    match compile_operator(spec) {
        Ok(operator) => Ok((operator, spec.negated)),
        Err(e) if spec.name == OperatorName::Rx => {
            tracing::error!(
                rule_id = %rule_id.as_deref().unwrap_or("(no id)"),
                pattern = %spec.argument,
                error = %e,
                "rule has an invalid @rx pattern and can never match; \
                 the rest of the ruleset was loaded"
            );
            let never = compile_operator(&OperatorSpec {
                negated: false,
                name: OperatorName::NoMatch,
                argument: String::new(),
            })?;
            // Negation is dropped deliberately. `!@rx <invalid>` with the
            // negation preserved would invert "never matches" into "matches
            // every request", turning a dead rule into one that blocks all
            // traffic -- far worse than the silence being fixed here.
            Ok((never, false))
        }
        Err(e) => Err(e),
    }
}

/// Warn once per distinct unsupported `ctl:` directive found in a ruleset.
///
/// Deduplicated by `directive=value`: CRS applies the same `ctl:` to hundreds
/// of rules, and one line per rule would bury the message it is trying to
/// deliver.
fn report_unsupported_controls(directives: &[Directive]) {
    let mut seen: std::collections::BTreeMap<String, (&'static str, Vec<String>)> =
        std::collections::BTreeMap::new();

    let mut chain_id: Option<String> = None;
    for directive in directives {
        let actions = match directive {
            Directive::SecRule(rule) => &rule.actions,
            Directive::SecAction(action) => &action.actions,
            _ => continue,
        };
        let rule_id = extract_id(actions).or_else(|| chain_id.clone());
        chain_id = if has_chain(actions) {
            rule_id.clone()
        } else {
            None
        };
        for (name, value, reason) in super::control::unsupported_controls(actions) {
            let key = if value.is_empty() {
                name
            } else {
                format!("{name}={value}")
            };
            let entry = seen.entry(key).or_insert_with(|| (reason, Vec::new()));
            entry
                .1
                .push(rule_id.clone().unwrap_or_else(|| "(no id)".into()));
        }
    }

    for (spec, (reason, ids)) in seen {
        tracing::warn!(
            directive = %spec,
            rules_affected = ids.len(),
            rule_ids = %ids.join(","),
            reason = %reason,
            "ctl: directive is not implemented and will have no effect"
        );
    }
}

fn extract_id(actions: &[Action]) -> Option<String> {
    numeric_id(actions).map(|id| id.to_string())
}

fn numeric_id(actions: &[Action]) -> Option<u64> {
    for action in actions {
        if let Action::Metadata(MetadataAction::Id(id)) = action {
            return Some(*id);
        }
    }
    None
}

/// Check if chain action is present.
fn has_chain(actions: &[Action]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, Action::Flow(FlowAction::Chain)))
}

/// Extract and compile transformation pipeline.
fn extract_transformations(actions: &[Action]) -> Result<TransformationPipeline> {
    let mut names = Vec::new();
    for action in actions {
        if let Action::Transformation(t) = action {
            names.push(t.clone());
        }
    }
    if names.is_empty() {
        Ok(TransformationPipeline::new())
    } else {
        TransformationPipeline::from_names(&names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_simple_rule() {
        let rules = r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#;
        let ruleset = CompiledRuleset::from_string(rules).unwrap();
        assert_eq!(ruleset.rule_count(), 1);

        let phase1_rules = ruleset.rules_for_phase(Phase::RequestHeaders);
        assert_eq!(phase1_rules.len(), 1);
        assert_eq!(phase1_rules[0].id, Some("1".to_string()));
    }

    #[test]
    fn test_compile_multiple_phases() {
        let rules = r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
            SecRule REQUEST_BODY "@rx attack" "id:2,phase:2,deny"
        "#;
        let ruleset = CompiledRuleset::from_string(rules).unwrap();
        assert_eq!(ruleset.rule_count(), 2);

        assert_eq!(ruleset.rules_for_phase(Phase::RequestHeaders).len(), 1);
        assert_eq!(ruleset.rules_for_phase(Phase::RequestBody).len(), 1);
    }

    #[test]
    fn test_engine_mode() {
        let rules = r#"
            SecRuleEngine DetectionOnly
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#;
        let ruleset = CompiledRuleset::from_string(rules).unwrap();
        assert_eq!(ruleset.engine_mode(), RuleEngineMode::DetectionOnly);
    }
}
