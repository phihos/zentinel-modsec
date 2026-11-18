//! Compiled ruleset for efficient rule matching.

use crate::error::{Error, Result};
use crate::operators::{compile_operator, Operator};
use crate::parser::{
    Action, Directive, DisruptiveAction, FlowAction, MetadataAction, OperatorName, OperatorSpec,
    Parser, RuleEngineMode as ParserRuleEngineMode, RuleIdSelector, Selection, UpdateTargetById,
    VariableSpec,
};
use crate::transformations::TransformationPipeline;

use super::phase::Phase;
use std::collections::HashMap;
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
    by_phase: HashMap<Phase, Vec<CompiledRule>>,
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
            by_phase: HashMap::new(),
            markers: HashMap::new(),
        }
    }

    /// Add a rule to a specific phase.
    pub fn add(&mut self, phase: Phase, rule: CompiledRule) {
        self.by_phase.entry(phase).or_default().push(rule);
    }

    /// Record a marker at the current end of every phase's rule list.
    pub fn add_marker(&mut self, name: String) {
        let positions = Phase::ALL
            .iter()
            .map(|&phase| (phase, self.by_phase.get(&phase).map_or(0, |v| v.len())))
            .collect();
        self.markers.insert(name, positions);
    }

    /// Get rules for a phase.
    pub fn for_phase(&self, phase: Phase) -> &[CompiledRule] {
        self.by_phase
            .get(&phase)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get a marker's position within one phase.
    pub fn marker(&self, name: &str, phase: Phase) -> Option<usize> {
        self.markers.get(name).and_then(|p| p.get(&phase)).copied()
    }

    /// Get total rule count.
    pub fn count(&self) -> usize {
        self.by_phase.values().map(|v| v.len()).sum()
    }
}

impl Default for Rules {
    fn default() -> Self {
        Self::new()
    }
}

/// A fully compiled ruleset ready for transaction processing.
pub struct CompiledRuleset {
    /// Compiled rules.
    rules: Rules,
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
        apply_action_updates(&mut directives)?;
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
        super::diagnostics::report(&directives, &mut ruleset.selectors);

        // SecRuleRemoveById and SecRuleUpdateTargetById are applied against
        // the whole ruleset once loading completes (like ModSecurity, where
        // they modify already-defined rules). Removals are collected up front
        // so removed rules are never compiled; target updates are applied
        // after the compile loop.
        let removals: Vec<RuleIdSelector> = directives
            .iter()
            .filter_map(|d| match d {
                Directive::SecRuleRemoveById(ids) => Some(ids.iter().copied()),
                _ => None,
            })
            .flatten()
            .collect();
        let mut target_updates: Vec<(Option<String>, UpdateTargetById)> = Vec::new();
        // When a removed rule is a chain head, its continuation rules (which
        // usually carry no id of their own) must be dropped with it.
        let mut skipping_removed_chain = false;

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

                    if skipping_removed_chain {
                        // Continuation of a removed chained rule.
                        skipping_removed_chain = is_chain;
                        continue;
                    }
                    if id_is_removed(&id, &removals) {
                        skipping_removed_chain = is_chain;
                        continue;
                    }

                    let transformations = extract_transformations(&rule.actions)?;

                    let operator_spec = rule.operator.clone();
                    let (operator, operator_negated) =
                        compile_operator_reporting(&rule.operator, &id)?;

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

                    let rules_for_phase = ruleset.rules.by_phase.entry(phase).or_default();
                    let idx = rules_for_phase.len();
                    rules_for_phase.push(compiled);

                    // Handle chaining
                    if let Some((chain_phase, chain_idx)) = pending_chain.take() {
                        if chain_phase == phase {
                            if let Some(prev_rule) = ruleset
                                .rules
                                .by_phase
                                .get_mut(&chain_phase)
                                .and_then(|r| r.get_mut(chain_idx))
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
                    if id_is_removed(&id, &removals) {
                        continue;
                    }
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
        for rule in ruleset.rules.by_phase.values().flatten() {
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

/// Check whether a rule's ID is covered by any `SecRuleRemoveById` selector.
///
/// Rules without an ID cannot be targeted by ID, and an ID that does not parse
/// as a number never matches a numeric selector.
fn id_is_removed(id: &Option<String>, removals: &[RuleIdSelector]) -> bool {
    let Some(numeric) = id.as_ref().and_then(|s| s.parse::<u64>().ok()) else {
        return false;
    };
    removals.iter().any(|selector| selector.matches(numeric))
}

/// Apply updates to previously declared logical rules before compiling their
/// actions. Keep only IDs named by updates, and preserve directive order even
/// when a later SecRuleRemoveById removes the entire chain during compilation.
fn apply_action_updates(directives: &mut [Directive]) -> Result<()> {
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
    if targets.is_empty() {
        return Ok(());
    }

    let mut in_chain = false;
    let mut chain_id = None;
    for index in 0..directives.len() {
        let (earlier, current) = directives.split_at_mut(index);
        let (actions, unconditional) = match &current[0] {
            Directive::SecRule(rule) => (&rule.actions, false),
            Directive::SecAction(rule) => (&rule.actions, true),
            Directive::SecRuleRemoveById(ids) => {
                // Removals apply to this ID throughout the compiled ruleset.
                // A redeclaration cannot restore an explicitly removed ID.
                targets.retain(|id, _| !ids.iter().any(|range| range.matches(*id)));
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
    for rules in ruleset.rules.by_phase.values_mut() {
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
) -> Result<(Arc<dyn Operator>, bool)> {
    // A byte range supplied by a transaction macro is validated after expansion.
    if spec.name == OperatorName::ValidateByteRange
        && spec
            .argument
            .split_once("%{")
            .is_some_and(|(_, rest)| rest.contains('}'))
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
