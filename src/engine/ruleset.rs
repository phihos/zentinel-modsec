//! Compiled ruleset for efficient rule matching.

mod compile;
mod dispatch;
mod edits;
mod multiphase;
pub(super) use multiphase::split_target;

use std::{collections::HashMap, sync::Arc};

use super::phase::Phase;
use crate::error::Result;
use crate::operators::Operator;
use crate::parser::{
    Action, Directive, FlowAction, MetadataAction, OperatorSpec, Parser, VariableSpec,
};
use crate::transformations::TransformationPipeline;

pub(super) use dispatch::{CompiledFlow, CompiledSetVar, RuleDispatch, NUMERIC_TX_SLOTS};

// Keep tracing filters stable when compiler internals move between modules.
pub(super) const LOG_TARGET: &str = module_path!();

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
#[derive(Default)]
pub struct Rules {
    /// Rules organized by phase.
    by_phase: [Vec<CompiledRule>; Phase::ALL.len()],
    /// Markers for skipAfter, as the index the marker occupies in *each*
    /// phase's rule list. A marker separates rules in every phase, not only in
    /// the phase of the rules written around it, so a phase-2 `skipAfter` must
    /// be able to resume at the phase-2 position of the same marker.
    markers: HashMap<String, Vec<usize>>,
    marker_positions: [Vec<usize>; Phase::ALL.len()],
}

impl Rules {
    /// Create empty rules.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule to a specific phase.
    pub fn add(&mut self, phase: Phase, rule: CompiledRule) {
        self.by_phase[phase.index()].push(rule);
    }

    /// Record a marker at the current end of every phase's rule list.
    pub fn add_marker(&mut self, name: String) {
        let serial = self.marker_positions[0].len();
        self.markers.entry(name).or_default().push(serial);
        for (positions, rules) in self.marker_positions.iter_mut().zip(&self.by_phase) {
            positions.push(rules.len());
        }
    }

    /// Get rules for a phase.
    pub fn for_phase(&self, phase: Phase) -> &[CompiledRule] {
        &self.by_phase[phase.index()]
    }

    /// Get a marker's position within one phase.
    pub fn marker(&self, name: &str, phase: Phase) -> Option<usize> {
        let serial = *self.markers.get(name)?.last()?;
        Some(self.marker_positions[phase.index()][serial])
    }

    /// Get total rule count.
    pub fn count(&self) -> usize {
        self.by_phase.iter().map(|v| v.len()).sum()
    }
}

/// Select the Coraza behaviors required by a connector. The default preserves
/// the standalone engine's declared phases and dynamic regex operands.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompileOptions {
    /// Evaluate targets when their source becomes available.
    pub multiphase: bool,
    /// Anchor text regexes to the entire value unless the pattern enables `m`.
    pub no_regex_multiline: bool,
    /// Treat macro-like text in regex operands as part of the regex.
    pub literal_regex_arguments: bool,
}

impl CompileOptions {
    /// The flags and regex operand semantics of the HAPTIC Go Coraza backend.
    pub const CORAZA_SPOA: Self = Self {
        multiphase: true,
        no_regex_multiline: true,
        literal_regex_arguments: true,
    };
}

/// Markers are phase-independent instructions between rules. A cursor tracks
/// their source order even when several markers share one rule position.
pub(super) struct PhaseMarkers<'a> {
    positions: &'a [usize],
    by_name: &'a HashMap<String, Vec<usize>>,
    cursor: usize,
}

impl PhaseMarkers<'_> {
    pub fn next_position(&self) -> Option<usize> {
        self.positions.get(self.cursor).copied()
    }

    pub fn take_through(&mut self, rule: usize) -> usize {
        let remaining = &self.positions[self.cursor..];
        if remaining.first().is_none_or(|&next| next > rule) {
            return 0;
        }
        let count = remaining.partition_point(|&next| next <= rule);
        self.cursor += count;
        count
    }

    pub fn skip_after(&mut self, name: &str) -> Option<usize> {
        let occurrences = self.by_name.get(name)?;
        let serial = *occurrences.get(occurrences.partition_point(|&n| n < self.cursor))?;
        self.cursor = serial + 1;
        Some(self.positions[serial])
    }
}

/// A fully compiled ruleset ready for transaction processing.
#[derive(Default)]
pub struct CompiledRuleset {
    /// Compiled rules.
    rules: Rules,
    rule_count: usize,
    pub(super) multiphase: bool,
    dispatch: [Vec<RuleDispatch>; Phase::ALL.len()],
    pub(super) header_slots: [Vec<Box<[u8]>>; Phase::ALL.len()],
    pub(super) width_sources: [super::target_indices::WidthSources; Phase::ALL.len()],
    pub(super) tx_defaults: Option<Box<super::initialization::TxDefaults>>,
    pub(super) needs_upload_paths: bool,
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
        Self::default()
    }

    pub(super) fn phase_markers(&self, phase: Phase) -> PhaseMarkers<'_> {
        PhaseMarkers {
            positions: if self.multiphase {
                &self.rules.marker_positions[phase.index()]
            } else {
                &[]
            },
            by_name: &self.rules.markers,
            cursor: 0,
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

    /// Get the compiled immutable body acquisition policy.
    pub fn body_config(&self) -> &super::body::BodyConfig {
        &self.body_config
    }

    /// Get rules scheduled for a phase, in configuration order. In multiphase
    /// mode each entry retains its declared phase and its phase-specific targets.
    pub fn rules_for_phase(&self, phase: Phase) -> &[CompiledRule] {
        self.rules.for_phase(phase)
    }

    pub(super) fn dispatch_for_phase(&self, phase: Phase) -> &[RuleDispatch] {
        &self.dispatch[phase.index()]
    }

    /// Get total rule count.
    pub fn rule_count(&self) -> usize {
        self.rule_count
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

pub(super) fn rule_actions(directive: &Directive) -> Option<&[Action]> {
    match directive {
        Directive::SecRule(rule) => Some(&rule.actions),
        Directive::SecAction(action) => Some(&action.actions),
        _ => None,
    }
}

pub(super) fn numeric_id(actions: &[Action]) -> Option<u64> {
    for action in actions {
        if let Action::Metadata(MetadataAction::Id(id)) = action {
            return Some(*id);
        }
    }
    None
}

/// Check if chain action is present.
pub(super) fn has_chain(actions: &[Action]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, Action::Flow(FlowAction::Chain)))
}

/// Tags are exact and case-sensitive, as in Coraza's tag exclusions.
pub(crate) fn has_tag(actions: &[Action], tag: &str) -> bool {
    actions.iter().any(|action| {
        matches!(action,
        Action::Metadata(MetadataAction::Tag(value)) if value == tag)
    })
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
