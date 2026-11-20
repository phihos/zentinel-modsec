//! Prepare the execution plan for each phase after configuration edits are final.

use std::collections::{HashMap, HashSet};

use super::{CompiledRule, CompiledRuleset, Rules};
use crate::engine::macro_template::MacroTemplate;
use crate::engine::{
    control::CtlDirective, initialization::TxDefaults, phase::Phase, split_operator_macro,
    target_indices,
};
use crate::parser::{
    Action, DataAction, DisruptiveAction, FlowAction, MetadataAction, OperatorName, SetVarValue,
};
use crate::variables::{folded_key, ByteValue};

/// Per-transaction positions reserved for frequent numeric TX lookups.
pub(in crate::engine) const NUMERIC_TX_SLOTS: usize = 4;

pub(in crate::engine) struct CompiledSetVar {
    pub action_index: usize,
    pub key_template: Option<MacroTemplate>,
    pub value_template: Option<MacroTemplate>,
    /// Literal TX keys can be folded once, when configuration updates are final.
    pub key: Option<ByteValue>,
    pub value: Option<ByteValue>,
}

/// Execution metadata for a finalized rule. The public parsed rule and its ordered
/// actions remain the source for captures, control arguments and audit messages.
#[derive(Default)]
pub(in crate::engine) struct RuleDispatch {
    /// A rule with no variables available in this phase still occupies a skip position.
    pub inactive: bool,
    /// This chain can be evaluated in multiple phases.
    pub multiphase_chain: bool,
    pub targets: target_indices::TargetIndices,
    /// First logical rule for which a miss on this target plan proves nothing.
    pub after_empty_targets: usize,
    pub selections: Box<[crate::variables::TargetSelection]>,
    /// Immutable numeric predicates match the full input without capture groups.
    pub numeric: Option<crate::operators::NumericComparison>,
    /// A static comparison of one literal TX member or its count, without transforms or exclusions.
    pub single_tx_numeric: bool,
    pub numeric_tx_slot: Option<u8>,
    pub dynamic: bool,
    pub operand: Option<MacroTemplate>,
    pub message: Option<MacroTemplate>,
    pub logdata: Option<MacroTemplate>,
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
pub(in crate::engine) enum CompiledFlow {
    #[default]
    Next,
    Chain,
    Skip(u32),
    SkipAfter {
        destination: Option<usize>,
        action: usize,
    },
}

impl RuleDispatch {
    fn compile(
        rule: &CompiledRule,
        rules: &Rules,
        phase: Phase,
        literal_regex_arguments: bool,
        programs: &crate::variables::SelectorPrograms,
        removed_tags: &HashSet<&str>,
        target_tags: &HashSet<&str>,
    ) -> Self {
        let dynamic = !(literal_regex_arguments && rule.operator_spec.name == OperatorName::Rx)
            && rule.operator_spec.argument.contains("%{")
            && !rule.operator_spec.name.has_literal_source();
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
            targets: target_indices::TargetIndices::compile(&rule.variables, minimum),
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
            operand: dynamic.then(|| MacroTemplate::compile(&rule.operator_spec.argument)),
            within_tx_key: if dynamic && rule.operator_spec.name == OperatorName::Within {
                split_operator_macro(&rule.operator_spec.argument).and_then(
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
                        OperatorName::IpMatchFromDataset
                            | OperatorName::GeoLookup
                            | OperatorName::StrMatch
                            | OperatorName::RestPath
                    );
                }
                Action::Data(DataAction::SetVar(op)) => {
                    setvars.push(CompiledSetVar {
                        action_index: index,
                        key_template: op
                            .key
                            .contains("%{")
                            .then(|| MacroTemplate::compile(&op.key)),
                        value_template: match &op.value {
                            SetVarValue::Macro(raw) => Some(MacroTemplate::compile(raw)),
                            _ => None,
                        },
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
                Action::Metadata(MetadataAction::Msg(text)) => {
                    dispatch.message = Some(MacroTemplate::compile(text))
                }
                Action::Metadata(MetadataAction::LogData(text)) => {
                    dispatch.logdata = Some(MacroTemplate::compile(text))
                }
                Action::Metadata(MetadataAction::Tag(tag)) => {
                    dispatch.removable_by_tag |= removed_tags.contains(tag.as_str());
                    dispatch.target_removable_by_tag |= target_tags.contains(tag.as_str());
                }
                Action::Flow(FlowAction::MultiMatch) => dispatch.multi_match = true,
                Action::Flow(FlowAction::Chain) => dispatch.flow = CompiledFlow::Chain,
                Action::Flow(FlowAction::Skip(n)) => dispatch.flow = CompiledFlow::Skip(*n),
                Action::Flow(FlowAction::SkipAfter(marker)) => {
                    dispatch.flow = CompiledFlow::SkipAfter {
                        destination: rules.marker(marker, phase),
                        action: index,
                    };
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
            .take(target_indices::PREFIX)
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
        let keys = Self::frequent_keys(members, 4, target_indices::HEADER_SLOTS);
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

    pub(in crate::engine) fn disruptive<'a>(
        &self,
        rule: &'a CompiledRule,
    ) -> Option<&'a DisruptiveAction> {
        match rule.actions.get(self.disruptive) {
            Some(Action::Disruptive(action)) => Some(action),
            _ => None,
        }
    }
}

impl CompiledRuleset {
    pub(super) fn compile_dispatch(
        &mut self,
        schedule: Option<&super::multiphase::Schedule>,
        literal_regex_arguments: bool,
    ) {
        // All updates, markers and possible transaction controls are known now.
        let mut removed_tags = HashSet::new();
        let mut target_tags = HashSet::new();
        for ctl in self.controls.values() {
            match ctl {
                CtlDirective::RuleRemoveByTag(tag) => {
                    removed_tags.insert(tag.as_str());
                }
                CtlDirective::RuleRemoveTargetByTag { tag, .. } => {
                    target_tags.insert(tag.as_str());
                }
                _ => {}
            }
        }
        for phase in Phase::ALL {
            let rules = self.rules.for_phase(phase);
            let dispatch = &mut self.dispatch[phase.index()];
            *dispatch = rules
                .iter()
                .enumerate()
                .map(|(index, rule)| {
                    let mut plan = RuleDispatch::compile(
                        rule,
                        &self.rules,
                        phase,
                        literal_regex_arguments,
                        &self.selectors,
                        &removed_tags,
                        &target_tags,
                    );
                    if let Some(schedule) = schedule {
                        let entry = &schedule[phase.index()][index];
                        plan.inactive = entry.inactive;
                        plan.multiphase_chain = entry.repeated_chain;
                    }
                    plan
                })
                .collect();
            RuleDispatch::assign_numeric_tx_slots(dispatch);
            self.header_slots[phase.index()] = RuleDispatch::assign_header_slots(rules, dispatch);
            let sources = &mut self.width_sources[phase.index()];
            for (rule, plan) in rules.iter().zip(dispatch.iter_mut()) {
                sources.restpath |= rule.operator_spec.name == OperatorName::RestPath;
                plan.targets.finalize();
                plan.targets.add_width_sources(sources, &rule.variables);
            }
            let mut next = rules.len();
            for index in (0..rules.len()).rev() {
                if !rules[index].is_chain {
                    next = index + 1;
                }
                dispatch[index].after_empty_targets = match rules.get(next) {
                    Some(rule)
                        if !rule.variables.is_empty()
                            && rule.variables.len() <= target_indices::PREFIX
                            && dispatch[index].targets == dispatch[next].targets =>
                    {
                        dispatch[next].after_empty_targets
                    }
                    _ => next,
                };
            }
        }
        // Replaying past a tagged marker would reorder changes to MATCHED_VAR.
        let header_rules = self.rules_for_phase(Phase::RequestHeaders);
        let prefix = self
            .phase_markers(Phase::RequestHeaders)
            .next_position()
            .unwrap_or(header_rules.len());
        self.tx_defaults = TxDefaults::compile(
            &header_rules[..prefix],
            self.dispatch_for_phase(Phase::RequestHeaders),
        );
    }
}
