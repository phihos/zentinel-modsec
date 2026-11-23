//! What can be worked out about a rule's targets when the ruleset loads.
//!
//! The plans sit beside the compiled rules, one per rule by phase and
//! position. A target a plan says nothing about is resolved from its parsed
//! form, as every target is when a rule runs without a plan.

use super::control::CtlDirective;
use super::ruleset::CompiledRule;
use crate::parser::{Selection, VariableName, VariableSpec};
use crate::variables::HashMapCollection;

/// How one target of a rule finds its values.
pub(super) enum TargetPlan {
    /// From the parsed target, by the resolver.
    Resolver,
    /// `TX:key`: the key as `TX` stores it, and where it sits in a
    /// transaction that took the prepared initial state over.
    TxKey {
        lowered: String,
        position: Option<usize>,
    },
    /// `REQUEST_HEADERS:key`: the key as the headers store it.
    HeaderKey { lowered: String },
}

/// The plan of one rule.
pub(super) struct RulePlan {
    targets: Vec<TargetPlan>,
    /// Whether a `ctl:ruleRemoveByTag` of the ruleset names a tag of this rule.
    pub(super) removable_by_tag: bool,
    /// Whether a `ctl:ruleRemoveTargetByTag` of the ruleset names a tag of
    /// this rule.
    pub(super) targets_removable_by_tag: bool,
}

/// The tags the `ctl:` actions of a ruleset can name. A `ctl:` argument is
/// taken as written, so no transaction names another.
#[derive(Default)]
pub(super) struct ControlTags {
    rules: Vec<String>,
    targets: Vec<String>,
}

impl ControlTags {
    /// Note the tags the `ctl:` actions of `rule` name.
    pub(super) fn note(&mut self, rule: &CompiledRule) {
        for ctl in &rule.on_match.control_ops {
            match CtlDirective::parse(ctl) {
                CtlDirective::RuleRemoveByTag(tag) => self.rules.push(tag),
                CtlDirective::RuleRemoveTargetByTag { tag, .. } => self.targets.push(tag),
                _ => {}
            }
        }
    }
}

impl RulePlan {
    /// Plan the targets of `rule`. `initial_tx` is `TX` as the prepared
    /// leading rules of phase 1 leave it, if any were prepared.
    pub(super) fn prepare(
        rule: &CompiledRule,
        initial_tx: Option<&HashMapCollection>,
        tags: &ControlTags,
    ) -> Self {
        let named = |tags: &[String]| rule.tags().any(|tag| tags.iter().any(|t| t == tag));
        Self {
            removable_by_tag: named(&tags.rules),
            targets_removable_by_tag: named(&tags.targets),
            targets: rule
                .variables
                .iter()
                .map(|spec| plan_target(spec, initial_tx))
                .collect(),
        }
    }

    /// The plan of the target at `position` in the rule.
    pub(super) fn target(&self, position: usize) -> &TargetPlan {
        self.targets.get(position).unwrap_or(&TargetPlan::Resolver)
    }
}

fn plan_target(spec: &VariableSpec, initial_tx: Option<&HashMapCollection>) -> TargetPlan {
    let Some(Selection::Key(key)) = &spec.selection else {
        return TargetPlan::Resolver;
    };
    if !spec.exclusions.is_empty() {
        return TargetPlan::Resolver;
    }
    let lowered = key.to_ascii_lowercase();
    match spec.name {
        VariableName::Tx => {
            // A key the initial state does not hold is looked up by name;
            // no variable sits at this position.
            let position = initial_tx.and_then(|tx| tx.position(&lowered));
            TargetPlan::TxKey { lowered, position }
        }
        VariableName::RequestHeaders => TargetPlan::HeaderKey { lowered },
        _ => TargetPlan::Resolver,
    }
}
