//! What can be worked out about a rule's targets when the ruleset loads.
//!
//! The plans sit beside the compiled rules, one per rule by phase and
//! position. A target a plan says nothing about is resolved from its parsed
//! form, as every target is when a rule runs without a plan.

use super::ruleset::CompiledRule;
use crate::parser::{Selection, VariableName, VariableSpec};
use crate::variables::TxCollection;

/// How one target of a rule finds its values.
pub(super) enum TargetPlan {
    /// From the parsed target, by the resolver.
    Resolver,
    /// `TX:key`: the key as `TX` stores it, and where it sits in a
    /// transaction that took the prepared initial state over.
    TxKey { lowered: String, position: usize },
    /// `REQUEST_HEADERS:key`: the key as the headers store it.
    HeaderKey { lowered: String },
}

/// The plan of one rule.
pub(super) struct RulePlan {
    targets: Vec<TargetPlan>,
}

impl RulePlan {
    /// Plan the targets of `rule`. `initial_tx` is `TX` as the prepared
    /// leading rules of phase 1 leave it, if any were prepared.
    pub(super) fn prepare(rule: &CompiledRule, initial_tx: Option<&TxCollection>) -> Self {
        Self {
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

fn plan_target(spec: &VariableSpec, initial_tx: Option<&TxCollection>) -> TargetPlan {
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
            let position = initial_tx
                .and_then(|tx| tx.position(&lowered))
                .unwrap_or(usize::MAX);
            TargetPlan::TxKey { lowered, position }
        }
        VariableName::RequestHeaders => TargetPlan::HeaderKey { lowered },
        _ => TargetPlan::Resolver,
    }
}
