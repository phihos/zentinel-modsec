//! Apply ordered load-time edits to rule declarations and compiled targets.

use std::collections::HashSet;

use super::{has_chain, has_tag, numeric_id, rule_actions, CompiledRuleset};
use crate::error::{Error, Result};
use crate::parser::{
    Action, Directive, DisruptiveAction, FlowAction, MetadataAction, Parser, RuleIdSelector,
    Selection, UpdateTargetById, VariableSpec,
};

/// Resolve removals and action updates against the logical rules declared so far.
pub(super) fn apply_rule_edits(directives: &mut Vec<Directive>) -> Result<()> {
    let updates = directives.iter().any(|d| {
        matches!(
            d,
            Directive::SecRuleUpdateActionById { .. }
                | Directive::SecRuleUpdateActionByIdRanges { .. }
        )
    });
    let is_removal = |d: &Directive| {
        matches!(
            d,
            Directive::SecRuleRemoveById(_)
                | Directive::SecRuleRemoveByTag(_)
                | Directive::SecRuleRemoveByMsg(_)
        )
    };
    if !updates && !directives.iter().any(is_removal) {
        return Ok(());
    }
    let mut index = RuleEditIndex {
        removed: vec![false; directives.len()],
        track_starters: updates,
        ..Default::default()
    };
    let mut defaults = Parser::new();
    for slot in 0..directives.len() {
        let (earlier, current) = directives.split_at_mut(slot);
        let current = &mut current[0];
        if index.defer_defaults {
            if index.in_chain
                && rule_actions(current)
                    .unwrap_or_default()
                    .iter()
                    .any(|action| matches!(action, Action::Disruptive(_)))
            {
                return Err(Error::Config {
                    message: "disruptive actions can only be specified in the chain starter".into(),
                });
            }
            if let Directive::SecRule(rule) = current {
                rule.actions = defaults.merge_default_actions(std::mem::take(&mut rule.actions));
            }
        }
        match current {
            Directive::SecDefaultAction(actions) if updates => {
                defaults.set_default_actions(actions)
            }
            Directive::SecRuleRemoveById(ids) => index.remove(earlier, |actions| {
                numeric_id(actions)
                    .is_some_and(|id| ids.iter().any(|selector| selector.matches(id)))
            }),
            Directive::SecRuleRemoveByTag(tag) => {
                index.remove(earlier, |actions| has_tag(actions, tag))
            }
            Directive::SecRuleRemoveByMsg(msg) => index.remove(earlier, |actions| {
                actions.iter().rev().find_map(|action| match action {
                    Action::Metadata(MetadataAction::Msg(value)) => Some(value),
                    _ => None,
                }) == Some(&*msg)
            }),
            Directive::SecRuleUpdateActionById { id, actions } => {
                index.update(earlier, &[RuleIdSelector::Single(*id)], actions)?;
            }
            Directive::SecRuleUpdateActionByIdRanges { selectors, actions } => {
                index.update(earlier, selectors, actions)?;
            }
            declaration => {
                if let Some(actions) = rule_actions(declaration) {
                    index.record(slot, actions)?;
                }
            }
        }
    }
    if updates && index.in_chain {
        // With no next rule, the reference evaluates the last link by itself.
        if let Some(slot) = index.last_rule {
            rule_actions_mut(&mut directives[slot])
                .retain(|a| !matches!(a, Action::Flow(FlowAction::Chain)));
        }
    }
    let mut removed = index.removed.into_iter();
    directives.retain(|_| !removed.next().unwrap());
    Ok(())
}

/// Tracks the live logical rules as earlier declarations are removed or amended.
/// Slots refer to the original directive list until all edits have been applied.
#[derive(Default)]
struct RuleEditIndex {
    removed: Vec<bool>,
    track_starters: bool,
    starters: Vec<usize>,
    ids: HashSet<u64>,
    last_rule: Option<usize>,
    in_chain: bool,
    defer_defaults: bool,
}

impl RuleEditIndex {
    fn record(&mut self, slot: usize, actions: &[Action]) -> Result<()> {
        if self.track_starters && !self.in_chain {
            if let Some(id) = numeric_id(actions) {
                if !self.ids.insert(id) {
                    return Err(Error::DuplicateRuleId { id });
                }
            }
            self.starters.push(slot);
        }
        self.in_chain = has_chain(actions);
        self.last_rule = Some(slot);
        Ok(())
    }

    fn remove(&mut self, earlier: &[Directive], matches: impl Fn(&[Action]) -> bool) {
        let mut child = false;
        let mut remove = false;
        for (declaration, deleted) in earlier.iter().zip(&mut self.removed) {
            let Some(actions) = rule_actions(declaration) else {
                continue;
            };
            if *deleted {
                continue;
            }
            if !child {
                remove = matches(actions);
            }
            *deleted = remove;
            child = has_chain(actions);
        }
        if self.last_rule.is_some_and(|slot| self.removed[slot]) {
            self.last_rule = earlier.iter().enumerate().rposition(|(slot, declaration)| {
                !self.removed[slot] && rule_actions(declaration).is_some()
            });
            self.in_chain = self
                .last_rule
                .and_then(|slot| rule_actions(&earlier[slot]))
                .is_some_and(has_chain);
        }
        if self.track_starters {
            self.starters.retain(|&slot| !self.removed[slot]);
            self.refresh_ids(earlier);
        }
    }

    fn update(
        &mut self,
        earlier: &mut [Directive],
        selectors: &[RuleIdSelector],
        changes: &[Action],
    ) -> Result<()> {
        self.defer_defaults |= has_chain(changes);
        for selector in selectors {
            let mut found = false;
            for &slot in &self.starters {
                let original = rule_actions_mut(&mut earlier[slot]);
                if !numeric_id(original).is_some_and(|id| selector.matches(id)) {
                    continue;
                }
                for change in changes {
                    // Only the latest declaration can acquire a new continuation.
                    if matches!(change, Action::Flow(FlowAction::Chain)) {
                        if self.last_rule != Some(slot) {
                            continue;
                        }
                        self.in_chain = true;
                    }
                    original.retain(|old| !crate::parser::action_supersedes(change, old));
                    original.push(match change {
                        // The updater has no default action list to expand block.
                        Action::Disruptive(DisruptiveAction::Block) => {
                            Action::Disruptive(DisruptiveAction::Pass)
                        }
                        _ => change.clone(),
                    });
                }
                found = true;
                if matches!(selector, RuleIdSelector::Single(_)) {
                    break;
                }
            }
            if let RuleIdSelector::Single(id) = selector {
                if !found {
                    return Err(Error::Config {
                        message: format!(
                            "SecRuleUpdateActionById: rule {id} not found before this directive"
                        ),
                    });
                }
                break;
            }
        }
        if changes
            .iter()
            .any(|action| matches!(action, Action::Metadata(MetadataAction::Id(_))))
        {
            self.refresh_ids(earlier);
        }
        Ok(())
    }

    fn refresh_ids(&mut self, directives: &[Directive]) {
        self.ids.clear();
        self.ids.extend(
            self.starters
                .iter()
                .filter_map(|&slot| rule_actions(&directives[slot]).and_then(numeric_id)),
        );
    }
}

fn rule_actions_mut(directive: &mut Directive) -> &mut Vec<Action> {
    match directive {
        Directive::SecRule(rule) => &mut rule.actions,
        Directive::SecAction(rule) => &mut rule.actions,
        _ => unreachable!("only rule declarations are indexed"),
    }
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
pub(super) fn apply_target_updates(
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
                if let Some(replaced) = update
                    .replaced
                    .as_deref()
                    .and_then(|target| crate::parser::parse_single_variable(target).ok())
                {
                    rule.variables
                        .retain(|var| !variable_matches_target(var, &replaced));
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
                crate::engine::diagnostics::report_added_targets(
                    &update.additions,
                    rule.id.as_deref(),
                    &mut ruleset.selectors,
                );
                rule.variables.extend(update.additions.iter().cloned());
            }
        }
    }
}

/// Whether a rule variable refers to the target named by a directive argument
/// such as `ARGS:bar` or `REQUEST_HEADERS`.
fn variable_matches_target(var: &VariableSpec, parsed: &VariableSpec) -> bool {
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
