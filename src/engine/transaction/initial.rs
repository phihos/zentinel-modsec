//! The state the leading rules of phase 1 leave behind when they read
//! nothing of the request, worked out once when the ruleset loads.
//!
//! CRS opens phase 1 with rules such as `SecAction "setvar:tx.x=1"` and
//! `SecRule &TX:x "@eq 0" "setvar:tx.x=1"`. `TX` is empty when a transaction
//! starts, so those rules match the same way and leave the same variables,
//! matched rules and messages behind in every transaction. The engine runs
//! them once at load, with the interpreter that would run them for a request,
//! and a transaction that starts with nothing in it takes the result over.

use super::{MatchedData, OpenRecord, Transaction};
use crate::actions::{DisruptiveOutcome, FlowOutcome, SetVarOperation};
use crate::engine::intervention::RuleMessage;
use crate::engine::operand_macro;
use crate::engine::phase::Phase;
use crate::engine::ruleset::CompiledRule;
use crate::parser::{OperatorName, VariableName};
use crate::variables::HashMapCollection;
use std::sync::Arc;

/// What a transaction holds once the leading rules of phase 1 have run.
pub(in crate::engine) struct InitialState {
    /// How many rules of phase 1 this stands for.
    rules: usize,
    tx: Arc<HashMapCollection>,
    matched_rules: Vec<String>,
    matched_vars: Vec<(String, String)>,
    messages: Vec<RuleMessage>,
    captures: Vec<String>,
    matched_data: Vec<MatchedData>,
    /// Whether the last record still waits for its variable and value.
    open_record: Option<OpenRecord>,
}

impl InitialState {
    /// Run the leading rules of `rules`, the rules of phase 1, for as long as
    /// they read only `TX`, and keep what they leave behind. `None` when the
    /// first rule already reads more.
    pub(in crate::engine) fn prepare(rules: &[CompiledRule]) -> Option<Self> {
        // The rules are handed over directly, so the transaction's own
        // ruleset stays empty. Its default status goes unused: no rule that
        // can intervene is run here once it matches.
        let mut scratch = Transaction::new(Arc::default(), 0);
        let mut open_record = None;
        let mut count = 0;
        for rule in rules {
            if !decides_on_tx(rule) {
                break;
            }
            // A rule that does not match does nothing, whatever its actions.
            let Ok(matches) = scratch.evaluate_rule(rule, None) else {
                break;
            };
            if !matches.is_empty() && !acts_on_tx(rule) {
                break;
            }
            // One rule at a time: none of them is part of a chain or jumps,
            // so the interpreter carries nothing from one to the next but
            // the transaction and the open record.
            let next = count + 1;
            scratch
                .run_rules_from(
                    &rules[..next],
                    &[],
                    count,
                    Phase::RequestHeaders,
                    &mut open_record,
                )
                .ok()?;
            count = next;
        }
        if count == 0 {
            return None;
        }
        Some(Self {
            rules: count,
            tx: scratch.tx.into_shared(),
            matched_rules: scratch.matched_rules,
            matched_vars: scratch.matched_vars,
            messages: scratch.messages,
            captures: scratch.captures,
            matched_data: scratch.matched_data,
            open_record,
        })
    }

    /// `TX` as the prepared rules leave it.
    pub(in crate::engine) fn tx(&self) -> &HashMapCollection {
        &self.tx
    }

    /// Put `transaction`, which has run no rule and holds nothing in `TX`,
    /// into this state. Returns the index of the rule phase 1 goes on with.
    pub(super) fn restore(
        &self,
        transaction: &mut Transaction,
        open_record: &mut Option<OpenRecord>,
    ) -> usize {
        transaction.tx.share(&self.tx);
        transaction.matched_rules.clone_from(&self.matched_rules);
        transaction.matched_vars.clone_from(&self.matched_vars);
        transaction.messages.clone_from(&self.messages);
        transaction.captures.clone_from(&self.captures);
        transaction.matched_data.clone_from(&self.matched_data);
        *open_record = self.open_record;
        self.rules
    }
}

/// Whether `rule` matches or not depends on nothing but `TX` and the rule
/// itself: its targets are `TX`, the macros of its operand are
/// `%{tx.<name>}`, and its operator only compares its argument with the
/// value. A chain is left to the interpreter.
fn decides_on_tx(rule: &CompiledRule) -> bool {
    !rule.is_chain
        && rule.chain_next.is_none()
        && rule
            .variables
            .iter()
            .all(|spec| spec.name == VariableName::Tx && spec.exclusions.is_empty())
        && compares_its_argument(rule.operator_spec.name)
        && !rule.operand_unresolvable
        && operand_macro::reads_only_tx(&rule.operator_spec.argument)
}

/// Whether a match of `rule` reads and writes nothing but `TX`, and leaves
/// the rules after it to run in order: it may set `TX` variables, capture and
/// log. A `ctl:`, a jump, an action that can intervene, and a macro of the
/// request in a `setvar` or in the logged message are not that.
fn acts_on_tx(rule: &CompiledRule) -> bool {
    let on_match = &rule.on_match;
    let only_tx = operand_macro::reads_only_tx;
    on_match.control_ops.is_empty()
        && on_match.flow == FlowOutcome::Continue
        && matches!(on_match.disruptive, None | Some(DisruptiveOutcome::Pass))
        && on_match.setvar_ops.iter().all(|op| {
            op.collection.eq_ignore_ascii_case("tx")
                && only_tx(&op.name)
                && match &op.operation {
                    SetVarOperation::Macro(raw) => only_tx(raw),
                    _ => true,
                }
        })
        && (rule.metadata.nolog
            || [&rule.metadata.msg, &rule.metadata.logdata]
                .into_iter()
                .flatten()
                .all(|text| only_tx(text)))
}

/// Whether the operator's result is a function of its argument and the value
/// alone: no file, no lookup, no state of its own.
fn compares_its_argument(operator: OperatorName) -> bool {
    use OperatorName::*;
    matches!(
        operator,
        Rx | Pm
            | StreQ
            | Contains
            | ContainsWord
            | BeginsWith
            | EndsWith
            | Within
            | StrMatch
            | Eq
            | Ne
            | Gt
            | Ge
            | Lt
            | Le
            | NoMatch
            | UnconditionalMatch
    )
}

#[cfg(test)]
mod tests {
    use crate::engine::ruleset::CompiledRuleset;

    /// How many leading rules of phase 1 the ruleset prepared.
    fn prepared(rules: &str) -> usize {
        CompiledRuleset::from_string(rules)
            .expect("rules load")
            .initial_state()
            .map_or(0, |initial| initial.rules)
    }

    const SETUP: &str = "SecAction \"id:1,phase:1,pass,nolog,setvar:'tx.a=1'\"\n";

    /// `SETUP`, then `rule`, then a rule that could be prepared.
    fn after_setup(rule: &str) -> usize {
        prepared(&format!(
            "{SETUP}{rule}\nSecAction \"id:90,phase:1,pass,nolog,setvar:'tx.z=1'\""
        ))
    }

    #[test]
    fn rules_that_read_and_write_only_tx_are_prepared() {
        for rule in [
            r#"SecAction "id:2,phase:1,pass,log,msg:'setup %{tx.a}',logdata:'%{TX.a}',tag:'t',setvar:'tx.b=%{tx.a}'""#,
            r#"SecAction "id:2,phase:1,nolog,setvar:'tx.b=+1',setvar:'!tx.a',setvar:'tx.c_%{tx.a}=-%{tx.b}'""#,
            r#"SecRule &TX:b "@eq 0" "id:2,phase:1,pass,nolog,setvar:'tx.b=1'""#,
            r#"SecRule TX:a|TX:/^b/|&TX "@rx ^(\d)$" "id:2,phase:1,pass,nolog,capture,t:trim,multiMatch""#,
            r#"SecRule TX:a "!@lt %{tx.a}" "id:2,phase:1,pass,nolog""#,
            r#"SecRule TX "@pm 1 2" "phase:1,pass,nolog""#,
            r#"SecRule TX:a "@eq 1" "id:2,phase:1,pass,nolog,msg:'%{MATCHED_VAR}',logdata:'%{REQUEST_URI}'""#,
        ] {
            assert_eq!(after_setup(rule), 3, "{rule}");
        }
    }

    #[test]
    fn a_rule_that_may_read_the_request_ends_the_prepared_rules() {
        for rule in [
            r#"SecRule REQUEST_METHOD "@streq GET" "id:2,phase:1,pass,nolog""#,
            r#"SecRule TX:a|ARGS "@eq 1" "id:2,phase:1,pass,nolog""#,
            r#"SecRule &ARGS "@eq 0" "id:2,phase:1,pass,nolog""#,
            r#"SecRule MATCHED_VAR "@eq 1" "id:2,phase:1,pass,nolog""#,
            r#"SecRule TX|!TX:a "@eq 1" "id:2,phase:1,pass,nolog""#,
            r#"SecRule TX:a "@streq %{REQUEST_METHOD}" "id:2,phase:1,pass,nolog""#,
            r#"SecRule TX:a "@streq %{request_headers.host}" "id:2,phase:1,pass,nolog""#,
            r#"SecRule TX:a "@streq %{matched_var}" "id:2,phase:1,pass,nolog""#,
            r#"SecRule TX:a "@streq %{a}" "id:2,phase:1,pass,nolog""#,
            r#"SecRule TX:a "@gt %{env.limit}" "id:2,phase:1,pass,nolog""#,
            r#"SecRule TX:a "@detectSQLi" "id:2,phase:1,pass,nolog""#,
            r#"SecRule TX:a "@ipMatch 192.0.2.0/24" "id:2,phase:1,pass,nolog""#,
            r#"SecAction "id:2,phase:1,pass,nolog,setvar:'tx.b=%{REQUEST_METHOD}'""#,
            r#"SecAction "id:2,phase:1,pass,nolog,setvar:'tx.b=+%{ARGS.n}'""#,
            r#"SecAction "id:2,phase:1,pass,nolog,setvar:'tx.b_%{unique_id}=1'""#,
            r#"SecAction "id:2,phase:1,pass,nolog,setvar:'tx.b=%{MATCHED_VAR_NAME}'""#,
            r#"SecAction "id:2,phase:1,pass,log,msg:'at %{REQUEST_URI}'""#,
            r#"SecAction "id:2,phase:1,pass,log,logdata:'%{MATCHED_VAR}'""#,
        ] {
            assert_eq!(after_setup(rule), 1, "{rule}");
        }
    }

    #[test]
    fn a_rule_that_changes_which_rules_run_ends_the_prepared_rules() {
        for rule in [
            r#"SecAction "id:2,phase:1,pass,nolog,ctl:ruleRemoveById=90""#,
            r#"SecAction "id:2,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly""#,
            r#"SecAction "id:2,phase:1,pass,nolog,skip:1""#,
            r#"SecAction "id:2,phase:1,pass,nolog,skipAfter:END""#,
            r#"SecAction "id:2,phase:1,deny,nolog""#,
            r#"SecAction "id:2,phase:1,block,nolog""#,
            r#"SecAction "id:2,phase:1,allow,nolog""#,
            r#"SecAction "id:2,phase:1,drop,nolog""#,
            r#"SecAction "id:2,phase:1,redirect:https://example.org/,nolog""#,
            "SecRule TX:a \"@eq 1\" \"id:2,phase:1,pass,nolog,chain\"\n    SecRule TX:a \"@eq 1\" \"setvar:'tx.b=1'\"",
        ] {
            assert_eq!(after_setup(rule), 1, "{rule}");
        }
    }

    #[test]
    fn a_rule_that_does_not_match_is_prepared_whatever_its_actions() {
        for rule in [
            r#"SecRule &TX:a "@eq 0" "id:2,phase:1,deny,status:500,log,msg:'no setup at %{REQUEST_URI}'""#,
            r#"SecRule TX:a "@eq 9" "id:2,phase:1,pass,nolog,skipAfter:END,ctl:ruleEngine=Off""#,
            r#"SecRule TX:a "@gt %{tx.a}" "id:2,phase:1,allow,nolog,setvar:'tx.b=%{REQUEST_METHOD}'""#,
            r#"SecRule TX:missing "!@eq 1" "id:2,phase:1,drop,nolog""#,
        ] {
            assert_eq!(after_setup(rule), 3, "{rule}");
        }
    }

    #[test]
    fn only_the_leading_rules_of_phase_1_are_prepared() {
        // A marker is no rule, and rules of other phases are not in the way.
        assert_eq!(
            prepared(
                r#"
                SecAction "id:20,phase:2,pass,nolog,setvar:'tx.late=1'"
                SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1'"
                SecMarker "BEGIN"
                SecRule REQUEST_URI "@rx ." "id:21,phase:2,pass,nolog"
                SecAction "id:2,phase:1,pass,nolog,setvar:'tx.b=1'"
                SecAction "id:3,pass,nolog,setvar:'tx.c=1'"
                SecRule REQUEST_URI "@rx ." "id:4,phase:1,pass,nolog"
                SecAction "id:5,phase:1,pass,nolog,setvar:'tx.d=1'"
                "#
            ),
            2
        );
        assert_eq!(prepared(""), 0);
        assert_eq!(
            prepared(r#"SecAction "id:20,phase:2,pass,nolog,setvar:'tx.late=1'""#),
            0
        );
    }

    #[test]
    fn rules_are_prepared_as_load_time_directives_leave_them() {
        let rules = |directive: &str| {
            prepared(&format!(
                r#"
                SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1'"
                SecRule TX:a "@eq 1" "id:2,phase:1,pass,nolog,tag:'optional'"
                SecRule REQUEST_URI "@rx ." "id:3,phase:1,pass,nolog,tag:'reader'"
                SecAction "id:4,phase:1,pass,nolog,setvar:'tx.d=1'"
                {directive}
                "#
            ))
        };
        assert_eq!(rules(""), 2);
        assert_eq!(rules("SecRuleRemoveById 2"), 1);
        assert_eq!(rules("SecRuleRemoveById 3"), 3);
        assert_eq!(rules("SecRuleRemoveByTag \"reader\""), 3);
        assert_eq!(rules("SecRuleUpdateTargetById 2 \"ARGS:n\""), 1);
        assert_eq!(rules("SecRuleUpdateTargetById 2 \"!TX:a\""), 1);
        assert_eq!(rules("SecRuleEngine DetectionOnly"), 2);
        // Nothing runs when the engine is off, so nothing is prepared.
        assert_eq!(rules("SecRuleEngine Off"), 0);
    }
}
