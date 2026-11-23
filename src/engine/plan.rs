//! What can be worked out about a rule's targets when the ruleset loads.
//!
//! The plans sit beside the compiled rules, one per rule by phase and
//! position, and leave the rules as they were parsed. A target a plan says
//! nothing about is resolved from its parsed form, as every target is when a
//! rule runs without a plan.

use super::ruleset::CompiledRule;
use crate::parser::{Selection, VariableName, VariableSpec};
use crate::variables::HashMapCollection;

/// How one target of a rule finds its values.
pub(super) enum TargetPlan {
    /// From the parsed target, by the resolver.
    Resolver,
    /// `TX:key`: the key as the rule wrote it and as `TX` stores it, and
    /// where the variables a transaction shares hold it, if they do.
    TxKey {
        key: String,
        lowered: String,
        position: Option<usize>,
    },
    /// `REQUEST_HEADERS:key`: the key as the rule wrote it and as the
    /// headers store it.
    HeaderKey { key: String, lowered: String },
}

/// The plan of one rule.
pub(super) struct RulePlan {
    targets: Vec<TargetPlan>,
}

impl RulePlan {
    /// Plan the targets of `rule`. `shared_tx` holds the `TX` variables a
    /// transaction takes over from the ruleset, if it prepared any.
    pub(super) fn prepare(rule: &CompiledRule, shared_tx: Option<&HashMapCollection>) -> Self {
        Self {
            targets: rule
                .variables
                .iter()
                .map(|spec| plan_target(spec, shared_tx))
                .collect(),
        }
    }

    /// The plan of the target at `position` in the rule.
    pub(super) fn target(&self, position: usize) -> &TargetPlan {
        self.targets.get(position).unwrap_or(&TargetPlan::Resolver)
    }
}

/// Plan one target. Only a target that selects one key and leaves nothing
/// out is prepared: its values are all the values of that key.
fn plan_target(spec: &VariableSpec, shared_tx: Option<&HashMapCollection>) -> TargetPlan {
    let Some(Selection::Key(key)) = &spec.selection else {
        return TargetPlan::Resolver;
    };
    if !spec.exclusions.is_empty() {
        return TargetPlan::Resolver;
    }
    let key = key.clone();
    let lowered = key.to_ascii_lowercase();
    match spec.name {
        VariableName::Tx => {
            let position = shared_tx
                .and_then(|tx| tx.find(&lowered))
                .map(|(position, _)| position);
            TargetPlan::TxKey {
                key,
                lowered,
                position,
            }
        }
        VariableName::RequestHeaders => TargetPlan::HeaderKey { key, lowered },
        _ => TargetPlan::Resolver,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ruleset::CompiledRuleset;
    use crate::engine::transaction::Transaction;
    use crate::variables::Collection;
    use std::sync::Arc;

    /// Two leading rules that read only `TX`, so the ruleset prepares their
    /// variables and transactions share them.
    const SETUP: &str = r#"
        SecAction "id:1,phase:1,pass,nolog,setvar:'tx.level=2',setvar:'tx.Score=0'"
        SecRule &TX:limit "@eq 0" "id:2,phase:1,pass,nolog,setvar:'tx.limit=5'"
    "#;

    /// Everything a caller can read of a transaction that ran `rules` on one
    /// request. `touch` takes `TX` before phase 1, so nothing is shared.
    fn outcome(ruleset: CompiledRuleset, touch: bool) -> String {
        let mut tx = Transaction::new(Arc::new(ruleset), 403);
        if touch {
            tx.tx_mut();
        }
        tx.process_uri("/shop?item=book&ITEM=pen", "POST", "HTTP/1.1")
            .unwrap();
        for (name, value) in [
            ("Host", "shop.example"),
            ("User-Agent", "curl/8"),
            ("X-Trace", "one"),
            ("x-trace", "two"),
        ] {
            tx.add_request_header(name, value).unwrap();
        }
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        tx.process_logging().unwrap();
        format!(
            "{:?}\n{:?}\n{:?}\n{:?}\n{:?}",
            tx.matched_rules(),
            tx.matched_data(),
            tx.messages(),
            tx.intervention(),
            tx.tx().all(),
        )
    }

    /// Run `rules` after `SETUP` with plans and without, and expect the same
    /// outcome and the rule ids in `matched` among the matched rules.
    fn same_with_and_without_plans(rules: &str, matched: &[&str]) {
        let load = || CompiledRuleset::from_string(&format!("{SETUP}{rules}")).expect("rules load");
        for touch in [false, true] {
            let planned = outcome(load(), touch);
            assert_eq!(planned, outcome(load().without_plans(), touch), "{rules}");
            let ids = planned.lines().next().unwrap();
            for id in matched {
                assert!(ids.contains(&format!("\"{id}\"")), "{id} in {ids}");
            }
        }
    }

    /// The plan of the last rule of phase 1 in `rules` after `SETUP`, target
    /// by target.
    fn planned(rules: &str, targets: usize) -> Vec<String> {
        let ruleset = CompiledRuleset::from_string(&format!("{SETUP}{rules}")).unwrap();
        let plan = ruleset
            .plans_for_phase(crate::engine::phase::Phase::RequestHeaders)
            .last()
            .unwrap();
        (0..targets)
            .map(|position| match plan.target(position) {
                TargetPlan::Resolver => "resolver".to_string(),
                TargetPlan::TxKey {
                    key,
                    lowered,
                    position,
                } => format!("tx {key} {lowered} {position:?}"),
                TargetPlan::HeaderKey { key, lowered } => format!("header {key} {lowered}"),
            })
            .collect()
    }

    #[test]
    fn a_key_is_prepared_and_anything_else_left_to_the_resolver() {
        assert_eq!(
            planned(
                r#"SecRule TX:Level|TX:later|&TX:limit|TX:/^l/|TX|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS|ARGS:item "@eq 1" "id:10,phase:1,pass""#,
                9
            ),
            [
                "tx Level level Some(0)",
                "tx later later None",
                "tx limit limit Some(2)",
                "resolver",
                "resolver",
                "header User-Agent user-agent",
                "resolver",
                "resolver",
                // Past the rule's targets.
                "resolver",
            ]
        );
        // A rule that leaves a target out has the resolver apply that.
        assert_eq!(
            planned(
                r#"SecRule TX:level|REQUEST_HEADERS:Host|!REQUEST_HEADERS:Host "@eq 1" "id:10,phase:1,pass""#,
                2
            ),
            ["resolver", "resolver"]
        );
    }

    #[test]
    fn shared_tx_variables_read_the_same() {
        same_with_and_without_plans(
            r#"
            SecRule TX:LEVEL "@eq 2" "id:10,phase:1,pass,log,msg:'%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'"
            SecRule TX:level|TX:Score|TX:limit "@ge 0" "id:11,phase:2,pass,log,logdata:'%{MATCHED_VAR_NAME}'"
            SecRule &TX:level "@eq 1" "id:12,phase:2,pass"
            SecRule &TX:missing "@eq 0" "id:13,phase:2,pass"
            SecRule TX:missing "@unconditionalMatch" "id:14,phase:2,pass"
            "#,
            &["10", "11", "12", "13"],
        );
    }

    #[test]
    fn changed_and_deleted_tx_variables_read_the_same() {
        same_with_and_without_plans(
            r#"
            SecRule REQUEST_METHOD "POST" "id:10,phase:1,pass,setvar:'tx.score=+3',setvar:'!tx.level',setvar:'tx.own=1'"
            SecRule TX:score "@eq 3" "id:11,phase:1,pass"
            SecRule &TX:level "@eq 0" "id:12,phase:1,pass"
            SecRule TX:level "@unconditionalMatch" "id:13,phase:1,pass"
            SecRule TX:OWN "@eq 1" "id:14,phase:1,pass"
            SecRule REQUEST_METHOD "POST" "id:15,phase:2,pass,setvar:'tx.level=7',setvar:'!tx.own'"
            SecRule TX:level "@eq 7" "id:16,phase:2,pass"
            SecRule &TX:own "@eq 0" "id:17,phase:2,pass"
            "#,
            &["10", "11", "12", "14", "15", "16", "17"],
        );
    }

    #[test]
    fn captures_read_the_same() {
        same_with_and_without_plans(
            r#"
            SecRule REQUEST_URI "@rx ^/(\w+)" "id:10,phase:1,pass,capture"
            SecRule TX:1 "@streq shop" "id:11,phase:1,pass"
            SecRule TX:0|TX:2 "@contains shop" "id:12,phase:1,pass"
            "#,
            &["10", "11", "12"],
        );
    }

    #[test]
    fn request_headers_read_the_same() {
        same_with_and_without_plans(
            r#"
            SecRule REQUEST_HEADERS:User-Agent "@contains curl" "id:10,phase:1,pass,log,msg:'%{MATCHED_VAR_NAME}'"
            SecRule REQUEST_HEADERS:X-TRACE "@rx ^t" "id:11,phase:1,pass,log,logdata:'%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'"
            SecRule &REQUEST_HEADERS:x-trace "@eq 2" "id:12,phase:1,pass"
            SecRule &REQUEST_HEADERS:Missing "@eq 0" "id:13,phase:1,pass"
            SecRule REQUEST_HEADERS:Missing "@unconditionalMatch" "id:14,phase:1,pass"
            SecRule REQUEST_HEADERS:host "@streq shop.example" "id:15,phase:2,pass,chain"
                SecRule TX:limit "@eq 5" "chain"
                SecRule REQUEST_HEADERS:User-Agent "!@contains wget" ""
            "#,
            &["10", "11", "12", "13", "15"],
        );
    }

    #[test]
    fn target_removals_apply_the_same() {
        same_with_and_without_plans(
            r#"
            SecRule REQUEST_METHOD "POST" "id:10,phase:1,pass,ctl:ruleRemoveTargetById=11;TX:level,ctl:ruleRemoveTargetById=12;REQUEST_HEADERS:User-Agent,ctl:ruleRemoveTargetByTag=quiet;REQUEST_HEADERS:x-trace"
            SecRule TX:level|TX:limit "@ge 1" "id:11,phase:1,pass,log,logdata:'%{MATCHED_VAR_NAME}'"
            SecRule REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Host "@rx ." "id:12,phase:1,pass,log,logdata:'%{MATCHED_VAR_NAME}'"
            SecRule &REQUEST_HEADERS:X-Trace "@eq 0" "id:13,phase:1,pass,tag:'quiet'"
            SecRule &REQUEST_HEADERS:X-Trace "@eq 2" "id:14,phase:1,pass"
            "#,
            &["10", "11", "12", "13", "14"],
        );
    }
}
