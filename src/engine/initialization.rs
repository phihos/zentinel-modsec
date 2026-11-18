//! Precompute leading TX defaults whose only input is the initially empty collection.
use super::ruleset::{CompiledFlow, CompiledRule, RuleDispatch};
use crate::parser::{Action, DataAction, OperatorName, SetVarValue};
use crate::variables::{folded_key, ByteValue, MemberSelector};
use indexmap::IndexMap;

// Bound both the planner's work and the per-ruleset defaults it retains.
const MAX_RULES: usize = 64;
const MAX_ASSIGNMENTS: usize = 128;
const MIN_DEFAULTS: usize = 8;

pub(super) struct TxDefaults {
    pub end: usize,
    // Final literal assignments, in first-insertion order.
    pub assignments: Box<[(ByteValue, ByteValue)]>,
    pub ids: Box<[u8]>,
    pub counts: Box<[(u8, u8)]>,
    pub last_count: Option<(u8, u8)>,
}

impl TxDefaults {
    pub fn count_value(dispatch: &[RuleDispatch], (index, n): (u8, u8)) -> (ByteValue, ByteValue) {
        let name = dispatch[usize::from(index)].selections[0]
            .match_name
            .as_deref()
            .unwrap();
        (name.clone(), ByteValue::decimal(i64::from(n)))
    }

    pub fn compile(rules: &[CompiledRule], dispatch: &[RuleDispatch]) -> Option<Box<Self>> {
        let mut assignments = IndexMap::<ByteValue, ByteValue>::new();
        let mut ids = Vec::new();
        let mut counts = Vec::new();
        let mut last_count = None;
        let mut end = 0;
        for (index, (rule, plan)) in rules.iter().zip(dispatch).take(MAX_RULES).enumerate() {
            if rule.is_chain || !matches!(plan.flow, CompiledFlow::Next) {
                break;
            }
            let count =
                if plan.single_tx_numeric && rule.variables[0].count_mode && !rule.operator_negated
                {
                    let MemberSelector::Key(key) = &plan.selections[0].member else {
                        unreachable!("compiled literal TX selector")
                    };
                    let present = assignments.contains_key(key.as_ref());
                    let value = if present { b"1" } else { b"0" };
                    if !plan
                        .numeric
                        .expect("compiled numeric predicate")
                        .matches(value)
                    {
                        end = index + 1;
                        continue;
                    }
                    Some(u8::from(present))
                } else if rule.variables.is_empty()
                    && rule.operator_spec.name == OperatorName::UnconditionalMatch
                    && !rule.operator_negated
                    && !plan.dynamic
                {
                    None
                } else {
                    break;
                };
            // Only a passing rule with literal writes can be replayed without
            // reading request data, changing controls, or stopping this phase.
            if plan.capture
                || plan.multi_match
                || plan.disruptive(rule).is_some()
                || plan.controls_from != rule.actions.len()
                || assignments.len() + plan.setvars.len() > MAX_ASSIGNMENTS
                || plan.setvars.iter().any(|op| op.key.is_none())
            {
                break;
            }
            let copied = if plan.setvars.iter().any(|op| op.value.is_none()) {
                let Some(source) = literal_copy_source(rule, plan, &assignments) else {
                    break;
                };
                Some(source)
            } else {
                None
            };
            for op in &plan.setvars {
                let key = op.key.as_ref().unwrap();
                let value = op.value.as_ref().or(copied.as_ref()).unwrap();
                assignments.insert(key.clone(), value.clone());
            }
            if rule.id.is_some() {
                ids.push(index as u8);
            }
            last_count = count.map(|n| (index as u8, n));
            counts.extend(last_count);
            end = index + 1;
        }
        (assignments.len() >= MIN_DEFAULTS).then(|| {
            Box::new(Self {
                end,
                assignments: assignments.into_iter().collect(),
                ids: ids.into_boxed_slice(),
                counts: counts.into_boxed_slice(),
                last_count,
            })
        })
    }
}

// An exact TX reference is assignment syntax. A leading sign, a second macro
// or any surrounding text requires the interpreter, as does an unknown source.
fn literal_copy_source(
    rule: &CompiledRule,
    plan: &RuleDispatch,
    assignments: &IndexMap<ByteValue, ByteValue>,
) -> Option<ByteValue> {
    let [op] = &*plan.setvars else { return None };
    let Action::Data(DataAction::SetVar(spec)) = &rule.actions[op.action_index] else {
        return None;
    };
    let SetVarValue::Macro(raw) = &spec.value else {
        return None;
    };
    let ("", name, "") = super::split_operator_macro(raw)? else {
        return None;
    };
    let (collection, key) = name.split_once('.')?;
    if !collection.eq_ignore_ascii_case("tx") {
        return None;
    }
    assignments
        .get(folded_key(key.as_bytes()).as_ref())
        .cloned()
}

#[cfg(test)]
mod tests {
    use crate::variables::ByteCollection;
    use crate::ModSecurity;

    #[test]
    fn leaves_request_inputs_and_observable_actions_for_the_interpreter() {
        let prefix = r#"SecAction "id:1,phase:1,pass,setvar:tx.a=0,setvar:tx.b=1,setvar:tx.c=2,setvar:tx.d=3,setvar:tx.e=4,setvar:tx.f=5,setvar:tx.g=6,setvar:tx.h=7""#;
        for boundary in [
            r#"SecAction "id:2,phase:1,pass,setvar:tx.a=+%{TX.b}""#,
            r#"SecAction "id:2,phase:1,pass,setvar:tx.a=-%{TX.b}""#,
            r#"SecAction "id:2,phase:1,pass,setvar:tx.a=%{TX.b}%{TX.c}""#,
            r#"SecAction "id:2,phase:1,pass,setvar:tx.a=%{TX.absent}""#,
            r#"SecAction "id:2,phase:1,pass,setvar:tx.a=%{request_headers.host}""#,
            r#"SecAction "id:2,phase:1,pass,setvar:tx.a=42,setvar:tx.b=%{TX.a}""#,
            r#"SecAction "id:2,phase:1,pass,ctl:ruleEngine=DetectionOnly""#,
            r#"SecAction "id:2,phase:1,pass,skip:1""#,
            r#"SecRule &TX:a "@eq 1" "id:2,phase:1,deny""#,
            r#"SecRule &TX:a "@eq 1" "id:2,phase:1,pass,capture""#,
            r#"SecRule REQUEST_URI "@unconditionalMatch" "id:2,phase:1,pass""#,
        ] {
            let engine = ModSecurity::from_string(&format!("{prefix}\n{boundary}")).unwrap();
            assert_eq!(
                engine.ruleset().tx_defaults.as_ref().unwrap().end,
                1,
                "{boundary}"
            );
        }
    }

    #[test]
    fn audit_reads_before_and_after_phase_changes_publish_each_match_once() {
        let mut config = String::from("SecRuleEngine On\n");
        for i in 1..=8 {
            config.push_str(&format!(
                "SecRule &TX:k{i} \"@eq 0\" \"id:{i},phase:1,pass,setvar:tx.k{i}=1\"\n"
            ));
        }
        config.push_str(
            r#"SecRule REQUEST_URI "@streq /" "id:9,phase:1,pass"
SecRule TX:k1 "@eq 1" "id:10,phase:2,pass"
SecRule TX:k2 "@eq 1" "id:11,phase:5,pass""#,
        );
        let engine = ModSecurity::from_string(&config).unwrap();
        for read_between_phases in [false, true] {
            let mut fast = engine.new_transaction();
            let mut reference = engine.new_transaction();
            reference.set_record_setvar_effects(true);
            for tx in [&mut fast, &mut reference] {
                assert!(tx.matched_rules().is_empty());
                assert!(tx.matched_data().is_empty());
                tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
                tx.process_request_headers().unwrap();
            }
            if read_between_phases {
                assert_eq!(fast.matched_rules(), reference.matched_rules());
                assert_eq!(fast.matched_data(), reference.matched_data());
                assert_eq!(fast.matched_data().len(), 9);
            }
            for tx in [&mut fast, &mut reference] {
                tx.process_request_body().unwrap();
                tx.process_logging().unwrap();
            }
            assert_eq!(fast.matched_rules(), reference.matched_rules());
            assert_eq!(fast.matched_data(), reference.matched_data());
            assert_eq!(fast.matched_data().len(), 11);
        }
    }

    #[test]
    fn replay_preserves_order_and_match_evidence_before_a_request_dependent_rule() {
        let mut config = String::from("SecRuleEngine On\n");
        for i in 1..=8 {
            config.push_str(&format!(
                "SecRule &TX:K{i} \"@eq 0\" \"id:{i},phase:1,pass,setvar:tx.K{i}={i}\"\n"
            ));
        }
        config.push_str(
            r#"
SecRule &TX:k1 "@eq 0" "id:9,phase:1,deny"
SecRule &TX:k1 "@eq 1" "id:20,phase:1,pass,setvar:tx.saved=%{Tx.k2}"
SecRule &TX:k1 "@eq 1" "id:10,phase:1,pass,setvar:tx.K2=42"
SecAction "id:21,phase:1,pass,setvar:tx.saved_twice=%{tx.saved}"
SecRule REQUEST_URI "@streq /check" "id:11,phase:1,pass,setvar:tx.previous=%{tx.k2}"
SecRule TX:previous "@eq 42" "id:12,phase:1,deny"
"#,
        );
        let engine = ModSecurity::from_string(&config).unwrap();
        assert_eq!(engine.ruleset().tx_defaults.as_ref().unwrap().end, 12);
        for path in ["/", "/check"] {
            for seeded in [false, true] {
                let run = |trace| {
                    let mut tx = engine.new_transaction();
                    tx.set_record_setvar_effects(trace);
                    if seeded {
                        tx.tx_mut().set_bytes("K1", "caller");
                    }
                    tx.process_uri(path, "GET", "HTTP/1.1").unwrap();
                    assert!(tx.matched_data().is_empty());
                    tx.process_request_headers().unwrap();
                    tx
                };
                let (fast, reference) = (run(false), run(true));
                assert_eq!(fast.tx().all_bytes(), reference.tx().all_bytes());
                assert_eq!(fast.tx().get_bytes(b"saved_twice").unwrap()[0], b"2");
                assert_eq!(fast.matched_rules(), reference.matched_rules());
                assert_eq!(fast.matched_data(), reference.matched_data());
                assert_eq!(fast.has_intervention(), reference.has_intervention());
                if seeded {
                    assert_eq!(fast.tx().get_bytes(b"k1").unwrap()[0], b"caller");
                }
            }
        }
    }
}
