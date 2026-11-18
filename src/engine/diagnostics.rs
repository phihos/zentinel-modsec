//! Load-time inventory of accepted semantics the engine does not execute.
//!
//! Keep this separate from evaluation: warning once at load identifies affected
//! rules without adding branches or log noise to the request path.
use std::collections::{BTreeMap, BTreeSet};

use crate::parser::{
    Action, DataAction, Directive, FlowAction, LoggingAction, MetadataAction, OperatorName,
    Selection, SetVarValue, VariableName, VariableSpec, XmlTarget,
};
use crate::variables::SelectorPrograms;

type Diagnostics = BTreeMap<(String, String, &'static str), BTreeSet<String>>;

fn record(found: &mut Diagnostics, kind: &str, name: &str, reason: &'static str, id: &str) {
    found
        .entry((kind.into(), name.into(), reason))
        .or_default()
        .insert(id.into());
}

/// Report recognized no-ops and approximations, grouped by capability and IDs.
pub(super) fn report(
    directives: &[Directive],
    programs: &mut SelectorPrograms,
) -> crate::Result<()> {
    let all_ids: BTreeSet<String> = directives
        .iter()
        .filter_map(|directive| {
            let actions = match directive {
                Directive::SecRule(rule) => &rule.actions,
                Directive::SecAction(rule) => &rule.actions,
                _ => return None,
            };
            id(actions)
        })
        .collect();
    let global_ids = if all_ids.is_empty() {
        "(ruleset)".into()
    } else {
        all_ids.into_iter().collect::<Vec<_>>().join(",")
    };
    let mut found = Diagnostics::new();
    let mut chain_id = None;
    for directive in directives {
        let (actions, variables, operator) = match directive {
            Directive::SecRule(rule) => (
                &rule.actions,
                rule.variables.as_slice(),
                Some(&rule.operator),
            ),
            Directive::SecAction(rule) => (&rule.actions, &[][..], None),
            Directive::Unknown(name) if !name.eq_ignore_ascii_case("SecComponentSignature") => {
                record(
                    &mut found,
                    "directive",
                    name,
                    "directive is not implemented and has no effect",
                    &global_ids,
                );
                continue;
            }
            _ => continue,
        };
        let effective_id = id(actions)
            .or_else(|| chain_id.clone())
            .unwrap_or_else(|| "(no id)".into());
        chain_id = if actions
            .iter()
            .any(|a| matches!(a, Action::Flow(FlowAction::Chain)))
        {
            Some(effective_id.clone())
        } else {
            None
        };
        report_variables(&mut found, variables, &effective_id, programs);
        if let Some(operator) = operator {
            let reason = match operator.name {
                OperatorName::VerifyCc | OperatorName::VerifySsn | OperatorName::VerifyCpf |
                OperatorName::ValidateHash | OperatorName::ValidateDtd |
                OperatorName::Rbl | OperatorName::GeoLookup | OperatorName::GsbLookup |
                OperatorName::InspectFile | OperatorName::FuzzyHash | OperatorName::Rsub =>
                    Some("operator is a placeholder and always returns no match (negation may invert that result)"),
                OperatorName::StrMatch => Some("operator is approximated by substring matching"),
                _ => None,
            };
            if let Some(reason) = reason {
                record(
                    &mut found,
                    "operator",
                    &format!("{:?}", operator.name),
                    reason,
                    &effective_id,
                );
            }
            if !operator.name.uses_data_file() {
                report_macros(&mut found, &operator.argument, &effective_id);
            }
        }
        for action in actions {
            if let Action::Data(DataAction::SetVar(spec)) = action {
                crate::parser::validate_setvar_target(&spec.collection, &spec.key)?;
            }
            report_action(&mut found, action, &effective_id);
        }
    }
    emit(found);
    Ok(())
}

pub(super) fn report_added_targets(
    variables: &[VariableSpec],
    rule_id: Option<&str>,
    programs: &mut SelectorPrograms,
) {
    let mut found = Diagnostics::new();
    report_variables(
        &mut found,
        variables,
        rule_id.unwrap_or("(no id)"),
        programs,
    );
    emit(found);
}

fn emit(found: Diagnostics) {
    for ((kind, name, reason), ids) in found {
        tracing::warn!(feature = %kind, name = %name, rule_ids = %ids.into_iter().collect::<Vec<_>>().join(","), %reason,
            "accepted configuration has unsupported or approximated semantics");
    }
}

fn id(actions: &[Action]) -> Option<String> {
    actions.iter().find_map(|action| match action {
        Action::Metadata(MetadataAction::Id(id)) => Some(id.to_string()),
        _ => None,
    })
}

fn report_variables(
    found: &mut Diagnostics,
    variables: &[VariableSpec],
    id: &str,
    programs: &mut SelectorPrograms,
) {
    for variable in variables {
        if !variable.name.is_implemented() {
            record(
                found,
                "variable",
                &format!("{:?}", variable.name),
                "variable has no resolver and contributes no values",
                id,
            );
        }
        if variable.name == VariableName::Xml
            && XmlTarget::from_selection(variable.selection.as_ref()).is_none()
        {
            record(
                found,
                "variable",
                "XML selector",
                "only bare XML, XML:/* and XML://@* are implemented",
                id,
            );
        }
        if variable.name != VariableName::Xml {
            if let Some(Selection::Regex(pattern)) = &variable.selection {
                report_regex(found, pattern, variable.name, id, programs);
            }
        }
        for exclusion in &variable.exclusions {
            if let Some((name, pattern)) = crate::variables::regex_exclusion(exclusion) {
                report_regex(found, pattern, name, id, programs);
            }
        }
    }
}

fn report_regex(
    found: &mut Diagnostics,
    pattern: &str,
    collection: VariableName,
    id: &str,
    programs: &mut SelectorPrograms,
) {
    // Syntax alone is insufficient: valid regexes may exceed the compiled
    // program limit. Reuse the resolver cache so this also warms successful
    // selectors once, and failed compilations remain cached for evaluation.
    if programs.add(pattern, collection).is_none() {
        record(
            found,
            "variable-regex",
            pattern,
            "selector or exclusion regex cannot be compiled and will match nothing",
            id,
        );
    }
}

fn report_action(found: &mut Diagnostics, action: &Action, id: &str) {
    let ignored = "action is accepted but is not executed";
    let (name, reason) = match action {
        Action::Unsupported(name) => {
            record(found, "action", name, ignored, id);
            return;
        }
        Action::Data(DataAction::InitCol { .. }) => ("initcol", ignored),
        Action::Data(DataAction::SetUid(_)) => ("setuid", ignored),
        Action::Data(DataAction::SetSid(_)) => ("setsid", ignored),
        Action::Data(DataAction::ExpireVar { .. }) => ("expirevar", ignored),
        Action::Data(DataAction::DeprecateVar(_)) => ("deprecatevar", ignored),
        Action::Data(DataAction::Exec(_)) => ("exec", ignored),
        Action::Data(DataAction::Prepend(_)) => ("prepend", ignored),
        Action::Data(DataAction::Append(_)) => ("append", ignored),
        Action::Logging(action) => {
            let name = match action {
                LoggingAction::Log => "log",
                LoggingAction::NoLog => "nolog",
                LoggingAction::AuditLog => "auditlog",
                LoggingAction::NoAuditLog => "noauditlog",
                LoggingAction::SanitiseMatched => "sanitiseMatched",
                LoggingAction::SanitizeMatched => "sanitizeMatched",
                LoggingAction::SanitiseArg(_) => "sanitiseArg",
                LoggingAction::SanitiseRequestHeader(_) => "sanitiseRequestHeader",
                LoggingAction::SanitiseResponseHeader(_) => "sanitiseResponseHeader",
            };
            (name, "engine has no logging or sanitization subsystem; the embedding caller must implement this policy")
        }
        Action::Transformation(name)
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "parityeven7bit" | "parityodd7bit" | "parityzero7bit"
            ) =>
        {
            record(
                found,
                "transformation",
                name,
                "transformation is a placeholder and leaves its input unchanged",
                id,
            );
            return;
        }
        Action::Data(DataAction::SetVar(spec)) => {
            report_macros(found, &spec.key, id);
            if let SetVarValue::Macro(value) = &spec.value {
                report_macros(found, value, id);
            }
            return;
        }
        _ => return,
    };
    record(found, "action", name, reason, id);
}

fn report_macros(found: &mut Diagnostics, value: &str, id: &str) {
    let mut remaining = value;
    while let Some((_, after)) = remaining.split_once("%{") {
        let Some((name, tail)) = after.split_once('}') else {
            break;
        };
        remaining = tail;
        let lower = name.to_ascii_lowercase();
        let supported = match lower.split_once('.') {
            Some((collection, _)) => matches!(
                collection,
                "tx" | "request_headers" | "args" | "args_get" | "args_post"
            ),
            None => {
                matches!(
                    lower.as_str(),
                    "matched_var" | "matched_var_name" | "unique_id" | "arguments_limit_reached"
                ) || VariableName::from_str(name).is_none()
            }
        };
        if !supported {
            record(
                found,
                "macro",
                name,
                "macro source is not implemented and expands to an empty string",
                id,
            );
        }
    }
}
