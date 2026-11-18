//! Transaction mutations applied for each matching rule value.
use super::{SetVarChange, SetVarEffect, Transaction};
use crate::engine::control::CtlDirective;
use crate::engine::phase::Phase;
use crate::engine::ruleset::{CompiledRule, CompiledSetVar, RuleDispatch};
use crate::parser::{Action, DataAction, SetVarSpec, SetVarValue};
use crate::variables::ByteValue;

impl Transaction {
    /// SecLang applies every setvar before the controls for the same match.
    pub(super) fn apply_match_actions(
        &mut self,
        rule: &CompiledRule,
        dispatch: &RuleDispatch,
        logical_id: Option<&str>,
    ) {
        for prepared in &dispatch.setvars {
            let Action::Data(DataAction::SetVar(op)) = &rule.actions[prepared.action_index] else {
                unreachable!("compiled setvar action index");
            };
            self.apply_setvar(op, prepared, logical_id);
        }
        for action in &rule.actions[dispatch.controls_from..] {
            if let Action::Control(control) = action {
                let directive = self
                    .ruleset
                    .controls
                    .get(control)
                    .expect("compiled control action")
                    .clone();
                self.apply_control(directive);
            }
        }
    }

    fn apply_control(&mut self, directive: CtlDirective) {
        match &directive {
            CtlDirective::Unsupported { .. } => return,
            CtlDirective::RequestBodyLimit(_) if self.phase > Phase::RequestHeaders => return,
            CtlDirective::ResponseBodyLimit(_) | CtlDirective::ResponseBodyProcessorJson
                if self.phase > Phase::ResponseHeaders =>
            {
                return
            }
            CtlDirective::ResponseBodyProcessorJson => {
                self.response.json.get_or_insert_with(Default::default);
            }
            CtlDirective::RequestBodyProcessor(processor) => {
                self.request.body_processor.clone_from(processor);
            }
            _ => {}
        }
        self.controls.apply_compiled(
            directive,
            Some(&self.ruleset.selectors),
            self.ruleset.multiphase,
        );
    }

    /// Apply a setvar operation.
    fn apply_setvar(&mut self, op: &SetVarSpec, prepared: &CompiledSetVar, rule_id: Option<&str>) {
        let record = rule_id.filter(|_| self.record_setvar_effects);
        let (key, audit_key) = match &prepared.key {
            Some(key) => (key.clone(), record.map(|_| op.key.clone())),
            None => {
                let expanded = self.expand_macros_bytes(&op.key);
                let key = ByteValue::from(crate::variables::folded_key(&expanded));
                (
                    key,
                    record.map(|_| ByteValue::from(expanded).display_text().to_owned()),
                )
            }
        };
        use crate::parser::SetVarOperand;
        let change = match &op.value {
            SetVarValue::Delete => {
                self.tx.delete_canonical(key.as_bytes());
                Some(SetVarChange::Delete)
            }
            SetVarValue::Unresolved => return,
            value => {
                let expanded = match value {
                    SetVarValue::Macro(raw) => Some(self.expand_macros_bytes(raw)),
                    _ => None,
                };
                let operation = match (value, expanded.as_deref()) {
                    (_, Some(bytes)) => SetVarOperand::parse(bytes),
                    (SetVarValue::Increment(n), _) => SetVarOperand::Add(*n),
                    (SetVarValue::Decrement(n), _) => SetVarOperand::Subtract(*n),
                    _ => SetVarOperand::Text,
                };
                match operation {
                    SetVarOperand::Unresolved => return,
                    SetVarOperand::Text => {
                        let value = if let Some(bytes) = expanded {
                            ByteValue::from(bytes)
                        } else {
                            prepared
                                .value
                                .as_ref()
                                .expect("compiled literal assignment")
                                .clone()
                        };
                        let change = record.map(|_| match value.as_utf8() {
                            Ok(text) => SetVarChange::Set(text.to_owned()),
                            Err(_) => SetVarChange::SetBytes(value.as_bytes().to_vec()),
                        });
                        self.tx.set_canonical(key, value);
                        change
                    }
                    SetVarOperand::Add(n) | SetVarOperand::Subtract(n) => {
                        let subtract = matches!(operation, SetVarOperand::Subtract(_));
                        let delta = if subtract { n.wrapping_neg() } else { n };
                        if !self.tx.increment_canonical(key, delta, false) {
                            return;
                        }
                        Some(if subtract {
                            SetVarChange::Decrement(n)
                        } else {
                            SetVarChange::Increment(n)
                        })
                    }
                }
            }
        };
        if let (Some(rule_id), Some(key), Some(op_change)) = (record, audit_key, change) {
            self.setvar_effects.push(SetVarEffect {
                rule_id: rule_id.into(),
                collection: op.collection.to_ascii_lowercase(),
                key,
                op: op_change,
            });
        }
    }
}
