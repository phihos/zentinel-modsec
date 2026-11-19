//! Compile SecLang declarations, apply configuration edits and finalize execution plans.

use std::{collections::HashMap, sync::Arc};

use super::{
    edits::{apply_rule_edits, apply_target_updates},
    has_chain,
    multiphase::SourceOrder,
    numeric_id, CompileOptions, CompiledRule, CompiledRuleset, RuleEngineMode, Rules,
};
use crate::engine::{control::CtlDirective, diagnostics, phase::Phase, split_operator_macro};
use crate::error::{Error, Result};
use crate::operators::{compile_operator, Operator, RegexOptions, RxOperator};
use crate::parser::{
    Action, DataAction, Directive, MetadataAction, OperatorName, OperatorSpec,
    RuleEngineMode as ParserRuleEngineMode, SecRule, Selection, SetVarValue, UpdateTargetById,
};
use crate::transformations::TransformationPipeline;

impl CompiledRuleset {
    /// Compile parsed directives into a ruleset.
    pub fn compile(directives: Vec<Directive>) -> Result<Self> {
        Self::compile_with_options(directives, CompileOptions::default())
    }

    /// Compile using Coraza's tagged multiphase evaluation. Rules can inspect
    /// variables as soon as their source becomes available.
    pub fn compile_multiphase(directives: Vec<Directive>) -> Result<Self> {
        Self::compile_with_options(
            directives,
            CompileOptions {
                multiphase: true,
                ..CompileOptions::default()
            },
        )
    }

    /// Compile using explicit connector compatibility options.
    pub fn compile_with_options(
        mut directives: Vec<Directive>,
        options: CompileOptions,
    ) -> Result<Self> {
        let mut order = options.multiphase.then(SourceOrder::default);
        if options.coraza_rule_semantics {
            validate_coraza_defaults(&directives)?;
        }
        apply_rule_edits(&mut directives)?;
        let mut ruleset = Self {
            multiphase: options.multiphase,
            coraza_rule_semantics: options.coraza_rule_semantics,
            ..Self::default()
        };
        let mut pending_chain: Option<(Phase, usize)> = None;

        diagnostics::report(&directives, &mut ruleset.selectors)?;

        let mut target_updates: Vec<(Option<String>, UpdateTargetById)> = Vec::new();

        let mut datasets = HashMap::new();
        let mut regex = RegexOptions {
            multiline: !options.no_regex_multiline,
            // The Go connector defaults to Off unless the rule file enables it.
            prefilter: !options.coraza_rule_semantics,
        };
        for directive in directives {
            let directive = match directive {
                Directive::SecAction(action) => Directive::SecRule(SecRule {
                    actions: action.actions,
                    location: action.location,
                    variables: vec![],
                    operator: OperatorSpec {
                        negated: false,
                        name: OperatorName::UnconditionalMatch,
                        argument: String::new(),
                    },
                }),
                other => other,
            };
            match directive {
                Directive::SecDataset(name, records) => {
                    if datasets.insert(name.clone(), records).is_some() {
                        tracing::warn!(target: super::LOG_TARGET, dataset = name, "overwriting named dataset");
                    }
                }
                Directive::SecRuleEngine(mode) => {
                    ruleset.engine_mode = match mode {
                        ParserRuleEngineMode::On => RuleEngineMode::On,
                        ParserRuleEngineMode::Off => RuleEngineMode::Off,
                        ParserRuleEngineMode::DetectionOnly => RuleEngineMode::DetectionOnly,
                    };
                }
                Directive::SecRxPreFilter(enabled) => regex.prefilter = enabled,
                Directive::SecRule(rule) => {
                    let (phase, index) = ruleset.rules.compile_rule(
                        rule,
                        &mut pending_chain,
                        &datasets,
                        options.literal_regex_arguments,
                        regex,
                    )?;
                    if let Some(order) = &mut order {
                        order.rule(phase, index, &ruleset.rules.for_phase(phase)[index]);
                    }
                }
                Directive::SecRuleUpdateTargetById(update) => {
                    // Applied after every rule is compiled: the directive may
                    // appear before or after the rule it targets, and CRS
                    // exclusion files are conventionally included last.
                    target_updates.push((None, update));
                }
                Directive::SecRuleUpdateTargetByTag(update) => {
                    target_updates.push((Some(update.tag), update.targets));
                }
                Directive::SecMarker(marker) => {
                    if let Some(order) = &mut order {
                        // Coraza appends SecMarker as a top-level rule. A later
                        // SecRule can no longer attach to the preceding chain.
                        pending_chain = None;
                        order.marker(marker.name.clone());
                    }
                    ruleset.rules.add_marker(marker.name);
                }
                Directive::SecRequestBodyAccess(value) => {
                    ruleset.body_config.request_access = value
                }
                Directive::SecResponseBodyAccess(value) => {
                    ruleset.body_config.response_access = value
                }
                Directive::SecArgumentsLimit(value) => ruleset.body_config.argument_limit = value,
                Directive::SecRequestBodyJsonDepthLimit(value) => {
                    ruleset.body_config.request_json_depth_limit = value
                }
                Directive::SecResponseBodyJsonDepthLimit(value) => {
                    ruleset.body_config.response_json_depth_limit = value
                }
                Directive::SecRequestBodyInMemoryLimit(value) => {
                    ruleset.body_config.request_in_memory_limit = Some(value);
                }
                Directive::SecRequestBodyLimit(value) => ruleset.body_config.request_limit = value,
                Directive::SecResponseBodyLimit(value) => {
                    ruleset.body_config.response_limit = value
                }
                Directive::SecRequestBodyLimitAction(value) => {
                    ruleset.body_config.request_limit_action = value
                }
                Directive::SecResponseBodyLimitAction(value) => {
                    ruleset.body_config.response_limit_action = value
                }
                Directive::SecUploadDir(dir) => {
                    tempfile::tempfile_in(&dir).map_err(|e| Error::Config {
                        message: format!("SecUploadDir {}: {e}", dir.display()),
                    })?;
                    ruleset.body_config.upload_dir = Some(dir);
                }
                Directive::SecResponseBodyMimeType(value) => {
                    ruleset.body_config.response_mime_types = value
                }
                Directive::SecResponseBodyMimeTypesClear => {
                    ruleset.body_config.response_mime_types.clear()
                }
                _ => {
                    // Other directives (SecDefaultAction, etc.) handled elsewhere
                }
            }
        }

        apply_target_updates(&mut ruleset, &target_updates);
        ruleset.compile_controls();
        ruleset.rule_count = ruleset.rules.count();
        let schedule = order.map(|order| order.build(&mut ruleset.rules));
        ruleset.compile_dispatch(schedule.as_ref(), options.literal_regex_arguments);
        ruleset.needs_upload_paths = ruleset
            .rules
            .by_phase
            .iter()
            .flatten()
            .any(reads_upload_paths);
        ruleset.body_config.validate()?;
        if ruleset.engine_mode == RuleEngineMode::DetectionOnly {
            ruleset.body_config.request_limit_action =
                crate::parser::BodyLimitAction::ProcessPartial;
            ruleset.body_config.response_limit_action =
                crate::parser::BodyLimitAction::ProcessPartial;
        }

        Ok(ruleset)
    }

    fn compile_controls(&mut self) {
        for rule in self.rules.by_phase.iter().flatten() {
            for action in &rule.actions {
                if let Action::Control(ctl) = action {
                    self.controls.entry(ctl.clone()).or_insert_with(|| {
                        let directive = CtlDirective::parse(ctl);
                        if let CtlDirective::RuleRemoveTargetByTag { target, .. } = &directive {
                            if let Ok(spec) = crate::parser::parse_single_variable(target) {
                                if let Some(Selection::Regex(pattern)) = spec.selection {
                                    self.selectors.add(&pattern, spec.name);
                                }
                            }
                        }
                        directive
                    });
                }
            }
        }
    }
}

// Go validates accumulated defaults the next time it parses a rule.
fn validate_coraza_defaults(directives: &[Directive]) -> Result<()> {
    let Some(last_rule) = directives
        .iter()
        .rposition(|d| matches!(d, Directive::SecRule(_) | Directive::SecAction(_)))
    else {
        return Ok(());
    };
    let mut defined = [false; 6];
    let invalid = |reason: &str| crate::error::Error::Config {
        message: format!("SecDefaultAction {reason}"),
    };
    for directive in &directives[..last_rule] {
        let Directive::SecDefaultAction(actions) = directive else {
            continue;
        };
        let mut phase = 0;
        let mut disruptive = false;
        for action in actions {
            match action {
                Action::Metadata(MetadataAction::Phase(p)) => phase = usize::from(*p),
                Action::Metadata(MetadataAction::LogData(_) | MetadataAction::Status(_)) => {}
                Action::Metadata(_) => return Err(invalid("must not contain metadata actions")),
                Action::Transformation(_) => {
                    return Err(invalid("must not contain transformation actions"))
                }
                Action::Disruptive(_) => disruptive = true,
                _ => {}
            }
        }
        if !(1..=5).contains(&phase) {
            return Err(invalid("must contain a phase between 1 and 5"));
        }
        if !disruptive {
            return Err(invalid("must contain a disruptive action"));
        }
        if defined[phase] {
            return Err(invalid("already defined for this phase"));
        }
        defined[phase] = true;
    }
    Ok(())
}

impl Rules {
    fn compile_rule(
        &mut self,
        rule: SecRule,
        pending_chain: &mut Option<(Phase, usize)>,
        datasets: &HashMap<String, Vec<String>>,
        literal_regex_arguments: bool,
        regex: RegexOptions,
    ) -> Result<(Phase, usize)> {
        // Continuations inherit their starter's phase, including when it differs
        // from the default phase of a rule without a phase action.
        let phase = pending_chain.map_or_else(|| extract_phase(&rule.actions), |(phase, _)| phase);
        let id = numeric_id(&rule.actions).map(|id| id.to_string());
        let is_chain = has_chain(&rule.actions);
        let transformations = extract_transformations(&rule.actions)?;
        let (operator, operator_negated) = compile_operator_reporting(
            &rule.operator,
            id.as_deref(),
            rule.location.file.as_deref(),
            datasets,
            literal_regex_arguments,
            regex,
        )?;
        let phase_rules = &mut self.by_phase[phase.index()];
        let index = phase_rules.len();
        if let Some((_, previous)) = *pending_chain {
            phase_rules[previous].chain_next = Some(index);
        }
        phase_rules.push(CompiledRule {
            id,
            phase,
            variables: rule.variables,
            operator,
            operator_negated,
            operator_spec: rule.operator,
            transformations,
            actions: rule.actions,
            is_chain,
            chain_next: None,
        });
        *pending_chain = is_chain.then_some((phase, index));
        Ok((phase, index))
    }
}

/// Extract phase from actions, defaulting to Phase 2.
fn extract_phase(actions: &[Action]) -> Phase {
    for action in actions {
        if let Action::Metadata(MetadataAction::Phase(p)) = action {
            return Phase::from_number(*p).unwrap_or(Phase::RequestBody);
        }
    }
    Phase::RequestBody // ModSecurity default
}

/// Compile a rule's operator, reporting an unusable `@rx` pattern rather than
/// failing the whole load.
///
/// An invalid regex used to be discovered lazily at match time and swallowed
/// into a no-match, so the rule was dead and nothing said so. Rejecting the
/// pattern outright would fix the silence but introduce a worse failure: a
/// single pattern this engine cannot parse — a PCRE construct the `regex`
/// crate does not implement, say — would stop the entire ruleset from
/// loading, and with it the WAF.
///
/// So the rule is kept and can never match, exactly as before, but the
/// operator is told at load time which rule is dead and why. Every other
/// operator keeps failing the load, as it did before: those arguments come
/// from the same config the operator is editing, not from a third-party
/// ruleset.
fn compile_operator_reporting(
    spec: &OperatorSpec,
    rule_id: Option<&str>,
    rule_file: Option<&std::path::Path>,
    datasets: &HashMap<String, Vec<String>>,
    literal_regex_arguments: bool,
    regex: RegexOptions,
) -> Result<(Arc<dyn Operator>, bool)> {
    if spec.name == OperatorName::ValidateSchema {
        let root = rule_file
            .and_then(std::path::Path::parent)
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let schema = crate::operators::schema::SchemaOperator::load(&spec.argument, root)?;
        return Ok((Arc::new(schema), spec.negated));
    }
    // A byte range supplied by a transaction macro is validated after expansion.
    if spec.name == OperatorName::ValidateByteRange
        && split_operator_macro(&spec.argument).is_some()
    {
        return Ok((
            Arc::new(crate::operators::ValidateByteRangeOperator::new(
                &spec.argument,
            )),
            spec.negated,
        ));
    }
    let dataset = if spec.name.uses_dataset() {
        datasets.get(&spec.argument).map(Vec::as_slice)
    } else {
        None
    };
    let compiled = if spec.name == OperatorName::Rx && literal_regex_arguments {
        RxOperator::from_coraza_pattern(&spec.argument, regex)
            .map(|rx| Arc::new(rx) as Arc<dyn Operator>)
    } else if spec.name == OperatorName::Rx && split_operator_macro(&spec.argument).is_some() {
        // The expression is supplied at evaluation time. Retain the declaration's
        // options on a shared, never-matching program until the operand is bound.
        RxOperator::with_options(r"\b\B", regex).map(|rx| Arc::new(rx) as Arc<dyn Operator>)
    } else {
        crate::operators::compile_with_dataset(spec, dataset, regex)
    };
    match compiled {
        Ok(operator) => Ok((operator, spec.negated)),
        Err(e) if spec.name == OperatorName::Rx => {
            tracing::error!(
                target: super::LOG_TARGET,
                rule_id = %rule_id.unwrap_or("(no id)"),
                pattern = %spec.argument,
                error = %e,
                "rule has an invalid @rx pattern and can never match; \
                 the rest of the ruleset was loaded"
            );
            let never = compile_operator(&OperatorSpec {
                negated: false,
                name: OperatorName::NoMatch,
                argument: String::new(),
            })?;
            // Negation is dropped deliberately. `!@rx <invalid>` with the
            // negation preserved would invert "never matches" into "matches
            // every request", turning a dead rule into one that blocks all
            // traffic -- far worse than the silence being fixed here.
            Ok((never, false))
        }
        Err(e) => Err(e),
    }
}

/// Extract and compile transformation pipeline.
fn extract_transformations(actions: &[Action]) -> Result<TransformationPipeline> {
    let mut names = Vec::new();
    for action in actions {
        if let Action::Transformation(t) = action {
            names.push(t.clone());
        }
    }
    if names.is_empty() {
        Ok(TransformationPipeline::new())
    } else {
        TransformationPipeline::from_names(&names)
    }
}

/// Create named files only if a rule can observe them. Run after target and
/// action updates, once per ruleset rather than on each multipart request.
fn reads_upload_paths(rule: &CompiledRule) -> bool {
    fn uses_macro(mut text: &str) -> bool {
        while let Some((_, name, rest)) = split_operator_macro(text) {
            if name
                .split('.')
                .next()
                .is_some_and(|n| n.eq_ignore_ascii_case("FILES_TMPNAMES"))
            {
                return true;
            }
            text = rest;
        }
        false
    }
    rule.variables
        .iter()
        .any(|v| v.name == crate::parser::VariableName::FilesTmpnames)
        || (!rule.operator_spec.name.has_literal_source()
            && uses_macro(&rule.operator_spec.argument))
        || rule.actions.iter().any(|action| match action {
            Action::Metadata(MetadataAction::Msg(value) | MetadataAction::LogData(value)) => {
                uses_macro(value)
            }
            Action::Data(DataAction::SetVar(spec)) => {
                uses_macro(&spec.key)
                    || matches!(&spec.value, SetVarValue::Macro(value) if uses_macro(value))
            }
            _ => false,
        })
}
