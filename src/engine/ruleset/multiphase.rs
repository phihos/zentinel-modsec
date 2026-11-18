//! Coraza's tagged evaluator schedules a logical rule at its declared and
//! inferred phases, then filters individual targets. Compile that schedule
//! once so transactions can use the ordinary per-phase dispatch loop.

use super::{CompiledRule, Phase, Rules};
use crate::parser::{VariableName, VariableSpec};

#[derive(Default)]
pub(super) struct SourceOrder(Vec<Event>);

enum Event {
    Rule {
        phase: Phase,
        index: usize,
        inferred: Phases,
    },
    Marker(String),
}

/// Bit zero denotes a target with no inferred phase (such as TX).
#[derive(Default, Clone, Copy)]
struct Phases(u8);

impl Phases {
    fn of(phase: Phase) -> u8 {
        1 << phase.number()
    }

    fn contains(self, phase: Phase) -> bool {
        self.0 & Self::of(phase) != 0
    }

    fn through(self, phase: Phase) -> bool {
        self.0 & ((Self::of(phase) << 1) - 1) != 0
    }
}

pub(super) type Schedule = [Vec<Entry>; Phase::ALL.len()];

pub(super) struct Entry {
    pub inactive: bool,
    pub repeated_chain: bool,
}

impl SourceOrder {
    pub fn marker(&mut self, name: String) {
        self.0.push(Event::Marker(name));
    }

    pub fn rule(&mut self, phase: Phase, index: usize, rule: &CompiledRule) {
        // Coraza records inferred phases on insertion. Subsequent target edits
        // change the targets examined when the rule runs.
        let mut inferred = Phases(Phases::of(phase));
        for target in &rule.variables {
            match target.name {
                VariableName::Args | VariableName::ArgsNames => {
                    inferred.0 |=
                        Phases::of(Phase::RequestHeaders) | Phases::of(Phase::RequestBody);
                }
                name => inferred.0 |= earliest(name).map_or(1, Phases::of),
            }
        }
        self.0.push(Event::Rule {
            phase,
            index,
            inferred,
        });
    }

    pub fn build(self, rules: &mut Rules) -> Schedule {
        let mut declared = std::mem::take(rules);
        for rule in declared.by_phase.iter_mut().flatten() {
            rule.variables = std::mem::take(&mut rule.variables)
                .into_iter()
                .flat_map(|target| split_target(target, true))
                .collect();
        }
        let mut metadata = Schedule::default();
        let mut phases = Phases::default();
        let mut child = false;
        let mut chain_min = None;
        let mut repeated_chain = false;
        for event in self.0 {
            let (phase, index, inferred) = match event {
                Event::Rule {
                    phase,
                    index,
                    inferred,
                } => (phase, index, inferred),
                Event::Marker(name) => {
                    rules.add_marker(name);
                    continue;
                }
            };
            let siblings = declared.for_phase(phase);
            let rule = &siblings[index];
            if !child {
                chain_min = child_min_phase(rule, siblings);
                phases = if rule.is_chain {
                    let mut phases = Phases(Phases::of(phase));
                    for candidate in Phase::ALL {
                        if candidate < phase
                            && Some(candidate) >= chain_min
                            && inferred.through(candidate)
                        {
                            phases.0 |= Phases::of(candidate);
                        }
                    }
                    phases
                } else {
                    inferred
                };
                repeated_chain = rule.is_chain && phases.0.count_ones() > 1;
            }
            for candidate in Phase::ALL.into_iter().filter(|p| phases.contains(*p)) {
                let mut scheduled = rule.clone();
                scheduled.is_chain = rule.chain_next.is_some();
                if !child {
                    scheduled.variables.retain(|target| {
                        let min = earliest(target.name);
                        if rule.is_chain {
                            // Earlier parent targets run once when the last
                            // required child becomes available. Other parent
                            // targets may run again until the declared phase.
                            Some(candidate) >= chain_min
                                && !(min.is_some()
                                    && min < chain_min
                                    && Some(candidate) != chain_min)
                        } else {
                            min.is_none_or(|min| min == candidate)
                        }
                    });
                }
                let output_index = rules.for_phase(candidate).len();
                scheduled.chain_next = rule.chain_next.map(|_| output_index + 1);
                metadata[candidate.index()].push(Entry {
                    inactive: !rule.variables.is_empty() && scheduled.variables.is_empty(),
                    repeated_chain,
                });
                rules.add(candidate, scheduled);
            }
            child = rule.chain_next.is_some();
        }
        metadata
    }
}

fn child_min_phase(rule: &CompiledRule, siblings: &[CompiledRule]) -> Option<Phase> {
    let mut next = rule.chain_next;
    let mut min = None;
    while let Some(index) = next {
        let link = &siblings[index];
        min = min.max(link.variables.iter().filter_map(|v| earliest(v.name)).min());
        next = link.chain_next;
    }
    min
}

pub(in crate::engine) fn split_target(
    mut target: VariableSpec,
    multiphase: bool,
) -> impl Iterator<Item = VariableSpec> {
    use VariableName::*;
    let post = match target.name {
        Args if multiphase => {
            target.name = ArgsGet;
            Some(ArgsPost)
        }
        ArgsNames if multiphase => {
            target.name = ArgsGetNames;
            Some(ArgsPostNames)
        }
        _ => None,
    };
    let post = post.map(|name| VariableSpec {
        name,
        ..target.clone()
    });
    std::iter::once(target).chain(post).map(|mut target| {
        if matches!(
            target.name,
            ArgsGet | ArgsPost | ArgsGetNames | ArgsPostNames
        ) {
            for exclusion in &mut target.exclusions {
                let (collection, selector) = exclusion.split_once(':').unwrap_or((exclusion, ""));
                if collection.eq_ignore_ascii_case("ARGS")
                    || collection.eq_ignore_ascii_case("ARGS_NAMES")
                {
                    let mut expanded = target.name.seclang_name().to_owned();
                    if !selector.is_empty() {
                        expanded.push(':');
                        expanded.push_str(selector);
                    }
                    *exclusion = expanded;
                }
            }
        }
        target
    })
}

/// Mirrors minPhase in Coraza v3.8.1's rule_multiphase.go. Unlisted
/// collections (including TX) are evaluated whenever the rule is scheduled.
fn earliest(name: VariableName) -> Option<Phase> {
    use VariableName::*;
    Some(match name {
        ArgsGet | ArgsGetNames | ArgsPath | ArgsCombinedSize | UniqueId | Time | TimeDay
        | TimeEpoch | TimeHour | TimeMin | TimeMon | TimeSec | TimeWday | TimeYear
        | QueryString | RemoteAddr | RemoteHost | RemotePort | RequestBasename
        | RequestFilename | RequestLine | RequestMethod | RequestProtocol | RequestUri
        | RequestUriRaw | ServerAddr | ServerName | ServerPort | RequestHeadersNames
        | RequestCookies | RequestHeaders | Geo | RequestCookiesNames | Env => {
            Phase::RequestHeaders
        }
        ArgsPost
        | ArgsPostNames
        | FilesCombinedSize
        | FullRequestLength
        | InboundDataError
        | MultipartDataAfter
        | MultipartDuplicatePartHeader
        | MultipartInvalidQuoting
        | ReqBodyError
        | ReqBodyErrorMsg
        | ReqBodyProcessorError
        | ReqBodyProcessorErrorMsg
        | RequestBody
        | RequestBodyLength
        | FilesSizes
        | FilesNames
        | MultipartFilename
        | MultipartFilenameCharset
        | MultipartFilenameLanguage
        | MultipartName
        | Files
        | FilesTmpnames
        | Xml
        | MultipartPartHeaders
        | Args
        | ArgsNames => Phase::RequestBody,
        ResponseContentType | ResponseProtocol | ResponseStatus | StatusLine
        | ResponseHeadersNames | ResponseHeaders => Phase::ResponseHeaders,
        OutboundDataError | ResponseBody | ResponseContentLength | ResponseArgs => {
            Phase::ResponseBody
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ruleset::{CompiledFlow, CompiledRuleset};
    use crate::parser::Parser;

    fn compile(text: &str) -> CompiledRuleset {
        let mut parser = Parser::new();
        parser.parse(text).unwrap();
        CompiledRuleset::compile_multiphase(parser.into_directives()).unwrap()
    }

    fn ids(rules: &[CompiledRule]) -> Vec<Option<&str>> {
        rules.iter().map(|rule| rule.id.as_deref()).collect()
    }

    #[test]
    fn keeps_order_and_resolves_markers_in_each_execution_phase() {
        let rules = compile(
            r#"
            SecRule REQUEST_METHOD "@streq POST" "id:101,phase:2,pass,skipAfter:done"
            SecAction "id:102,phase:1,pass"
            SecRule REQUEST_BODY "@streq abc" "id:103,phase:2,pass"
            SecMarker done
            SecMarker second
            SecRule ARGS "@streq blue" "id:104,phase:2,pass"
        "#,
        );
        assert_eq!(rules.rule_count(), 4);
        for (phase, expected) in [(Phase::RequestHeaders, "102"), (Phase::RequestBody, "103")] {
            let scheduled = rules.rules_for_phase(phase);
            assert_eq!(ids(scheduled), [Some("101"), Some(expected), Some("104")]);
            assert_eq!(scheduled[0].phase, Phase::RequestBody);
            let plans = rules.dispatch_for_phase(phase);
            assert_eq!(plans[0].inactive, phase == Phase::RequestBody);
            assert_eq!(rules.phase_markers(phase).take_through(2), 2);
            assert!(matches!(
                plans[0].flow,
                CompiledFlow::SkipAfter {
                    destination: Some(2),
                    ..
                }
            ));
        }
    }

    #[test]
    fn splits_counts_and_exclusions_including_updated_targets() {
        let rules = compile(
            r#"
            SecRule &ARGS|ARGS_NAMES|!ARGS_NAMES:color "@eq 2" "id:101,phase:2,pass"
            SecRuleUpdateTargetById 101 "!ARGS:size"
        "#,
        );
        for (phase, arg, names) in [
            (
                Phase::RequestHeaders,
                VariableName::ArgsGet,
                VariableName::ArgsGetNames,
            ),
            (
                Phase::RequestBody,
                VariableName::ArgsPost,
                VariableName::ArgsPostNames,
            ),
        ] {
            let targets = &rules.rules_for_phase(phase)[0].variables;
            assert_eq!(targets.len(), 2);
            assert!(targets[0].count_mode);
            for (target, name) in targets.iter().zip([arg, names]) {
                assert_eq!(target.name, name);
                for key in ["color", "size"] {
                    assert!(target
                        .exclusions
                        .contains(&format!("{}:{key}", name.seclang_name())));
                }
            }
        }
    }

    #[test]
    fn defers_chain_to_latest_required_child_and_keeps_child_targets() {
        let rules = compile(
            r#"
            SecRule REQUEST_METHOD "@streq POST" "id:101,phase:3,pass,chain"
                SecRule REQUEST_BODY "@streq blue" "chain"
                SecRule ARGS_NAMES "@streq color" "pass"
            SecRule TX:enabled "@eq 1" "id:102,phase:2,pass,chain"
                SecRule REQUEST_METHOD "@streq GET" "pass"
        "#,
        );
        let headers = rules.rules_for_phase(Phase::RequestHeaders);
        assert_eq!(ids(headers), [Some("102"), None]);
        assert_eq!(headers[0].chain_next, Some(1));
        let body = rules.rules_for_phase(Phase::RequestBody);
        assert_eq!(ids(body), [Some("101"), None, None, Some("102"), None]);
        assert_eq!(body[0].chain_next, Some(1));
        assert_eq!(body[1].chain_next, Some(2));
        assert_eq!(body[3].chain_next, Some(4));
        assert_eq!(body[2].variables.len(), 2);
        assert!(rules
            .dispatch_for_phase(Phase::RequestBody)
            .iter()
            .all(|plan| plan.multiphase_chain));
        assert!(rules.dispatch_for_phase(Phase::ResponseHeaders)[0].inactive);
    }

    #[test]
    fn target_update_changes_evaluation_without_reinferring_phase() {
        let rules = compile(
            r#"
            SecRule TX:color "@streq blue" "id:101,phase:2,pass"
            SecRuleUpdateTargetById 101 "ARGS"
        "#,
        );
        assert!(rules.rules_for_phase(Phase::RequestHeaders).is_empty());
        let targets = &rules.rules_for_phase(Phase::RequestBody)[0].variables;
        assert_eq!(
            targets.iter().map(|v| v.name).collect::<Vec<_>>(),
            [VariableName::Tx, VariableName::ArgsPost]
        );
    }
}
