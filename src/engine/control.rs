//! Per-transaction control directives (`ctl:`).
//!
//! `ctl:` actions override engine behaviour for the remainder of one
//! transaction only. They must never mutate the shared compiled ruleset:
//! rulesets are behind an `Arc` and evaluated concurrently, so a rule removed
//! by one request would vanish for every request in flight.
//!
//! State therefore lives on the [`Transaction`](super::transaction::Transaction)
//! in [`TransactionControls`], is consulted during evaluation, and dies with
//! the transaction.
//!
//! Directives this engine cannot honour are reported at load time rather than
//! accepted and quietly dropped — see [`CtlDirective::Unsupported`] and
//! [`unsupported_controls`]. Silently accepting a security directive that does
//! nothing is the failure this module exists to fix, so reintroducing it for
//! the subset that is not implemented would defeat the point.
//!
//! Reporting is a warning rather than a hard error because CRS ships
//! directives this engine does not implement, `ctl:auditLogParts` among
//! them: rejecting those would make CRS unloadable, which is a worse
//! outcome than running it with a known and stated gap.

use crate::variables::{compile_selector, folded_key, SelectorPrograms};
use std::collections::HashSet;
use std::sync::Arc;

use crate::parser::{ControlAction, Selection, VariableSpec};

use super::ruleset::RuleEngineMode;

/// An inclusive range of rule IDs, as written by `ctl:ruleRemoveById`.
///
/// ModSecurity accepts both a single ID and a `start-end` range; a single ID
/// is stored as a range whose ends are equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleIdRange {
    start: u64,
    end: u64,
}

/// Transaction audit mode selected by a rule for use by the connector's writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditEngineMode {
    /// Record all transactions.
    On,
    /// Suppress the audit record.
    Off,
    /// Select transactions using matched audit actions and relevant status.
    RelevantOnly,
}

/// A parsed `ctl:` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtlDirective {
    /// `ctl:ruleEngine=On|Off|DetectionOnly`
    RuleEngine(RuleEngineMode),
    /// Override the connector's audit policy for this transaction.
    AuditEngine(AuditEngineMode),
    /// Replace, add, or remove parts of the audit record.
    AuditLogParts(String),
    /// `ctl:ruleRemoveById=ID` or `=START-END`, or several separated by commas.
    RuleRemoveById(Vec<RuleIdRange>),
    /// `ctl:ruleRemoveByTag=TAG` (exact, case-sensitive rule tag).
    RuleRemoveByTag(String),
    /// `ctl:ruleRemoveTargetById=ID;TARGET`
    RuleRemoveTargetById {
        /// ID of the rule the exclusion applies to.
        rule_id: String,
        /// Target to drop from that rule, e.g. `ARGS:token`.
        target: String,
    },
    /// `ctl:ruleRemoveTargetByTag=TAG;TARGET` (exact, case-sensitive tag).
    RuleRemoveTargetByTag {
        /// Rule tag to select.
        tag: String,
        /// Target to drop from the selected rules.
        target: String,
    },
    /// `ctl:requestBodyAccess=On|Off`
    RequestBodyAccess(bool),
    /// `ctl:responseBodyAccess=On|Off`
    ResponseBodyAccess(bool),
    /// Local request inspection threshold in bytes.
    RequestBodyLimit(usize),
    /// Local response inspection threshold in bytes.
    ResponseBodyLimit(usize),
    /// `ctl:requestBodyProcessor=URLENCODED|MULTIPART|JSON|XML|RAW`
    RequestBodyProcessor(String),
    /// `ctl:responseBodyProcessor=JSON`
    ResponseBodyProcessorJson,
    /// Expose an otherwise unprocessed body (Coraza 3.8.1 uses URLENCODED).
    ForceRequestBodyVariable(bool),
    /// Bypass the response MIME allowlist; body access and size limits still apply.
    ForceResponseBodyVariable(bool),
    /// A directive this engine does not implement.
    ///
    /// Kept as a distinct variant so it can be reported rather than discarded.
    Unsupported {
        /// The directive name as written.
        directive: String,
        /// The value as written, empty if the directive had none.
        value: String,
        /// Why this engine cannot honour it, for the operator-facing warning.
        reason: &'static str,
    },
}

/// Body processors this engine can actually run.
const SUPPORTED_BODY_PROCESSORS: &[&str] = &["URLENCODED", "MULTIPART", "JSON", "XML", "RAW"];

impl CtlDirective {
    /// Interpret a parsed `ctl:` action.
    ///
    /// Never fails: anything unrecognised becomes [`CtlDirective::Unsupported`]
    /// carrying the reason, so the caller decides whether to warn or reject.
    pub fn parse(action: &ControlAction) -> Self {
        let directive = action.directive.trim();
        let value = action.value.trim();

        match directive.to_ascii_lowercase().as_str() {
            "ruleengine" => match value.to_ascii_lowercase().as_str() {
                "on" => CtlDirective::RuleEngine(RuleEngineMode::On),
                "off" => CtlDirective::RuleEngine(RuleEngineMode::Off),
                "detectiononly" => CtlDirective::RuleEngine(RuleEngineMode::DetectionOnly),
                _ => CtlDirective::unsupported(
                    directive,
                    value,
                    "ruleEngine accepts only On, Off or DetectionOnly",
                ),
            },

            "ruleremovebyid" => match parse_id_ranges(value) {
                Some(ranges) if !ranges.is_empty() => CtlDirective::RuleRemoveById(ranges),
                _ => CtlDirective::unsupported(
                    directive,
                    value,
                    "ruleRemoveById expects a rule ID or an ID range such as 942100-942999",
                ),
            },

            "ruleremovebytag" => {
                // Coraza splits any optional collection suffix before
                // dispatching ctl actions. It validates a regex key there,
                // but whole-rule removal always selects by the tag alone.
                let (tag, suffix) = action.value.split_once(';').unwrap_or((&action.value, ""));
                if let Some((_, key)) = suffix.split_once(':') {
                    let key = key.trim();
                    if let Some(pattern) = key.strip_prefix('/').and_then(|p| p.strip_suffix('/')) {
                        let escaped = pattern
                            .as_bytes()
                            .iter()
                            .rev()
                            .take_while(|b| **b == b'\\')
                            .count()
                            % 2
                            == 1;
                        if !escaped && (pattern.is_empty() || regex::Regex::new(pattern).is_err()) {
                            return Self::unsupported(
                                directive,
                                value,
                                "ruleRemoveByTag has an invalid ctl collection-key regex",
                            );
                        }
                    }
                }
                Self::RuleRemoveByTag(tag.to_owned())
            }

            "ruleremovetargetbyid" => match value.split_once(';') {
                Some((rule_id, target))
                    if !rule_id.trim().is_empty() && !target.trim().is_empty() =>
                {
                    let Ok(spec) = crate::parser::parse_single_variable(target.trim()) else {
                        return Self::unsupported(
                            directive,
                            value,
                            "ruleRemoveTargetById has an invalid target",
                        );
                    };
                    if rule_id.trim().parse::<u64>().is_err()
                        || spec.count_mode
                        || matches!(spec.selection, Some(Selection::Regex(_)))
                    {
                        return Self::unsupported(directive, value,
                            "ruleRemoveTargetById requires one numeric ID and a literal, non-count target; regex keys are not implemented for this control");
                    }
                    CtlDirective::RuleRemoveTargetById {
                        rule_id: rule_id.trim().to_string(),
                        target: target.trim().to_string(),
                    }
                }
                _ => CtlDirective::unsupported(
                    directive,
                    value,
                    "ruleRemoveTargetById expects ID;TARGET, for example 942100;ARGS:token",
                ),
            },

            "ruleremovetargetbytag" => {
                let Some((tag, target)) = value.split_once(';') else {
                    return Self::unsupported(
                        directive,
                        value,
                        "ruleRemoveTargetByTag expects TAG;TARGET",
                    );
                };
                let (tag, target) = (tag.trim(), target.trim());
                if tag.is_empty() || target.is_empty() || target.contains('|') {
                    return Self::unsupported(
                        directive,
                        value,
                        "ruleRemoveTargetByTag expects a nonempty tag and one target",
                    );
                }
                let Ok(spec) = crate::parser::parse_single_variable(target) else {
                    return Self::unsupported(
                        directive,
                        value,
                        "ruleRemoveTargetByTag target is not a supported variable",
                    );
                };
                if spec.count_mode {
                    return Self::unsupported(
                        directive,
                        value,
                        "ruleRemoveTargetByTag target cannot use count mode",
                    );
                }
                if let Some(Selection::Regex(pattern)) = &spec.selection {
                    if compile_selector(pattern, spec.name).is_err() {
                        return Self::unsupported(
                            directive,
                            value,
                            "ruleRemoveTargetByTag target has an invalid regex",
                        );
                    }
                }
                CtlDirective::RuleRemoveTargetByTag {
                    tag: tag.to_string(),
                    target: target.to_string(),
                }
            }

            "requestbodylimit" | "responsebodylimit" => {
                let Some(limit) = value
                    .parse::<i64>()
                    .ok()
                    .and_then(|n| usize::try_from(n).ok())
                else {
                    return Self::unsupported(
                        directive,
                        value,
                        "body limit must be a nonnegative integer",
                    );
                };
                if directive.eq_ignore_ascii_case("requestbodylimit") {
                    Self::RequestBodyLimit(limit)
                } else {
                    Self::ResponseBodyLimit(limit)
                }
            }
            "requestbodyaccess" => match value.to_ascii_lowercase().as_str() {
                "on" => CtlDirective::RequestBodyAccess(true),
                "off" => CtlDirective::RequestBodyAccess(false),
                _ => CtlDirective::unsupported(
                    directive,
                    value,
                    "requestBodyAccess accepts only On or Off",
                ),
            },

            "forcerequestbodyvariable" => match value.to_ascii_lowercase().as_str() {
                "on" => Self::ForceRequestBodyVariable(true),
                "off" => Self::ForceRequestBodyVariable(false),
                _ => Self::unsupported(
                    directive,
                    value,
                    "forceRequestBodyVariable accepts only On or Off",
                ),
            },
            "forceresponsebodyvariable" => match value.to_ascii_lowercase().as_str() {
                "on" => Self::ForceResponseBodyVariable(true),
                "off" => Self::ForceResponseBodyVariable(false),
                _ => Self::unsupported(
                    directive,
                    value,
                    "forceResponseBodyVariable accepts only On or Off",
                ),
            },
            "responsebodyaccess" => match value.to_ascii_lowercase().as_str() {
                "on" => CtlDirective::ResponseBodyAccess(true),
                "off" => CtlDirective::ResponseBodyAccess(false),
                _ => CtlDirective::unsupported(
                    directive,
                    value,
                    "responseBodyAccess accepts only On or Off",
                ),
            },

            "responsebodyprocessor" if value.eq_ignore_ascii_case("json") => {
                Self::ResponseBodyProcessorJson
            }
            "responsebodyprocessor" => Self::unsupported(
                directive,
                value,
                "only the JSON response processor is supported",
            ),
            "requestbodyprocessor" => {
                let upper = value.to_ascii_uppercase();
                if SUPPORTED_BODY_PROCESSORS.contains(&upper.as_str()) {
                    CtlDirective::RequestBodyProcessor(upper)
                } else {
                    CtlDirective::unsupported(
                        directive,
                        value,
                        "requestBodyProcessor accepts only URLENCODED, MULTIPART, \
                         JSON, XML or RAW",
                    )
                }
            }

            "auditengine" => match value.to_ascii_lowercase().as_str() {
                "off" => Self::AuditEngine(AuditEngineMode::Off),
                "on" => Self::AuditEngine(AuditEngineMode::On),
                "relevantonly" => Self::AuditEngine(AuditEngineMode::RelevantOnly),
                _ => Self::unsupported(directive, value, "expected On, Off, or RelevantOnly"),
            },
            "auditlogparts" => {
                let letters = value
                    .strip_prefix(['+', '-'])
                    .or_else(|| value.strip_prefix('A')?.strip_suffix('Z'));
                if letters.is_some_and(|parts| parts.bytes().all(|p| (b'B'..=b'K').contains(&p))) {
                    Self::AuditLogParts(value.to_owned())
                } else {
                    Self::unsupported(directive, value, "invalid audit log parts")
                }
            }

            _ => CtlDirective::unsupported(directive, value, "unrecognised ctl directive"),
        }
    }

    fn unsupported(directive: &str, value: &str, reason: &'static str) -> Self {
        CtlDirective::Unsupported {
            directive: directive.to_string(),
            value: value.to_string(),
            reason,
        }
    }
}

/// How a logical rule's active tag controls restrict a given collection.
#[derive(PartialEq, Eq)]
pub(super) enum TagTargetRemoval {
    None,
    Members,
    All,
}

/// Parse `942100`, `942100-942999`, or a comma-separated mix of the two.
fn parse_id_ranges(value: &str) -> Option<Vec<RuleIdRange>> {
    let mut ranges = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Rule IDs are unsigned, so a '-' can only be a range separator.
        let range = match part.split_once('-') {
            Some((start, end)) => {
                let start: u64 = start.trim().parse().ok()?;
                let end: u64 = end.trim().parse().ok()?;
                if start > end {
                    return None;
                }
                RuleIdRange { start, end }
            }
            None => {
                let id: u64 = part.parse().ok()?;
                RuleIdRange { start: id, end: id }
            }
        };
        ranges.push(range);
    }
    Some(ranges)
}

/// Control state accumulated over the life of one transaction.
///
/// Every field is an override: `None`/empty means "defer to the ruleset".
#[derive(Debug, Default, Clone)]
pub struct TransactionControls {
    engine_mode: Option<RuleEngineMode>,
    pub(super) audit_engine: Option<AuditEngineMode>,
    audit_log_parts: Vec<String>,
    response_body_access: Option<bool>,
    // Sorted, disjoint inclusive intervals for all active ruleRemoveById controls.
    removed_rules: Vec<RuleIdRange>,
    removed_tags: Vec<String>,
    /// `(rule id, parsed target)` pairs from `ctl:ruleRemoveTargetById`.
    ///
    /// The target is parsed once when the directive fires rather than once per
    /// resolved value: a rule over a large collection would otherwise re-parse
    /// the same string thousands of times.
    removed_targets: Vec<(String, VariableSpec)>,
    /// Parsed tag targets and, for regex keys, the compiled key matcher.
    removed_tag_targets: Vec<(String, VariableSpec, Option<Arc<regex::bytes::Regex>>)>,
    request_body_access: Option<bool>,
    pub(crate) request_body_limit: Option<usize>,
    pub(crate) response_body_limit: Option<usize>,
    request_body_processor: Option<String>,
    response_json: bool,
    force_request_body_variable: bool,
    force_response_body_variable: bool,
    /// Unsupported directives already reported, so a rule that fires on every
    /// request does not produce a warning per request.
    reported: HashSet<String>,
}

impl TransactionControls {
    /// Apply a directive to this transaction.
    ///
    /// Later directives win over earlier ones for single-valued settings;
    /// removals accumulate, since `ctl:ruleRemoveById` is additive in
    /// ModSecurity.
    pub fn apply(&mut self, directive: CtlDirective) {
        self.apply_compiled(directive, None, false);
    }

    pub(crate) fn apply_compiled(
        &mut self,
        directive: CtlDirective,
        programs: Option<&SelectorPrograms>,
        multiphase: bool,
    ) {
        match directive {
            CtlDirective::RuleEngine(mode) => self.engine_mode = Some(mode),
            CtlDirective::AuditEngine(mode) => self.audit_engine = Some(mode),
            CtlDirective::AuditLogParts(change) => self.audit_log_parts.push(change),
            CtlDirective::RuleRemoveById(ranges) => self.add_removed_ids(ranges),
            CtlDirective::RuleRemoveByTag(tag) => {
                if !self.removed_tags.contains(&tag) {
                    self.removed_tags.push(tag);
                }
            }
            CtlDirective::RuleRemoveTargetById { rule_id, target } => {
                // Parse with the same parser used for rule variables so
                // collection names round-trip: SecLang writes REQUEST_HEADERS
                // where the enum variant renders as RequestHeaders.
                match crate::parser::parse_single_variable(&target) {
                    Ok(spec) => self.removed_targets.extend(
                        super::ruleset::split_target(spec, multiphase)
                            .map(|target| (rule_id.clone(), target)),
                    ),
                    Err(_) => {
                        let key = format!("ruleRemoveTargetById={rule_id};{target}");
                        if self.reported.insert(key) {
                            tracing::warn!(
                                rule_id = %rule_id,
                                target = %target,
                                "ignoring ctl:ruleRemoveTargetById with an unparseable target"
                            );
                        }
                    }
                }
            }
            CtlDirective::RuleRemoveTargetByTag { tag, target } => {
                // Normal loading validates these in CtlDirective::parse.
                // Direct callers receive a visible warning for malformed input.
                match crate::parser::parse_single_variable(&target) {
                    Ok(spec) if !spec.count_mode => {
                        let regex = match &spec.selection {
                            Some(Selection::Regex(pattern)) => {
                                let compiled = if let Some(programs) = programs {
                                    programs.get(pattern, spec.name).cloned()
                                } else {
                                    compile_selector(pattern, spec.name).ok().map(Arc::new)
                                };
                                if compiled.is_none() {
                                    tracing::warn!(%tag, %target, "invalid ctl:ruleRemoveTargetByTag target");
                                    return;
                                }
                                compiled
                            }
                            _ => None,
                        };
                        self.removed_tag_targets.extend(
                            super::ruleset::split_target(spec, multiphase)
                                .map(|target| (tag.clone(), target, regex.clone())),
                        );
                    }
                    _ => tracing::warn!(%tag, %target, "invalid ctl:ruleRemoveTargetByTag target"),
                }
            }
            CtlDirective::RequestBodyLimit(n) => self.request_body_limit = Some(n),
            CtlDirective::ResponseBodyLimit(n) => self.response_body_limit = Some(n),
            CtlDirective::RequestBodyAccess(on) => self.request_body_access = Some(on),
            CtlDirective::ResponseBodyAccess(on) => self.response_body_access = Some(on),
            CtlDirective::ResponseBodyProcessorJson => self.response_json = true,
            CtlDirective::RequestBodyProcessor(p) => self.request_body_processor = Some(p),
            CtlDirective::ForceResponseBodyVariable(on) => self.force_response_body_variable = on,
            CtlDirective::ForceRequestBodyVariable(on) => self.force_request_body_variable = on,
            CtlDirective::Unsupported {
                directive,
                value,
                reason,
            } => {
                // Compile-time validation already rejected these for rulesets
                // loaded through the normal path. Reaching here means a ruleset
                // was built some other way, so say so once rather than
                // pretending the directive took effect.
                let key = format!("{directive}={value}");
                if self.reported.insert(key) {
                    tracing::warn!(
                        directive = %directive,
                        value = %value,
                        reason = %reason,
                        "ignoring unsupported ctl directive"
                    );
                }
            }
        }
    }

    /// Engine mode for this transaction, given the ruleset's configured mode.
    pub fn engine_mode(&self, ruleset_mode: RuleEngineMode) -> RuleEngineMode {
        self.engine_mode.unwrap_or(ruleset_mode)
    }

    pub(super) fn audit_log_parts(&self, base: &str) -> String {
        let mut selected = base.to_owned();
        for change in &self.audit_log_parts {
            let add = change.starts_with('+');
            if add || change.starts_with('-') {
                // Coraza canonicalizes relative edits to the ordered optional parts.
                selected = ('B'..='K')
                    .filter(|&part| {
                        if change[1..].contains(part) {
                            add
                        } else {
                            selected.contains(part)
                        }
                    })
                    .collect();
            } else {
                selected.clone_from(change);
            }
        }
        selected
    }

    fn add_removed_ids(&mut self, mut ranges: Vec<RuleIdRange>) {
        // A list normally arrives in one directive. Sorting it once also
        // lets an empty transaction grow the interval table from the end.
        ranges.sort_unstable_by_key(|r| r.start);
        for mut added in ranges {
            let first = self
                .removed_rules
                .partition_point(|r| r.end.saturating_add(1) < added.start);
            let count = self.removed_rules[first..]
                .partition_point(|r| r.start <= added.end.saturating_add(1));
            if count == 0 {
                self.removed_rules.insert(first, added);
            } else {
                let last = first + count - 1;
                added.start = added.start.min(self.removed_rules[first].start);
                added.end = added.end.max(self.removed_rules[last].end);
                self.removed_rules[first] = added;
                self.removed_rules.drain(first + 1..=last);
            }
        }
    }

    /// Whether `ctl:ruleRemoveById` has excluded this rule.
    pub fn is_rule_removed(&self, rule_id: Option<&str>) -> bool {
        if self.removed_rules.is_empty() {
            return false;
        }
        let Some(id) = rule_id.and_then(|id| id.trim().parse::<u64>().ok()) else {
            return false;
        };
        let index = self.removed_rules.partition_point(|r| r.end < id);
        self.removed_rules.get(index).is_some_and(|r| r.start <= id)
    }

    pub(crate) fn is_tag_removed(&self, actions: &[crate::parser::Action]) -> bool {
        self.removed_tags
            .iter()
            .any(|tag| super::ruleset::has_tag(actions, tag))
    }

    /// Whether any target exclusion applies to this rule.
    ///
    /// Checked before the per-variable filter so the common case -- no
    /// exclusions at all -- costs one comparison rather than a scan per
    /// variable.
    pub fn has_target_removals(&self, rule_id: Option<&str>) -> bool {
        match rule_id {
            Some(id) => self.removed_targets.iter().any(|(r, _)| r == id),
            None => false,
        }
    }

    /// Whether one resolved value was excluded from this rule by
    /// `ctl:ruleRemoveTargetById`.
    ///
    /// Exclusion filters *values*, not variable specifications, because the
    /// shape CRS actually uses is a rule targeting a whole collection with an
    /// exclusion naming one member:
    ///
    /// ```text
    /// SecRule ARGS "@detectSQLi" "id:942100,..."
    /// ctl:ruleRemoveTargetById=942100;ARGS:json.token
    /// ```
    ///
    /// Dropping the spec would remove `ARGS` entirely and disable the rule;
    /// leaving it would exclude nothing. Only removing the one resolved value
    /// named `ARGS:json.token` does what the operator asked.
    ///
    /// `resolved_name` is the name the resolver produced, in `COLLECTION:key`
    /// form for collections and a bare name otherwise.
    pub fn is_target_removed(
        &self,
        rule_id: Option<&str>,
        var: &VariableSpec,
        resolved_name: &str,
    ) -> bool {
        self.is_target_removed_bytes(rule_id, var, resolved_name.as_bytes())
    }

    /// Whether a tag exclusion selects this rule (or its chain starter).
    pub fn has_tag_target_removals(&self, actions: &[crate::parser::Action]) -> bool {
        self.removed_tag_targets
            .iter()
            .any(|(tag, _, _)| super::ruleset::has_tag(actions, tag))
    }

    pub(super) fn tag_target_removal(
        &self,
        actions: &[crate::parser::Action],
        var: &VariableSpec,
    ) -> TagTargetRemoval {
        let mut removal = TagTargetRemoval::None;
        for (tag, target, _) in &self.removed_tag_targets {
            if target.name == var.name && super::ruleset::has_tag(actions, tag) {
                if target.selection.is_none() {
                    return TagTargetRemoval::All;
                }
                removal = TagTargetRemoval::Members;
            }
        }
        removal
    }

    /// Whether a value is excluded by an exact matching rule tag.
    pub fn is_tag_target_removed(
        &self,
        actions: &[crate::parser::Action],
        var: &VariableSpec,
        resolved_name: &str,
    ) -> bool {
        self.is_tag_target_removed_bytes(actions, var, resolved_name.as_bytes())
    }

    /// Filter an original byte-valued target without matching its display text.
    pub fn is_target_removed_bytes(
        &self,
        rule_id: Option<&str>,
        var: &VariableSpec,
        name: &[u8],
    ) -> bool {
        self.removed_member(rule_id, var, member(name))
    }

    pub(crate) fn removed_member(
        &self,
        rule_id: Option<&str>,
        var: &VariableSpec,
        key: Option<&[u8]>,
    ) -> bool {
        rule_id.is_some_and(|id| {
            self.removed_targets
                .iter()
                .any(|(rule, target)| rule == id && target_matches_member(var, target, key, None))
        })
    }

    /// Apply tag target exclusions to original collection-key bytes.
    pub fn is_tag_target_removed_bytes(
        &self,
        actions: &[crate::parser::Action],
        var: &VariableSpec,
        name: &[u8],
    ) -> bool {
        self.removed_tag_member(actions, var, member(name))
    }

    pub(crate) fn removed_tag_member(
        &self,
        actions: &[crate::parser::Action],
        var: &VariableSpec,
        key: Option<&[u8]>,
    ) -> bool {
        self.removed_tag_targets.iter().any(|(tag, target, regex)| {
            super::ruleset::has_tag(actions, tag)
                && target_matches_member(var, target, key, regex.as_deref())
        })
    }

    /// Whether a rule selected JSON response processing.
    pub fn response_json_selected(&self) -> bool {
        self.response_json
    }

    /// Whether the response bypasses the configured MIME filter.
    pub fn force_response_body_variable(&self) -> bool {
        self.force_response_body_variable
    }

    /// Whether the request body should be parsed at all.
    pub fn request_body_access(&self) -> bool {
        self.request_body_access.unwrap_or(true)
    }

    /// Resolve a request access override against the compiled global policy.
    pub fn request_body_access_or(&self, configured: bool) -> bool {
        self.request_body_access.unwrap_or(configured)
    }

    /// Resolve a response access override against the compiled global policy.
    pub fn response_body_access_or(&self, configured: bool) -> bool {
        self.response_body_access.unwrap_or(configured)
    }

    /// Whether a processor should be selected for an otherwise opaque body.
    pub fn force_request_body_variable(&self) -> bool {
        self.force_request_body_variable
    }

    /// Body processor forced by `ctl:requestBodyProcessor`, if any.
    pub fn request_body_processor(&self) -> Option<&str> {
        self.request_body_processor.as_deref()
    }
}

fn member(name: &[u8]) -> Option<&[u8]> {
    name.iter().position(|&b| b == b':').map(|i| &name[i + 1..])
}

fn target_matches_member(
    var: &VariableSpec,
    target: &VariableSpec,
    member: Option<&[u8]>,
    regex: Option<&regex::bytes::Regex>,
) -> bool {
    if var.name != target.name {
        return false;
    }
    match &target.selection {
        None => true,
        Some(Selection::Key(wanted)) => {
            member.is_some_and(|key| folded_key(key) == folded_key(wanted.as_bytes()))
        }
        Some(Selection::Regex(_)) => {
            member.is_some_and(|key| regex.is_some_and(|re| re.is_match(&folded_key(key))))
        }
    }
}

/// Collect the unsupported `ctl:` directives in a set of actions.
///
/// Used at ruleset compile time so an operator learns at startup that a
/// directive will not take effect, rather than discovering it from a
/// bypassed rule in production.
pub fn unsupported_controls(
    actions: &[crate::parser::Action],
) -> Vec<(String, String, &'static str)> {
    let mut found = Vec::new();
    for action in actions {
        if let crate::parser::Action::Control(ctl) = action {
            if let CtlDirective::Unsupported {
                directive,
                value,
                reason,
            } = CtlDirective::parse(ctl)
            {
                found.push((directive, value, reason));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctl(directive: &str, value: &str) -> ControlAction {
        ControlAction {
            directive: directive.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn overlapping_adjacent_and_repeated_id_removals_remain_a_union() {
        let mut state = TransactionControls::default();
        state.apply(CtlDirective::parse(&ctl(
            "ruleRemoveById",
            "20-30,8,0,4-7,18446744073709551615",
        )));
        state.apply(CtlDirective::parse(&ctl(
            "ruleRemoveById",
            "29-33,8-12,21,18446744073709551614",
        )));
        for id in 0..40 {
            assert_eq!(
                state.is_rule_removed(Some(&id.to_string())),
                id == 0 || (4..=12).contains(&id) || (20..=33).contains(&id)
            );
        }
        assert!(state.is_rule_removed(Some(" 0005 ")));
        assert!(state.is_rule_removed(Some(&u64::MAX.to_string())));
        assert!(!state.is_rule_removed(Some("named-rule")));
        assert_eq!(state.removed_rules.len(), 4);
    }

    #[test]
    fn rule_engine_values_are_case_insensitive() {
        for (value, expected) in [
            ("Off", RuleEngineMode::Off),
            ("off", RuleEngineMode::Off),
            ("On", RuleEngineMode::On),
            ("DetectionOnly", RuleEngineMode::DetectionOnly),
            ("detectiononly", RuleEngineMode::DetectionOnly),
        ] {
            assert_eq!(
                CtlDirective::parse(&ctl("ruleEngine", value)),
                CtlDirective::RuleEngine(expected),
                "ruleEngine={value}"
            );
        }
    }

    #[test]
    fn directive_names_are_case_insensitive() {
        // CRS writes ctl:ruleRemoveById, but SecLang is not case sensitive here.
        assert!(matches!(
            CtlDirective::parse(&ctl("RULEREMOVEBYID", "1")),
            CtlDirective::RuleRemoveById(_)
        ));
    }

    #[test]
    fn single_ids_ranges_and_lists_all_parse() {
        let single = CtlDirective::parse(&ctl("ruleRemoveById", "942100"));
        assert_eq!(
            single,
            CtlDirective::RuleRemoveById(vec![RuleIdRange {
                start: 942100,
                end: 942100
            }])
        );

        let range = CtlDirective::parse(&ctl("ruleRemoveById", "942100-942999"));
        assert_eq!(
            range,
            CtlDirective::RuleRemoveById(vec![RuleIdRange {
                start: 942100,
                end: 942999
            }])
        );

        let list = CtlDirective::parse(&ctl("ruleRemoveById", "1,5-7"));
        assert_eq!(
            list,
            CtlDirective::RuleRemoveById(vec![
                RuleIdRange { start: 1, end: 1 },
                RuleIdRange { start: 5, end: 7 },
            ])
        );
    }

    #[test]
    fn an_inverted_range_is_rejected_rather_than_silently_empty() {
        // 999-1 matching nothing would look identical to a working exclusion.
        assert!(matches!(
            CtlDirective::parse(&ctl("ruleRemoveById", "999-1")),
            CtlDirective::Unsupported { .. }
        ));
    }

    #[test]
    fn ranges_match_ids_by_number_not_string() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl("ruleRemoveById", "942100-942999")));

        assert!(controls.is_rule_removed(Some("942100")));
        assert!(controls.is_rule_removed(Some("942500")));
        assert!(controls.is_rule_removed(Some("942999")));
        assert!(!controls.is_rule_removed(Some("943000")));
        // String comparison would place "9421000" inside the range.
        assert!(!controls.is_rule_removed(Some("9421000")));
        assert!(!controls.is_rule_removed(None));
    }

    #[test]
    fn removals_accumulate_but_engine_mode_is_replaced() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl("ruleRemoveById", "1")));
        controls.apply(CtlDirective::parse(&ctl("ruleRemoveById", "2")));
        assert!(controls.is_rule_removed(Some("1")));
        assert!(controls.is_rule_removed(Some("2")));

        controls.apply(CtlDirective::parse(&ctl("ruleEngine", "Off")));
        controls.apply(CtlDirective::parse(&ctl("ruleEngine", "DetectionOnly")));
        assert_eq!(
            controls.engine_mode(RuleEngineMode::On),
            RuleEngineMode::DetectionOnly
        );
    }

    #[test]
    fn engine_mode_defers_to_the_ruleset_when_unset() {
        let controls = TransactionControls::default();
        assert_eq!(
            controls.engine_mode(RuleEngineMode::DetectionOnly),
            RuleEngineMode::DetectionOnly
        );
    }

    #[test]
    fn remove_target_requires_both_halves() {
        assert_eq!(
            CtlDirective::parse(&ctl("ruleRemoveTargetById", "942100;ARGS:token")),
            CtlDirective::RuleRemoveTargetById {
                rule_id: "942100".to_string(),
                target: "ARGS:token".to_string(),
            }
        );
        for bad in ["942100", "942100;", ";ARGS:token", ""] {
            assert!(
                matches!(
                    CtlDirective::parse(&ctl("ruleRemoveTargetById", bad)),
                    CtlDirective::Unsupported { .. }
                ),
                "{bad:?} should not parse"
            );
        }
    }

    #[test]
    fn target_matching_uses_seclang_names() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl(
            "ruleRemoveTargetById",
            "1;REQUEST_HEADERS:User-Agent",
        )));

        let var = crate::parser::parse_single_variable("REQUEST_HEADERS:User-Agent").unwrap();
        assert!(controls.is_target_removed(Some("1"), &var, "REQUEST_HEADERS:User-Agent"));
        // Same target, different rule.
        assert!(!controls.is_target_removed(Some("2"), &var, "REQUEST_HEADERS:User-Agent"));

        let other = crate::parser::parse_single_variable("REQUEST_HEADERS:Referer").unwrap();
        assert!(!controls.is_target_removed(Some("1"), &other, "REQUEST_HEADERS:Referer"));

        // Header keys are case insensitive.
        assert!(controls.is_target_removed(Some("1"), &var, "REQUEST_HEADERS:user-agent"));
    }

    /// The shape CRS actually uses: the rule targets a whole collection and
    /// the exclusion names one member. Matching on the specification alone
    /// cannot express this -- the spec is `ARGS` either way -- so the resolved
    /// value name is what decides.
    #[test]
    fn a_keyed_target_excludes_one_member_of_a_collection_rule() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl(
            "ruleRemoveTargetById",
            "942100;ARGS:json.token",
        )));

        let whole_args = crate::parser::parse_single_variable("ARGS").unwrap();
        assert!(controls.is_target_removed(Some("942100"), &whole_args, "ARGS:json.token"));
        assert!(!controls.is_target_removed(Some("942100"), &whole_args, "ARGS:json.query"));
    }

    /// Coraza GetField folds the original member name for literal exceptions.
    #[test]
    fn argument_exclusions_fold_the_observed_member_name() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl(
            "ruleRemoveTargetById",
            "1;ARGS:Token",
        )));

        let args = crate::parser::parse_single_variable("ARGS").unwrap();
        assert!(controls.is_target_removed(Some("1"), &args, "ARGS:Token"));
        assert!(controls.is_target_removed(Some("1"), &args, "ARGS:token"));
    }

    /// A keyed target cannot select a scalar variable, which has no members.
    #[test]
    fn a_keyed_target_does_not_match_a_scalar_variable() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl(
            "ruleRemoveTargetById",
            "1;REQUEST_URI:x",
        )));

        let uri = crate::parser::parse_single_variable("REQUEST_URI").unwrap();
        assert!(!controls.is_target_removed(Some("1"), &uri, "REQUEST_URI"));
    }

    #[test]
    fn an_unkeyed_target_excludes_the_whole_collection() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl("ruleRemoveTargetById", "1;ARGS")));

        // Naming the collection with no key excludes every member of it, for
        // a rule targeting the collection or any single member.
        let whole = crate::parser::parse_single_variable("ARGS").unwrap();
        assert!(controls.is_target_removed(Some("1"), &whole, "ARGS:token"));
        assert!(controls.is_target_removed(Some("1"), &whole, "ARGS:anything"));

        let keyed = crate::parser::parse_single_variable("ARGS:token").unwrap();
        assert!(controls.is_target_removed(Some("1"), &keyed, "ARGS:token"));

        // A different collection is untouched.
        let cookies = crate::parser::parse_single_variable("REQUEST_COOKIES").unwrap();
        assert!(!controls.is_target_removed(Some("1"), &cookies, "REQUEST_COOKIES:token"));
    }

    #[test]
    fn unimplemented_features_are_reported_not_accepted() {
        // The whole point: a directive this engine cannot honour must not look
        // like it worked.
        for (directive, value) in [
            ("requestBodyProcessor", "YAML"),
            ("auditEngine", "unknown"),
            ("auditLogParts", "+Z"),
            ("forceRequestBodyVariable", "sometimes"),
        ] {
            assert!(
                matches!(
                    CtlDirective::parse(&ctl(directive, value)),
                    CtlDirective::Unsupported { .. }
                ),
                "ctl:{directive}={value} should be reported as unsupported"
            );
        }
    }

    #[test]
    fn implemented_body_processors_are_accepted() {
        for value in [
            "URLENCODED",
            "urlencoded",
            "MULTIPART",
            "JSON",
            "json",
            "XML",
            "xml",
        ] {
            assert!(
                matches!(
                    CtlDirective::parse(&ctl("requestBodyProcessor", value)),
                    CtlDirective::RequestBodyProcessor(_)
                ),
                "ctl:requestBodyProcessor={value} should be accepted"
            );
        }
    }

    #[test]
    fn body_access_defaults_to_on() {
        let mut controls = TransactionControls::default();
        assert!(controls.request_body_access());

        controls.apply(CtlDirective::parse(&ctl("requestBodyAccess", "Off")));
        assert!(!controls.request_body_access());
    }
}
