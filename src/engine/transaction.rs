//! Transaction processing for ModSecurity.

use std::borrow::Cow;
use std::sync::{Arc, OnceLock};

use super::body::{BodyState, BodyWriteResult};
use super::control::{CtlDirective, TagTargetRemoval, TransactionControls};
use super::intervention::Intervention;
use super::match_log::{MatchLog, MatchedRules, RawMatch, RuleLocation};
use super::phase::Phase;
use super::ruleset::{CompiledFlow, CompiledRule, CompiledRuleset, RuleDispatch, RuleEngineMode};
use super::target_indices::{ActiveTargets, RequestCollections};
use crate::actions::rule_metadata;
use crate::error::Result;
use crate::operators::{compile_operator_bytes, ByteOperatorResult, Operator};
use crate::parser::{
    Action, BodyLimitAction, DataAction, DisruptiveAction, MetadataAction, SetVarSpec, SetVarValue,
    VariableSpec,
};
use crate::variables::{
    ByteCollection, ByteValue, RequestData, ResponseData, TxCollection, VariableResolver,
};

/// Recognize the two media types for this processor and its structured suffix.
fn structured_media_type(media: &str, application: &str, text: &str, suffix: &str) -> bool {
    media.eq_ignore_ascii_case(application)
        || media.eq_ignore_ascii_case(text)
        || media
            .rsplit_once('+')
            .is_some_and(|(_, subtype)| subtype.eq_ignore_ascii_case(suffix))
}

/// A ModSecurity transaction for processing a single request.
pub struct Transaction {
    /// Compiled ruleset reference.
    ruleset: Arc<CompiledRuleset>,
    /// Request data.
    request: RequestData,
    request_line: OnceLock<Box<[u8]>>,
    /// Response data.
    response: ResponseData,
    /// TX collection (mutable variables).
    tx: TxCollection,
    numeric_tx_indices: [usize; super::ruleset::NUMERIC_TX_SLOTS],
    /// Current phase.
    phase: Phase,
    /// Intervention (if any).
    intervention: Option<Intervention>,
    /// Default block status.
    default_status: u16,
    /// Matched rules.
    matched_rules: MatchedRules,
    /// Last phase skipped by a request-wide or transaction-wide allow.
    allow_through: Option<Phase>,
    /// Matched variables for current rule evaluation.
    matched_vars: Vec<(ByteValue, ByteValue)>,
    /// Per-transaction `ctl:` overrides.
    controls: TransactionControls,
    /// Every variable that caused a rule to match, in order.
    ///
    /// Separate from `matched_vars`, which ModSecurity scopes to the current
    /// rule so that `MATCHED_VARS` reads correctly. This accumulates for the
    /// whole transaction, because audit logging wants to answer "what did
    /// rule 942100 actually see" after the fact.
    matched_data: MatchLog<(RuleLocation, RawMatch)>,
    /// What each `setvar` that ran did, in order. See [`SetVarEffect`].
    setvar_effects: Vec<SetVarEffect>,
    /// Whether `setvar_effects` is filled. Off by default.
    record_setvar_effects: bool,
    /// Optional expanded message snapshots, captured when each rule completes.
    rule_messages: Vec<RuleMessage>,
    record_rule_messages: bool,
    request_body_state: BodyState,
    response_body_state: BodyState,
}

/// Audit snapshots from a matched link.
struct RuleOutcome {
    first_data: Option<RawMatch>,
    first_message: Option<RuleMessage>,
}

/// The first static match ends the read-only scan. Only this stage is
/// prepared before actions run; later members retain their raw target values.
struct PreparedStage {
    value: ByteValue,
    result: ByteOperatorResult,
    resume_after: Option<usize>,
}

#[derive(Default)]
struct ResolvedTarget {
    first: Option<(ByteValue, PreparedStage)>,
    remaining: Vec<(ByteValue, Vec<u8>)>,
}

struct StaticSearch<'a> {
    rule: &'a CompiledRule,
    within: Option<&'a [u8]>,
    numeric: Option<crate::operators::NumericComparison>,
    regex: Option<&'a crate::operators::RxOperator>,
    capture: bool,
    multi_match: bool,
}

impl StaticSearch<'_> {
    fn first_match(&self, raw: &[u8], mut record: impl FnMut(PreparedStage)) -> Result<()> {
        let execute = |value: &[u8]| -> Result<Option<ByteOperatorResult>> {
            let whole_input = self
                .numeric
                .map(|numeric| numeric.matches(value))
                .or_else(|| {
                    self.within
                        .map(|haystack| crate::operators::WithinOperator::matches(haystack, value))
                });
            if let Some(matched) = whole_input {
                return Ok(
                    (matched != self.rule.operator_negated).then(|| ByteOperatorResult {
                        matched,
                        ..Default::default()
                    }),
                );
            }
            if let Some(regex) = self.regex {
                return Ok(regex.rule_match(value, self.capture, self.rule.operator_negated));
            }
            let result = self.rule.operator.execute_rule_bytes(value, self.capture)?;
            Ok((result.matched != self.rule.operator_negated).then_some(result))
        };
        if self.rule.transformations.is_empty() {
            if let Some(result) = execute(raw)? {
                record(PreparedStage {
                    value: ByteValue::from(raw),
                    result,
                    resume_after: self.multi_match.then_some(0),
                });
            }
            return Ok(());
        }
        if !self.rule.operator_negated
            && self.rule.transformations.preserves_token_width_bounds()
            && self
                .regex
                .is_some_and(|regex| regex.rejects_short_token(raw))
        {
            return Ok(());
        }
        if self.multi_match {
            self.rule
                .transformations
                .visit_byte_stages(raw, None, |stage, value| {
                    Ok(execute(value)?.map(|result| {
                        record(PreparedStage {
                            value: ByteValue::from(value),
                            result,
                            resume_after: Some(stage),
                        });
                    }))
                })?;
        } else {
            let transformed = self.rule.transformations.apply_bytes(raw)?;
            if let Some(result) = execute(&transformed)? {
                record(PreparedStage {
                    value: ByteValue::from(transformed),
                    result,
                    resume_after: None,
                });
            }
        }
        Ok(())
    }
}

/// What a rule matched on.
///
/// `matched_rules()` gives rule IDs, which says a rule fired but not why.
/// Without the variable and value there is no way to tell a true positive
/// from a false one, or to write a useful audit log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedData {
    /// ID of the rule that matched, if it has one.
    pub rule_id: Option<String>,
    /// Name of the variable that matched, e.g. `ARGS:json.q`.
    pub variable: String,
    /// The variable's value, after transformations were applied.
    ///
    /// This is what `MATCHED_VAR` resolves to -- the whole value, not the
    /// portion the operator hit.
    pub value: String,
    /// The portion of the value the operator matched, when it reports one.
    ///
    /// `@contains evil` against `something-evil-here` gives `evil` here and
    /// the full string in `value`. Numeric operators report the whole input
    /// on a positive match. A negated numeric match leaves this `None`.
    pub matched_portion: Option<String>,
    /// Original variable-name bytes, before display escaping.
    pub variable_bytes: Vec<u8>,
    /// Original transformed value bytes, before display escaping.
    pub value_bytes: Vec<u8>,
    /// Original matched portion bytes, before display escaping.
    pub matched_portion_bytes: Option<Vec<u8>>,
}

/// Expanded message data for a completed logical rule.
///
/// Values are original bytes captured at match time, before a later rule can
/// overwrite TX captures or scores. Rendering/escaping and logging policy belong
/// to the connector; recording is opt-in and does not emit log messages itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMessage {
    /// ID of the standalone rule or completed chain starter.
    pub rule_id: String,
    /// Expanded `msg` bytes, if configured.
    pub message: Option<Vec<u8>>,
    /// Expanded `logdata` bytes, if configured.
    pub logdata: Option<Vec<u8>>,
}

/// What a `setvar` did to a collection.
///
/// The values are the ones that were applied: any `%{...}` macro in the rule
/// has been expanded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetVarChange {
    /// `setvar:tx.name=value`
    Set(String),
    /// An assignment containing invalid UTF-8, retained without replacement.
    SetBytes(Vec<u8>),
    /// `setvar:tx.name=+n`
    Increment(i64),
    /// `setvar:tx.name=-n`
    Decrement(i64),
    /// `setvar:!tx.name`
    Delete,
}

/// One `setvar` that ran, with the rule it belongs to.
///
/// The engine records these without interpreting them: it does not know which
/// variables a ruleset uses for scoring. A caller that wants "the rules that
/// raised the anomaly score" filters on `key` and `op` itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetVarEffect {
    /// ID of the rule, or for a chain link without an id of its own, of the
    /// chain's starter.
    pub rule_id: String,
    /// Collection named by the rule, lowercased: `"tx"`.
    pub collection: String,
    /// Variable name as written in the rule, e.g. `inbound_anomaly_score_pl1`.
    pub key: String,
    /// The operation, with macros already expanded.
    pub op: SetVarChange,
}

impl Transaction {
    /// Create a new transaction.
    pub fn new(ruleset: Arc<CompiledRuleset>, default_status: u16) -> Self {
        Self {
            ruleset,
            request: RequestData::new(),
            request_line: OnceLock::new(),
            response: ResponseData::new(),
            tx: TxCollection::new(),
            numeric_tx_indices: [usize::MAX; super::ruleset::NUMERIC_TX_SLOTS],
            phase: Phase::RequestHeaders,
            intervention: None,
            default_status,
            matched_rules: MatchedRules::default(),
            allow_through: None,
            matched_vars: Vec::new(),
            controls: TransactionControls::default(),
            matched_data: MatchLog::default(),
            setvar_effects: Vec::new(),
            record_setvar_effects: false,
            rule_messages: Vec::new(),
            record_rule_messages: false,
            request_body_state: BodyState::default(),
            response_body_state: BodyState::default(),
        }
    }

    /// Enable expanded rule message snapshots for a connector or audit consumer.
    /// Disabled by default; this does not change rule evaluation or log policy.
    pub fn set_record_rule_messages(&mut self, enabled: bool) {
        self.record_rule_messages = enabled;
    }

    /// Messages captured when logical rules completed, in evaluation order.
    /// Empty unless [`Self::set_record_rule_messages`] was enabled.
    pub fn rule_messages(&self) -> &[RuleMessage] {
        &self.rule_messages
    }

    fn expand_rule_message(&self, actions: &[Action]) -> Option<RuleMessage> {
        let (mut id, mut msg, mut logdata) = (None, None, None);
        for action in actions {
            match action {
                Action::Metadata(MetadataAction::Id(value)) => id = Some(value),
                Action::Metadata(MetadataAction::Msg(value)) => msg = Some(value),
                Action::Metadata(MetadataAction::LogData(value)) => logdata = Some(value),
                _ => {}
            }
        }
        Some(RuleMessage {
            rule_id: id?.to_string(),
            message: msg.map(|s| self.expand_operator_macros_bytes(s).into_owned()),
            logdata: logdata.map(|s| self.expand_operator_macros_bytes(s).into_owned()),
        })
    }

    /// Set the client address, backing `REMOTE_ADDR` and `REMOTE_PORT`.
    ///
    /// Without this there is no way for a caller to populate them, so every
    /// IP-based rule -- `@ipMatch`, CRS IP reputation, allow and deny lists --
    /// evaluated against an empty string and never matched.
    pub fn set_client_addr(&mut self, ip: &str, port: u16) {
        self.request.client_ip = ip.to_string();
        self.request.client_port = port;
    }

    /// Set the local address, backing `SERVER_ADDR` and `SERVER_PORT`.
    pub fn set_server_addr(&mut self, ip: &str, port: u16) {
        self.request.server_addr = ip.to_string();
        self.request.server_port = port;
    }

    /// Set the server name, backing `SERVER_NAME`.
    pub fn set_server_name(&mut self, name: &str) {
        self.request.server_name = name.to_string();
    }

    /// Every variable that caused a rule to match, in order.
    ///
    /// Pairs with [`matched_rules`](Self::matched_rules): that says which
    /// rules fired, this says what they saw.
    pub fn matched_data(&self) -> &[MatchedData] {
        self.matched_data.as_slice(&self.ruleset, self.phase)
    }

    /// Record what every `setvar` does, for [`setvar_effects`](Self::setvar_effects).
    ///
    /// Off by default: a rule that matches many values runs its `setvar` for
    /// each, so a request with hundreds of arguments records thousands of
    /// entries (about 250 KB with stock CRS at paranoia 1 for 200 arguments
    /// that each trip several rules). Call this before processing the request.
    pub fn set_record_setvar_effects(&mut self, enabled: bool) {
        self.record_setvar_effects = enabled;
    }

    /// Every `setvar` that ran in this transaction, in order of execution.
    ///
    /// Empty unless [`set_record_setvar_effects`](Self::set_record_setvar_effects)
    /// was enabled first. A rule over several values (`ARGS`, request headers)
    /// runs its `setvar` once per matching value, as libmodsecurity does, and
    /// each run is an entry.
    ///
    /// A `setvar` on a chain link runs when that link matches, so a chain that
    /// fails later still leaves the effects of its earlier links here; they are
    /// attributed to the chain's starter. A `setvar` of a rule with no id is
    /// not listed.
    ///
    /// Pairs with [`matched_rules`](Self::matched_rules) and
    /// [`matched_data`](Self::matched_data): those say which rules fired and
    /// what they saw, this says what they did to TX.
    pub fn setvar_effects(&self) -> &[SetVarEffect] {
        &self.setvar_effects
    }

    /// Process the request URI.
    pub fn process_uri(&mut self, uri: &str, method: &str, protocol: &str) -> Result<()> {
        self.request_line.take();
        self.request.set_uri_bytes(uri.as_bytes());
        self.request.set_method(method);
        self.request.set_protocol(protocol);
        Ok(())
    }

    /// Process an original request line without replacing invalid UTF-8.
    pub fn process_uri_bytes(&mut self, uri: &[u8], method: &[u8], protocol: &[u8]) -> Result<()> {
        self.request_line.take();
        self.request.set_uri_bytes(uri);
        self.request.set_method_bytes(method);
        self.request.set_protocol_bytes(protocol);
        Ok(())
    }

    /// Add original request header bytes without UTF-8 replacement.
    pub fn add_request_header_bytes(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        self.request.add_header_bytes(name, value);
        Ok(())
    }

    /// Add a request header.
    pub fn add_request_header(&mut self, name: &str, value: &str) -> Result<()> {
        self.request.add_header(name, value);
        Ok(())
    }

    /// Process request headers (Phase 1).
    pub fn process_request_headers(&mut self) -> Result<()> {
        self.check_body_callback(true)?;
        if self.request_body_state.headers_processed || self.phase > Phase::RequestHeaders {
            return Ok(());
        }
        self.request_body_state.headers_processed = true;
        self.phase = Phase::RequestHeaders;
        self.run_body_callback(Phase::RequestHeaders)?;
        self.finalize_pending_body(true)
    }

    /// Append a chunk to the bounded request inspection buffer.
    ///
    /// The caller still owns and forwards the original input. This compatibility
    /// wrapper does not report partial acquisition; connectors needing that count
    /// should use [`Self::write_request_body`] and always check intervention().
    pub fn append_request_body(&mut self, data: &[u8]) -> Result<()> {
        self.write_request_body(data).map(|_| ())
    }

    /// Acquire a bounded prefix and report exactly how much was retained.
    /// Before headers this prefix is provisional, so phase-1 ctl policy can run
    /// before a limit decision. No body phase runs before its headers.
    pub fn write_request_body(&mut self, data: &[u8]) -> Result<BodyWriteResult> {
        self.write_body(data, true)
    }

    /// Process request body (Phase 2).
    pub fn process_request_body(&mut self) -> Result<()> {
        self.check_body_callback(true)?;
        if !self.request_body_state.headers_processed
            || self.request_body_state.processed
            || self.phase > Phase::RequestBody
            || self.intervention.is_some()
        {
            return Ok(());
        }
        self.request_body_state.processed = true;
        self.phase = Phase::RequestBody;
        if self.engine_mode() == RuleEngineMode::Off {
            return Ok(());
        }

        // Coraza does not select a fallback processor for an empty body.
        if self.request.body.is_empty() {
            self.run_body_callback(Phase::RequestBody)?;
            return Ok(());
        }

        // ctl:requestBodyAccess=Off, typically set in phase 1, suppresses body
        // parsing entirely. Phase 2 rules still run; they just find no ARGS_POST
        // or FILES, which is what disabling body access means.
        if !self.request_body_accessible() {
            self.run_body_callback(Phase::RequestBody)?;
            return Ok(());
        }

        // ctl:requestBodyProcessor overrides Content-Type sniffing. CRS relies
        // on this to force a processor when the header is absent or lying.
        if let Some(forced) = self.controls.request_body_processor() {
            match forced {
                "MULTIPART" => {
                    if !self.process_multipart_body() {
                        tracing::warn!(
                            "ctl:requestBodyProcessor=MULTIPART, but the body has no parseable \
                             boundary; body arguments were not extracted"
                        );
                    }
                }
                "URLENCODED" => {
                    self.request.parse_form_body();
                    self.request.body_processor = "URLENCODED".to_string();
                }
                "JSON" => self.process_json_body(),
                "XML" => self.process_xml_body(),
                "RAW" => self.request.body_processor = "RAW".to_string(),
                // CtlDirective::parse admits no other value.
                other => debug_assert!(false, "unsupported forced body processor: {other}"),
            }
            self.run_body_callback(Phase::RequestBody)?;
            return Ok(());
        }

        // Parameters may contain opaque bytes. Only the trimmed media type
        // participates in JSON and XML selection.
        let media = self
            .request
            .headers
            .first_value_bytes(b"content-type")
            .and_then(|header| {
                let end = memchr::memchr(b';', header).unwrap_or(header.len());
                std::str::from_utf8(&header[..end]).ok()
            })
            .unwrap_or_default()
            .trim();
        if self.request.body_processor == "MULTIPART" {
            // Multipart body processor: populates ARGS_POST, FILES and
            // MULTIPART_PART_HEADERS. Never fall back to the urlencoded
            // parser for multipart payloads — that would produce bogus ARGS.
            if !self.process_multipart_body() {
                tracing::warn!(
                    "multipart/form-data request without a parseable boundary; \
                     body arguments were not extracted"
                );
            }
        } else if structured_media_type(media, "application/xml", "text/xml", "xml") {
            self.process_xml_body();
        } else if structured_media_type(media, "application/json", "text/json", "json") {
            // JSON bodies previously fell through to the urlencoded parser,
            // which extracts nothing usable from them -- so ARGS was empty and
            // rules like CRS 942100 (`SecRule ARGS "@detectSQLi"`) had nothing
            // to inspect. An injection payload was blocked in a form body and
            // passed unexamined in a JSON body.
            self.process_json_body();
        } else if self.request.body_processor == "URLENCODED"
            || self.controls.force_request_body_variable()
        {
            // Pinned Coraza selects URLENCODED for forceRequestBodyVariable
            // when no other processor exists. It exposes the acquired body and
            // extracts form arguments; explicit RAW deliberately does not.
            self.request.parse_form_body();
            self.request.body_processor = "URLENCODED".to_string();
        }

        self.run_body_callback(Phase::RequestBody)?;
        Ok(())
    }

    /// Select the original Content-Type bytes for multipart boundary parsing.
    fn process_multipart_body(&mut self) -> bool {
        let content_type = self
            .request
            .headers
            .first_value_bytes(b"content-type")
            .unwrap_or_default()
            .to_vec();
        self.request.parse_multipart_body_bytes(&content_type)
    }

    /// Run the XML body processor, recording any failure.
    ///
    /// As with JSON, a failure is not fatal: phase 2 still runs so a rule
    /// testing `REQBODY_ERROR` can act on it.
    fn process_xml_body(&mut self) {
        if let Err(e) = self.request.parse_xml_body() {
            tracing::debug!(
                error = %e,
                "request body could not be processed as XML; REQBODY_ERROR is set"
            );
        }
    }

    /// Run the JSON body processor, recording any failure.
    ///
    /// A failure is deliberately not fatal: the request still goes through
    /// phase 2 so that rules testing `REQBODY_ERROR` can act on it, which is
    /// how CRS rule 200002 blocks bodies it could not parse. Dropping the
    /// request here instead would take that decision away from the ruleset.
    fn process_json_body(&mut self) {
        if let Err(e) = self.request.parse_json_body() {
            tracing::debug!(
                error = %e,
                "request body could not be processed as JSON; REQBODY_ERROR is set"
            );
        }
    }

    /// Add a response header.
    pub fn add_response_header(&mut self, name: &str, value: &str) -> Result<()> {
        self.response.add_header(name, value);
        Ok(())
    }

    /// Add original response header bytes without UTF-8 replacement.
    pub fn add_response_header_bytes(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        self.response.add_header_bytes(name, value);
        Ok(())
    }

    /// Supply the received response status and protocol, then run phase 3.
    ///
    /// Connectors should use this entry point so response rules inspect the
    /// actual response metadata rather than the initial empty/default state.
    pub fn process_response_headers_with_status(
        &mut self,
        status: u16,
        protocol: &str,
    ) -> Result<()> {
        self.check_body_callback(false)?;
        if self.response_body_state.headers_processed || self.phase > Phase::ResponseHeaders {
            return Ok(());
        }
        self.response.set_status(status);
        self.response.set_protocol(protocol);
        self.process_response_headers()
    }

    /// Process response headers (Phase 3) using the currently stored metadata.
    ///
    /// Use [`Self::process_response_headers_with_status`] when supplying a real
    /// response from an HTTP connector. This method remains for existing callers.
    pub fn process_response_headers(&mut self) -> Result<()> {
        self.check_body_callback(false)?;
        if self.response_body_state.headers_processed || self.phase > Phase::ResponseHeaders {
            return Ok(());
        }
        self.response_body_state.headers_processed = true;
        self.phase = Phase::ResponseHeaders;
        self.run_body_callback(Phase::ResponseHeaders)?;
        self.finalize_pending_body(false)
    }

    /// Append a chunk to the bounded response inspection buffer.
    /// Use [`Self::write_response_body`] to observe partial acquisition, and
    /// always check intervention() before forwarding response bytes.
    pub fn append_response_body(&mut self, data: &[u8]) -> Result<()> {
        self.write_response_body(data).map(|_| ())
    }

    /// Acquire a response prefix without copying bytes beyond its limit.
    pub fn write_response_body(&mut self, data: &[u8]) -> Result<BodyWriteResult> {
        self.write_body(data, false)
    }

    /// Process response body (Phase 4), at most once after phase 3.
    pub fn process_response_body(&mut self) -> Result<()> {
        self.check_body_callback(false)?;
        if !self.response_body_state.headers_processed
            || self.response_body_state.processed
            || self.phase > Phase::ResponseBody
            || self.intervention.is_some()
        {
            return Ok(());
        }
        self.response_body_state.processed = true;
        self.phase = Phase::ResponseBody;
        self.response.body_inspected =
            self.response_body_accessible() && self.response_body_processable();
        self.run_body_callback(Phase::ResponseBody)?;
        Ok(())
    }

    /// Whether global and current ctl policy permit request acquisition.
    pub fn request_body_accessible(&self) -> bool {
        self.controls
            .request_body_access_or(self.ruleset.body_config().request_access)
    }

    /// Whether global and current ctl policy permit response acquisition.
    pub fn response_body_accessible(&self) -> bool {
        self.controls
            .response_body_access_or(self.ruleset.body_config().response_access)
    }

    /// Whether the response media type is selected for phase-4 body inspection.
    pub fn response_body_processable(&self) -> bool {
        let media_type = self.response.content_type_bytes();
        self.ruleset
            .body_config()
            .response_mime_types
            .iter()
            .any(|allowed| media_type == allowed.as_bytes())
    }

    /// Number of bytes currently retained for request inspection.
    pub fn request_body_buffered_len(&self) -> usize {
        self.request.body.len()
    }

    /// Number of bytes currently retained for response inspection.
    pub fn response_body_buffered_len(&self) -> usize {
        self.response.body.len()
    }

    fn check_body_callback(&self, request: bool) -> Result<()> {
        let state = if request {
            &self.request_body_state
        } else {
            &self.response_body_state
        };
        if let Some(message) = &state.failure {
            return Err(crate::Error::BodyCallbackFailed {
                direction: if request { "request" } else { "response" },
                message: message.clone(),
            });
        }
        Ok(())
    }

    fn run_body_callback(&mut self, phase: Phase) -> Result<()> {
        if let Err(error) = self.run_phase(phase) {
            let state = if phase <= Phase::RequestBody {
                &mut self.request_body_state
            } else {
                &mut self.response_body_state
            };
            state.failure = Some(error.to_string());
            return Err(error);
        }
        Ok(())
    }

    fn body_limit_action(&self, request: bool) -> BodyLimitAction {
        // DetectionOnly must remain non-disruptive even when enabled by ctl.
        if self.engine_mode() == RuleEngineMode::DetectionOnly {
            BodyLimitAction::ProcessPartial
        } else if request {
            self.ruleset.body_config().request_limit_action
        } else {
            self.ruleset.body_config().response_limit_action
        }
    }

    fn write_body(&mut self, data: &[u8], request: bool) -> Result<BodyWriteResult> {
        self.check_body_callback(request)?;
        let (state, body_phase, direction) = if request {
            (&self.request_body_state, Phase::RequestBody, "request")
        } else {
            (&self.response_body_state, Phase::ResponseBody, "response")
        };
        let processed = state.processed || self.phase > body_phase;
        let pending_headers = !state.headers_processed;
        let limit_reached = state.limit_reached;
        let accessible = if request {
            self.request_body_accessible()
        } else {
            self.response_body_accessible()
        };
        if !accessible || self.engine_mode() == RuleEngineMode::Off {
            return Ok(BodyWriteResult {
                consumed: 0,
                limit_reached,
                pending_headers,
                inspection_complete: processed,
            });
        }
        if processed && !limit_reached && !data.is_empty() {
            return Err(crate::Error::BodyAlreadyProcessed { direction });
        }
        if processed || self.intervention.is_some() || limit_reached {
            return Ok(BodyWriteResult {
                consumed: 0,
                limit_reached,
                pending_headers,
                inspection_complete: processed,
            });
        }
        let limit = if request {
            self.ruleset.body_config().request_limit
        } else {
            self.ruleset.body_config().response_limit
        };
        let current = if request {
            self.request.body.len()
        } else {
            self.response.body.len()
        };
        let remaining = limit.saturating_sub(current);
        let reached = data.len() >= remaining;
        let action = self.body_limit_action(request);
        let consumed = data.len().min(remaining);
        // Reserve before committing acquisition state: a recoverable allocation
        // failure must not mark an uncopied prefix as complete.
        if !(reached && !pending_headers && action == BodyLimitAction::Reject) {
            let body = if request {
                &mut self.request.body
            } else {
                &mut self.response.body
            };
            let required = current + consumed;
            if required > body.capacity() {
                // Amortize small writes without requesting capacity beyond the inspection limit.
                let capacity = required.max(body.capacity().saturating_mul(2).min(limit));
                body.try_reserve_exact(capacity - current)
                    .or_else(|error| {
                        if capacity > required {
                            body.try_reserve_exact(consumed)
                        } else {
                            Err(error)
                        }
                    })
                    .map_err(|source| crate::Error::BodyBufferAllocation { source })?;
            }
        }
        if reached {
            if !pending_headers {
                self.log_body_limit(request, action);
            }
            if request {
                self.request.inbound_data_error = true;
                self.request_body_state.limit_reached = true;
            } else {
                self.response.outbound_data_error = true;
                self.response_body_state.limit_reached = true;
            }
            if !pending_headers && action == BodyLimitAction::Reject {
                self.reject_body_limit(request);
                return Ok(BodyWriteResult {
                    consumed: 0,
                    limit_reached: true,
                    pending_headers: false,
                    inspection_complete: false,
                });
            }
            if pending_headers {
                let state = if request {
                    &mut self.request_body_state
                } else {
                    &mut self.response_body_state
                };
                state.pending_reject_length = Some(current);
            }
        }
        let body = if request {
            &mut self.request.body
        } else {
            &mut self.response.body
        };
        body.extend_from_slice(&data[..consumed]);
        if reached && !pending_headers {
            if request {
                self.process_request_body()?;
            } else {
                self.process_response_body()?;
            }
        }
        let processed = if request {
            self.request_body_state.processed
        } else {
            self.response_body_state.processed
        };
        Ok(BodyWriteResult {
            consumed,
            limit_reached: reached,
            pending_headers,
            inspection_complete: processed,
        })
    }

    fn log_body_limit(&self, request: bool, action: BodyLimitAction) {
        let limit = if request {
            self.ruleset.body_config().request_limit
        } else {
            self.ruleset.body_config().response_limit
        };
        tracing::warn!(
            direction = if request { "request" } else { "response" },
            limit,
            ?action,
            "body reached its configured inspection limit"
        );
    }

    fn reject_body_limit(&mut self, request: bool) {
        if self.intervention.is_none() {
            self.intervention = Some(Intervention::deny(
                if request { 413 } else { 500 },
                if request {
                    Phase::RequestBody
                } else {
                    Phase::ResponseBody
                },
                None,
            ));
        }
    }

    fn finalize_pending_body(&mut self, request: bool) -> Result<()> {
        let accessible = if request {
            self.request_body_accessible()
        } else {
            self.response_body_accessible()
        };
        if !accessible || self.engine_mode() == RuleEngineMode::Off {
            if request {
                self.request.body = Vec::new();
                self.request.inbound_data_error = false;
                self.request_body_state.limit_reached = false;
                self.request_body_state.pending_reject_length = None;
            } else {
                self.response.body = Vec::new();
                self.response.outbound_data_error = false;
                self.response_body_state.limit_reached = false;
                self.response_body_state.pending_reject_length = None;
            }
            return Ok(());
        }
        let previous = if request {
            self.request_body_state.pending_reject_length.take()
        } else {
            self.response_body_state.pending_reject_length.take()
        };
        if let Some(previous) = previous {
            let action = self.body_limit_action(request);
            self.log_body_limit(request, action);
            if action == BodyLimitAction::Reject {
                if request {
                    self.request.body.truncate(previous);
                } else {
                    self.response.body.truncate(previous);
                }
                self.reject_body_limit(request);
            } else if request {
                self.process_request_body()?;
            } else {
                self.process_response_body()?;
            }
        }
        Ok(())
    }

    /// Process logging phase (Phase 5), including after a denial.
    ///
    /// Matching pinned Coraza, repeated calls rerun phase 5, and a disruptive
    /// logging rule can replace an earlier intervention without ending phase 5.
    /// An earlier global `allow` suppresses logging rules.
    pub fn process_logging(&mut self) -> Result<()> {
        self.phase = Phase::Logging;
        self.run_phase(Phase::Logging)?;
        Ok(())
    }

    /// Get current intervention (if any).
    pub fn intervention(&self) -> Option<&Intervention> {
        self.intervention.as_ref()
    }

    /// Check if there's an intervention.
    pub fn has_intervention(&self) -> bool {
        self.intervention.is_some()
    }

    /// Get matched rule IDs.
    pub fn matched_rules(&self) -> &[String] {
        self.matched_rules.as_slice(&self.ruleset, self.phase)
    }

    /// Read the current legacy `TX:anomaly_score` value, or zero if absent.
    ///
    /// CRS versions with per-paranoia scores compute their own aggregates, such
    /// as `TX:blocking_inbound_anomaly_score`. Read those keys through `tx()`;
    /// this accessor does not invent or overwrite rule-owned scoring variables.
    pub fn anomaly_score(&self) -> i32 {
        self.tx
            .get_bytes(b"anomaly_score")
            .and_then(|values| {
                values
                    .first()
                    .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok())
            })
            .unwrap_or(0)
    }

    /// Get the TX collection.
    pub fn tx(&self) -> &TxCollection {
        &self.tx
    }

    /// Get mutable TX collection.
    pub fn tx_mut(&mut self) -> &mut TxCollection {
        &mut self.tx
    }

    /// The engine mode in force for this transaction.
    ///
    /// `ctl:ruleEngine` overrides the ruleset's configured mode for the
    /// remainder of the transaction; with no override this is the ruleset's
    /// own mode.
    fn engine_mode(&self) -> RuleEngineMode {
        self.controls.engine_mode(self.ruleset.engine_mode())
    }

    /// Run rules for a specific phase.
    fn run_phase(&mut self, phase: Phase) -> Result<()> {
        if self.allow_through.is_some_and(|last| phase <= last)
            || (self.intervention.is_some() && phase != Phase::Logging)
        {
            return Ok(());
        }

        // ctl:ruleEngine overrides the ruleset's mode for this transaction, so
        // the effective mode has to be re-read rather than captured once: a
        // rule in an earlier phase may have switched it off.
        if self.engine_mode() == RuleEngineMode::Off {
            return Ok(());
        }

        // Keep the immutable ruleset alive independently of mutable transaction state.
        let ruleset = Arc::clone(&self.ruleset);
        let rules = ruleset.rules_for_phase(phase);
        if rules.is_empty() {
            return Ok(());
        }

        let dispatch = ruleset.dispatch_for_phase(phase);
        let available =
            RequestCollections::new(&self.request, ruleset.width_sources[phase.index()])
                .with_headers(&self.request, &ruleset.header_slots[phase.index()]);
        let mut chain_start = None;
        // What each link matched, held with the starter's id: a chain that
        // fails part-way did not match, so it leaves nothing in matched_data.
        let mut pending_chain_data = Vec::new();
        let mut skip_count: u32 = 0;
        let mut skip_after: Option<usize> = None;

        let mut idx = 0;
        if phase == Phase::RequestHeaders
            && self.tx.is_empty()
            && !self.record_setvar_effects
            && !self.record_rule_messages
        {
            if let Some(defaults) = &ruleset.tx_defaults {
                self.apply_tx_defaults(&ruleset, defaults);
                idx = defaults.end;
            }
        }
        let mut phase_end = rules.len();
        while idx < phase_end {
            // Handle skipAfter
            if let Some(next) = skip_after.take() {
                if next < idx {
                    break;
                }
                idx = next;
                continue;
            }

            let rule = &rules[idx];

            let targets = dispatch[idx].targets.select(available);
            if !targets.may_match(rule.variables.len()) && chain_start.is_none() && skip_count == 0
            {
                idx = dispatch[idx].after_empty_targets;
                continue;
            }

            // Coraza applies removals before counting skip:N, at the entry
            // to a logical rule. A child tag cannot select its starter.
            // Likewise a removal fired by the starter cannot cancel its own
            // chain while it is still executing.
            if chain_start.is_none() {
                let removed = self.controls.is_rule_removed(rule.id.as_deref())
                    || (dispatch[idx].removable_by_tag
                        && self.controls.is_tag_removed(&rule.actions));
                if removed || skip_count > 0 {
                    if !removed {
                        skip_count -= 1;
                    }
                    while idx + 1 < rules.len() && rules[idx].is_chain {
                        idx += 1;
                    }
                    idx += 1;
                    continue;
                }
            }

            // Evaluate rule
            // Runtime tag exclusions apply to every link of the logical rule,
            // including children that carry no tag of their own.
            let starter_index = chain_start.unwrap_or(idx);
            let starter = &rules[starter_index];
            let starter_dispatch = &dispatch[starter_index];
            let tag_actions = if starter_dispatch.target_removable_by_tag {
                starter.actions.as_slice()
            } else {
                &[]
            };
            let link_rule_id = rule.id.as_deref().or(starter.id.as_deref());
            let standalone = !rule.is_chain && chain_start.is_none();
            let outcome = if targets.may_match(rule.variables.len()) {
                self.evaluate_rule(
                    rule,
                    &dispatch[idx],
                    link_rule_id,
                    tag_actions,
                    standalone,
                    targets,
                )?
            } else {
                None
            };
            if let Some(outcome) = outcome {
                // Controls can change the mode only on a match. Finish recording
                // this link, then stop before evaluating another logical rule.
                if dispatch[idx].controls_from < rule.actions.len()
                    && self.engine_mode() == RuleEngineMode::Off
                {
                    phase_end = 0;
                }
                let RuleOutcome {
                    first_data,
                    first_message,
                } = outcome;
                if let Some(data) = first_data {
                    let source = RuleLocation::new(
                        phase,
                        if rule.id.is_some() {
                            idx
                        } else {
                            starter_index
                        },
                    );
                    let data = (source, data);
                    if standalone {
                        self.matched_data.extend(&ruleset, std::iter::once(data));
                    } else {
                        pending_chain_data.push(data);
                    }
                }

                if rule.is_chain {
                    // A link that expects more links after it. Hold the
                    // starter's remaining actions: nothing else may fire until
                    // the whole chain has matched. The starter's id is held
                    // back too, so a chain that later fails does not count as
                    // a match.
                    chain_start.get_or_insert(idx);
                    idx += 1;
                    continue;
                }

                // Either a standalone rule, or the final link of a chain that
                // has now matched in full. A completed chain keeps the
                // starter's disruptive action, flow and metadata.
                if chain_start.take().is_some() {
                    self.matched_data
                        .extend(&ruleset, pending_chain_data.drain(..));
                }
                if starter.id.is_some() {
                    self.matched_rules
                        .push(&ruleset, RuleLocation::new(phase, starter_index));
                }

                if self.record_rule_messages {
                    if let Some(message) =
                        first_message.or_else(|| self.expand_rule_message(&starter.actions))
                    {
                        self.rule_messages.push(message);
                    }
                }

                match starter_dispatch.flow {
                    CompiledFlow::Skip(n) => skip_count = n,
                    CompiledFlow::SkipAfter(next) => skip_after = Some(next),
                    // Chain links have already been visited by this point.
                    CompiledFlow::Chain | CompiledFlow::Next => {}
                }
                match starter_dispatch.disruptive(starter) {
                    None | Some(DisruptiveAction::Pass) => {}
                    _ if self.engine_mode() != RuleEngineMode::On => {}
                    Some(DisruptiveAction::AllowPhase) => return Ok(()),
                    Some(DisruptiveAction::AllowRequest) => {
                        if phase.is_request_phase() {
                            self.allow_through = Some(Phase::RequestBody);
                            return Ok(());
                        }
                    }
                    Some(DisruptiveAction::Allow) => {
                        self.allow_through = Some(Phase::Logging);
                        return Ok(());
                    }
                    Some(action) => {
                        let metadata = rule_metadata(&starter.actions);
                        let id = rule.id.clone();
                        let mut intervention = match action {
                            DisruptiveAction::Deny | DisruptiveAction::Block => {
                                let default = if matches!(action, DisruptiveAction::Block) {
                                    self.default_status
                                } else {
                                    403
                                };
                                Intervention::deny(
                                    metadata.status.filter(|s| *s != 0).unwrap_or(default),
                                    phase,
                                    id,
                                )
                            }
                            DisruptiveAction::Redirect(url) => {
                                let mut it = Intervention::redirect(url.clone(), phase, id);
                                it.status = metadata
                                    .status
                                    .filter(|s| matches!(s, 301 | 302 | 303 | 307))
                                    .unwrap_or(302);
                                it
                            }
                            DisruptiveAction::Drop => {
                                let mut it = Intervention::drop(phase, id);
                                it.status = metadata.status.unwrap_or(0);
                                it
                            }
                            _ => unreachable!("non-interrupting actions handled above"),
                        };
                        intervention.add_metadata(metadata);
                        self.intervention = Some(intervention);
                        if phase != Phase::Logging {
                            return Ok(());
                        }
                    }
                }
            } else {
                // Rule didn't match. If it belongs to a chain, the chain as a
                // whole cannot match: drop the starter's held actions and skip
                // past the remaining links so they are never evaluated on
                // their own.
                if chain_start.take().is_some() || rule.is_chain {
                    pending_chain_data.clear();
                    while idx < rules.len() && rules[idx].is_chain {
                        idx += 1;
                    }
                    idx += 1;
                    continue;
                }
            }

            idx += 1;
        }

        Ok(())
    }

    fn apply_tx_defaults(
        &mut self,
        ruleset: &CompiledRuleset,
        defaults: &super::initialization::TxDefaults,
    ) {
        let phase = Phase::RequestHeaders;
        let dispatch = ruleset.dispatch_for_phase(phase);
        self.tx
            .apply_defaults(&defaults.assignments, defaults.capture_limit);
        // These are the first matches in a fresh transaction. The ruleset
        // already contains their IDs and count results in execution order.
        self.matched_rules = MatchedRules::from_defaults(&defaults.ids);
        self.matched_data = MatchLog::with_default_prefix(!defaults.counts.is_empty());
        self.matched_vars.clear();
        self.matched_vars.extend(
            defaults
                .last_count
                .map(|entry| super::initialization::TxDefaults::count_value(dispatch, entry)),
        );
    }

    /// A target's values are snapshotted together. The next target is
    /// resolved after this target's actions, so it sees updated TX state.
    fn resolve_rule_target(
        &self,
        spec: &VariableSpec,
        selection: &crate::variables::TargetSelection,
        logical_id: Option<&str>,
        tag_actions: &[Action],
        search: Option<&StaticSearch<'_>>,
        target: &mut ResolvedTarget,
    ) -> Result<()> {
        let resolver = VariableResolver::new_bytes(
            &self.request,
            &self.response,
            &self.tx,
            &self.matched_vars,
        )
        .with_request_line(&self.request_line);
        let by_id = self.controls.has_target_removals(logical_id);
        let by_tag = if tag_actions.is_empty() {
            TagTargetRemoval::None
        } else {
            self.controls.tag_target_removal(tag_actions, spec)
        };
        let match_name = |prefix: &str, member: Option<&[u8]>| {
            selection
                .match_name
                .as_deref()
                .cloned()
                .unwrap_or_else(|| crate::variables::qualified_name(prefix, member))
        };
        let mut error = None;
        let mut count = 0usize;
        if by_tag != TagTargetRemoval::All {
            resolver.visit_values(spec, selection, |prefix, member, value| {
                if (by_id && self.controls.removed_member(logical_id, spec, member))
                    || (by_tag == TagTargetRemoval::Members
                        && self.controls.removed_tag_member(tag_actions, spec, member))
                {
                    return;
                }
                if spec.count_mode {
                    count += 1;
                    return;
                }
                if error.is_some() {
                    return;
                }
                if let Some(search) = search.filter(|_| target.first.is_none()) {
                    if let Err(e) = search.first_match(value, |stage| {
                        target.first = Some((match_name(prefix, member), stage));
                    }) {
                        error = Some(e);
                    }
                } else {
                    // A match can change selection controls or mutate the collection.
                    // Snapshot remaining members before running the first match's actions.
                    target
                        .remaining
                        .push((match_name(prefix, member), value.to_vec()));
                }
            });
        }
        if let Some(error) = error {
            return Err(error);
        }
        if spec.count_mode {
            let name = selection
                .match_name
                .as_deref()
                .expect("compiled count target name");
            // Presence checks on a named header or TX variable normally produce 0 or 1.
            let value: Cow<'_, [u8]> = match count {
                0 => Cow::Borrowed(b"0"),
                1 => Cow::Borrowed(b"1"),
                _ => Cow::Owned(count.to_string().into_bytes()),
            };
            if let Some(search) = search {
                search.first_match(&value, |stage| target.first = Some((name.clone(), stage)))?;
            } else {
                target.remaining.push((name.clone(), value.into_owned()));
            }
        }
        Ok(())
    }

    fn evaluate_rule(
        &mut self,
        rule: &CompiledRule,
        dispatch: &RuleDispatch,
        logical_id: Option<&str>,
        tag_actions: &[Action],
        standalone: bool,
        targets: ActiveTargets,
    ) -> Result<Option<RuleOutcome>> {
        let mut outcome: Option<RuleOutcome> = None;
        let mut bound_operator = None;
        let dynamic = dispatch.dynamic;
        let capture = dispatch.capture;
        let multi_match = dispatch.multi_match;

        let search = StaticSearch {
            within: None,
            numeric: dispatch.numeric,
            regex: if rule.operator_spec.name == crate::parser::OperatorName::Rx {
                rule.operator.compiled_regex()
            } else {
                None
            },
            rule,
            capture,
            multi_match,
        };
        let mut evaluate = |tx: &mut Self,
                            name: Option<&ByteValue>,
                            value: &[u8],
                            prepared: Option<(&ByteValue, ByteOperatorResult)>|
         -> Result<()> {
            let snapshot = prepared.as_ref().map(|(snapshot, _)| *snapshot);
            let result = if let Some((_, result)) = prepared {
                result
            } else if let Some(numeric) = dispatch.numeric {
                ByteOperatorResult {
                    matched: numeric.matches(value),
                    ..Default::default()
                }
            } else {
                let operator: &dyn Operator = if dynamic {
                    if bound_operator.is_none() {
                        let expanded =
                            tx.expand_operator_macros_bytes(&rule.operator_spec.argument);
                        bound_operator =
                            Some(compile_operator_bytes(&rule.operator_spec, &expanded)?);
                    }
                    bound_operator.as_deref().expect("bound just above")
                } else {
                    rule.operator.as_ref()
                };
                operator.execute_rule_bytes(value, capture)?
            };
            if result.matched == rule.operator_negated {
                return Ok(());
            }

            let first = outcome.is_none();
            let outcome = outcome.get_or_insert_with(|| {
                tx.matched_vars.clear();
                RuleOutcome {
                    first_data: None,
                    first_message: None,
                }
            });
            let matched_value =
                name.map(|_| snapshot.cloned().unwrap_or_else(|| ByteValue::from(value)));
            let need_portion = capture || (first && name.is_some());
            // A positive static comparison reuses the input; a negated one
            // has no matched portion. Other operators report their own bytes.
            let mut portion = if result.matched
                && (dispatch.numeric.is_some()
                    || (snapshot.is_some() && dispatch.within_tx_key.is_some()))
            {
                need_portion.then(|| {
                    matched_value
                        .clone()
                        .unwrap_or_else(|| ByteValue::from(value))
                })
            } else {
                result
                    .matched_value
                    .filter(|_| need_portion)
                    .map(ByteValue::from)
            };
            if let (Some(name), Some(value)) = (name, matched_value) {
                if first {
                    // TX:0 retains its own copy when capture is enabled. Otherwise
                    // the audit snapshot can take ownership of the operator result.
                    let audit_portion = if capture {
                        portion.clone()
                    } else {
                        portion.take()
                    };
                    outcome.first_data = Some(RawMatch {
                        variable: name.clone(),
                        value: value.clone(),
                        portion: audit_portion,
                    });
                }
                tx.matched_vars.push((name.clone(), value));
            }
            if capture {
                tx.store_captures(portion, result.captures);
            }
            // SecLang runs all setvars before the controls for each
            // matching value. The parsed operations belong to the ruleset.
            for prepared in &dispatch.setvars {
                let Action::Data(DataAction::SetVar(op)) = &rule.actions[prepared.action_index]
                else {
                    unreachable!("compiled setvar action index");
                };
                tx.apply_setvar(op, prepared, logical_id);
            }
            for action in &rule.actions[dispatch.controls_from..] {
                let Action::Control(ctl) = action else {
                    continue;
                };
                let directive = tx
                    .ruleset
                    .controls
                    .get(ctl)
                    .expect("compiled control action")
                    .clone();
                if !matches!(directive, CtlDirective::Unsupported { .. }) {
                    if let CtlDirective::RequestBodyProcessor(ref processor) = directive {
                        tx.request.body_processor = processor.clone();
                    }
                    tx.controls
                        .apply_compiled(directive, Some(&tx.ruleset.selectors));
                }
            }
            if first && standalone && tx.record_rule_messages {
                outcome.first_message = tx.expand_rule_message(&rule.actions);
            }
            // Captures, MATCHED_VAR and setvar may all change a macro even
            // between two transformation stages of the same target value.
            bound_operator = None;
            Ok(())
        };

        if dispatch.single_tx_numeric
            && tag_actions.is_empty()
            && !self.controls.has_target_removals(logical_id)
        {
            let selection = &dispatch.selections[0];
            let crate::variables::MemberSelector::Key(key) = &selection.member else {
                unreachable!("compiled literal TX key")
            };
            let live = match dispatch.numeric_tx_slot {
                Some(slot) => self
                    .tx
                    .indexed_value(key, &mut self.numeric_tx_indices[usize::from(slot)]),
                None => self.tx.canonical_value(key),
            };
            let value = match (rule.variables[0].count_mode, live) {
                (true, Some(_)) => b"1".as_slice(),
                (true, None) => b"0".as_slice(),
                (false, Some(value)) => value,
                (false, None) => return Ok(outcome),
            };
            let matched = dispatch
                .numeric
                .expect("compiled numeric TX predicate")
                .matches(value);
            if matched != rule.operator_negated {
                let value = ByteValue::from(value);
                let result = ByteOperatorResult {
                    matched,
                    ..Default::default()
                };
                evaluate(
                    self,
                    selection.match_name.as_deref(),
                    value.as_bytes(),
                    Some((&value, result)),
                )?;
            }
            return Ok(outcome);
        }
        if rule.variables.is_empty() {
            // SecAction has no target and matches exactly once.
            evaluate(self, None, b"", None)?;
        }
        for index in targets.indices(&rule.variables) {
            let spec = &rule.variables[index];
            let selection = &dispatch.selections[index];
            let mut target = ResolvedTarget::default();
            // Read the TX operand for this target. After the first match, actions
            // may change it and subsequent evaluations use the dynamic binder.
            let within = dispatch
                .within_tx_key
                .as_deref()
                .map(|key| self.tx.canonical_value(key).unwrap_or_default());
            let search =
                (!dynamic || within.is_some()).then_some(StaticSearch { within, ..search });
            self.resolve_rule_target(
                spec,
                selection,
                logical_id,
                tag_actions,
                search.as_ref(),
                &mut target,
            )?;
            if let Some((name, stage)) = target.first {
                evaluate(
                    self,
                    Some(&name),
                    stage.value.as_bytes(),
                    Some((&stage.value, stage.result)),
                )?;
                if let Some(after) = stage.resume_after {
                    rule.transformations.visit_byte_stages(
                        stage.value.as_bytes(),
                        Some(after),
                        |_, value| {
                            evaluate(self, Some(&name), value, None)?;
                            Ok(None::<()>)
                        },
                    )?;
                }
            }
            for (name, value) in target.remaining {
                if multi_match {
                    rule.transformations.for_each_byte_stage(&value, |stage| {
                        evaluate(self, Some(&name), stage, None)
                    })?;
                } else {
                    let transformed = rule.transformations.apply_bytes(&value)?;
                    evaluate(self, Some(&name), &transformed, None)?;
                }
            }
        }
        Ok(outcome)
    }

    /// Expand against current transaction state. Literal text and standalone
    /// macro values can be borrowed until the caller needs to store a snapshot.
    fn expand_operator_macros_bytes<'a>(&'a self, arg: &'a str) -> Cow<'a, [u8]> {
        self.expand_macros_bytes::<false>(arg)
    }

    fn expand_macros_bytes<'a, const KEEP_MISSING: bool>(&'a self, arg: &'a str) -> Cow<'a, [u8]> {
        let mut output = Vec::new();
        let mut rest = arg;
        while let Some((prefix, name, suffix)) = super::split_operator_macro(rest) {
            let value = self.macro_value_bytes::<KEEP_MISSING>(name);
            if prefix.is_empty() && output.is_empty() && suffix.is_empty() {
                return Cow::Borrowed(value);
            }
            output.reserve(prefix.len() + value.len());
            output.extend_from_slice(prefix.as_bytes());
            output.extend_from_slice(value);
            rest = suffix;
        }
        if output.is_empty() {
            Cow::Borrowed(rest.as_bytes())
        } else {
            output.extend_from_slice(rest.as_bytes());
            Cow::Owned(output)
        }
    }

    fn macro_value_bytes<'a, const KEEP_MISSING: bool>(&'a self, name: &'a str) -> &'a [u8] {
        let Some((collection, key)) = name.split_once('.') else {
            if name.eq_ignore_ascii_case("matched_var") {
                return self
                    .matched_vars
                    .last()
                    .map(|(_, v)| v.as_bytes())
                    .unwrap_or_default();
            }
            if name.eq_ignore_ascii_case("matched_var_name") {
                return self
                    .matched_vars
                    .last()
                    .map(|(k, _)| k.as_bytes())
                    .unwrap_or_default();
            }
            return self
                .tx
                .first_value_bytes(name.as_bytes())
                .unwrap_or_default();
        };
        let key = key.as_bytes();
        if collection.eq_ignore_ascii_case("tx") {
            return self.tx.first_value_bytes(key).unwrap_or(if KEEP_MISSING {
                name.as_bytes()
            } else {
                &[]
            });
        }
        if collection.eq_ignore_ascii_case("request_headers") {
            return self
                .request
                .headers
                .first_value_bytes(key)
                .unwrap_or(if KEEP_MISSING { name.as_bytes() } else { &[] });
        }
        let value = if collection.eq_ignore_ascii_case("args") {
            self.request
                .args_get
                .first_value_bytes(key)
                .or_else(|| self.request.args_post.first_value_bytes(key))
        } else if collection.eq_ignore_ascii_case("args_get") {
            self.request.args_get.first_value_bytes(key)
        } else if collection.eq_ignore_ascii_case("args_post") {
            self.request.args_post.first_value_bytes(key)
        } else {
            return &[];
        };
        // A missing ARGS macro expands to its original name.
        value.unwrap_or(name.as_bytes())
    }

    /// Publish the captures of a `capture` rule as `TX:0`..`TX:9`.
    ///
    /// `whole` is the text the operator matched (TX:0); `groups` are the regex
    /// groups, in order (TX:1...). Slots the match did not fill are removed so
    /// a stale value from an earlier rule cannot be read.
    ///
    /// Clearing all ten slots first is deliberate, and differs from
    /// libmodsecurity v3: there each capture is stored on its own and nothing
    /// is removed (`operators/rx.cc:104-113`), so a higher slot written by an
    /// earlier rule survives a match that did not fill it. A rule that reads
    /// `%{tx.3}` after a match with two groups then sees the old value. No
    /// ruleset should depend on a leftover like that, so the stale read is
    /// closed here.
    fn store_captures(&mut self, whole: Option<ByteValue>, groups: Vec<Vec<u8>>) {
        const SLOTS: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
        self.tx.clear_capture_slots();
        if let Some(whole) = whole {
            self.tx.set_bytes(SLOTS[0], whole);
        }
        for (&slot, group) in SLOTS[1..].iter().zip(groups) {
            self.tx.set_bytes(slot, group);
        }
    }

    /// Apply a setvar operation.
    fn apply_setvar(
        &mut self,
        op: &SetVarSpec,
        prepared: &super::ruleset::CompiledSetVar,
        rule_id: Option<&str>,
    ) {
        let record = rule_id.filter(|_| self.record_setvar_effects);
        let (key, audit_key) = match &prepared.key {
            Some(key) => (key.clone(), record.map(|_| op.key.clone())),
            None => {
                let expanded = self.expand_macros_bytes::<true>(&op.key);
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
                    SetVarValue::Macro(raw) => Some(self.expand_macros_bytes::<true>(raw)),
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

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("phase", &self.phase)
            .field("has_intervention", &self.intervention.is_some())
            .field("anomaly_score", &self.anomaly_score())
            .field("matched_rules", &self.matched_rules())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variables::Collection;

    fn make_ruleset(rules: &str) -> Arc<CompiledRuleset> {
        Arc::new(CompiledRuleset::from_string(rules).unwrap())
    }

    #[test]
    fn macro_expansion_preserves_literals_and_first_binary_values() {
        let mut tx = Transaction::new(make_ruleset(""), 403);
        tx.tx.set_bytes("x", "value");
        tx.request.args_get.add_bytes("label", b"\xff".as_slice());
        tx.request.args_get.add_bytes("label", "later");
        tx.request.args_post.add_bytes("label", "body");
        tx.request.add_header_bytes(b"X-Report", b"summary");

        for (template, expected) in [
            ("%{x}", b"value".as_slice()),
            ("%%{x}-%{}-%{Tx.X}-%{", b"%value-%{}-value-%{"),
            ("%{tx.a%{x}}", b"}"),
            ("%{tX.absent}%{ARGS.Label}", b"\xff"),
            ("%{arGs_Get.label}%{args_post.label}", b"\xffbody"),
            ("%{ArGs.Missing}", b"ArGs.Missing"),
            ("%{Request_Headers.X-REPORT}", b"summary"),
            ("%{unknown.foo} and %{matched_var}", b" and "),
            ("%{x}%{x}", b"valuevalue"),
        ] {
            assert_eq!(tx.expand_operator_macros_bytes(template).as_ref(), expected);
        }
    }

    #[test]
    fn literal_argument_lookups_do_not_request_a_collection_scan() {
        let rules = make_ruleset(
            r#"SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRule ARGS:chosen "@rx ^book$" "id:901,phase:1,pass"
SecRule ARGS_GET_NAMES:chosen "@pm chosen" "id:902,phase:1,pass"
SecRule ARGS_POST:chosen "@rx ^book$" "id:903,phase:1,pass"
SecRule ARGS:/^cho/ "@rx ^book$" "id:904,phase:2,pass""#,
        );
        assert!(!rules.width_sources[Phase::RequestHeaders.index()].arguments);
        assert!(rules.width_sources[Phase::RequestBody.index()].arguments);
        let mut tx = Transaction::new(rules, 403);
        let mut uri = String::from("/?");
        for i in 0..512 {
            uri.push_str(&format!("field{i}=a&"));
        }
        uri.push_str("chosen=book");
        tx.process_uri(&uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.matched_rules(), ["901", "902", "904"]);
    }

    #[test]
    fn argument_width_pruning_matches_unpruned_evaluation() {
        let config = r#"SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS_NAMES "@rx (//)" "id:51,phase:1,pass,t:none,t:normalizePath,capture"
SecRule ARGS|XML:/*|TX:late "@rx (item[.]ok)" "id:52,phase:2,pass,capture,multiMatch,t:lowercase,setvar:tx.hits=+1,msg:'%{MATCHED_VAR}'"
SecRule &ARGS:empty "@rx ^0$" "id:53,phase:2,pass"
SecRule ARGS "!@rx zzzz" "id:54,phase:2,pass"
SecRule ARGS "@rx (?:.{0})" "id:55,phase:2,pass"
SecRule ARGS "@rx [!]" "id:56,phase:2,pass,t:hexDecode"
SecRule ARGS "@rx (?-u:\xFF)" "id:57,phase:2,pass,capture"
SecRule ARGS "@rx %{tx.needle}" "id:58,phase:2,pass"
SecRule ARGS "@pm item.ok longer" "id:60,phase:2,pass,t:none,t:lowercase,capture"
SecRule ARGS "@rx ^.{65}$" "id:59,phase:2,deny,status:406""#;
        let fast = make_ruleset(config);
        assert!(fast.width_sources[Phase::RequestBody.index()].arguments);
        let mut slow = CompiledRuleset::from_string(config).unwrap();
        slow.width_sources.fill(Default::default());
        let slow = Arc::new(slow);
        let unrelated = make_ruleset(r#"SecRule TX:test "@rx word" "id:1,phase:2,pass""#);
        assert_eq!(unrelated.width_sources, [Default::default(); 5]);
        for (uri, content_type, body) in [
            ("/?q=abc", "text/plain", ""),
            (
                "/?%2f=z&q=21&q=ITEM.ok",
                "application/x-www-form-urlencoded",
                "k=item.ok",
            ),
            ("/?name=%FF", "application/xml", "<root>item.ok</root>"),
            ("/?q=123", "application/json", r#"{"item":{"ok":123}}"#),
            (
                "/?q=x",
                "application/x-www-form-urlencoded",
                "q=01234567890123456789012345678901234567890123456789012345678901234",
            ),
        ] {
            let run = |rules| {
                let mut tx = Transaction::new(rules, 403);
                tx.set_record_rule_messages(true);
                tx.set_record_setvar_effects(true);
                tx.process_uri(uri, "POST", "HTTP/1.1").unwrap();
                tx.add_request_header("Content-Type", content_type).unwrap();
                tx.process_request_headers().unwrap();
                tx.tx_mut().set_bytes("late", "item.ok");
                tx.tx_mut().set_bytes("needle", "123");
                tx.append_request_body(body.as_bytes()).unwrap();
                tx.process_request_body().unwrap();
                tx
            };
            let (a, b) = (run(fast.clone()), run(slow.clone()));
            assert_eq!(a.matched_rules(), b.matched_rules());
            assert_eq!(a.matched_data(), b.matched_data());
            assert_eq!(a.rule_messages(), b.rule_messages());
            assert_eq!(a.setvar_effects(), b.setvar_effects());
            assert_eq!(a.tx.all_bytes(), b.tx.all_bytes());
            assert_eq!(
                a.intervention().map(|i| i.status),
                b.intervention().map(|i| i.status)
            );
            assert!(a.matched_rules().iter().any(|id| id == "52"));
            assert_eq!(
                a.matched_rules().iter().any(|id| id == "60"),
                uri.contains("ITEM.ok")
            );
            if content_type == "application/xml" {
                let first = a
                    .matched_data()
                    .iter()
                    .find(|m| m.rule_id.as_deref() == Some("52"))
                    .unwrap();
                assert!(first.variable.starts_with("XML"), "{first:?}");
                assert!(a.matched_rules().iter().any(|id| id == "57"));
            }
            if body.len() > 64 {
                assert_eq!(a.intervention().map(|i| i.status), Some(406));
            }
        }
    }

    #[test]
    fn header_masks_match_unpruned_evaluation_with_empty_and_duplicate_headers() {
        let config = r#"SecRuleEngine On
SecAction "id:60,phase:1,pass,ctl:ruleRemoveTargetById=67;REQUEST_HEADERS:X-Test"
SecRule REQUEST_HEADERS:X-Test "@rx (item[.]ok)" "id:61,phase:1,pass,capture,t:lowercase,setvar:tx.hits=+1"
SecRule REQUEST_HEADERS:x-test "@rx ^$" "id:62,phase:1,pass"
SecRule REQUEST_HEADERS:X-Test "!@rx item" "id:63,phase:1,pass"
SecRule REQUEST_HEADERS:X-Test|TX:late "@rx item" "id:64,phase:1,pass"
SecRule REQUEST_HEADERS:X-Test "@rx ." "id:67,phase:1,pass"
SecRule &REQUEST_HEADERS:X-Test "@eq 0" "id:65,phase:1,pass"
SecRule REQUEST_HEADERS:x-test "@rx (?-u:\xFF)" "id:66,phase:1,deny,status:406""#;
        let fast = make_ruleset(config);
        let slots = &fast.header_slots[Phase::RequestHeaders.index()];
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].as_ref(), b"x-test");
        let mut slow = CompiledRuleset::from_string(config).unwrap();
        slow.header_slots[Phase::RequestHeaders.index()].clear();
        let slow = Arc::new(slow);
        for count in [0, 1, 2, 32, 33] {
            let run = |rules| {
                let mut tx = Transaction::new(rules, 403);
                tx.tx_mut().set_bytes("late", "item");
                tx.set_record_rule_messages(true);
                tx.set_record_setvar_effects(true);
                for i in 0..count {
                    let value: &[u8] = match i {
                        0 => b"",
                        1 => b"ITEM.ok",
                        32 => b"\xff",
                        _ => b"short",
                    };
                    let key: &[u8] = if i % 2 == 0 { b"x-test" } else { b"X-TEST" };
                    tx.add_request_header_bytes(key, value).unwrap();
                }
                tx.process_request_headers().unwrap();
                tx
            };
            let (a, b) = (run(fast.clone()), run(slow.clone()));
            assert_eq!(a.matched_rules(), b.matched_rules());
            assert_eq!(a.matched_data(), b.matched_data());
            assert_eq!(a.rule_messages(), b.rule_messages());
            assert_eq!(a.setvar_effects(), b.setvar_effects());
            assert_eq!(a.tx.all_bytes(), b.tx.all_bytes());
            assert_eq!(a.matched_rules().iter().any(|id| id == "65"), count == 0);
            assert!(!a.matched_rules().iter().any(|id| id == "67"));
            assert_eq!(a.matched_rules().iter().any(|id| id == "62"), count > 0);
            assert_eq!(a.matched_rules().iter().any(|id| id == "61"), count > 1);
            assert_eq!(
                a.intervention().map(|i| i.status),
                (count == 33).then_some(406)
            );
        }
    }

    #[test]
    fn empty_target_runs_preserve_counted_skips_markers_and_chains() {
        let config = r#"SecRuleEngine On
SecRule REQUEST_METHOD "@streq POST" "id:70,phase:1,pass,skip:2,ctl:ruleRemoveById=71"
SecRule REQUEST_METHOD "@streq HEAD" "id:80,phase:1,pass,skipAfter:MIDDLE"
SecRule ARGS "@streq hit" "id:71,phase:1,pass,chain"
SecRule REQUEST_METHOD "@rx ." "setvar:tx.child=1"
SecRule ARGS "@streq hit" "id:72,phase:1,pass"
SecMarker MIDDLE
SecRule ARGS "@streq hit" "id:73,phase:1,pass"
SecAction "id:74,phase:1,pass,setvar:tx.visited=1"
SecRule REQUEST_METHOD "@rx ." "id:75,phase:1,pass,chain,setvar:tx.starter=1"
SecRule ARGS "@streq hit" "chain"
SecRule REQUEST_METHOD "@rx ." "setvar:tx.tail=1"
SecRule &ARGS "@eq 0" "id:76,phase:1,pass"
SecAction "id:77,phase:1,pass,setvar:tx.done=1""#;
        let fast = make_ruleset(config);
        let rules = fast.dispatch_for_phase(Phase::RequestHeaders);
        assert!(rules[2].after_empty_targets >= 6);
        // TX:unset always resolves to no values, but its mutable collection
        // keeps the reference evaluator on the ordinary per-rule path.
        let reference = make_ruleset(&config.replace("SecRule ARGS ", "SecRule ARGS|TX:unset "));
        for method in ["GET", "HEAD", "POST"] {
            for uri in ["/", "/?v=hit"] {
                let run = |rules| {
                    let mut tx = Transaction::new(rules, 403);
                    tx.set_record_rule_messages(true);
                    tx.set_record_setvar_effects(true);
                    tx.process_uri(uri, method, "HTTP/1.1").unwrap();
                    tx.process_request_headers().unwrap();
                    tx
                };
                let (a, b) = (run(fast.clone()), run(reference.clone()));
                assert_eq!(a.matched_rules(), b.matched_rules());
                assert_eq!(a.matched_data(), b.matched_data());
                assert_eq!(a.rule_messages(), b.rule_messages());
                assert_eq!(a.setvar_effects(), b.setvar_effects());
                assert_eq!(a.tx.all_bytes(), b.tx.all_bytes());
                assert!(a.matched_rules().iter().any(|id| id == "77"));
            }
        }
    }

    #[test]
    fn first_static_hit_resumes_once_and_preserves_effects_before_a_callback_error() {
        use crate::operators::OperatorResult;
        use std::sync::Mutex;

        struct Recorder(Mutex<Vec<Vec<u8>>>);
        impl Operator for Recorder {
            fn name(&self) -> &'static str {
                "recorder"
            }
            fn execute(&self, _: &str) -> OperatorResult {
                unreachable!("byte evaluation required")
            }
            fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
                self.0.lock().unwrap().push(value.to_vec());
                if value == b"tail" {
                    return Err(crate::Error::Config {
                        message: "test callback stopped".into(),
                    });
                }
                if value.ends_with(&[0xff]) {
                    Ok(ByteOperatorResult {
                        matched: true,
                        matched_value: Some(value.to_vec()),
                        captures: vec![value.to_vec()],
                    })
                } else {
                    Ok(ByteOperatorResult::no_match())
                }
            }
        }
        let rules = make_ruleset(
            r#"SecRule ARGS_GET:k "@rx ." "id:77,phase:1,pass,capture,multiMatch,t:lowercase,t:uppercase,setvar:tx.hits=+1,setvar:tx.last=%{MATCHED_VAR}""#,
        );
        let mut rule = rules.rules_for_phase(Phase::RequestHeaders)[0].clone();
        let recorder = Arc::new(Recorder(Mutex::new(Vec::new())));
        rule.operator = recorder.clone();
        for (query, expected) in [
            (
                "/?k=skip&k=MiXeD%FF&k=tail&k=never",
                vec![
                    &b"skip"[..],
                    b"SKIP",
                    b"MiXeD\xff",
                    b"mixed\xff",
                    b"MIXED\xff",
                    b"tail",
                ],
            ),
            ("/?k=tail&k=never", vec![&b"tail"[..]]),
        ] {
            recorder.0.lock().unwrap().clear();
            let mut tx = Transaction::new(rules.clone(), 403);
            tx.process_uri(query, "GET", "HTTP/1.1").unwrap();
            let error = tx
                .evaluate_rule(
                    &rule,
                    &rules.dispatch_for_phase(Phase::RequestHeaders)[0],
                    Some("77"),
                    &rule.actions,
                    true,
                    rules.dispatch_for_phase(Phase::RequestHeaders)[0]
                        .targets
                        .select(RequestCollections::new(&tx.request, Default::default())),
                )
                .err()
                .unwrap();
            assert!(error.to_string().contains("test callback stopped"));
            assert_eq!(*recorder.0.lock().unwrap(), expected);
            if expected.len() == 1 {
                assert!(tx.tx().get("hits").is_none());
            } else {
                assert_eq!(tx.tx().get("hits"), Some(vec!["3"]));
                assert_eq!(tx.tx().get_bytes(b"last"), Some(vec![&b"MIXED\xff"[..]]));
                assert_eq!(tx.tx().get_bytes(b"1"), Some(vec![&b"MIXED\xff"[..]]));
            }
        }
    }

    #[test]
    fn test_basic_match() {
        let ruleset = make_ruleset(
            r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#,
        );
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/admin/dashboard", "GET", "HTTP/1.1")
            .unwrap();
        tx.process_request_headers().unwrap();

        assert!(tx.has_intervention());
        let intervention = tx.intervention().unwrap();
        assert_eq!(intervention.status, 403);
    }

    #[test]
    fn test_no_match() {
        let ruleset = make_ruleset(
            r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#,
        );
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/public/index.html", "GET", "HTTP/1.1")
            .unwrap();
        tx.process_request_headers().unwrap();

        assert!(!tx.has_intervention());
    }

    #[test]
    fn test_setvar() {
        let ruleset = make_ruleset(
            r#"
            SecRule REQUEST_URI "@contains /test" "id:1,phase:1,pass,setvar:TX.score=5"
        "#,
        );
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/test/page", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        assert!(!tx.has_intervention());
        let score = tx
            .tx()
            .get("score")
            .and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(score, Some("5".to_string()));
    }

    #[test]
    fn test_operator_arg_macro_ge_threshold() {
        // @ge with a %{tx.*} argument must compare against the resolved value.
        let ruleset = make_ruleset(
            r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:tx.threshold=5"
            SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,nolog,setvar:tx.score=10"
            SecRule TX:score "@ge %{tx.threshold}" "id:3,phase:1,deny"
        "#,
        );
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(
            tx.has_intervention(),
            "score 10 >= threshold 5 should block"
        );
    }

    #[test]
    fn test_operator_arg_macro_ge_below_threshold() {
        let ruleset = make_ruleset(
            r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:tx.threshold=5"
            SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,nolog,setvar:tx.score=3"
            SecRule TX:score "@ge %{tx.threshold}" "id:3,phase:1,deny"
        "#,
        );
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(
            !tx.has_intervention(),
            "score 3 < threshold 5 should not block"
        );
    }

    #[test]
    fn test_negated_within_macro_does_not_block_allowed() {
        // Regression for the 911100 case: a negated @within whose argument is a
        // resolvable macro must not block when the value IS in the list.
        let ruleset = make_ruleset(
            r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:tx.allowed=GET"
            SecRule REQUEST_METHOD "!@within %{tx.allowed}" "id:2,phase:1,deny"
        "#,
        );
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(!tx.has_intervention(), "GET is allowed, must not block");
    }

    #[test]
    fn test_negated_within_macro_blocks_disallowed() {
        let ruleset = make_ruleset(
            r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:tx.allowed=GET"
            SecRule REQUEST_METHOD "!@within %{tx.allowed}" "id:2,phase:1,deny"
        "#,
        );
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(tx.has_intervention(), "POST is not allowed, must block");
    }

    #[test]
    fn test_secaction_sets_tx_and_macro_resolves() {
        // CRS-style: SecAction (no variables) seeds a TX threshold that a later
        // rule's operator macro resolves against.
        let ruleset = make_ruleset(
            r#"
            SecAction "id:1,phase:1,pass,nolog,setvar:tx.threshold=5"
            SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,nolog,setvar:tx.score=10"
            SecRule TX:score "@ge %{tx.threshold}" "id:3,phase:1,deny"
        "#,
        );
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let threshold = tx
            .tx()
            .get("threshold")
            .and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(
            threshold,
            Some("5".to_string()),
            "SecAction setvar must apply"
        );
        assert!(tx.has_intervention(), "10 >= 5 should block");
    }

    #[test]
    fn test_request_header_named_selector_matches() {
        // REQUEST_HEADERS:User-Agent must match regardless of header-name case.
        let ruleset = make_ruleset(
            r#"
            SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:1,phase:1,deny"
        "#,
        );
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("User-Agent", "sqlmap/1.0").unwrap();
        tx.process_request_headers().unwrap();
        assert!(tx.has_intervention(), "User-Agent selector should match");
    }

    #[test]
    fn test_setvar_value_macro_accumulates() {
        // CRS-style score accumulation: setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'
        // must add the resolved delta (5), and twice must yield 10.
        let ruleset = make_ruleset(
            r#"
            SecAction "id:1,phase:1,pass,nolog,setvar:tx.critical_anomaly_score=5"
            SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,nolog,setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"
            SecRule REQUEST_URI "@contains /" "id:3,phase:1,pass,nolog,setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"
        "#,
        );
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let score = tx
            .tx()
            .get("anomaly_score")
            .and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(
            score,
            Some("10".to_string()),
            "two +5 macro increments should total 10"
        );
    }

    #[test]
    fn test_setvar_value_macro_unresolved_is_noop() {
        // An unresolved macro delta must not silently increment by 1.
        let ruleset = make_ruleset(
            r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:'tx.anomaly_score=+%{tx.missing}'"
        "#,
        );
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let score = tx
            .tx()
            .get("anomaly_score")
            .and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(score, None, "an unresolved increment leaves the key absent");
    }

    #[test]
    fn test_detection_only_mode() {
        let _ruleset = make_ruleset(
            r#"
            SecRuleEngine DetectionOnly
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#,
        );
        let mut tx = Transaction::new(
            Arc::new(
                CompiledRuleset::from_string(
                    r#"
                SecRuleEngine DetectionOnly
                SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
            "#,
                )
                .unwrap(),
            ),
            403,
        );
        tx.process_uri("/admin/dashboard", "GET", "HTTP/1.1")
            .unwrap();
        tx.process_request_headers().unwrap();

        // Should match but not block
        assert!(!tx.has_intervention());
        assert!(tx.matched_rules().contains(&"1".to_string()));
    }
}

#[cfg(test)]
mod body_buffer_boundaries {
    use crate::ModSecurity;

    #[test]
    fn partial_body_reserves_only_its_bounded_prefix() {
        let engine = ModSecurity::from_string("SecRequestBodyAccess On\nSecRequestBodyLimit 4\nSecRequestBodyLimitAction ProcessPartial").unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(
            tx.write_request_body(&vec![b'x'; 65536]).unwrap().consumed,
            4
        );
        assert_eq!(tx.request.body.len(), 4);
        assert!(tx.request.body.capacity() <= 4);
        assert!(tx.request.inbound_data_error);
    }

    #[test]
    fn small_writes_grow_amortized_and_respect_a_non_power_of_two_limit() {
        let engine = ModSecurity::from_string(
            "SecRequestBodyAccess On\nSecRequestBodyLimit 100\nSecRequestBodyLimitAction ProcessPartial",
        ).unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let mut growths = 0;
        for _ in 0..100 {
            let previous = tx.request.body.capacity();
            assert_eq!(tx.write_request_body(b"x").unwrap().consumed, 1);
            growths += usize::from(tx.request.body.capacity() > previous);
            assert!(tx.request.body.capacity() <= 100);
        }
        assert!(growths <= 8);
        assert_eq!(tx.request_body_buffered_len(), 100);
    }

    #[test]
    fn reject_does_not_reserve_or_copy_the_over_limit_chunk() {
        let engine = ModSecurity::from_string(
            "SecRequestBodyAccess On\nSecRequestBodyLimit 4\nSecRequestBodyLimitAction Reject",
        )
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(
            tx.write_request_body(&vec![b'x'; 65536]).unwrap().consumed,
            0
        );
        assert_eq!(tx.request.body.capacity(), 0);
        assert_eq!(tx.intervention().unwrap().status, 413);
    }

    #[test]
    fn engine_off_never_acquires_body_bytes_even_after_the_body_callback() {
        let engine =
            ModSecurity::from_string("SecRuleEngine Off\nSecRequestBodyAccess On").unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.write_request_body(b"ignored").unwrap().consumed, 0);
        assert_eq!(tx.request.body.capacity(), 0);
        assert!(!tx.request.inbound_data_error);
    }
}
