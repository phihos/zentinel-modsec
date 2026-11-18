//! Request and response body acquisition, processing and limit enforcement.

use super::Transaction;
use crate::engine::body::{append_memory, BodyState, BodyWriteResult, RequestSpool};
use crate::engine::{intervention::Intervention, phase::Phase, ruleset::RuleEngineMode};
use crate::error::Result;
use crate::parser::BodyLimitAction;

#[derive(Clone, Copy)]
enum BodySide {
    Request,
    Response,
}

impl BodySide {
    fn name(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }

    fn header_phase(self) -> Phase {
        match self {
            Self::Request => Phase::RequestHeaders,
            Self::Response => Phase::ResponseHeaders,
        }
    }

    fn body_phase(self) -> Phase {
        match self {
            Self::Request => Phase::RequestBody,
            Self::Response => Phase::ResponseBody,
        }
    }

    fn state(self, tx: &Transaction) -> &BodyState {
        match self {
            Self::Request => &tx.request_body_state,
            Self::Response => &tx.response_body_state,
        }
    }

    fn check_failure(self, state: &BodyState) -> Result<()> {
        if let Some(message) = &state.failure {
            return Err(crate::Error::BodyCallbackFailed {
                direction: self.name(),
                message: message.clone(),
            });
        }
        Ok(())
    }

    fn state_mut(self, tx: &mut Transaction) -> &mut BodyState {
        match self {
            Self::Request => &mut tx.request_body_state,
            Self::Response => &mut tx.response_body_state,
        }
    }

    fn data_error_mut(self, tx: &mut Transaction) -> &mut bool {
        match self {
            Self::Request => &mut tx.request.inbound_data_error,
            Self::Response => &mut tx.response.outbound_data_error,
        }
    }

    fn buffered_len(self, tx: &Transaction) -> usize {
        match self {
            Self::Request => tx.request_body_buffered_len(),
            Self::Response => tx.response_body_buffered_len(),
        }
    }
}

struct BodyPolicy {
    accessible: bool,
    limit: usize,
    storage: usize,
    action: BodyLimitAction,
}

/// Recognize the two media types for this processor and its structured suffix.
fn structured_media_type(media: &str, application: &str, text: &str, suffix: &str) -> bool {
    media.eq_ignore_ascii_case(application)
        || media.eq_ignore_ascii_case(text)
        || media
            .rsplit_once('+')
            .is_some_and(|(_, subtype)| subtype.eq_ignore_ascii_case(suffix))
}

impl Transaction {
    /// Process request headers (Phase 1).
    pub fn process_request_headers(&mut self) -> Result<()> {
        self.process_headers(BodySide::Request, |_| {})
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
        self.write_body(BodySide::Request, data)
    }

    /// Process request body (Phase 2).
    pub fn process_request_body(&mut self) -> Result<()> {
        self.process_body(BodySide::Request)
    }

    fn inspect_request_body(&mut self) -> Result<()> {
        if self.request_body_buffered_len() > 0 && self.request_body_accessible() {
            if self.request_spool.is_some() && !self.selected_request_processor().is_empty() {
                self.materialize_request_spool()?;
            }
            self.request.body_processed = true;
            match self.selected_request_processor() {
                "MULTIPART" => {
                    if !self.process_multipart_body() {
                        tracing::warn!("multipart request without a parseable boundary");
                    }
                }
                "URLENCODED" => {
                    self.request.parse_form_body();
                    self.request.body_processor = "URLENCODED".to_string();
                }
                "JSON" => self.process_json_body(),
                "XML" => self.process_xml_body(),
                "RAW" => self.request.body_processor = "RAW".to_string(),
                _ => {}
            }
        }
        Ok(())
    }

    fn materialize_request_spool(&mut self) -> Result<()> {
        if let Some(spool) = &mut self.request_spool {
            match spool.read_prefix() {
                Ok(body) => self.request.body = body,
                Err(error) => {
                    self.request_body_state.failure = Some(error.to_string());
                    return Err(error);
                }
            }
            self.request_spool = None;
        }
        Ok(())
    }

    fn selected_request_processor(&self) -> &str {
        if let Some(forced) = self.controls.request_body_processor() {
            return forced;
        }
        if self.request.body_processor == "MULTIPART" {
            return "MULTIPART";
        }
        if self.autodetect_structured_bodies {
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
            if structured_media_type(media, "application/xml", "text/xml", "xml") {
                return "XML";
            } else if structured_media_type(media, "application/json", "text/json", "json") {
                return "JSON";
            }
        }
        if self.request.body_processor == "URLENCODED"
            || self.controls.force_request_body_variable()
        {
            "URLENCODED"
        } else {
            ""
        }
    }

    /// Select the original Content-Type bytes for multipart boundary parsing.
    fn process_multipart_body(&mut self) -> bool {
        let content_type = self
            .request
            .headers
            .first_value_bytes(b"content-type")
            .unwrap_or_default()
            .to_vec();
        self.request.parse_multipart(
            &content_type,
            self.ruleset.needs_upload_paths,
            self.ruleset.body_config().upload_dir.as_deref(),
        )
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
        match self.request.parse_json_body() {
            Ok(()) => self
                .tx
                .set_bytes("json_request_body", self.request.body.as_slice()),
            Err(e) => tracing::debug!(
                error = %e,
                "request body could not be processed as JSON; REQBODY_ERROR is set"
            ),
        }
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
        self.process_headers(BodySide::Response, |tx| {
            tx.response.set_status(status);
            tx.connector_metadata.response_status = true;
            tx.response.set_protocol(protocol);
        })
    }

    /// Process response headers (Phase 3) using the currently stored metadata.
    ///
    /// Use [`Self::process_response_headers_with_status`] when supplying a real
    /// response from an HTTP connector. This method remains for existing callers.
    pub fn process_response_headers(&mut self) -> Result<()> {
        self.process_headers(BodySide::Response, |_| {})
    }

    fn process_headers(
        &mut self,
        side: BodySide,
        set_metadata: impl FnOnce(&mut Self),
    ) -> Result<()> {
        let state = side.state(self);
        side.check_failure(state)?;
        let phase = side.header_phase();
        if state.headers_processed || self.phase > phase {
            return Ok(());
        }
        set_metadata(self);
        side.state_mut(self).headers_processed = true;
        self.phase = phase;
        self.run_body_callback(side)?;
        self.finalize_pending_body(side)
    }

    /// Append a chunk to the bounded response inspection buffer.
    /// Use [`Self::write_response_body`] to observe partial acquisition, and
    /// always check intervention() before forwarding response bytes.
    pub fn append_response_body(&mut self, data: &[u8]) -> Result<()> {
        self.write_response_body(data).map(|_| ())
    }

    /// Acquire a response prefix without copying bytes beyond its limit.
    pub fn write_response_body(&mut self, data: &[u8]) -> Result<BodyWriteResult> {
        self.write_body(BodySide::Response, data)
    }

    /// Process response body (Phase 4), at most once after phase 3.
    pub fn process_response_body(&mut self) -> Result<()> {
        self.process_body(BodySide::Response)
    }

    fn process_body(&mut self, side: BodySide) -> Result<()> {
        let state = side.state(self);
        side.check_failure(state)?;
        let phase = side.body_phase();
        if !state.headers_processed
            || state.processed
            || self.phase > phase
            || self.intervention.is_some()
        {
            return Ok(());
        }
        side.state_mut(self).processed = true;
        self.phase = phase;
        match side {
            BodySide::Request if self.engine_mode() == RuleEngineMode::Off => return Ok(()),
            BodySide::Request => self.inspect_request_body()?,
            BodySide::Response => self.inspect_response_body(),
        }
        self.run_body_callback(side)
    }

    fn inspect_response_body(&mut self) {
        self.response.body_inspected =
            self.response_body_accessible() && self.response_body_processable();
        if self.response.body_inspected && self.engine_mode() != RuleEngineMode::Off {
            if let Some(json) = &mut self.response.json {
                let config = self.ruleset.body_config();
                let body = self.response.body.as_slice();
                let result = if body.is_empty() {
                    Err("invalid JSON".to_owned())
                } else {
                    crate::variables::json::parse(
                        body,
                        &mut json.args,
                        config.argument_limit,
                        config.response_json_depth_limit,
                        &mut self.request.arguments_limit_reached,
                    )
                };
                match result {
                    Ok(()) => self.tx.set_bytes("json_response_body", body),
                    Err(error) => json.error = Some(error),
                }
            }
        }
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

    /// Whether the response is selected for phase-4 inspection by MIME type or ctl.
    pub fn response_body_processable(&self) -> bool {
        if self.controls.force_response_body_variable() {
            return true;
        }
        let media_type = self.response.content_type_bytes();
        self.ruleset
            .body_config()
            .response_mime_types
            .iter()
            .any(|allowed| media_type == allowed.as_bytes())
    }

    /// Number of bytes currently retained for request inspection.
    pub fn request_body_buffered_len(&self) -> usize {
        self.request_spool
            .as_ref()
            .map_or(self.request.body.len(), |spool| spool.len())
    }

    /// Parsed response JSON and any processor error when a rule selected JSON.
    pub fn response_json(&self) -> Option<&crate::variables::ResponseJson> {
        self.response.json.as_deref()
    }

    /// Number of bytes currently retained for response inspection.
    pub fn response_body_buffered_len(&self) -> usize {
        self.response.body.len()
    }

    fn run_body_callback(&mut self, side: BodySide) -> Result<()> {
        self.run_phase(self.phase).inspect_err(|error| {
            side.state_mut(self).failure = Some(error.to_string());
        })
    }

    fn body_policy(&self, side: BodySide) -> BodyPolicy {
        let config = self.ruleset.body_config();
        let (accessible, local, storage, action) = match side {
            BodySide::Request => (
                self.request_body_accessible(),
                self.controls.request_body_limit,
                config.request_limit,
                config.request_limit_action,
            ),
            BodySide::Response => (
                self.response_body_accessible(),
                self.controls.response_body_limit,
                config.response_limit,
                config.response_limit_action,
            ),
        };
        let mode = self.engine_mode();
        BodyPolicy {
            accessible: accessible && mode != RuleEngineMode::Off,
            limit: local.unwrap_or(storage),
            storage,
            // A transaction can switch to detection-only in header rules.
            action: if mode == RuleEngineMode::DetectionOnly {
                BodyLimitAction::ProcessPartial
            } else {
                action
            },
        }
    }

    fn write_body(&mut self, side: BodySide, data: &[u8]) -> Result<BodyWriteResult> {
        let state = side.state(self);
        side.check_failure(state)?;
        let processed = state.processed || self.phase > side.body_phase();
        let pending_headers = !state.headers_processed;
        let limit_reached = state.limit_reached;
        let mut result = BodyWriteResult {
            consumed: 0,
            limit_reached,
            pending_headers,
            inspection_complete: processed,
        };
        let policy = self.body_policy(side);
        if !policy.accessible {
            return Ok(result);
        }
        if processed && !limit_reached && !data.is_empty() {
            return Err(crate::Error::BodyAlreadyProcessed {
                direction: side.name(),
            });
        }
        if processed || self.intervention.is_some() || limit_reached || policy.limit == 0 {
            result.limit_reached |= policy.limit == 0;
            if pending_headers && result.limit_reached && !data.is_empty() {
                side.state_mut(self).pending_discarded = true;
            }
            return Ok(result);
        }
        let current = side.buffered_len(self);
        let remaining = policy.limit.saturating_sub(current);
        result.limit_reached = data.len() >= remaining;
        let reject =
            result.limit_reached && !pending_headers && policy.action == BodyLimitAction::Reject;
        if !reject {
            let consumed = data.len().min(remaining);
            if consumed > policy.storage.saturating_sub(current) {
                if result.limit_reached {
                    *side.data_error_mut(self) = true;
                }
                return Err(crate::Error::BodyStorageLimit {
                    direction: side.name(),
                    limit: policy.storage,
                });
            }
            let bytes = &data[..consumed];
            let capacity_limit = policy.limit.min(policy.storage);
            match side {
                BodySide::Request => self.append_request_prefix(bytes, capacity_limit)?,
                BodySide::Response => {
                    append_memory(&mut self.response.body, bytes, capacity_limit)?
                }
            }
            result.consumed = consumed;
        }
        if result.limit_reached {
            *side.data_error_mut(self) = true;
            let state = side.state_mut(self);
            state.limit_reached = true;
            if pending_headers {
                state.pending_reject_length = Some(current);
                state.pending_discarded = result.consumed < data.len();
            } else {
                self.finish_at_limit(side, policy)?;
                result.inspection_complete = side.state(self).processed;
            }
        }
        Ok(result)
    }

    fn append_request_prefix(&mut self, data: &[u8], limit: usize) -> Result<()> {
        if let Some(spool) = &mut self.request_spool {
            return spool.append(data).map_err(crate::Error::BodySpoolIo);
        }
        let threshold = self
            .ruleset
            .body_config()
            .request_in_memory_limit
            .unwrap_or(limit)
            .min(limit);
        if self.request.body.len() + data.len() <= threshold {
            return append_memory(&mut self.request.body, data, threshold);
        }
        let mut spool = RequestSpool::new(&self.request.body).map_err(crate::Error::BodySpoolIo)?;
        spool.append(data).map_err(crate::Error::BodySpoolIo)?;
        self.request_spool = Some(Box::new(spool));
        self.request.body = Vec::new();
        Ok(())
    }

    fn truncate_request_body(&mut self, len: usize) {
        if len == 0 {
            self.request_spool = None;
            self.request.body = Vec::new();
        } else if let Some(spool) = &mut self.request_spool {
            spool.truncate(len);
        } else {
            self.request.body.truncate(len);
        }
    }

    fn finish_at_limit(&mut self, side: BodySide, policy: BodyPolicy) -> Result<()> {
        tracing::warn!(
            direction = side.name(),
            limit = policy.limit,
            action = ?policy.action,
            "body reached its configured inspection limit"
        );
        if policy.action == BodyLimitAction::Reject {
            if self.intervention.is_none() {
                let status = match side {
                    BodySide::Request => 413,
                    BodySide::Response => 500,
                };
                self.intervention = Some(Intervention::deny(status, side.body_phase(), None));
            }
            Ok(())
        } else {
            self.process_body(side)
        }
    }

    fn finalize_pending_body(&mut self, side: BodySide) -> Result<()> {
        let policy = self.body_policy(side);
        let length = side.buffered_len(self);
        let state = side.state_mut(self);
        let previous = state.pending_reject_length.take();
        let discarded = std::mem::take(&mut state.pending_discarded);
        if !policy.accessible || policy.limit == 0 {
            state.limit_reached = false;
            *side.data_error_mut(self) = false;
            match side {
                BodySide::Request => self.truncate_request_body(0),
                BodySide::Response => self.response.body = Vec::new(),
            }
            return Ok(());
        }
        // Header rules may raise the limit; a discarded tail cannot be recovered.
        if length < policy.limit {
            if discarded && self.intervention.is_none() {
                let state = side.state_mut(self);
                state.failure = Some(
                    "header rules raised the limit after provisional body bytes were discarded"
                        .into(),
                );
                return side.check_failure(state);
            }
            if previous.is_some() {
                side.state_mut(self).limit_reached = false;
                *side.data_error_mut(self) = false;
            }
            return Ok(());
        }
        state.limit_reached = true;
        *side.data_error_mut(self) = true;
        let retained = if policy.action == BodyLimitAction::Reject {
            // Keep the previous complete chunk only if it fits the final limit.
            previous.filter(|len| *len < policy.limit).unwrap_or(0)
        } else {
            policy.limit
        };
        match side {
            BodySide::Request => self.truncate_request_body(retained),
            BodySide::Response => self.response.body.truncate(retained),
        }
        self.finish_at_limit(side, policy)
    }
}

#[cfg(test)]
mod body_buffer_boundaries {
    use crate::ModSecurity;

    #[test]
    fn spilled_and_resident_forms_publish_the_same_prefix_in_phase_two() {
        for threshold in [3, 8] {
            let engine = ModSecurity::from_string(&format!(
                r#"
SecRequestBodyAccess On
SecRequestBodyLimit 8
SecRequestBodyInMemoryLimit {threshold}
SecRequestBodyLimitAction ProcessPartial
SecRule REQUEST_BODY_LENGTH "@gt 0" "id:1,phase:1,pass"
SecRule REQUEST_BODY "@streq x=abcdef" "id:2,phase:2,pass"
SecRule ARGS_POST:x "@streq abcdef" "id:3,phase:2,pass""#
            ))
            .unwrap();
            let mut tx = engine.new_transaction();
            tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
                .unwrap();
            tx.write_request_body(b"x=a").unwrap();
            assert!(tx.request_spool.is_none());
            tx.write_request_body(b"bc").unwrap();
            assert_eq!(tx.request_body_buffered_len(), 5);
            assert_eq!(tx.request_spool.is_some(), threshold == 3);
            if threshold == 3 {
                assert_eq!(tx.request.body.capacity(), 0);
            }
            tx.process_request_headers().unwrap();
            assert_eq!(tx.write_request_body(b"defghi").unwrap().consumed, 3);
            assert_eq!(tx.matched_rules(), ["2", "3"]);
            assert_eq!(tx.request_body_buffered_len(), 8);
        }
    }

    #[test]
    fn spooled_provisional_bytes_are_discarded_when_headers_disable_access() {
        let engine = ModSecurity::from_string(
            r#"SecRequestBodyAccess On
SecRequestBodyInMemoryLimit 2
SecAction "id:1,phase:1,pass,ctl:requestBodyAccess=Off""#,
        )
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.write_request_body(b"sample").unwrap();
        assert!(tx.request_spool.is_some());
        tx.process_request_headers().unwrap();
        assert!(tx.request_spool.is_none());
        assert_eq!(tx.request_body_buffered_len(), 0);
    }

    #[test]
    fn unknown_media_keeps_the_spool_and_binary_raw_reads_it_in_full() {
        for raw in [false, true] {
            let rule = if raw {
                r#"SecAction "id:1,phase:1,pass,ctl:requestBodyProcessor=RAW""#
            } else {
                ""
            };
            let engine = ModSecurity::from_string(&format!(
                "SecRequestBodyAccess On\nSecRequestBodyInMemoryLimit 2\n{rule}"
            ))
            .unwrap();
            let mut tx = engine.new_transaction();
            tx.process_request_headers().unwrap();
            for chunk in [b"one".as_slice(), &[255, 0, 128], b"two"] {
                tx.write_request_body(chunk).unwrap();
            }
            tx.process_request_body().unwrap();
            assert_eq!(tx.request_body_buffered_len(), 9);
            assert_eq!(tx.request_spool.is_some(), !raw);
            assert_eq!(
                tx.request.request_body_bytes_variable(),
                if raw {
                    b"one\xff\0\x80two".as_slice()
                } else {
                    b""
                }
            );
        }
    }

    #[test]
    fn memory_limit_is_checked_against_the_final_request_limit() {
        for config in [
            "SecRequestBodyInMemoryLimit 0",
            "SecRequestBodyInMemoryLimit -1",
            "SecRequestBodyInMemoryLimit 3\nSecRequestBodyLimit 2",
        ] {
            assert!(ModSecurity::from_string(config).is_err());
        }
        assert!(
            ModSecurity::from_string("SecRequestBodyInMemoryLimit 3\nSecRequestBodyLimit 3")
                .is_ok()
        );
    }

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
