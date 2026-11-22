//! Intervention tracking for blocked requests.

use super::phase::Phase;
use crate::actions::RuleMetadata;

/// An intervention (blocking decision) from rule processing.
#[derive(Debug, Clone)]
pub struct Intervention {
    /// HTTP status code to return.
    pub status: u16,
    /// Redirect URL (if applicable).
    pub url: Option<String>,
    /// Log message.
    pub log: Option<String>,
    /// Rule IDs that triggered the intervention.
    pub rule_ids: Vec<String>,
    /// Phase in which intervention occurred.
    pub phase: Phase,
    /// Whether to drop the connection.
    pub drop_connection: bool,
    /// Matched rule metadata.
    pub metadata: Vec<RuleMetadata>,
}

impl Intervention {
    /// Create a new intervention.
    pub fn new(status: u16, phase: Phase) -> Self {
        Self {
            status,
            url: None,
            log: None,
            rule_ids: Vec::new(),
            phase,
            drop_connection: false,
            metadata: Vec::new(),
        }
    }

    /// Create a deny intervention.
    pub fn deny(status: u16, phase: Phase, rule_id: Option<String>) -> Self {
        let mut intervention = Self::new(status, phase);
        if let Some(id) = rule_id {
            intervention.rule_ids.push(id);
        }
        intervention
    }

    /// Create a redirect intervention.
    pub fn redirect(url: String, phase: Phase, rule_id: Option<String>) -> Self {
        let mut intervention = Self::new(302, phase);
        intervention.url = Some(url);
        if let Some(id) = rule_id {
            intervention.rule_ids.push(id);
        }
        intervention
    }

    /// Create a drop intervention.
    pub fn drop(phase: Phase, rule_id: Option<String>) -> Self {
        let mut intervention = Self::new(444, phase);
        intervention.drop_connection = true;
        if let Some(id) = rule_id {
            intervention.rule_ids.push(id);
        }
        intervention
    }

    /// Add a rule ID, ignoring one already recorded.
    ///
    /// A rule reports its id both directly and through its metadata, so without
    /// this the triggering rule appears twice -- which reaches operators as a
    /// duplicated `X-WAF-Rule` and audit entry.
    pub fn add_rule_id(&mut self, id: String) {
        if !self.rule_ids.contains(&id) {
            self.rule_ids.push(id);
        }
    }

    /// Add metadata from a matched rule.
    pub fn add_metadata(&mut self, metadata: RuleMetadata) {
        if let Some(ref id) = metadata.id {
            if !self.rule_ids.contains(id) {
                self.rule_ids.push(id.clone());
            }
        }
        if let Some(ref msg) = metadata.msg {
            if self.log.is_none() {
                self.log = Some(msg.clone());
            }
        }
        self.metadata.push(metadata);
    }

    /// Set log message.
    pub fn set_log(&mut self, log: String) {
        self.log = Some(log);
    }

    /// Format as a log entry.
    pub fn format_log(&self) -> String {
        let mut parts = vec![format!("[status {}]", self.status)];

        if !self.rule_ids.is_empty() {
            parts.push(format!("[rule_ids: {}]", self.rule_ids.join(", ")));
        }

        if let Some(ref log) = self.log {
            parts.push(format!("[msg: {}]", log));
        }

        if let Some(ref url) = self.url {
            parts.push(format!("[redirect: {}]", url));
        }

        parts.push(format!("[phase: {}]", self.phase.name()));

        parts.join(" ")
    }
}

impl Default for Intervention {
    fn default() -> Self {
        Self::new(403, Phase::RequestHeaders)
    }
}

/// Builder for creating interventions.
#[derive(Debug, Clone)]
pub struct InterventionBuilder {
    intervention: Intervention,
}

impl InterventionBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            intervention: Intervention::default(),
        }
    }

    /// Set status code.
    pub fn status(mut self, status: u16) -> Self {
        self.intervention.status = status;
        self
    }

    /// Set phase.
    pub fn phase(mut self, phase: Phase) -> Self {
        self.intervention.phase = phase;
        self
    }

    /// Set redirect URL.
    pub fn redirect(mut self, url: String) -> Self {
        self.intervention.status = 302;
        self.intervention.url = Some(url);
        self
    }

    /// Set drop connection flag.
    pub fn drop_connection(mut self) -> Self {
        self.intervention.drop_connection = true;
        self.intervention.status = 444;
        self
    }

    /// Add rule ID.
    pub fn rule_id(mut self, id: String) -> Self {
        self.intervention.rule_ids.push(id);
        self
    }

    /// Set log message.
    pub fn log(mut self, msg: String) -> Self {
        self.intervention.log = Some(msg);
        self
    }

    /// Build the intervention.
    pub fn build(self) -> Intervention {
        self.intervention
    }
}

impl Default for InterventionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_lines_are_written_as_v3_writes_them() {
        let m = super::RuleMessage {
            rule_id: Some("932300".into()),
            rev: None,
            msg: Some("say \"hi\"\u{1}".into()),
            data: Some("\r\nMAIL\u{1}\\\"\u{e9}".into()),
            severity: Some(2),
            ver: Some("OWASP_CRS/4.30.0".into()),
            maturity: None,
            accuracy: None,
            tags: vec!["a\"b".into()],
        };
        assert_eq!(
            m.log_line(),
            r#"[id "932300"] [rev ""] [msg "say "hi"\x01"] [data "\x0d\x0aMAIL\x01\x5c\x22\xc3\xa9"] [severity "2"] [ver "OWASP_CRS/4.30.0"] [maturity "0"] [accuracy "0"] [tag "a\x22b"]"#
        );
    }

    /// `data` is cut at 200 bytes before it is escaped, as v3's `limitTo`
    #[test]
    fn data_is_cut_at_200_bytes() {
        let m = super::RuleMessage {
            rule_id: Some("1".into()),
            rev: None,
            msg: None,
            data: Some("a".repeat(250)),
            severity: None,
            ver: None,
            maturity: None,
            accuracy: None,
            tags: Vec::new(),
        };
        assert!(m.log_line().contains(&format!(
            "[data \"{} (50 characters omitted)\"]",
            "a".repeat(200)
        )));
    }

    #[test]
    fn test_deny_intervention() {
        let intervention =
            Intervention::deny(403, Phase::RequestHeaders, Some("12345".to_string()));
        assert_eq!(intervention.status, 403);
        assert_eq!(intervention.rule_ids, vec!["12345".to_string()]);
        assert!(!intervention.drop_connection);
    }

    #[test]
    fn test_redirect_intervention() {
        let intervention = Intervention::redirect(
            "https://example.com/blocked".to_string(),
            Phase::RequestHeaders,
            Some("12345".to_string()),
        );
        assert_eq!(intervention.status, 302);
        assert_eq!(
            intervention.url,
            Some("https://example.com/blocked".to_string())
        );
    }

    #[test]
    fn test_builder() {
        let intervention = InterventionBuilder::new()
            .status(403)
            .phase(Phase::RequestBody)
            .rule_id("100".to_string())
            .log("SQL Injection detected".to_string())
            .build();

        assert_eq!(intervention.status, 403);
        assert_eq!(intervention.phase, Phase::RequestBody);
        assert_eq!(intervention.rule_ids, vec!["100".to_string()]);
    }

    #[test]
    fn test_format_log() {
        let intervention =
            Intervention::deny(403, Phase::RequestHeaders, Some("942100".to_string()));
        let log = intervention.format_log();
        assert!(log.contains("[status 403]"));
        assert!(log.contains("942100"));
    }
}

/// What a rule that matched says about it, as ModSecurity v3 records it
/// (`RuleMessage`, `rule_message.h`): its id, `rev`, `msg` and `logdata` with
/// their macros expanded at the match (`%{MATCHED_VAR}`, `%{TX.0}`), its
/// severity, version, maturity, accuracy and tags. Every matched rule leaves
/// one but a `nolog` rule, as v3's `m_saveMessage` defaults to true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMessage {
    /// The rule's id (a chain's starter's).
    pub rule_id: Option<String>,
    /// `rev`.
    pub rev: Option<String>,
    /// `msg`, expanded.
    pub msg: Option<String>,
    /// `logdata`, expanded.
    pub data: Option<String>,
    /// `severity`.
    pub severity: Option<u8>,
    /// `ver`.
    pub ver: Option<String>,
    /// `maturity`.
    pub maturity: Option<u8>,
    /// `accuracy`.
    pub accuracy: Option<u8>,
    /// `tag`s, in order.
    pub tags: Vec<String>,
}

impl RuleMessage {
    /// The rule's part of the line v3 logs for it, as `RuleMessage::_details`
    /// writes it (`rule_message.cc`): `[id ""] [rev ""] [msg ""] [data ""]
    /// [severity ""] [ver ""] [maturity ""] [accuracy ""]` and a `[tag ""]`
    /// for each tag. `msg` is as written; `data` is cut at 200 bytes
    /// (`limitTo`) and, with `rev`, `ver` and the tags, escaped by
    /// `toHexIfNeeded` with `"` and `\` among the bytes written `\xHH`. The
    /// line then goes through `toHexIfNeeded` as `RuleMessage::log` sends it,
    /// so it is one line of printable ASCII. An absent number is 0, as v3's
    /// defaults. The file, line, hostname, URI, unique id and reference v3
    /// adds are the embedding application's.
    pub fn log_line(&self) -> String {
        let mut out = String::new();
        let mut field = |name: &str, value: &str| {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push('[');
            out.push_str(name);
            out.push_str(" \"");
            out.push_str(value);
            out.push_str("\"]");
        };
        let quoted =
            |value: Option<&str>| to_hex_if_needed(value.unwrap_or_default().as_bytes(), true);
        field("id", self.rule_id.as_deref().unwrap_or("0"));
        field("rev", &quoted(self.rev.as_deref()));
        field("msg", self.msg.as_deref().unwrap_or_default());
        field(
            "data",
            &to_hex_if_needed(
                &limit_to(200, self.data.as_deref().unwrap_or_default()),
                true,
            ),
        );
        field("severity", &self.severity.unwrap_or(0).to_string());
        field("ver", &quoted(self.ver.as_deref()));
        field("maturity", &self.maturity.unwrap_or(0).to_string());
        field("accuracy", &self.accuracy.unwrap_or(0).to_string());
        for tag in &self.tags {
            field("tag", &quoted(Some(tag)));
        }
        to_hex_if_needed(out.as_bytes(), false)
    }
}

/// v3's `utils::string::limitTo`: the first `amount` bytes, and
/// ` (N characters omitted)` for the N bytes after them.
fn limit_to(amount: usize, value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    if bytes.len() <= amount {
        return bytes.to_vec();
    }
    let mut out = bytes[..amount].to_vec();
    out.extend_from_slice(format!(" ({} characters omitted)", bytes.len() - amount).as_bytes());
    out
}

/// v3's `utils::string::toHexIfNeeded`: a byte below 0x20 or above 0x7e is
/// `\xHH`, and with `escape_spec` so are `"` and `\`. The result is ASCII.
fn to_hex_if_needed(bytes: &[u8], escape_spec: bool) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if !(0x20..=0x7e).contains(&b) || (escape_spec && (b == b'"' || b == b'\\')) {
            out.push_str(&format!("\\x{b:02x}"));
        } else {
            out.push(char::from(b));
        }
    }
    out
}
