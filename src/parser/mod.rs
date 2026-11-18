//! SecRule parser module.
//!
//! This module handles parsing of ModSecurity configuration directives including:
//! - SecRule: The main rule directive
//! - SecAction: Actions without matching
//! - SecMarker: Named markers for skipAfter
//! - SecRuleEngine: Enable/disable rule processing
//! - Include: File inclusion
//!
//! ## SecRule Syntax
//!
//! ```text
//! SecRule VARIABLES "OPERATOR" "ACTIONS"
//! ```
//!
//! Where:
//! - VARIABLES: Comma-separated list of variables to inspect
//! - OPERATOR: Pattern to match (e.g., @rx, @contains)
//! - ACTIONS: Comma-separated list of actions (e.g., id:1,deny,log)

mod action;
mod directive;
mod lexer;
mod operator;
mod variable;

pub use action::{
    parse_actions, Action, ControlAction, DataAction, DisruptiveAction, FlowAction, LoggingAction,
    MetadataAction, SetVarSpec, SetVarValue,
};
pub use directive::{
    BodyLimitAction, Directive, RuleEngineMode, RuleIdSelector, SecAction, SecMarker, SecRule,
    UpdateTargetById, UpdateTargetByTag,
};
pub use lexer::{Lexer, Token, TokenKind};
pub use operator::{OperatorName, OperatorSpec};
pub(crate) use variable::parse_single_variable;
pub use variable::{Selection, VariableName, VariableSpec, XmlTarget};

use crate::error::{Error, Result, SourceLocation};
use std::collections::HashMap;
use std::path::Path;

// Coraza counts Include directives cumulatively, including directives in
// previously loaded files. One glob is one directive regardless of its size.
const MAX_INCLUDES: usize = 100;

/// Parser for ModSecurity configuration files.
pub struct Parser {
    /// Parsed directives.
    directives: Vec<Directive>,
    /// Number of Include directives expanded into this configuration.
    include_count: usize,
    /// Current source location for error reporting.
    location: SourceLocation,
    /// Default actions to apply to rules, keyed by the phase they configure.
    ///
    /// `SecDefaultAction` is per-phase in ModSecurity -- CRS issues one for
    /// each of the five phases -- so a single flat list would let the last
    /// directive parsed govern every phase.
    default_actions: HashMap<u8, Vec<Action>>,
}

impl Parser {
    /// Create a new parser.
    pub fn new() -> Self {
        Self {
            directives: Vec::new(),
            include_count: 0,
            location: SourceLocation::default(),
            default_actions: HashMap::new(),
        }
    }

    /// Append one caller-supplied source atomically. Included files participate
    /// in the same append, so rollback only needs a single checkpoint.
    fn try_append(&mut self, parse: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let count = self.directives.len();
        let includes = self.include_count;
        let defaults = self.default_actions.clone();
        let location = self.location.clone();
        if let Err(error) = parse(self) {
            self.directives.truncate(count);
            self.include_count = includes;
            self.default_actions = defaults;
            self.location = location;
            return Err(error);
        }
        Ok(())
    }

    /// Parse a configuration string.
    pub fn parse(&mut self, input: &str) -> Result<()> {
        self.parse_with_location(input, None)
    }

    /// Parse a configuration string with file location.
    pub fn parse_with_location(&mut self, input: &str, file: Option<&Path>) -> Result<()> {
        self.try_append(|parser| parser.parse_input(input, file))
    }

    fn parse_input(&mut self, input: &str, file: Option<&Path>) -> Result<()> {
        self.location.file = file.map(|p| p.to_path_buf());
        self.location.line = 1;
        self.location.column = 1;

        let mut lexer = Lexer::new(input);

        while let Some(token) = lexer.next_token() {
            self.location.line = token.line;
            self.location.column = token.column;

            match token.kind {
                TokenKind::Directive(name) => {
                    let directive = self.parse_directive(&name, &mut lexer)?;
                    self.directives.push(directive);
                }
                TokenKind::Comment => {
                    // Skip comments
                }
                TokenKind::Newline => {
                    // Skip blank lines
                }
                _ => {
                    return Err(Error::parse(
                        format!("unexpected token: {:?}", token.kind),
                        self.location.to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Parse a configuration file.
    pub fn parse_file(&mut self, path: &Path) -> Result<()> {
        self.try_append(|parser| parser.read_file(path))
    }

    fn read_file(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path).map_err(|e| Error::RuleFileLoad {
            path: path.to_path_buf(),
            source: e,
        })?;
        self.parse_input(&content, Some(path))
    }

    /// Parse files matching a glob pattern.
    pub fn parse_glob(&mut self, pattern: &str) -> Result<()> {
        self.try_append(|parser| parser.read_glob(pattern))
    }

    fn read_glob(&mut self, pattern: &str) -> Result<()> {
        let paths = glob::glob(pattern)
            .map_err(|e| Error::parse(format!("invalid glob pattern: {}", e), pattern))?;

        for entry in paths {
            let path = entry.map_err(|e| Error::parse(e.to_string(), pattern))?;
            let metadata = path.metadata().map_err(|source| Error::RuleFileLoad {
                path: path.clone(),
                source,
            })?;
            if metadata.is_file() {
                self.read_file(&path)?;
            }
        }

        Ok(())
    }

    /// Get the parsed directives.
    pub fn into_directives(self) -> Vec<Directive> {
        self.directives
    }

    /// Get a reference to the parsed directives.
    pub fn directives(&self) -> &[Directive] {
        &self.directives
    }

    /// Parse a directive starting from the directive name.
    fn parse_directive(&mut self, name: &str, lexer: &mut Lexer) -> Result<Directive> {
        match name.to_lowercase().as_str() {
            "secrule" => self.parse_secrule(lexer),
            "secaction" => self.parse_secaction(lexer),
            "secmarker" => self.parse_secmarker(lexer),
            "secruleengine" => self.parse_secruleengine(lexer),
            "secdefaultaction" => self.parse_secdefaultaction(lexer),
            "secruleremovebyid" => self.parse_secruleremovebyid(lexer),
            "secruleupdatetargetbyid" => self.parse_secruleupdatetargetbyid(lexer),
            "secruleupdatetargetbytag" => self.parse_secruleupdatetargetbytag(lexer),
            "secruleupdateactionbyid" => {
                // Preserve the target ID for the load diagnostic. Applying the
                // action update remains unsupported.
                let id_text = self.expect_argument(lexer, "SecRuleUpdateActionById id")?;
                let id = id_text
                    .trim_matches(|c| c == '\'' || c == '"')
                    .parse()
                    .map_err(|_| {
                        Error::parse(
                            "SecRuleUpdateActionById requires a numeric rule ID",
                            self.location.to_string(),
                        )
                    })?;
                let actions =
                    self.expect_quoted_argument(lexer, "SecRuleUpdateActionById actions")?;
                Ok(Directive::SecRuleUpdateActionById {
                    id,
                    actions: action::parse_actions(&actions)?,
                })
            }
            "secrequestbodyaccess" => self.parse_boolean_directive(lexer, "SecRequestBodyAccess"),
            "secresponsebodyaccess" => self.parse_boolean_directive(lexer, "SecResponseBodyAccess"),
            "secrequestbodylimit" => self.parse_body_limit(lexer, true),
            "secresponsebodylimit" => self.parse_body_limit(lexer, false),
            "secrequestbodylimitaction" => self.parse_body_limit_action(lexer, true),
            "secresponsebodylimitaction" => self.parse_body_limit_action(lexer, false),
            "secresponsebodymimetype" => {
                let mut types = Vec::new();
                while self.peek_more_arguments(lexer) {
                    let argument = self.expect_argument(lexer, "SecResponseBodyMimeType")?;
                    types.extend(argument.split_whitespace().map(str::to_owned));
                }
                if types.is_empty() {
                    return Err(Error::parse(
                        "SecResponseBodyMimeType requires a MIME type",
                        self.location.to_string(),
                    ));
                }
                Ok(Directive::SecResponseBodyMimeType(types))
            }
            "secresponsebodymimetypesclear" => {
                if self.peek_more_arguments(lexer) {
                    return Err(Error::parse(
                        "SecResponseBodyMimeTypesClear takes no arguments",
                        self.location.to_string(),
                    ));
                }
                Ok(Directive::SecResponseBodyMimeTypesClear)
            }
            "include" => self.parse_include(lexer),
            // Recognized engine-config/metadata directives that have no effect on
            // rule evaluation — skip quietly rather than warning.
            "seccomponentsignature" => {
                self.skip_to_end_of_line(lexer);
                Ok(Directive::Unknown(name.to_string()))
            }
            _ => {
                // Skip unknown directives with a warning
                tracing::warn!(
                    directive = name,
                    location = %self.location,
                    "unknown directive, skipping"
                );
                self.skip_to_end_of_line(lexer);
                Ok(Directive::Unknown(name.to_string()))
            }
        }
    }

    /// Parse a SecRule directive.
    fn parse_secrule(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        // Parse variables
        let variables_str = self.expect_argument(lexer, "SecRule variables")?;
        let variables = variable::parse_variables(&variables_str)?;

        // Parse operator
        let operator_str = self.expect_quoted_argument(lexer, "SecRule operator")?;
        let mut operator = operator::parse_operator(&operator_str)?;
        self.resolve_operator_file_path(&mut operator);

        // Parse actions (optional)
        let actions = if self.peek_quoted(lexer) {
            let actions_str = self.expect_quoted_argument(lexer, "SecRule actions")?;
            let mut actions = action::parse_actions(&actions_str)?;
            // Apply default actions
            actions = self.merge_default_actions(actions);
            actions
        } else {
            // No actions of its own: it still inherits the defaults for the
            // phase it lands in, which with no `phase` action is phase 2.
            self.defaults_for_phase(DEFAULT_PHASE).to_vec()
        };

        Ok(Directive::SecRule(SecRule {
            variables,
            operator,
            actions,
            location: self.location.clone(),
        }))
    }

    /// Resolve a relative data-file argument (`@pmFromFile`/`@ipMatchFromFile`)
    /// against the directory of the file currently being parsed, matching how
    /// ModSecurity/CRS reference their `.data` files.
    fn resolve_operator_file_path(&self, operator: &mut OperatorSpec) {
        if !operator.name.uses_data_file() {
            return;
        }
        if std::path::Path::new(&operator.argument).is_absolute() {
            return;
        }
        if let Some(parent) = self.location.file.as_ref().and_then(|f| f.parent()) {
            operator.argument = parent
                .join(&operator.argument)
                .to_string_lossy()
                .into_owned();
        }
    }

    /// Parse a SecAction directive.
    fn parse_secaction(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let actions_str = self.expect_quoted_argument(lexer, "SecAction")?;
        let actions = action::parse_actions(&actions_str)?;

        Ok(Directive::SecAction(SecAction {
            actions,
            location: self.location.clone(),
        }))
    }

    /// Parse a SecMarker directive.
    fn parse_secmarker(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let name = self.expect_argument(lexer, "SecMarker name")?;
        Ok(Directive::SecMarker(SecMarker { name }))
    }

    /// Parse a SecRuleEngine directive.
    fn parse_secruleengine(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let mode_str = self.expect_argument(lexer, "SecRuleEngine mode")?;
        let mode = match mode_str.to_lowercase().as_str() {
            "on" => RuleEngineMode::On,
            "off" => RuleEngineMode::Off,
            "detectiononly" => RuleEngineMode::DetectionOnly,
            _ => {
                return Err(Error::parse(
                    format!("invalid SecRuleEngine mode: {}", mode_str),
                    self.location.to_string(),
                ));
            }
        };
        Ok(Directive::SecRuleEngine(mode))
    }

    /// Parse a SecDefaultAction directive.
    fn parse_secdefaultaction(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let actions_str = self.expect_quoted_argument(lexer, "SecDefaultAction")?;
        let actions = action::parse_actions(&actions_str)?;
        self.default_actions
            .insert(phase_of(&actions).unwrap_or(DEFAULT_PHASE), actions.clone());
        Ok(Directive::SecDefaultAction(actions))
    }

    /// Parse a SecRuleRemoveById directive.
    ///
    /// ModSecurity allows multiple IDs and ID ranges in a single directive,
    /// e.g. `SecRuleRemoveById 1 2 "9000-9010"`. IDs may appear as several
    /// arguments and/or space-separated inside one (quoted) argument.
    fn parse_secruleremovebyid(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let mut ids = Vec::new();
        loop {
            let arg = self.expect_argument(lexer, "SecRuleRemoveById")?;
            ids.extend(self.parse_id_selectors(&arg, "SecRuleRemoveById")?);
            if !self.peek_more_arguments(lexer) {
                break;
            }
        }
        Ok(Directive::SecRuleRemoveById(ids))
    }

    /// Parse a SecRuleUpdateTargetById directive.
    ///
    /// Syntax: `SecRuleUpdateTargetById ID TARGET1[|TARGET2|...] [REPLACED_TARGET]`
    /// where ID is a rule ID or ID range (space-separated lists accepted when
    /// quoted), targets may be `!`-prefixed exclusions, and the optional third
    /// argument names an existing target to replace.
    fn parse_secruleupdatetargetbyid(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let ids_str = self.expect_argument(lexer, "SecRuleUpdateTargetById id")?;
        let ids = self.parse_id_selectors(&ids_str, "SecRuleUpdateTargetById")?;

        let targets_str = self.expect_argument(lexer, "SecRuleUpdateTargetById targets")?;
        let (additions, exclusions) = variable::parse_update_targets(&targets_str)?;
        if additions.is_empty() && exclusions.is_empty() {
            return Err(Error::parse(
                "SecRuleUpdateTargetById requires at least one target",
                self.location.to_string(),
            ));
        }

        let replaced = if self.peek_more_arguments(lexer) {
            Some(self.expect_argument(lexer, "SecRuleUpdateTargetById replaced target")?)
        } else {
            None
        };

        Ok(Directive::SecRuleUpdateTargetById(UpdateTargetById {
            ids,
            additions,
            exclusions,
            replaced,
            location: self.location.clone(),
        }))
    }

    /// Parse a case-sensitive tag selector and its target update.
    fn parse_secruleupdatetargetbytag(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let tag = self.expect_argument(lexer, "SecRuleUpdateTargetByTag tag")?;
        if tag.is_empty() {
            return Err(Error::parse(
                "SecRuleUpdateTargetByTag requires a tag",
                self.location.to_string(),
            ));
        }
        let target_text = self.expect_argument(lexer, "SecRuleUpdateTargetByTag targets")?;
        let (additions, exclusions) = variable::parse_update_targets(&target_text)?;
        if additions.is_empty() && exclusions.is_empty() {
            return Err(Error::parse(
                "SecRuleUpdateTargetByTag requires at least one target",
                self.location.to_string(),
            ));
        }
        // Exclusion regexes must fail at load, not silently match nothing.
        for exclusion in &exclusions {
            validate_update_target(exclusion)?;
        }
        for addition in &additions {
            validate_target_regex(addition)?;
        }
        let replaced = if self.peek_more_arguments(lexer) {
            let target = self.expect_argument(lexer, "SecRuleUpdateTargetByTag replaced target")?;
            validate_update_target(&target)?;
            Some(target)
        } else {
            None
        };
        if self.peek_more_arguments(lexer) {
            return Err(Error::parse(
                "unexpected SecRuleUpdateTargetByTag argument",
                self.location.to_string(),
            ));
        }
        Ok(Directive::SecRuleUpdateTargetByTag(UpdateTargetByTag {
            tag,
            targets: UpdateTargetById {
                ids: Vec::new(),
                additions,
                exclusions,
                replaced,
                location: self.location.clone(),
            },
        }))
    }

    /// Parse a whitespace-separated list of rule IDs and inclusive ID ranges
    /// (`942100` or `942100-942199`).
    fn parse_id_selectors(&self, input: &str, context: &str) -> Result<Vec<RuleIdSelector>> {
        let mut selectors = Vec::new();
        for token in input.split_whitespace() {
            let selector = if let Some((start, end)) = token.split_once('-') {
                let start: u64 = start.trim().parse().map_err(|_| {
                    Error::parse(
                        format!("{context}: invalid rule id range '{token}'"),
                        self.location.to_string(),
                    )
                })?;
                let end: u64 = end.trim().parse().map_err(|_| {
                    Error::parse(
                        format!("{context}: invalid rule id range '{token}'"),
                        self.location.to_string(),
                    )
                })?;
                if start > end {
                    return Err(Error::parse(
                        format!("{context}: invalid rule id range '{token}' (start > end)"),
                        self.location.to_string(),
                    ));
                }
                RuleIdSelector::Range(start, end)
            } else {
                RuleIdSelector::Single(token.parse().map_err(|_| {
                    Error::parse(
                        format!("{context}: invalid rule id '{token}'"),
                        self.location.to_string(),
                    )
                })?)
            };
            selectors.push(selector);
        }
        if selectors.is_empty() {
            return Err(Error::parse(
                format!("{context}: expected at least one rule id"),
                self.location.to_string(),
            ));
        }
        Ok(selectors)
    }

    /// Check whether more arguments follow on the current logical line.
    fn peek_more_arguments(&self, lexer: &mut Lexer) -> bool {
        lexer.skip_whitespace();
        !matches!(lexer.peek(), None | Some('\n') | Some('\r') | Some('#'))
    }

    /// Parse a bounded byte count for request or response acquisition.
    fn parse_body_limit(&mut self, lexer: &mut Lexer, request: bool) -> Result<Directive> {
        let name = if request {
            "SecRequestBodyLimit"
        } else {
            "SecResponseBodyLimit"
        };
        let text = self.expect_argument(lexer, name)?;
        let limit = text
            .parse::<usize>()
            .ok()
            .filter(|limit| (1..=1_073_741_824).contains(limit))
            .ok_or_else(|| {
                Error::parse(
                    format!("{name} requires a byte count between 1 and 1073741824"),
                    self.location.to_string(),
                )
            })?;
        Ok(if request {
            Directive::SecRequestBodyLimit(limit)
        } else {
            Directive::SecResponseBodyLimit(limit)
        })
    }

    fn parse_body_limit_action(&mut self, lexer: &mut Lexer, request: bool) -> Result<Directive> {
        let name = if request {
            "SecRequestBodyLimitAction"
        } else {
            "SecResponseBodyLimitAction"
        };
        let text = self.expect_argument(lexer, name)?;
        let action = match text.to_ascii_lowercase().as_str() {
            "reject" => BodyLimitAction::Reject,
            "processpartial" => BodyLimitAction::ProcessPartial,
            _ => {
                return Err(Error::parse(
                    format!("{name} accepts Reject or ProcessPartial"),
                    self.location.to_string(),
                ))
            }
        };
        Ok(if request {
            Directive::SecRequestBodyLimitAction(action)
        } else {
            Directive::SecResponseBodyLimitAction(action)
        })
    }

    /// Parse a boolean directive (On/Off).
    fn parse_boolean_directive(&mut self, lexer: &mut Lexer, name: &str) -> Result<Directive> {
        let value_str = self.expect_argument(lexer, name)?;
        let value = match value_str.to_lowercase().as_str() {
            "on" => true,
            "off" => false,
            _ => {
                return Err(Error::parse(
                    format!("invalid {} value: {} (expected On/Off)", name, value_str),
                    self.location.to_string(),
                ));
            }
        };

        match name {
            "SecRequestBodyAccess" => Ok(Directive::SecRequestBodyAccess(value)),
            "SecResponseBodyAccess" => Ok(Directive::SecResponseBodyAccess(value)),
            _ => Ok(Directive::Unknown(name.to_string())),
        }
    }

    /// Parse an Include directive.
    fn parse_include(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let path = self.expect_argument(lexer, "Include path")?;
        if self.include_count >= MAX_INCLUDES {
            return Err(Error::parse(
                format!("configuration exceeds the limit of {MAX_INCLUDES} Include directives"),
                self.location.to_string(),
            ));
        }
        self.include_count += 1;

        let is_glob = path.contains(['*', '?', '[']);
        let path = Path::new(&path);
        let including_location = self.location.clone();
        let parent = including_location
            .file
            .as_deref()
            .and_then(Path::parent)
            .filter(|_| path.is_relative())
            .unwrap_or(Path::new(""));
        let resolved_path = parent.join(path);
        let parsed = if is_glob {
            // Only the directive's operand is a pattern. The declaring
            // directory may itself have brackets or other glob characters.
            let parent = parent.to_str().ok_or_else(|| {
                Error::parse(
                    "glob include needs a UTF-8 directory",
                    including_location.to_string(),
                )
            })?;
            let escaped = glob::Pattern::escape(parent);
            self.read_glob(&Path::new(&escaped).join(path).to_string_lossy())
        } else {
            self.read_file(&resolved_path)
        };
        self.location = including_location;
        parsed?;

        Ok(Directive::Include(resolved_path))
    }

    /// Expect an unquoted argument.
    fn expect_argument(&mut self, lexer: &mut Lexer, context: &str) -> Result<String> {
        lexer.skip_whitespace();

        match lexer.next_token() {
            Some(token) => match token.kind {
                TokenKind::Word(s) | TokenKind::QuotedString(s) => Ok(s),
                _ => Err(Error::parse(
                    format!("expected {} but got {:?}", context, token.kind),
                    self.location.to_string(),
                )),
            },
            None => Err(Error::parse(
                format!("expected {} but got end of input", context),
                self.location.to_string(),
            )),
        }
    }

    /// Expect a quoted argument.
    fn expect_quoted_argument(&mut self, lexer: &mut Lexer, context: &str) -> Result<String> {
        lexer.skip_whitespace();

        match lexer.next_token() {
            Some(token) => match token.kind {
                TokenKind::QuotedString(s) => Ok(s),
                _ => Err(Error::parse(
                    format!("expected quoted {} but got {:?}", context, token.kind),
                    self.location.to_string(),
                )),
            },
            None => Err(Error::parse(
                format!("expected quoted {} but got end of input", context),
                self.location.to_string(),
            )),
        }
    }

    /// Check if next token is a quoted string.
    fn peek_quoted(&self, lexer: &mut Lexer) -> bool {
        lexer.skip_whitespace();
        lexer.peek().map(|c| c == '"' || c == '\'').unwrap_or(false)
    }

    /// Skip to end of current line.
    fn skip_to_end_of_line(&self, lexer: &mut Lexer) {
        while let Some(token) = lexer.next_token() {
            // Comment tokens already consume their terminating newline.
            if matches!(token.kind, TokenKind::Comment | TokenKind::Newline) {
                break;
            }
        }
    }

    /// Merge default actions with rule-specific actions.
    fn merge_default_actions(&self, rule_actions: Vec<Action>) -> Vec<Action> {
        let phase = phase_of(&rule_actions).unwrap_or(DEFAULT_PHASE);
        let defaults = self.defaults_for_phase(phase);

        // `block` means "whatever disruptive action the defaults name", so the
        // default's disruptive action has to be captured before the merge below
        // discards it in favour of the rule's own.
        let inherited_disruptive = defaults
            .iter()
            .find(|a| matches!(a, Action::Disruptive(_)))
            .cloned();

        // A rule's actions replace the defaults they supersede (a `nolog`
        // displaces the default `log`), but must not displace each other:
        // `t:a,t:b`, `setvar:x,setvar:y`, `tag:a,tag:b` and `ctl:a,ctl:b` are
        // all meant to apply, in order. Only a single-valued action given
        // twice in one rule (two `msg:`, say) keeps just the last.
        let mut result = defaults.to_vec();
        let mut own: Vec<Action> = Vec::with_capacity(rule_actions.len());
        for action in rule_actions {
            result.retain(|a| !action_supersedes(&action, a));
            own.retain(|a| !action_supersedes(&action, a));
            own.push(action);
        }
        result.extend(own);

        // Resolve `block` against the inherited disruptive action. CRS sets
        // `SecDefaultAction "phase:N,log,auditlog,pass"` and then tags nearly
        // every rule `block`, meaning "score me, and let 949110 decide" -- so
        // treating `block` as a deny of its own turns the anomaly-scoring model
        // into block-on-first-match.
        if let Some(pos) = result
            .iter()
            .position(|a| matches!(a, Action::Disruptive(DisruptiveAction::Block)))
        {
            match inherited_disruptive {
                // A default that is itself `block` says nothing; leave it be.
                Some(Action::Disruptive(DisruptiveAction::Block)) | None => {}
                Some(inherited) => result[pos] = inherited,
            }
        }

        result
    }

    /// Defaults configured for a phase, or none if that phase has no
    /// `SecDefaultAction`.
    fn defaults_for_phase(&self, phase: u8) -> &[Action] {
        self.default_actions
            .get(&phase)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

/// The phase ModSecurity assigns when a rule does not name one.
const DEFAULT_PHASE: u8 = 2;

/// Phase named by a `phase:` action, if any.
fn phase_of(actions: &[Action]) -> Option<u8> {
    actions.iter().find_map(|a| match a {
        Action::Metadata(MetadataAction::Phase(p)) => Some(*p),
        _ => None,
    })
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether `new` supersedes `old`, so that `old` must be dropped when both are
/// present.
///
/// Actions that may legitimately repeat (transformations, `setvar`, `tag`,
/// `ctl`, `initcol`, ...) never supersede anything. Single-valued actions
/// supersede an earlier action of the same kind; `log`/`nolog` and
/// `auditlog`/`noauditlog` are opposites of one switch and supersede each other.
fn action_supersedes(new: &Action, old: &Action) -> bool {
    match (new, old) {
        (Action::Disruptive(_), Action::Disruptive(_)) => true,
        (Action::Flow(a), Action::Flow(b)) => {
            std::mem::discriminant(a) == std::mem::discriminant(b)
        }
        (Action::Metadata(a), Action::Metadata(b)) => {
            // `tag` accumulates; the rest are single-valued.
            !matches!(a, MetadataAction::Tag(_))
                && std::mem::discriminant(a) == std::mem::discriminant(b)
        }
        (Action::Logging(a), Action::Logging(b)) => {
            let group = |l: &LoggingAction| match l {
                LoggingAction::Log | LoggingAction::NoLog => Some(0),
                LoggingAction::AuditLog | LoggingAction::NoAuditLog => Some(1),
                LoggingAction::SanitiseMatched | LoggingAction::SanitizeMatched => Some(2),
                _ => None,
            };
            matches!((group(a), group(b)), (Some(x), Some(y)) if x == y)
        }
        (Action::Data(DataAction::Capture), Action::Data(DataAction::Capture)) => true,
        _ => false,
    }
}

/// Validate a target and its optional regex before accepting an exclusion.
fn validate_update_target(target: &str) -> Result<()> {
    let spec = parse_single_variable(target)?;
    if spec.count_mode {
        return Err(Error::parse(
            "target exclusions and replacements cannot use count mode",
            target,
        ));
    }
    validate_target_regex(&spec)
}

fn validate_target_regex(target: &VariableSpec) -> Result<()> {
    if let Some(Selection::Regex(pattern)) = &target.selection {
        crate::variables::compile_selector(pattern, target.name).map_err(|source| {
            Error::RegexCompile {
                pattern: pattern.clone(),
                source,
            }
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let mut parser = Parser::new();
        parser
            .parse(r#"SecRule REQUEST_URI "@contains /admin" "id:1,deny,status:403""#)
            .unwrap();

        assert_eq!(parser.directives.len(), 1);
        match &parser.directives[0] {
            Directive::SecRule(rule) => {
                assert_eq!(rule.variables.len(), 1);
                assert_eq!(rule.variables[0].name, VariableName::RequestUri);
            }
            _ => panic!("expected SecRule"),
        }
    }

    #[test]
    fn test_parse_secruleengine() {
        let mut parser = Parser::new();
        parser.parse("SecRuleEngine On").unwrap();

        assert_eq!(parser.directives.len(), 1);
        match &parser.directives[0] {
            Directive::SecRuleEngine(mode) => {
                assert_eq!(*mode, RuleEngineMode::On);
            }
            _ => panic!("expected SecRuleEngine"),
        }
    }

    #[test]
    fn test_relative_include_glob_resolves() {
        // `Include rules/*.conf` must resolve relative to the including file,
        // not the process CWD.
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("rules");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(
            sub.join("a.conf"),
            r#"SecRule REQUEST_URI "@contains /a" "id:101,phase:1,deny""#,
        )
        .unwrap();
        std::fs::write(
            sub.join("b.conf"),
            r#"SecRule REQUEST_URI "@contains /b" "id:102,phase:1,deny""#,
        )
        .unwrap();
        let entry = dir.path().join("entry.conf");
        std::fs::write(&entry, "Include rules/*.conf\n").unwrap();

        let mut parser = Parser::new();
        parser.parse_file(&entry).unwrap();
        let secrules = parser
            .directives
            .iter()
            .filter(|d| matches!(d, Directive::SecRule(_)))
            .count();
        assert_eq!(secrules, 2, "both included rule files should be parsed");
    }

    #[test]
    fn test_pmfromfile_relative_path_resolves() {
        // `@pmFromFile patterns.data` must resolve next to the rule file.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("patterns.data"), "evilword\n").unwrap();
        let conf = dir.path().join("rules.conf");
        std::fs::write(
            &conf,
            r#"SecRule ARGS "@pmFromFile patterns.data" "id:201,phase:1,deny""#,
        )
        .unwrap();

        let mut parser = Parser::new();
        parser.parse_file(&conf).unwrap();
        match &parser.directives[0] {
            Directive::SecRule(rule) => {
                let arg = &rule.operator.argument;
                let p = std::path::Path::new(arg);
                assert!(
                    p.is_absolute(),
                    "data path should be resolved to absolute: {arg}"
                );
                assert!(p.exists(), "resolved data path should exist: {arg}");
            }
            _ => panic!("expected SecRule"),
        }
    }

    #[test]
    fn test_normalise_path_transformation_alias() {
        // CRS uses the British spelling t:normalisePath; it must compile.
        let rs = crate::engine::CompiledRuleset::from_string(
            r#"SecRule REQUEST_URI "@contains /etc" "id:301,phase:1,t:normalisePath,deny""#,
        );
        assert!(
            rs.is_ok(),
            "normalisePath must be recognized: {:?}",
            rs.err()
        );
    }
}
