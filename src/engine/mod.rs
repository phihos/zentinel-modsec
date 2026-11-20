//! Transaction engine for ModSecurity rule processing.

pub mod body;
pub mod chain;
pub mod control;
mod diagnostics;
mod initialization;
pub mod intervention;
mod macro_template;
mod match_log;
pub mod phase;
pub mod ruleset;
pub mod scoring;
mod target_indices;
pub mod transaction;

pub use body::{BodyConfig, BodyLimitAction, BodyWriteResult};
pub use control::{CtlDirective, TransactionControls};
pub use intervention::Intervention;
pub use ruleset::{CompiledRuleset, Rules};
pub use transaction::{RuleMessage, SetVarChange, SetVarEffect, Transaction};

use crate::error::Result;
use std::sync::Arc;

/// Split at the first nonempty operator macro. Empty and unclosed placeholders
/// are literal text during both rule loading and transaction evaluation.
fn split_operator_macro(input: &str) -> Option<(&str, &str, &str)> {
    for (start, _) in input.match_indices("%{") {
        let (name, suffix) = input[start + 2..].split_once('}')?;
        if !name.is_empty() {
            return Some((&input[..start], name, suffix));
        }
    }
    None
}

/// Main ModSecurity engine.
pub struct ModSecurity {
    /// Compiled ruleset.
    ruleset: Arc<CompiledRuleset>,
    /// Default block status code.
    default_status: u16,
    autodetect_structured_bodies: bool,
}

impl ModSecurity {
    /// Create a new ModSecurity instance with the given ruleset.
    pub fn new(ruleset: CompiledRuleset) -> Self {
        Self {
            ruleset: Arc::new(ruleset),
            default_status: 403,
            autodetect_structured_bodies: true,
        }
    }

    /// Load rules from a file.
    pub fn from_file(path: &str) -> Result<Self> {
        let ruleset = CompiledRuleset::from_file(path)?;
        Ok(Self::new(ruleset))
    }

    /// Load rules from a string.
    pub fn from_string(rules: &str) -> Result<Self> {
        let ruleset = CompiledRuleset::from_string(rules)?;
        Ok(Self::new(ruleset))
    }

    /// Set the default block status code.
    pub fn set_default_status(&mut self, status: u16) {
        self.default_status = status;
    }

    /// Select JSON and XML request processors from Content-Type automatically.
    ///
    /// The default is enabled. Disable this for Coraza's policy of requiring
    /// an explicit `ctl:requestBodyProcessor` for JSON and XML. Form and
    /// multipart requests retain their automatic processors in both modes.
    pub fn set_autodetect_structured_request_bodies(&mut self, enabled: bool) {
        self.autodetect_structured_bodies = enabled;
    }

    /// Create a new transaction for processing a request.
    pub fn new_transaction(&self) -> Transaction {
        let mut tx = Transaction::new(Arc::clone(&self.ruleset), self.default_status);
        tx.autodetect_structured_bodies = self.autodetect_structured_bodies;
        tx
    }

    /// Create a transaction with a connector-supplied identifier.
    /// Surrounding whitespace is trimmed. An empty ID requests a generated one.
    pub fn new_transaction_with_id(&self, id: &str) -> Transaction {
        let mut tx = self.new_transaction();
        tx.set_initial_id(id);
        tx
    }

    /// Get the ruleset.
    pub fn ruleset(&self) -> &CompiledRuleset {
        &self.ruleset
    }

    /// Get the number of rules.
    pub fn rule_count(&self) -> usize {
        self.ruleset.rule_count()
    }
}

impl std::fmt::Debug for ModSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModSecurity")
            .field("rule_count", &self.ruleset.rule_count())
            .field("default_status", &self.default_status)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modsec_from_string() {
        let rules = r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#;
        let modsec = ModSecurity::from_string(rules).unwrap();
        assert_eq!(modsec.rule_count(), 1);
    }

    #[test]
    fn test_new_transaction() {
        let rules = r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#;
        let modsec = ModSecurity::from_string(rules).unwrap();
        let _tx = modsec.new_transaction();
    }
}
