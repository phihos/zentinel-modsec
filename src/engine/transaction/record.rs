//! What a transaction keeps of a match until somebody reads it.
//!
//! A matched rule's id and its message are copies of what the ruleset
//! already holds. A transaction keeps where the rule sits instead and makes
//! the copies when [`Transaction::matched_rules`] or
//! [`Transaction::messages`] is first called, so a caller that reads neither
//! pays for neither.
//!
//! [`Transaction::matched_rules`]: super::Transaction::matched_rules
//! [`Transaction::messages`]: super::Transaction::messages

use crate::engine::intervention::RuleMessage;
use crate::engine::phase::Phase;
use crate::engine::ruleset::{CompiledRule, CompiledRuleset};
use std::sync::OnceLock;

/// Where a rule sits in its ruleset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::engine) struct RuleAt {
    pub(super) phase: Phase,
    pub(super) index: usize,
}

impl RuleAt {
    fn rule(self, ruleset: &CompiledRuleset) -> Option<&CompiledRule> {
        ruleset.rules_for_phase(self.phase).get(self.index)
    }
}

/// Something a transaction records for a match and publishes on demand.
pub(in crate::engine) trait Record: Clone {
    /// What a caller reads.
    type Published;

    /// What a caller reads for this record, made from the rule in `ruleset`.
    fn publish(&self, ruleset: &CompiledRuleset) -> Option<Self::Published>;
}

/// A matched rule, published as its id.
impl Record for RuleAt {
    type Published = String;

    fn publish(&self, ruleset: &CompiledRuleset) -> Option<String> {
        self.rule(ruleset)?.id.clone()
    }
}

/// The message of a matched rule: the rule, and those of its texts that had
/// macros to expand at the match. A text without one is as the rule has it.
#[derive(Debug, Clone)]
pub(in crate::engine) struct MessageRecord {
    pub(super) rule: RuleAt,
    pub(super) msg: Option<String>,
    pub(super) data: Option<String>,
}

impl Record for MessageRecord {
    type Published = RuleMessage;

    fn publish(&self, ruleset: &CompiledRuleset) -> Option<RuleMessage> {
        let rule = &self.rule.rule(ruleset)?.metadata;
        Some(RuleMessage {
            rule_id: rule.id.clone(),
            rev: rule.rev.clone(),
            msg: self.msg.clone().or_else(|| rule.msg.clone()),
            data: self.data.clone().or_else(|| rule.logdata.clone()),
            severity: rule.severity,
            ver: rule.ver.clone(),
            maturity: rule.maturity,
            accuracy: rule.accuracy,
            tags: rule.tags.clone(),
        })
    }
}

/// The records of a transaction, in order, and what was published of them.
pub(in crate::engine) struct Records<R: Record> {
    /// The records nobody has read yet. Unused once `published` is set.
    pending: Vec<R>,
    /// Every record as published, from the first read on.
    published: OnceLock<Vec<R::Published>>,
}

impl<R: Record> Default for Records<R> {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            published: OnceLock::new(),
        }
    }
}

impl<R: Record> Records<R> {
    /// Add a record of a rule of `ruleset`.
    pub(super) fn push(&mut self, record: R, ruleset: &CompiledRuleset) {
        match self.published.get_mut() {
            Some(published) => published.extend(record.publish(ruleset)),
            None => self.pending.push(record),
        }
    }

    /// Every record so far, published.
    pub(super) fn as_slice(&self, ruleset: &CompiledRuleset) -> &[R::Published] {
        self.published.get_or_init(|| {
            let mut published = Vec::with_capacity(self.pending.len());
            published.extend(
                self.pending
                    .iter()
                    .filter_map(|record| record.publish(ruleset)),
            );
            published
        })
    }

    /// The records of a transaction nobody has read from.
    pub(super) fn into_pending(self) -> Vec<R> {
        debug_assert!(self.published.get().is_none());
        self.pending
    }

    /// Start over from `pending`.
    pub(super) fn restore(&mut self, pending: &[R]) {
        self.pending.clear();
        self.pending.extend_from_slice(pending);
        self.published = OnceLock::new();
    }
}
