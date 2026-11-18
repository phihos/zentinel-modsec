//! Byte selector programs owned by a live ruleset.
use super::{folded_key, qualified_name, ByteValue};
use crate::parser::{Selection, VariableName, VariableSpec};
use regex::bytes::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};

/// Count variables retain the selector as their match key, including regex
/// delimiters. The reference preserves argument selector case and folds the
/// selector of other collections.
fn count_name(spec: &VariableSpec) -> ByteValue {
    let prefix = spec.name.seclang_name();
    let key = match &spec.selection {
        Some(Selection::Key(key)) => std::borrow::Cow::Borrowed(key.as_bytes()),
        Some(Selection::Regex(pattern)) => format!("/{pattern}/").into_bytes().into(),
        None => return prefix.into(),
    };
    if ignore_case(spec.name) {
        qualified_name(prefix, Some(&folded_key(&key)))
    } else {
        qualified_name(prefix, Some(&key))
    }
}

pub(crate) fn regex_exclusion(target: &str) -> Option<(VariableName, &str)> {
    let (kind, selection) = target.split_once(':')?;
    Some((
        VariableName::from_str(kind)?,
        selection.strip_prefix('/')?.strip_suffix('/')?,
    ))
}

fn ignore_case(collection: VariableName) -> bool {
    !matches!(
        collection,
        VariableName::Args
            | VariableName::ArgsGet
            | VariableName::ArgsPost
            | VariableName::ArgsNames
            | VariableName::ArgsGetNames
            | VariableName::ArgsPostNames
    )
}

pub(crate) fn compile_selector(
    pattern: &str,
    collection: VariableName,
) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .case_insensitive(ignore_case(collection))
        .build()
}

/// Selection data shared by requests after target updates have been applied.
pub(crate) struct TargetSelection {
    pub member: MemberSelector,
    /// Fixed audit name for count targets and literal TX keys. Other named
    /// collections report the observed spelling of each member.
    pub match_name: Option<Box<ByteValue>>,
    exclusions: Box<[(Box<str>, MemberSelector)]>,
}

pub(crate) enum MemberSelector {
    All,
    Key(Box<[u8]>),
    Regex(Option<Arc<Regex>>),
}

impl MemberSelector {
    pub fn matches(&self, key: Option<&[u8]>) -> bool {
        match self {
            Self::All => true,
            Self::Key(wanted) => key == Some(wanted.as_ref()),
            Self::Regex(regex) => {
                key.is_some_and(|key| regex.as_ref().is_some_and(|re| re.is_match(key)))
            }
        }
    }
}

impl TargetSelection {
    pub fn compile(spec: &VariableSpec, programs: &SelectorPrograms) -> Self {
        let regex =
            |pattern: &str| MemberSelector::Regex(programs.get(pattern, spec.name).cloned());
        let member = match &spec.selection {
            Some(Selection::Key(key)) if !key.is_empty() => {
                // The three argument-name collections index the canonical bucket
                // using the selector's original spelling.
                let key = if matches!(
                    spec.name,
                    VariableName::ArgsNames
                        | VariableName::ArgsGetNames
                        | VariableName::ArgsPostNames
                ) {
                    key.as_bytes().into()
                } else {
                    folded_key(key.as_bytes()).into_owned().into_boxed_slice()
                };
                MemberSelector::Key(key)
            }
            Some(Selection::Regex(pattern)) => regex(pattern),
            _ => MemberSelector::All,
        };
        let exclusions = spec
            .exclusions
            .iter()
            .map(|target| {
                let (collection, selector) = target.split_once(':').unwrap_or((target, ""));
                let member = if selector.is_empty() {
                    MemberSelector::All
                } else if let Some(pattern) =
                    selector.strip_prefix('/').and_then(|s| s.strip_suffix('/'))
                {
                    regex(pattern)
                } else {
                    MemberSelector::Key(
                        folded_key(selector.as_bytes())
                            .into_owned()
                            .into_boxed_slice(),
                    )
                };
                (collection.into(), member)
            })
            .collect();
        let match_name = if spec.count_mode {
            Some(Box::new(count_name(spec)))
        } else if let (VariableName::Tx, MemberSelector::Key(key)) = (spec.name, &member) {
            Some(Box::new(qualified_name("TX", Some(key))))
        } else {
            None
        };
        Self {
            member,
            match_name,
            exclusions,
        }
    }

    pub fn excludes(&self, prefix: &str, key: Option<&[u8]>) -> bool {
        self.exclusions.iter().any(|(collection, selector)| {
            collection.eq_ignore_ascii_case(prefix) && selector.matches(key)
        })
    }
}

/// Read without locking on the request path. Invalid selectors are retained
/// as absent programs so their load warning and runtime verdict agree.
#[derive(Default)]
pub(crate) struct SelectorPrograms {
    by_case: [HashMap<String, Option<Arc<Regex>>>; 2],
}

impl SelectorPrograms {
    pub(crate) fn add(&mut self, pattern: &str, collection: VariableName) -> Option<&Arc<Regex>> {
        type Pool = [HashMap<String, Weak<Regex>>; 2];
        static POOL: LazyLock<Mutex<Pool>> = LazyLock::new(Default::default);
        let case = ignore_case(collection) as usize;
        self.by_case[case]
            .entry(pattern.to_owned())
            .or_insert_with(|| {
                let mut pool = POOL.lock().unwrap_or_else(|e| e.into_inner());
                let entries = &mut pool[case];
                if let Some(live) = entries.get(pattern).and_then(Weak::upgrade) {
                    return Some(live);
                }
                entries.retain(|_, program| program.strong_count() != 0);
                let program = Arc::new(compile_selector(pattern, collection).ok()?);
                entries.insert(pattern.to_owned(), Arc::downgrade(&program));
                Some(program)
            })
            .as_ref()
    }

    pub(crate) fn get(&self, pattern: &str, collection: VariableName) -> Option<&Arc<Regex>> {
        self.by_case[ignore_case(collection) as usize]
            .get(pattern)?
            .as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_loads_share_live_programs_and_drop_the_last_owner() {
        use crate::CompiledRuleset;
        const PATTERN: &str = "^selector-lifetime$";
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    CompiledRuleset::from_string(r#"SecRule ARGS:/^selector-lifetime$/ "@streq sample" "id:21,phase:1,pass""#).unwrap()
                })
            })
            .collect();
        let loads: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let first = loads[0].selectors.get(PATTERN, VariableName::Args).unwrap();
        for load in &loads {
            assert!(Arc::ptr_eq(
                first,
                load.selectors.get(PATTERN, VariableName::Args).unwrap()
            ));
        }
        let retired = Arc::downgrade(first);
        drop(loads);
        assert!(retired.upgrade().is_none());
        let next = CompiledRuleset::from_string(
            r#"SecRule ARGS:/^selector-lifetime$/ "@streq next" "id:22,phase:1,pass""#,
        )
        .unwrap();
        assert!(next
            .selectors
            .get(PATTERN, VariableName::Args)
            .unwrap()
            .is_match(b"selector-lifetime"));
    }
}
