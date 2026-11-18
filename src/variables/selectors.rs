//! Byte selector programs owned by a live ruleset.
use super::{folded_key, qualified_name, ByteValue};
use crate::parser::{Selection, VariableName, VariableSpec};
use regex::bytes::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};

/// Count variables retain the selector as their match key, including regex
/// delimiters. The reference preserves argument selector case and folds the
/// selector of other collections.
pub(crate) fn count_name(spec: &VariableSpec) -> ByteValue {
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
