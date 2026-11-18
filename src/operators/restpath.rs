//! REST path templates expose named captures as path arguments.
use super::{ByteOperatorResult, Operator, OperatorResult};
use crate::{Error, Result};
use regex::bytes::Regex;

pub(super) struct RestPath {
    regex: Regex,
    members: Vec<(usize, String)>,
}

impl RestPath {
    pub(super) fn new(template: &str) -> Result<Self> {
        // Give each placeholder a unique internal group. Go accepts repeated
        // and numeric names, which Rust regex capture names cannot express.
        let mut prefix = "__restpath".to_owned();
        while template.contains(&prefix) {
            prefix.push('_');
        }
        let mut pattern = String::new();
        let mut names = Vec::new();
        let mut rest = template;
        while let Some((before, suffix)) = rest.split_once('{') {
            let Some((name, after)) = suffix.split_once('}') else {
                break;
            };
            if name.is_empty() {
                pattern.push_str(before);
                pattern.push_str(r"\{\}");
            } else {
                if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                    return Err(Error::Config {
                        message: format!("invalid @restpath parameter {name:?}"),
                    });
                }
                pattern.push_str(before);
                pattern.push_str(&format!("(?P<{prefix}{}>(?-u:[^?/]+))", names.len()));
                names.push(name);
            }
            rest = after;
        }
        pattern.push_str(rest);
        let regex =
            Regex::new(&pattern).map_err(|source| Error::RegexCompile { pattern, source })?;
        let members = regex
            .capture_names()
            .enumerate()
            .filter_map(|(index, name)| {
                let name = name?;
                let original = name
                    .strip_prefix(&prefix)
                    .and_then(|suffix| suffix.parse::<usize>().ok())
                    .map_or(name, |i| names[i]);
                Some((index, original.to_owned()))
            })
            .collect();
        Ok(Self { regex, members })
    }
}

impl Operator for RestPath {
    fn execute(&self, value: &str) -> OperatorResult {
        self.execute_bytes(value.as_bytes())
            .expect("infallible path match")
            .into_text()
    }

    fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
        Ok(ByteOperatorResult {
            matched: self.regex.is_match(value),
            ..Default::default()
        })
    }

    fn execute_with_path_arguments(
        &self,
        value: &[u8],
        write: &mut dyn FnMut(&str, &[u8]),
    ) -> Result<ByteOperatorResult> {
        let Some(captures) = self.regex.captures(value) else {
            return Ok(ByteOperatorResult::no_match());
        };
        for (index, name) in &self.members {
            write(name, captures.get(*index).map_or(&[][..], |m| m.as_bytes()));
        }
        Ok(ByteOperatorResult {
            matched: true,
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        "restpath"
    }
}
