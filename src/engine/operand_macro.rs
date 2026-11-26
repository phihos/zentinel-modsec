//! `%{...}` macros in operator arguments and `setvar` operands.
//!
//! What a macro may name is decided here and nowhere else: the transaction
//! expands with [`expand`], and the ruleset asks [`unresolvable`] at load time
//! which macros that expansion cannot give the value libmodsecurity would.

use once_cell::sync::Lazy;
use regex::Regex;
use std::borrow::Cow;

static PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"%\{([^}]+)\}").expect("static macro regex is valid"));

/// A macro the engine can resolve against a transaction.
pub(super) enum OperandMacro<'a> {
    /// `%{MATCHED_VAR}`.
    MatchedVar,
    /// `%{MATCHED_VAR_NAME}`.
    MatchedVarName,
    /// `%{tx.<name>}`.
    Tx(&'a str),
    /// A bare `%{<name>}`: the variable of that name, as libmodsecurity reads
    /// it (`%{REQUEST_METHOD}`), or else `tx.<name>`. A numeric operator with
    /// a bare name that is no variable is left unable to match at load
    /// ([`unresolvable`]): libmodsecurity would read a variable there, never
    /// `tx.<name>`.
    Bare(&'a str),
    /// `%{request_headers.<name>}` (CRS 943110: `!@endsWith
    /// %{request_headers.host}`).
    RequestHeader(&'a str),
    /// `%{<collection>.<key>}` of any other collection the engine resolves: that
    /// member, as libmodsecurity expands any variable (CRS 920650:
    /// `%{ARGS._method}`).
    Member(&'a str, &'a str),
}

impl<'a> OperandMacro<'a> {
    /// Classify the text between `%{` and `}`, or `None` if it names a
    /// collection the engine does not resolve.
    fn parse(inner: &'a str) -> Option<Self> {
        if inner.eq_ignore_ascii_case("matched_var") {
            return Some(Self::MatchedVar);
        }
        if inner.eq_ignore_ascii_case("matched_var_name") {
            return Some(Self::MatchedVarName);
        }
        let Some((collection, name)) = inner.split_once('.') else {
            return Some(Self::Bare(inner));
        };
        if collection.eq_ignore_ascii_case("tx") {
            Some(Self::Tx(name))
        } else if collection.eq_ignore_ascii_case("request_headers") {
            Some(Self::RequestHeader(name))
        } else {
            resolved(collection).then_some(Self::Member(collection, name))
        }
    }
}

/// Whether `name` is a variable the engine resolves.
fn resolved(name: &str) -> bool {
    crate::parser::VariableName::from_str(&name.to_ascii_uppercase())
        .is_some_and(|v| v.is_implemented())
}

/// Replace every macro in `arg` with what `resolve` returns for it. A macro
/// the engine does not resolve becomes an empty string.
pub(super) fn expand<'a>(
    arg: &'a str,
    resolve: impl Fn(OperandMacro<'_>) -> Cow<'a, str>,
) -> Cow<'a, str> {
    let mut rest = arg;
    let mut copied = 0;
    let mut expanded = String::new();
    while let Some(start) = rest.find("%{") {
        let body = &rest[start + 2..];
        let Some(end) = body.find('}') else { break };
        if end == 0 {
            rest = &body[1..];
            continue;
        }
        let from = arg.len() - rest.len() + start;
        rest = &body[end + 1..];
        let value = OperandMacro::parse(&body[..end])
            .map(&resolve)
            .unwrap_or_default();
        if from == 0 && rest.is_empty() {
            return value;
        }
        if copied == 0 {
            expanded.reserve(arg.len());
        }
        expanded.push_str(&arg[copied..from]);
        expanded.push_str(&value);
        copied = arg.len() - rest.len();
    }
    if copied == 0 {
        return Cow::Borrowed(arg);
    }
    expanded.push_str(&arg[copied..]);
    Cow::Owned(expanded)
}

/// Whether every macro in `text` is a `%{tx.<name>}`, so that [`expand`]
/// reads nothing but TX for it.
pub(super) fn reads_only_tx(text: &str) -> bool {
    PATTERN.captures_iter(text).all(|caps| {
        let (_, [inner]) = caps.extract();
        matches!(OperandMacro::parse(inner), Some(OperandMacro::Tx(_)))
    })
}

/// The macros in `arg` whose value in libmodsecurity [`expand`] cannot
/// produce, as written: one on a collection it leaves empty
/// (`%{env.MAX_LEN}`), or a bare name that is no variable it resolves.
pub(super) fn unresolvable(arg: &str) -> impl Iterator<Item = &str> {
    PATTERN.captures_iter(arg).filter_map(|caps| {
        let (written, [inner]) = caps.extract();
        match OperandMacro::parse(inner) {
            None => Some(written),
            Some(OperandMacro::Bare(name)) => (!resolved(name)).then_some(written),
            Some(_) => None,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Captures;

    fn resolve(operand: OperandMacro) -> String {
        match operand {
            OperandMacro::MatchedVar => "<mv>".to_string(),
            OperandMacro::MatchedVarName => "<mvn>".to_string(),
            OperandMacro::Tx(name) => format!("<tx:{name}>"),
            OperandMacro::Bare(name) => format!("<bare:{name}>"),
            OperandMacro::RequestHeader(name) => format!("<h:{name}>"),
            OperandMacro::Member(collection, name) => format!("<{collection}:{name}>"),
        }
    }

    #[test]
    fn whole_macros_can_borrow_and_interpolated_macros_keep_literal_text() {
        fn resolve(_: OperandMacro<'_>) -> Cow<'static, str> {
            Cow::Borrowed("book")
        }
        assert!(matches!(
            expand("%{tx.item}", resolve),
            Cow::Borrowed("book")
        ));
        assert_eq!(
            expand("%{}-%{tx.item}-%{tx.item}", resolve),
            "%{}-book-book"
        );
        assert_eq!(expand("%{}-%{unfinished", resolve), "%{}-%{unfinished");
    }

    /// `expand` replaces exactly what `PATTERN` matches.
    #[test]
    fn expand_replaces_what_the_macro_pattern_matches() {
        for arg in [
            "",
            "plain",
            "%{tx.a}",
            "%{REMOTE_PORT}",
            "x%{tx.a}y%{MATCHED_VAR}z",
            "%{request_headers.host}%{matched_var_name}",
            "%{env.x} and %{tx.b}",
            "%{}",
            "%{}%{tx.a}",
            "%{}}%{tx.a}",
            "%{%{tx.a}",
            "%{tx.a",
            "%{tx.a}%{",
            "%%{tx.a}}",
            "100%",
            "%{a\nb}",
            "%{tx.é}é%{}",
        ] {
            let reference = PATTERN.replace_all(arg, |caps: &Captures| {
                OperandMacro::parse(&caps[1])
                    .map(resolve)
                    .unwrap_or_default()
            });
            assert_eq!(
                expand(arg, |operand| resolve(operand).into()),
                reference,
                "argument {arg:?}"
            );
        }
    }
}
