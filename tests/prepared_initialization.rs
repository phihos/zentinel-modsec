//! The rules a ruleset starts phase 1 with usually read nothing of the
//! request: CRS opens with `SecAction`s and `SecRule &TX:x "@eq 0"` defaults.
//! What they leave behind is the same for every transaction, so the engine may
//! prepare it once. These tests pin what a transaction shows after such rules,
//! and compare three ways of running each ruleset that must agree: as loaded,
//! with the embedder having touched `TX` before phase 1, and behind a leading
//! rule that reads the request and never matches.

use std::sync::Arc;
use std::thread;
use zentinel_modsec::engine::{SetVarChange, SetVarEffect, Transaction};
use zentinel_modsec::variables::MutableCollection;
use zentinel_modsec::ModSecurity;

/// A rule that reads the request, never matches and leaves no trace.
const REQUEST_READER: &str =
    "SecRule REMOTE_ADDR \"@streq no-such-address\" \"id:999999,phase:1,pass,nolog\"\n";

/// How a transaction is started.
#[derive(Clone, Copy, Debug)]
enum Start {
    /// As an embedding application normally does.
    Plain,
    /// The embedder asked for `TX` before the first phase.
    TxTouched,
    /// With [`REQUEST_READER`] in front of the ruleset.
    BehindRequestReader,
}

/// Everything a caller can read from a transaction.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    matched_rules: Vec<String>,
    matched_data: Vec<(Option<String>, String, String, Option<String>)>,
    messages: Vec<String>,
    tx: Vec<(String, String)>,
    intervention: Option<String>,
    anomaly_score: i32,
}

fn seen(tx: &Transaction) -> Seen {
    Seen {
        matched_rules: tx.matched_rules().to_vec(),
        matched_data: tx
            .matched_data()
            .iter()
            .map(|m| {
                (
                    m.rule_id.clone(),
                    m.variable.clone(),
                    m.value.clone(),
                    m.matched_portion.clone(),
                )
            })
            .collect(),
        messages: tx.messages().iter().map(|m| format!("{m:?}")).collect(),
        tx: tx
            .tx()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        intervention: tx.intervention().map(|i| format!("{i:?}")),
        anomaly_score: tx.anomaly_score(),
    }
}

fn engine(rules: &str, start: Start) -> ModSecurity {
    let rules = match start {
        Start::BehindRequestReader => format!("{REQUEST_READER}{rules}"),
        _ => rules.to_string(),
    };
    ModSecurity::from_string(&rules).expect("rules load")
}

fn request(engine: &ModSecurity, start: Start) -> Transaction {
    let mut tx = engine.new_transaction();
    if matches!(start, Start::TxTouched) {
        let _ = tx.tx_mut();
    }
    tx.process_uri("/shop?item=7&q=tea", "GET", "HTTP/1.1")
        .unwrap();
    tx.add_request_header("Host", "shop.example").unwrap();
    tx.set_client_addr("192.0.2.7", 40000);
    tx
}

fn finish(mut tx: Transaction) -> Transaction {
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.process_logging().unwrap();
    tx
}

/// Run `rules` each way and return what the plain run shows, after checking
/// that the other two show the same.
fn run(rules: &str) -> Seen {
    let plain = seen(&finish(request(&engine(rules, Start::Plain), Start::Plain)));
    for start in [Start::TxTouched, Start::BehindRequestReader] {
        let other = seen(&finish(request(&engine(rules, start), start)));
        assert_eq!(plain, other, "{start:?} differs for:\n{rules}");
    }
    plain
}

fn pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn ids(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|id| id.to_string()).collect()
}

/// Rules after the leading ones that record what those left for them.
const OBSERVERS: &str = r#"
SecRule REQUEST_METHOD "@streq GET" "id:800,phase:1,pass,nolog,setvar:'tx.seen_var=%{MATCHED_VAR}',setvar:'tx.seen_name=%{MATCHED_VAR_NAME}'"
SecRule &MATCHED_VARS "@ge 0" "id:801,phase:1,pass,nolog,setvar:'tx.seen_count=%{MATCHED_VAR}'"
SecRule TX:1 "@rx ." "id:802,phase:2,pass,nolog,setvar:'tx.seen_capture=%{MATCHED_VAR}'"
"#;

#[test]
fn leading_rules_that_read_only_tx_leave_their_matches_messages_and_values() {
    let rules = format!(
        r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.level=2',setvar:'tx.score=5'"
SecAction "id:2,phase:1,pass,log,msg:'setup done',tag:'setup',severity:'NOTICE',setvar:'tx.score=+3'"
SecRule &TX:limit "@eq 0" "id:3,phase:1,pass,nolog,setvar:'tx.limit=10'"
SecRule &TX:level "@eq 0" "id:4,phase:1,pass,nolog,setvar:'tx.level=1'"
SecRule TX:level "@lt %{{tx.limit}}" "id:5,phase:1,pass,nolog,setvar:'tx.copy=%{{tx.level}}',setvar:'tx.Mixed_Case=x'"
SecRule TX:/^l/ "@rx ^(\d)(\d?)$" "id:6,phase:1,pass,capture,log,msg:'level %{{tx.level}}',logdata:'%{{tx.0}}',t:none,setvar:'tx.hits=+1'"
SecRule TX:score "@gt 100" "id:7,phase:1,pass,nolog,setvar:'tx.never=1'"
SecRule TX "@streq 10" "phase:1,pass,nolog,setvar:'!tx.copy'"
{OBSERVERS}"#
    );
    let seen = run(&rules);
    assert_eq!(
        seen.matched_rules,
        ids(&["1", "2", "3", "5", "6", "800", "801", "802"])
    );
    assert_eq!(
        seen.tx,
        pairs(&[
            ("level", "2"),
            ("score", "8"),
            ("limit", "10"),
            ("mixed_case", "x"),
            ("hits", "2"),
            ("0", "10"),
            ("1", "1"),
            ("2", "0"),
            ("seen_var", "GET"),
            ("seen_name", "REQUEST_METHOD"),
            ("seen_count", "1"),
            ("seen_capture", "1"),
        ])
    );
    // Rule 6 matched `level` and `limit`; the id-less rule after it matched
    // `limit`. One record per rule, on the first value it matched.
    assert_eq!(
        seen.matched_data[..4],
        [
            (Some("3".into()), "&Tx".into(), "0".into(), Some("0".into())),
            (
                Some("5".into()),
                "TX:level".into(),
                "2".into(),
                Some("2".into())
            ),
            (
                Some("6".into()),
                "TX:level".into(),
                "2".into(),
                Some("2".into())
            ),
            (None, "TX:limit".into(), "10".into(), Some("10".into())),
        ]
    );
    assert_eq!(seen.messages.len(), 2);
    assert!(seen.messages[0].contains("setup done"));
    assert!(seen.messages[1].contains("level 2"));
}

#[test]
fn the_last_leading_match_is_matched_var_for_the_rule_after_it() {
    let seen = run(r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=alpha'"
SecRule TX:a "@contains lph" "id:2,phase:1,pass,nolog"
SecRule MATCHED_VAR "@streq alpha" "id:3,phase:1,pass,nolog,setvar:'tx.name=%{MATCHED_VAR_NAME}'"
SecRule MATCHED_VARS_NAMES "@streq MATCHED_VAR" "id:4,phase:1,pass,nolog"
"#);
    assert_eq!(seen.matched_rules, ids(&["1", "2", "3", "4"]));
    assert_eq!(seen.tx, pairs(&[("a", "alpha"), ("name", "MATCHED_VAR")]));
    assert_eq!(
        seen.matched_data[0],
        (
            Some("2".into()),
            "TX:a".into(),
            "alpha".into(),
            Some("lph".into())
        )
    );
}

#[test]
fn a_phase_made_only_of_leading_rules_keeps_its_last_match_for_the_next_phase() {
    let seen = run(r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=alpha'"
SecRule TX:a "@beginsWith al" "id:2,phase:1,pass,nolog"
SecRule MATCHED_VAR "@streq alpha" "id:3,phase:2,pass,nolog"
"#);
    assert_eq!(seen.matched_rules, ids(&["1", "2", "3"]));
    assert_eq!(
        seen.matched_data,
        [
            (
                Some("2".into()),
                "TX:a".into(),
                "alpha".into(),
                Some("al".into())
            ),
            (
                Some("3".into()),
                "MATCHED_VAR".into(),
                "alpha".into(),
                Some("alpha".into())
            ),
        ]
    );
}

#[test]
fn what_the_embedder_wrote_to_tx_before_the_first_phase_is_what_the_rules_read() {
    let rules = r#"
SecRuleEngine On
SecRule &TX:level "@eq 0" "id:1,phase:1,pass,nolog,setvar:'tx.level=1'"
SecRule &TX:mode "@eq 0" "id:2,phase:1,pass,nolog,setvar:'tx.mode=strict'"
SecRule TX:level "@ge 3" "id:3,phase:1,pass,nolog,setvar:'tx.high=1'"
"#;
    for start in [Start::Plain, Start::BehindRequestReader] {
        let engine = engine(rules, start);
        let mut tx = request(&engine, start);
        tx.tx_mut().set("LEVEL".to_string(), "4".to_string());
        let seen = seen(&finish(tx));
        assert_eq!(seen.matched_rules, ids(&["2", "3"]), "{start:?}");
        assert_eq!(
            seen.tx,
            pairs(&[("level", "4"), ("mode", "strict"), ("high", "1")]),
            "{start:?}"
        );
    }
    // A value set and removed again leaves TX as it was.
    let engine = engine(rules, Start::Plain);
    let mut tx = request(&engine, Start::Plain);
    tx.tx_mut().set("level".to_string(), "4".to_string());
    tx.tx_mut().delete("level");
    let seen = seen(&finish(tx));
    assert_eq!(seen.matched_rules, ids(&["1", "2"]));
    assert_eq!(seen.tx, pairs(&[("level", "1"), ("mode", "strict")]));
}

#[test]
fn recorded_setvar_effects_list_the_leading_rules_too() {
    let rules = r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.level=2'"
SecRule &TX:limit "@eq 0" "id:2,phase:1,pass,nolog,setvar:'tx.limit=10',setvar:'tx.level=+1'"
SecRule REQUEST_METHOD "@streq GET" "id:3,phase:1,pass,nolog,setvar:'!tx.limit'"
"#;
    let effect = |rule_id: &str, key: &str, op| SetVarEffect {
        rule_id: rule_id.to_string(),
        collection: "tx".to_string(),
        key: key.to_string(),
        op,
    };
    for start in [Start::Plain, Start::TxTouched, Start::BehindRequestReader] {
        let engine = engine(rules, start);
        let mut tx = request(&engine, start);
        tx.set_record_setvar_effects(true);
        let tx = finish(tx);
        assert_eq!(
            tx.setvar_effects(),
            [
                effect("1", "level", SetVarChange::Set("2".into())),
                effect("2", "limit", SetVarChange::Set("10".into())),
                effect("2", "level", SetVarChange::Increment(1)),
                effect("3", "limit", SetVarChange::Delete),
            ],
            "{start:?}"
        );
        assert_eq!(seen(&tx).tx, pairs(&[("level", "3")]), "{start:?}");
    }
}

#[test]
fn a_leading_rule_that_intervenes_ends_the_phase_where_it_stands() {
    for (action, expected) in [
        ("deny", "status: 403"),
        ("block", "status: 403"),
        ("redirect:https://example.org/", "example.org"),
        ("drop", "drop_connection: true"),
    ] {
        let seen = run(&format!(
            r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1'"
SecRule TX:a "@eq 1" "id:2,phase:1,{action},log,msg:'stop %{{tx.a}}'"
SecAction "id:3,phase:1,pass,nolog,setvar:'tx.after=1'"
"#
        ));
        assert_eq!(seen.matched_rules, ids(&["1", "2"]), "{action}");
        assert_eq!(seen.tx, pairs(&[("a", "1")]), "{action}");
        let intervention = seen.intervention.expect("the rule intervenes");
        assert!(intervention.contains(expected), "{action}: {intervention}");
        assert!(intervention.contains("stop 1"), "{action}: {intervention}");
    }

    let allowed = run(r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1'"
SecRule TX:a "@eq 1" "id:2,phase:1,allow,nolog"
SecAction "id:3,phase:1,pass,nolog,setvar:'tx.after=1'"
SecRule REQUEST_METHOD "@streq GET" "id:4,phase:2,deny"
"#);
    assert_eq!(allowed.matched_rules, ids(&["1", "2"]));
    assert_eq!(allowed.intervention, None);
}

#[test]
fn a_leading_rule_that_does_not_match_does_nothing() {
    // CRS 901001 denies when its setup was not loaded, and otherwise sits
    // unmatched among the rules that set the defaults.
    let rules = r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.setup=1'"
SecRule &TX:setup "@eq 0" "id:2,phase:1,deny,log,msg:'no setup at %{REQUEST_URI}'"
SecRule TX:setup "@eq 2" "id:3,phase:1,pass,nolog,skipAfter:END,ctl:ruleEngine=Off,setvar:'tx.m=%{REQUEST_METHOD}'"
SecRule TX:missing "!@eq 1" "id:4,phase:1,allow,nolog"
SecAction "id:5,phase:1,pass,nolog,setvar:'tx.after=1'"
SecMarker "END"
SecRule REQUEST_METHOD "@streq GET" "id:6,phase:1,pass,nolog"
"#;
    let unmatched = run(rules);
    assert_eq!(unmatched.matched_rules, ids(&["1", "5", "6"]));
    assert_eq!(unmatched.tx, pairs(&[("setup", "1"), ("after", "1")]));
    assert_eq!(unmatched.intervention, None);

    // With a value from the embedder the same rules match.
    for start in [Start::Plain, Start::BehindRequestReader] {
        let engine = engine(rules, start);
        let mut tx = request(&engine, start);
        tx.tx_mut().set("missing".to_string(), "0".to_string());
        let seen = seen(&finish(tx));
        assert_eq!(seen.matched_rules, ids(&["1", "4"]), "{start:?}");
        assert_eq!(
            seen.tx,
            pairs(&[("missing", "0"), ("setup", "1")]),
            "{start:?}"
        );
    }
}

#[test]
fn a_leading_deny_only_detects_in_detection_only_mode_and_takes_the_default_status() {
    let detecting = run(r#"
SecRuleEngine DetectionOnly
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1'"
SecRule TX:a "@eq 1" "id:2,phase:1,deny,nolog"
SecAction "id:3,phase:1,pass,nolog,setvar:'tx.after=1'"
"#);
    assert_eq!(detecting.matched_rules, ids(&["1", "2", "3"]));
    assert_eq!(detecting.intervention, None);
    assert_eq!(detecting.tx, pairs(&[("a", "1"), ("after", "1")]));

    let rules = r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1'"
SecRule TX:a "@eq 1" "id:2,phase:1,block,nolog"
"#;
    for start in [Start::Plain, Start::TxTouched, Start::BehindRequestReader] {
        for status in [403, 429] {
            let mut engine = engine(rules, start);
            engine.set_default_status(status);
            let tx = finish(request(&engine, start));
            assert_eq!(
                tx.intervention().map(|i| i.status),
                Some(status),
                "{start:?}"
            );
        }
    }
}

#[test]
fn an_engine_that_is_off_runs_no_leading_rule() {
    let seen = run(r#"
SecRuleEngine Off
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1'"
SecRule TX:a "@eq 1" "id:2,phase:1,deny"
"#);
    assert_eq!(seen.matched_rules, ids(&[]));
    assert_eq!(seen.tx, pairs(&[]));
    assert_eq!(seen.intervention, None);
}

#[test]
fn a_leading_ctl_takes_effect_on_the_rules_after_it() {
    let removed = run(r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1'"
SecAction "id:2,phase:1,pass,nolog,ctl:ruleRemoveById=4,ctl:ruleRemoveByTag=noisy"
SecAction "id:3,phase:1,pass,nolog,setvar:'tx.b=1'"
SecAction "id:4,phase:1,pass,nolog,setvar:'tx.c=1'"
SecAction "id:5,phase:1,pass,nolog,tag:'noisy',setvar:'tx.d=1'"
SecRule ARGS "@rx ." "id:6,phase:2,pass,nolog,tag:'noisy'"
"#);
    assert_eq!(removed.matched_rules, ids(&["1", "2", "3"]));
    assert_eq!(removed.tx, pairs(&[("a", "1"), ("b", "1")]));

    let off = run(r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1'"
SecRule TX:a "@eq 1" "id:2,phase:1,pass,nolog,ctl:ruleEngine=Off"
SecAction "id:3,phase:1,pass,nolog,setvar:'tx.b=1'"
"#);
    assert_eq!(off.matched_rules, ids(&["1", "2"]));
    assert_eq!(off.tx, pairs(&[("a", "1")]));

    let detecting = run(r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"
SecAction "id:2,phase:1,deny,nolog"
SecRule &TX:a "@eq 0" "id:3,phase:1,pass,nolog,ctl:ruleRemoveTargetById=4;ARGS:item"
SecRule ARGS "@rx ^\d$" "id:4,phase:2,pass,nolog"
"#);
    assert_eq!(detecting.matched_rules, ids(&["1", "2", "3"]));
    assert_eq!(detecting.intervention, None);
}

#[test]
fn a_leading_skip_or_skip_after_jumps_as_it_does_anywhere() {
    let seen = run(r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,skip:1,setvar:'tx.a=1'"
SecAction "id:2,phase:1,pass,nolog,setvar:'tx.skipped=1'"
SecRule TX:a "@eq 1" "id:3,phase:1,pass,nolog,skipAfter:END-SETUP"
SecAction "id:4,phase:1,pass,nolog,setvar:'tx.skipped=2'"
SecMarker "END-SETUP"
SecAction "id:5,phase:1,pass,nolog,setvar:'tx.b=1'"
SecRule TX:b "@eq 1" "id:6,phase:1,pass,nolog,skipAfter:NO-SUCH-MARKER"
SecAction "id:7,phase:1,pass,nolog,setvar:'tx.skipped=3'"
SecAction "id:8,phase:2,pass,nolog,setvar:'tx.c=1'"
"#);
    assert_eq!(seen.matched_rules, ids(&["1", "3", "5", "6", "8"]));
    assert_eq!(seen.tx, pairs(&[("a", "1"), ("b", "1"), ("c", "1")]));

    // A jump from behind the leading rules to a marker among them does not go back.
    let backwards = run(r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1'"
SecMarker "EARLY"
SecAction "id:2,phase:1,pass,nolog,setvar:'tx.b=1'"
SecRule REQUEST_METHOD "@streq GET" "id:3,phase:1,pass,nolog,skipAfter:EARLY"
SecAction "id:4,phase:1,pass,nolog,setvar:'tx.c=1'"
"#);
    assert_eq!(backwards.matched_rules, ids(&["1", "2", "3"]));
}

#[test]
fn a_leading_chain_matches_or_fails_as_a_whole() {
    let seen = run(r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1',setvar:'tx.b=2'"
SecRule TX:a "@eq 1" "id:2,phase:1,pass,nolog,chain,setvar:'tx.link=1'"
    SecRule TX:b "@eq 2" "setvar:'tx.chain=done'"
SecRule TX:a "@eq 1" "id:3,phase:1,pass,nolog,chain,setvar:'tx.half=1'"
    SecRule TX:b "@eq 9" "setvar:'tx.never=1'"
SecAction "id:4,phase:1,pass,nolog,setvar:'tx.after=1'"
"#);
    assert_eq!(seen.matched_rules, ids(&["1", "2", "4"]));
    assert_eq!(
        seen.tx,
        pairs(&[
            ("a", "1"),
            ("b", "2"),
            ("link", "1"),
            ("chain", "done"),
            ("half", "1"),
            ("after", "1"),
        ])
    );
    assert_eq!(seen.matched_data.len(), 2);
}

#[test]
fn a_leading_rule_that_reads_the_request_sees_this_request() {
    let seen = run(r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.method=%{REQUEST_METHOD}',setvar:'tx.host=%{request_headers.host}'"
SecAction "id:2,phase:1,pass,nolog,setvar:'tx.arg=%{ARGS.item}',setvar:'tx.addr=%{remote_addr}'"
SecAction "id:3,phase:1,pass,nolog,setvar:'tx.key_%{REQUEST_METHOD}=1',setvar:'tx.id=%{unique_id}',setvar:'!tx.id'"
SecRule TX:method "@streq %{REQUEST_METHOD}" "id:4,phase:1,pass,nolog"
SecRule TX:host "@streq %{request_headers.host}" "id:5,phase:1,pass,nolog"
SecRule TX:arg "@within %{ARGS.item} 8 9" "id:6,phase:1,pass,nolog"
SecRule TX:method|REQUEST_URI "@contains shop" "id:7,phase:1,pass,nolog"
SecRule TX:method "@streq GET" "id:8,phase:1,pass,log,msg:'on %{REQUEST_URI}',logdata:'%{MATCHED_VAR} via %{tx.host}'"
SecRule TX:method "@streq %{MATCHED_VAR}" "id:9,phase:1,pass,nolog,setvar:'tx.last=%{MATCHED_VAR_NAME}'"
"#);
    assert_eq!(
        seen.matched_rules,
        ids(&["1", "2", "3", "4", "5", "6", "7", "8", "9"])
    );
    assert_eq!(
        seen.tx,
        pairs(&[
            ("method", "GET"),
            ("host", "shop.example"),
            ("arg", "7"),
            ("addr", "192.0.2.7"),
            ("key_get", "1"),
            ("last", "TX:method"),
        ])
    );
    assert!(seen.messages[0].contains("on /shop?item=7&q=tea"));
    assert!(seen.messages[0].contains("GET via shop.example"));
}

#[test]
fn a_leading_rule_with_an_excluded_or_unusual_target_is_evaluated_as_written() {
    let seen = run(r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=x1',setvar:'tx.b=x2',setvar:'tx.sql=1 or 1=1'"
SecRule TX|!TX:a|!TX:sql "@beginsWith x" "id:2,phase:1,pass,nolog,setvar:'tx.kept=%{MATCHED_VAR_NAME}'"
SecRule &TX|!TX:a "@eq 3" "id:3,phase:1,pass,nolog"
SecRule TX:sql "@detectSQLi" "id:4,phase:1,pass,nolog"
SecRule TX:a "@rx ^X1$" "id:5,phase:1,pass,nolog,t:uppercase,multiMatch"
SecRule TX:/^[ab]$/ "!@streq x1" "id:6,phase:1,pass,nolog"
SecRule &TX:/^[ab]$/ "@eq 2" "id:7,phase:1,pass,nolog"
"#);
    assert_eq!(
        seen.matched_rules,
        ids(&["1", "2", "3", "4", "5", "6", "7"])
    );
    assert_eq!(
        seen.tx,
        pairs(&[
            ("a", "x1"),
            ("b", "x2"),
            ("sql", "1 or 1=1"),
            ("kept", "TX:b")
        ])
    );
}

#[test]
fn static_removals_and_target_updates_apply_to_leading_rules() {
    let seen = run(r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1'"
SecAction "id:2,phase:1,pass,nolog,setvar:'tx.b=1'"
SecAction "id:3,phase:1,pass,nolog,tag:'optional',setvar:'tx.c=1'"
SecRule TX:a "@eq 7" "id:4,phase:1,pass,nolog,setvar:'tx.d=%{MATCHED_VAR_NAME}'"
SecRule TX:a|TX:b "@eq 1" "id:5,phase:1,pass,nolog,setvar:'tx.e=%{MATCHED_VAR_NAME}'"
SecAction "id:6,phase:1,pass,nolog,setvar:'tx.f=1'"
SecRuleRemoveById 2
SecRuleRemoveByTag "optional"
SecRuleUpdateTargetById 4 "ARGS:item"
SecRuleUpdateTargetById 5 "!TX:b"
"#);
    assert_eq!(seen.matched_rules, ids(&["1", "4", "5", "6"]));
    assert_eq!(
        seen.tx,
        pairs(&[("a", "1"), ("d", "ARGS:item"), ("e", "TX:a"), ("f", "1")])
    );
}

#[test]
fn only_the_first_phase_starts_from_an_empty_tx() {
    let seen = run(r#"
SecRuleEngine On
SecRule &TX:a "@eq 0" "id:20,phase:2,pass,nolog,setvar:'tx.late=1'"
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=1'"
SecAction "id:21,phase:2,pass,nolog,setvar:'tx.a=+1'"
SecRule TX:a "@eq 1" "id:2,phase:1,pass,nolog,setvar:'tx.b=1'"
SecAction "id:50,phase:5,pass,nolog,setvar:'tx.a=+10'"
SecAction "id:3,pass,nolog,setvar:'tx.default_phase=1'"
"#);
    assert_eq!(seen.matched_rules, ids(&["1", "2", "21", "3", "50"]));
    assert_eq!(
        seen.tx,
        pairs(&[("a", "12"), ("b", "1"), ("default_phase", "1")])
    );
}

#[test]
fn running_a_phase_twice_or_out_of_order_runs_its_rules_on_what_is_there() {
    let rules = r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.a=+1'"
SecRule &TX:b "@eq 0" "id:2,phase:1,pass,nolog,setvar:'tx.b=1'"
SecAction "id:3,phase:2,pass,nolog,setvar:'tx.a=+10'"
"#;
    for start in [Start::Plain, Start::TxTouched, Start::BehindRequestReader] {
        let engine = engine(rules, start);

        let mut twice = request(&engine, start);
        twice.process_request_headers().unwrap();
        twice.process_request_headers().unwrap();
        let twice = seen(&twice);
        assert_eq!(twice.matched_rules, ids(&["1", "2", "1"]), "{start:?}");
        assert_eq!(twice.tx, pairs(&[("a", "2"), ("b", "1")]), "{start:?}");

        let mut body_first = request(&engine, start);
        body_first.process_request_body().unwrap();
        body_first.process_request_headers().unwrap();
        let body_first = seen(&body_first);
        assert_eq!(body_first.matched_rules, ids(&["3", "1", "2"]), "{start:?}");
        assert_eq!(
            body_first.tx,
            pairs(&[("a", "11"), ("b", "1")]),
            "{start:?}"
        );
    }
}

#[test]
fn every_transaction_of_one_ruleset_starts_from_the_same_state() {
    let rules = r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,log,msg:'setup',setvar:'tx.score=0',setvar:'tx.list=a',setvar:'tx.temp=1'"
SecRule &TX:limit "@eq 0" "id:2,phase:1,pass,nolog,setvar:'tx.limit=3'"
SecRule TX:list "@rx ^(a)$" "id:3,phase:1,pass,nolog,capture"
SecRule ARGS:n "@rx ^(\d+)$" "id:4,phase:1,pass,nolog,capture,setvar:'tx.score=+%{tx.1}',setvar:'tx.list=%{tx.list},%{tx.1}',setvar:'!tx.temp'"
SecRule TX:score "@ge %{tx.limit}" "id:5,phase:2,deny,nolog"
"#;
    let engine = Arc::new(engine(rules, Start::Plain));
    let reference = Arc::new(engine_reference(rules));
    let expect = |n: usize| {
        let run = |engine: &ModSecurity, start| {
            let mut tx = engine.new_transaction();
            if matches!(start, Start::TxTouched) {
                let _ = tx.tx_mut();
            }
            tx.process_uri(&format!("/?n={n}"), "GET", "HTTP/1.1")
                .unwrap();
            seen(&finish(tx))
        };
        let plain = run(&engine, Start::Plain);
        assert_eq!(plain, run(&engine, Start::TxTouched), "n={n}");
        assert_eq!(plain, run(&reference, Start::BehindRequestReader), "n={n}");
        assert_eq!(
            plain.tx[..2],
            pairs(&[("score", &n.to_string()), ("list", &format!("a,{n}"))]),
            "n={n}"
        );
        assert_eq!(plain.messages.len(), 1, "n={n}: {:?}", plain.messages);
        plain
    };
    // One after the other: what a transaction did to TX does not reach the next.
    let first = expect(1);
    assert_eq!(first.matched_rules, ids(&["1", "2", "3", "4"]));
    assert_eq!(first.intervention, None);
    assert!(expect(7).intervention.is_some());
    assert_eq!(expect(1), first);

    let workers: Vec<_> = (0..8)
        .map(|worker| {
            let engine = Arc::clone(&engine);
            thread::spawn(move || {
                (0..50)
                    .map(|i| {
                        let n = worker * 50 + i;
                        let mut tx = engine.new_transaction();
                        tx.process_uri(&format!("/?n={n}"), "GET", "HTTP/1.1")
                            .unwrap();
                        (n, seen(&finish(tx)))
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    for worker in workers {
        for (n, seen) in worker.join().unwrap() {
            assert_eq!(
                seen.tx[..2],
                pairs(&[("score", &n.to_string()), ("list", &format!("a,{n}"))])
            );
            assert_eq!(seen.intervention.is_some(), n >= 3, "n={n}");
        }
    }
}

fn engine_reference(rules: &str) -> ModSecurity {
    engine(rules, Start::BehindRequestReader)
}
