use zentinel_modsec::variables::Collection;
use zentinel_modsec::ModSecurity;

#[test]
fn invalid_body_limits_and_actions_fail_loading() {
    for directive in [
        "SecRequestBodyLimit 0",
        "SecRequestBodyLimit -1",
        "SecRequestBodyLimit 1073741825",
        "SecResponseBodyLimit 0",
        "SecResponseBodyLimit 1073741825",
        "SecRequestBodyLimitAction Ignore",
        "SecResponseBodyLimitAction Ignore",
        "SecResponseBodyMimeTypesClear text/plain",
    ] {
        assert!(ModSecurity::from_string(directive).is_err(), "{directive}");
    }
}

#[test]
fn body_access_defaults_off_without_disabling_query_rules() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule ARGS_POST:x "@contains attack" "id:1,phase:2,pass"
SecRule RESPONSE_BODY "@contains attack" "id:2,phase:4,pass"
SecRule ARGS_GET:x "@contains attack" "id:3,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?x=attack", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"x=attack").unwrap();
    tx.process_request_body().unwrap();
    tx.add_response_header("Content-Type", "text/plain")
        .unwrap();
    tx.process_response_headers_with_status(200, "HTTP/1.1")
        .unwrap();
    tx.append_response_body(b"attack").unwrap();
    tx.process_response_body().unwrap();
    assert_eq!(tx.matched_rules(), ["3"]);
}

#[test]
fn request_rejects_the_exact_limit_without_running_phase_two() {
    let engine = ModSecurity::from_string(
        r#"SecRequestBodyAccess On
SecRequestBodyLimit 4
SecRequestBodyLimitAction Reject
SecAction "id:1,phase:2,pass,setvar:tx.runs=+1""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"abcd").unwrap();
    assert_eq!(tx.intervention().map(|it| it.status), Some(413));
    tx.process_request_body().unwrap();
    assert_eq!(tx.tx().get("runs"), None);
}

#[test]
fn request_partial_retains_only_the_prefix_and_runs_phase_two_once() {
    let engine = ModSecurity::from_string(
        r#"SecRequestBodyAccess On
SecRequestBodyLimit 8
SecRequestBodyLimitAction ProcessPartial
SecRule ARGS_POST:x "@streq attack" "id:1,phase:2,pass,setvar:tx.runs=+1""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"x=attackTAIL").unwrap();
    tx.process_request_body().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1"]);
    assert_eq!(tx.tx().get("runs"), Some(vec!["1"]));
}

#[test]
fn response_reject_uses_status_500() {
    let engine = ModSecurity::from_string(
        r#"SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecResponseBodyLimit 4
SecResponseBodyLimitAction Reject"#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.add_response_header("Content-Type", "text/plain")
        .unwrap();
    tx.process_response_headers_with_status(200, "HTTP/1.1")
        .unwrap();
    tx.append_response_body(b"abcd").unwrap();
    assert_eq!(tx.intervention().map(|it| it.status), Some(500));
}

#[test]
fn an_early_body_call_cannot_run_phase_two_before_headers_or_twice() {
    let engine = ModSecurity::from_string(
        r#"SecRequestBodyAccess On
SecAction "id:1,phase:1,pass,setvar:tx.header=1"
SecAction "id:2,phase:2,pass,setvar:tx.runs=+1,setvar:tx.saw_header=%{tx.header}""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.append_request_body(b"x=attack").unwrap();
    tx.process_request_body().unwrap();
    assert!(tx.matched_rules().is_empty());
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    assert_eq!(tx.tx().get("runs"), Some(vec!["1"]));
    assert_eq!(tx.tx().get("saw_header"), Some(vec!["1"]));
}

#[test]
fn detection_only_from_config_or_ctl_never_rejects_a_body_limit() {
    for mode in [
        "SecRuleEngine DetectionOnly",
        "SecRuleEngine On\nSecAction \"id:9,phase:1,pass,ctl:ruleEngine=DetectionOnly\"",
    ] {
        let engine = ModSecurity::from_string(&format!(
            r#"{mode}
SecRequestBodyAccess On
SecRequestBodyLimit 4
SecRequestBodyLimitAction Reject
SecRule INBOUND_DATA_ERROR "@streq 1" "id:1,phase:2,pass,setvar:tx.runs=+1""#
        ))
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let written = tx.write_request_body(b"abcdef").unwrap();
        assert_eq!(written.consumed, 4);
        assert!(written.limit_reached && written.inspection_complete);
        assert!(tx.intervention().is_none());
        tx.process_request_body().unwrap();
        assert_eq!(tx.tx().get("runs"), Some(vec!["1"]));
    }
}

#[test]
fn a_preheader_limit_prefix_is_provisional_until_ctl_policy_runs() {
    for (control, retained, rejected) in [
        ("ctl:ruleEngine=DetectionOnly", 4, false),
        ("ctl:requestBodyAccess=Off", 0, false),
        ("pass", 0, true),
    ] {
        let engine = ModSecurity::from_string(&format!(
            r#"SecRequestBodyAccess On
SecRequestBodyLimit 4
SecRequestBodyLimitAction Reject
SecAction "id:9,phase:1,pass,{control}"
SecRule INBOUND_DATA_ERROR "@streq 1" "id:1,phase:2,pass,setvar:tx.runs=+1""#
        ))
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        let written = tx.write_request_body(b"abcdef").unwrap();
        assert_eq!(written.consumed, 4);
        assert!(written.pending_headers && written.limit_reached);
        assert!(!written.inspection_complete);
        assert!(tx.intervention().is_none());
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.request_body_buffered_len(), retained);
        assert_eq!(tx.intervention().is_some(), rejected);
    }
}

#[test]
fn streaming_reports_prefix_counts_and_never_processes_the_tail_again() {
    let engine = ModSecurity::from_string(
        r#"SecRequestBodyAccess On
SecRequestBodyLimit 4
SecRequestBodyLimitAction ProcessPartial
SecAction "id:1,phase:2,pass,setvar:tx.runs=+1""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.write_request_body(b"ab").unwrap().consumed, 2);
    let full = tx.write_request_body(b"cdef").unwrap();
    assert_eq!(full.consumed, 2);
    assert!(full.inspection_complete && full.limit_reached);
    assert_eq!(tx.write_request_body(b"tail").unwrap().consumed, 0);
    tx.process_request_body().unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.request_body_buffered_len(), 4);
    assert_eq!(tx.tx().get("runs"), Some(vec!["1"]));
}

#[test]
fn response_access_and_mime_replacement_control_visible_body_bytes() {
    for (policy, content_type, matches) in [
        ("", "text/plain", false),
        (
            "SecResponseBodyMimeType text/plain",
            "text/plain; charset=utf-8",
            true,
        ),
        (
            "SecResponseBodyMimeType text/plain\nSecResponseBodyMimeType text/html",
            "text/plain",
            false,
        ),
        (
            "SecResponseBodyMimeType text/plain\nSecResponseBodyMimeTypesClear",
            "text/plain",
            false,
        ),
    ] {
        let engine = ModSecurity::from_string(&format!(
            r#"SecRuleEngine DetectionOnly
SecResponseBodyAccess On
{policy}
SecRule RESPONSE_BODY "@streq attack" "id:1,phase:4,pass""#
        ))
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        tx.add_response_header("Content-Type", content_type)
            .unwrap();
        tx.process_response_headers_with_status(200, "HTTP/1.1")
            .unwrap();
        tx.append_response_body(b"attack").unwrap();
        tx.process_response_body().unwrap();
        tx.process_response_body().unwrap();
        assert_eq!(tx.matched_rules().iter().any(|id| id == "1"), matches);
    }
}

#[test]
fn response_partial_observes_outbound_error_and_phase_four_once() {
    let engine = ModSecurity::from_string(
        r#"SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecResponseBodyLimit 4
SecResponseBodyLimitAction ProcessPartial
SecRule RESPONSE_BODY "@streq evil" "id:1,phase:4,pass,setvar:tx.runs=+1"
SecRule OUTBOUND_DATA_ERROR "@streq 1" "id:2,phase:4,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.add_response_header("Content-Type", "text/plain")
        .unwrap();
    tx.process_response_headers_with_status(200, "HTTP/1.1")
        .unwrap();
    assert_eq!(tx.write_response_body(b"evilTAIL").unwrap().consumed, 4);
    assert_eq!(tx.write_response_body(b"tail").unwrap().consumed, 0);
    tx.process_response_body().unwrap();
    assert_eq!(tx.tx().get("runs"), Some(vec!["1"]));
    assert_eq!(tx.matched_rules(), ["1", "2"]);
}

#[test]
fn late_writes_after_an_explicit_body_end_fail_visibly() {
    let engine = ModSecurity::from_string("SecRequestBodyAccess On").unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"small").unwrap();
    tx.process_request_body().unwrap();
    assert!(matches!(
        tx.write_request_body(b"late"),
        Err(zentinel_modsec::Error::BodyAlreadyProcessed { .. })
    ));
    assert_eq!(tx.write_request_body(b"").unwrap().consumed, 0);
}

#[test]
fn request_and_response_ctl_access_overrides_are_transaction_local() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecResponseBodyMimeType text/plain
SecRule ARGS_GET:inspect "@streq yes" "id:9,phase:1,pass,ctl:requestBodyAccess=On"
SecRule RESPONSE_HEADERS:X-Inspect "@streq yes" "id:8,phase:3,pass,ctl:responseBodyAccess=On"
SecRule ARGS_POST:x "@streq attack" "id:1,phase:2,pass"
SecRule RESPONSE_BODY "@streq attack" "id:2,phase:4,pass""#,
    )
    .unwrap();
    for (inspect, consumed) in [("yes", 8), ("no", 0)] {
        let mut tx = engine.new_transaction();
        tx.process_uri(&format!("/?inspect={inspect}"), "POST", "HTTP/1.1")
            .unwrap();
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
            .unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(
            tx.write_request_body(b"x=attack").unwrap().consumed,
            consumed
        );
        tx.process_request_body().unwrap();
        tx.add_response_header("Content-Type", "text/plain")
            .unwrap();
        tx.add_response_header("X-Inspect", inspect).unwrap();
        tx.process_response_headers_with_status(200, "HTTP/1.1")
            .unwrap();
        assert_eq!(
            tx.write_response_body(b"attack").unwrap().consumed,
            if inspect == "yes" { 6 } else { 0 }
        );
        tx.process_response_body().unwrap();
        for id in ["1", "2"] {
            assert_eq!(
                tx.matched_rules().iter().any(|actual| actual == id),
                inspect == "yes"
            );
        }
    }
}

#[test]
fn duplicate_response_headers_do_not_rerun_or_replace_the_phase_metadata() {
    let engine = ModSecurity::from_string(
        r#"SecAction "id:1,phase:3,pass,setvar:tx.headers=+1"
SecRule RESPONSE_STATUS "@eq 200" "id:2,phase:4,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.process_response_headers_with_status(200, "HTTP/1.1")
        .unwrap();
    tx.process_response_headers_with_status(403, "HTTP/2.0")
        .unwrap();
    tx.process_response_body().unwrap();
    assert_eq!(tx.tx().get("headers"), Some(vec!["1"]));
    assert_eq!(tx.matched_rules(), ["1", "2"]);
}

#[test]
fn a_failed_body_callback_does_not_turn_into_success_on_retry() {
    let engine = ModSecurity::from_string(
        r#"SecRequestBodyAccess On
SecAction "id:1,phase:2,pass,setvar:tx.runs=+1"
SecRule ARGS_POST:x "@rx %{ARGS.pattern}" "id:2,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"x=value&pattern=%28").unwrap();
    assert!(tx.process_request_body().is_err());
    assert!(tx.process_request_body().is_err());
    assert_eq!(tx.tx().get("runs"), Some(vec!["1"]));
}

#[test]
fn all_header_and_body_callback_failures_remain_visible_without_replay() {
    for phase in 1..=4 {
        let engine = ModSecurity::from_string(&format!(
            r#"SecAction "id:1,phase:{phase},pass,setvar:tx.runs=+1"
SecRule ARGS_GET:x "@rx %{{ARGS_GET.pattern}}" "id:2,phase:{phase},pass""#
        ))
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/?x=value&pattern=%28", "GET", "HTTP/1.1")
            .unwrap();
        if phase > 1 {
            tx.process_request_headers().unwrap();
        }
        if phase > 2 {
            tx.process_request_body().unwrap();
        }
        if phase > 3 {
            tx.process_response_headers().unwrap();
        }
        for _ in 0..2 {
            let result = match phase {
                1 => tx.process_request_headers(),
                2 => tx.process_request_body(),
                3 => tx.process_response_headers(),
                _ => tx.process_response_body(),
            };
            assert!(result.is_err(), "phase {phase}");
        }
        if phase <= 2 {
            assert!(tx.write_request_body(b"late").is_err());
        } else {
            assert!(tx.write_response_body(b"late").is_err());
            assert!(tx
                .process_response_headers_with_status(200, "HTTP/1.1")
                .is_err());
        }
        assert_eq!(tx.tx().get("runs"), Some(vec!["1"]));
    }
}

#[test]
fn local_limits_are_selected_per_direction_per_request_and_per_phase() {
    let engine = ModSecurity::from_string(r#"SecRequestBodyAccess On
SecRequestBodyLimit 8
SecResponseBodyAccess On
SecResponseBodyLimit 8
SecResponseBodyLimitAction Reject
SecRule REQUEST_URI "@streq /limited" "id:10,phase:1,pass,ctl:requestBodyLimit=2,ctl:requestBodyLimit=4,ctl:responseBodyLimit=2"
SecRule REQUEST_URI "@streq /limited" "id:20,phase:3,pass,ctl:responseBodyLimit=4"
SecAction "id:30,phase:2,pass,ctl:requestBodyLimit=1"
SecAction "id:40,phase:4,pass,ctl:responseBodyLimit=1""#).unwrap();
    for (uri, request, expected_status) in [
        ("/limited", true, Some(413)),
        ("/limited", false, Some(500)),
        ("/other", true, None),
        ("/other", false, None),
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri(uri, "POST", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let result = if request {
            tx.write_request_body(b"four").unwrap()
        } else {
            tx.process_request_body().unwrap();
            tx.process_response_headers().unwrap();
            tx.write_response_body(b"four").unwrap()
        };
        assert_eq!(tx.intervention().map(|it| it.status), expected_status);
        assert_eq!(
            result.consumed,
            if expected_status.is_some() { 0 } else { 4 }
        );
    }
}

#[test]
fn zero_suppresses_acquisition_without_raising_data_errors() {
    for action in ["Reject", "ProcessPartial"] {
        let engine = ModSecurity::from_string(&format!(
            r#"SecRequestBodyAccess On
SecResponseBodyAccess On
SecRequestBodyLimitAction {action}
SecResponseBodyLimitAction {action}
SecAction "id:1,phase:1,pass,ctl:requestBodyLimit=0,ctl:responseBodyLimit=0"
SecRule INBOUND_DATA_ERROR "@streq 1" "id:2,phase:2,pass"
SecRule OUTBOUND_DATA_ERROR "@streq 1" "id:3,phase:4,pass""#
        ))
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_request_headers().unwrap();
        let read = tx.write_request_body(b"body").unwrap();
        assert_eq!(read.consumed, 0);
        assert!(read.limit_reached);
        tx.process_request_body().unwrap();
        tx.process_response_headers().unwrap();
        let read = tx.write_response_body(b"body").unwrap();
        assert_eq!(read.consumed, 0);
        assert!(read.limit_reached);
        tx.process_response_body().unwrap();
        assert_eq!(tx.matched_rules(), ["1"]);
        assert!(tx.intervention().is_none());
    }
}

#[test]
fn raised_threshold_preserves_storage_bound_and_reject_precedence() {
    for request in [true, false] {
        for action in ["Reject", "ProcessPartial"] {
            let engine = ModSecurity::from_string(&format!(
                r#"SecRequestBodyAccess On
SecResponseBodyAccess On
SecRequestBodyLimit 8
SecResponseBodyLimit 8
SecRequestBodyLimitAction {action}
SecResponseBodyLimitAction {action}
SecAction "id:1,phase:1,pass,ctl:requestBodyLimit=12,ctl:responseBodyLimit=12""#
            ))
            .unwrap();
            let mut tx = engine.new_transaction();
            tx.process_request_headers().unwrap();
            if !request {
                tx.process_request_body().unwrap();
                tx.process_response_headers().unwrap();
            }
            let write = |tx: &mut zentinel_modsec::Transaction, data: &[u8]| {
                if request {
                    tx.write_request_body(data)
                } else {
                    tx.write_response_body(data)
                }
            };
            assert!(matches!(
                write(&mut tx, b"123456789"),
                Err(zentinel_modsec::Error::BodyStorageLimit { limit: 8, .. })
            ));
            assert!(tx.intervention().is_none());
            assert_eq!(write(&mut tx, b"12345678").unwrap().consumed, 8);
            let result = write(&mut tx, b"9012");
            if action == "Reject" {
                assert_eq!(result.unwrap().consumed, 0);
                assert_eq!(
                    tx.intervention().map(|it| it.status),
                    Some(if request { 413 } else { 500 })
                );
            } else {
                assert!(matches!(
                    result,
                    Err(zentinel_modsec::Error::BodyStorageLimit { limit: 8, .. })
                ));
            }
            assert_eq!(
                if request {
                    tx.request_body_buffered_len()
                } else {
                    tx.response_body_buffered_len()
                },
                8
            );
        }
    }
}

#[test]
fn early_prefix_is_reconciled_once_with_final_header_limits() {
    for (local, action, retained, status) in [
        (0, "Reject", 0, None),
        (3, "ProcessPartial", 3, None),
        (4, "ProcessPartial", 4, None),
        (3, "Reject", 0, Some(413)),
        (8, "Reject", 4, None),
    ] {
        let engine = ModSecurity::from_string(&format!(
            r#"SecRequestBodyAccess On
SecRequestBodyLimit 8
SecRequestBodyLimitAction {action}
SecAction "id:1,phase:1,pass,ctl:requestBodyLimit={local}"
SecRule INBOUND_DATA_ERROR "@streq 1" "id:2,phase:2,pass""#
        ))
        .unwrap();
        let mut tx = engine.new_transaction();
        assert!(tx.write_request_body(b"data").unwrap().pending_headers);
        tx.process_request_headers().unwrap();
        assert_eq!(tx.request_body_buffered_len(), retained);
        assert_eq!(tx.intervention().map(|it| it.status), status);
        tx.process_request_body().unwrap();
        assert_eq!(
            tx.matched_rules().iter().any(|id| id == "2"),
            action == "ProcessPartial"
        );
    }
}

#[test]
fn raised_response_limit_can_resume_a_complete_provisional_prefix() {
    for (early, later_discarded, lost) in [
        (b"abc".as_slice(), false, false),
        (b"abcd", false, true),
        (b"abc", true, true),
    ] {
        let engine = ModSecurity::from_string(
            r#"SecResponseBodyAccess On
SecResponseBodyLimit 8
SecAction "id:1,phase:1,pass,ctl:responseBodyLimit=3"
SecAction "id:2,phase:3,pass,ctl:responseBodyLimit=6""#,
        )
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        let early_result = tx.write_response_body(early).unwrap();
        assert!(early_result.pending_headers && early_result.limit_reached);
        if later_discarded {
            assert_eq!(tx.write_response_body(b"x").unwrap().consumed, 0);
        }
        let headers = tx.process_response_headers();
        if lost {
            assert!(headers.is_err());
            assert!(tx.process_response_body().is_err());
        } else {
            headers.unwrap();
            let end = tx.write_response_body(b"def").unwrap();
            assert!(end.inspection_complete && end.limit_reached);
            assert_eq!(end.consumed, 3);
        }
    }
}
