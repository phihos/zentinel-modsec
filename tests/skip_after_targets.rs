//! Where `skipAfter` resumes.
//!
//! The position of a rule's marker is resolved when the rules load, so these
//! pin what the lookup at request time decided: the marker's position in the
//! phase being run, the last declaration of a repeated name, a completed
//! chain taking its starter's `skipAfter`, and a marker that is unknown or
//! not ahead ending the phase.

use zentinel_modsec::ModSecurity;

/// Rule IDs that matched, in order.
fn matched(rules: &str) -> Vec<String> {
    let m = ModSecurity::from_string(&format!("SecRuleEngine On\n{rules}")).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri("/api?q=hello", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

#[test]
fn the_marker_position_is_the_one_in_the_phase_being_run() {
    // Rules of both phases sit between the rule and its marker. The phase-2
    // jump passes the phase-2 rule only; the phase-1 jump the phase-1 rule.
    assert_eq!(
        matched(
            "SecAction \"id:1,phase:1,pass,nolog,skipAfter:M\"\n\
             SecAction \"id:2,phase:2,pass,nolog,skipAfter:M\"\n\
             SecAction \"id:3,phase:1,pass,nolog\"\n\
             SecAction \"id:4,phase:2,pass,nolog\"\n\
             SecMarker M\n\
             SecAction \"id:5,phase:1,pass,nolog\"\n\
             SecAction \"id:6,phase:2,pass,nolog\""
        ),
        vec!["1", "5", "2", "6"]
    );
}

#[test]
fn an_unknown_marker_skips_the_rest_of_the_phase_only() {
    assert_eq!(
        matched(
            "SecAction \"id:1,phase:1,pass,nolog,skipAfter:NOWHERE\"\n\
             SecAction \"id:2,phase:1,pass,nolog\"\n\
             SecAction \"id:3,phase:2,pass,nolog\""
        ),
        vec!["1", "3"]
    );
}

#[test]
fn a_marker_behind_the_rule_skips_the_rest_of_the_phase() {
    assert_eq!(
        matched(
            "SecMarker BEHIND\n\
             SecAction \"id:1,phase:1,pass,nolog,skipAfter:BEHIND\"\n\
             SecAction \"id:2,phase:1,pass,nolog\"\n\
             SecAction \"id:3,phase:2,pass,nolog\""
        ),
        vec!["1", "3"]
    );
}

#[test]
fn a_repeated_marker_name_resumes_at_its_last_declaration() {
    assert_eq!(
        matched(
            "SecAction \"id:1,phase:1,pass,nolog,skipAfter:M\"\n\
             SecAction \"id:2,phase:1,pass,nolog\"\n\
             SecMarker M\n\
             SecAction \"id:3,phase:1,pass,nolog\"\n\
             SecMarker M\n\
             SecAction \"id:4,phase:1,pass,nolog\""
        ),
        vec!["1", "4"]
    );
}

#[test]
fn a_completed_chain_takes_the_skip_after_of_its_starter() {
    assert_eq!(
        matched(
            "SecRule REQUEST_METHOD \"@streq POST\" \"id:1,phase:1,pass,nolog,chain,skipAfter:M\"\n\
             SecRule REQUEST_URI \"@contains api\" \"skipAfter:OTHER\"\n\
             SecAction \"id:2,phase:1,pass,nolog\"\n\
             SecMarker M\n\
             SecAction \"id:3,phase:1,pass,nolog\"\n\
             SecMarker OTHER\n\
             SecAction \"id:4,phase:1,pass,nolog\""
        ),
        vec!["1", "3", "4"]
    );
}

#[test]
fn a_chain_that_fails_does_not_skip() {
    assert_eq!(
        matched(
            "SecRule REQUEST_METHOD \"@streq POST\" \"id:1,phase:1,pass,nolog,chain,skipAfter:M\"\n\
             SecRule REQUEST_URI \"@contains nomatch\"\n\
             SecAction \"id:2,phase:1,pass,nolog\"\n\
             SecMarker M\n\
             SecAction \"id:3,phase:1,pass,nolog\""
        ),
        vec!["2", "3"]
    );
}

#[test]
fn a_skip_after_that_is_not_the_last_flow_action_is_not_taken() {
    // The last flow action of a rule decides what a match does next.
    assert_eq!(
        matched(
            "SecAction \"id:1,phase:1,pass,nolog,skipAfter:M,skip:1\"\n\
             SecAction \"id:2,phase:1,pass,nolog\"\n\
             SecAction \"id:3,phase:1,pass,nolog\"\n\
             SecMarker M\n\
             SecAction \"id:4,phase:1,pass,nolog\""
        ),
        vec!["1", "3", "4"]
    );
}

#[test]
fn the_last_of_two_skip_after_actions_decides() {
    assert_eq!(
        matched(
            "SecAction \"id:1,phase:1,pass,nolog,skipAfter:A,skipAfter:B\"\n\
             SecAction \"id:2,phase:1,pass,nolog\"\n\
             SecMarker A\n\
             SecAction \"id:3,phase:1,pass,nolog\"\n\
             SecMarker B\n\
             SecAction \"id:4,phase:1,pass,nolog\""
        ),
        vec!["1", "4"]
    );
}
