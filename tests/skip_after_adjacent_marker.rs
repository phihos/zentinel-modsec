//! `skipAfter` resumes at the first rule after its marker. A marker that
//! directly follows the jumping rule skips nothing, so the next rule runs.
//!
//! CRS ends each rule file with its paranoia-level gates followed by the
//! file's end marker. In a file without level-4 rules the last gate sits
//! directly before that marker, and at paranoia level 3 it is the gate that
//! fires. The jump used to be treated as one that does not lead forwards,
//! which skips the rest of the phase: every later rule file went unevaluated.

use zentinel_modsec::ModSecurity;

/// Rule IDs that matched, in order.
fn matched(rules: &str) -> Vec<String> {
    let msc =
        ModSecurity::from_string(&format!("SecRuleEngine On\n{rules}")).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

#[test]
fn a_marker_directly_after_the_rule_skips_nothing() {
    assert_eq!(
        matched(
            "SecAction \"id:1,phase:2,pass,nolog,skipAfter:END\"\n\
             SecMarker END\n\
             SecAction \"id:2,phase:2,pass,nolog\"\n\
             SecAction \"id:3,phase:2,pass,nolog\""
        ),
        ["1", "2", "3"]
    );
}

#[test]
fn the_last_gates_of_a_rule_file_do_not_end_their_phases() {
    // One gate per phase, then the marker, as at the end of a CRS file.
    assert_eq!(
        matched(
            "SecAction \"id:1,phase:1,pass,nolog,skipAfter:END-FILE\"\n\
             SecAction \"id:2,phase:2,pass,nolog,skipAfter:END-FILE\"\n\
             SecMarker END-FILE\n\
             SecAction \"id:3,phase:1,pass,nolog\"\n\
             SecAction \"id:4,phase:2,pass,nolog\""
        ),
        ["1", "3", "2", "4"]
    );
}

#[test]
fn a_marker_at_the_end_of_the_phase_ends_it() {
    assert_eq!(
        matched(
            "SecAction \"id:1,phase:2,pass,nolog,skipAfter:END\"\n\
             SecAction \"id:2,phase:2,pass,nolog\"\n\
             SecMarker END"
        ),
        ["1"]
    );
}

#[test]
fn a_marker_behind_the_rule_still_skips_the_rest_of_the_phase() {
    assert_eq!(
        matched(
            "SecMarker BEHIND\n\
             SecAction \"id:1,phase:2,pass,nolog,skipAfter:BEHIND\"\n\
             SecAction \"id:2,phase:2,pass,nolog\""
        ),
        ["1"]
    );
}
