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

