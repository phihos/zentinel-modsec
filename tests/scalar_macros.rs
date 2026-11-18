use zentinel_modsec::ModSecurity;

#[test]
fn scalar_and_collection_macros_match_coraza_across_phases() {
    let engine = ModSecurity::from_string(r#"SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecAction "id:101,phase:1,pass,log,setvar:tx.request_method=shadow,setvar:tx.reqbody_error_msg=shadow,setvar:tx.args=shadow,msg:'%{rEqUeSt_MeThOd}/%{request_method.ignored}/%{REQUEST_BASENAME}/%{reqbody_error_msg}/%{RESPONSE_STATUS}/%{REMOTE_PORT}/%{SERVER_PORT}/%{OUTBOUND_DATA_ERROR}',logdata:'%{ARGS}/%{ARGS_GET}/%{ARGS_POST}/%{tX}/%{request_headers}/%{ARGS_NAMES.NaMe}/%{REQUEST_HEADERS_NAMES.X-Test}/%{request_cookies.Name}'"
SecRule REQUEST_LINE "@streq %{Request_Line}" "id:102,phase:1,pass,log,setvar:tx.line=%{request_line},msg:'%{Tx.line}',logdata:'%{QUERY_STRING}'"
SecAction "id:201,phase:2,pass,log,msg:'%{request_body_length}/%{ARGS_COMBINED_SIZE}/%{REQBODY_PROCESSOR}',logdata:'%{request_body}'"
SecAction "id:301,phase:3,pass,log,msg:'%{response_status} %{Response_Protocol} %{response_content_type}',logdata:'%{response_headers.X-Server}/%{response_headers_names.X-Server}/%{response_content_length}'"
SecAction "id:401,phase:4,pass,log,msg:'%{response_content_length}',logdata:'%{response_body}'""#).unwrap();
    for (connected, first_message) in [
        (false, "POST/POST/index/////0"),
        (true, "POST/POST/index///0/8443/0"),
    ] {
        let mut tx = engine.new_transaction();
        tx.set_record_rule_messages(true);
        if connected {
            tx.set_client_addr("127.0.0.1", 0);
            tx.set_server_addr("127.0.0.1", 8443);
        }
        tx.process_uri("/docs/index?=zero&Name=first", "POST", "HTTP/1.1")
            .unwrap();
        tx.add_request_header("X-Test", "alpha").unwrap();
        tx.add_request_header("Cookie", "Name=value").unwrap();
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
            .unwrap();
        tx.process_request_headers().unwrap();
        tx.append_request_body(b"lang=en").unwrap();
        tx.process_request_body().unwrap();
        tx.add_response_header("Content-Type", "text/plain; charset=utf-8")
            .unwrap();
        tx.add_response_header("X-Server", "beta").unwrap();
        tx.process_response_headers_with_status(203, "HTTP/2")
            .unwrap();
        tx.append_response_body(b"\xffk").unwrap();
        tx.process_response_body().unwrap();

        let messages: Vec<_> = tx
            .rule_messages()
            .iter()
            .map(|rule| {
                (
                    rule.rule_id.as_str(),
                    rule.message.as_deref().unwrap(),
                    rule.logdata.as_deref().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            messages,
            [
                (
                    "101",
                    first_message.as_bytes(),
                    b"zero/zero/ARGS_POST/tX/request_headers/first/alpha/value".as_slice()
                ),
                (
                    "102",
                    b"POST /docs/index?=zero&Name=first HTTP/1.1".as_slice(),
                    b"=zero&Name=first".as_slice()
                ),
                ("201", b"7/19/URLENCODED".as_slice(), b"lang=en".as_slice()),
                (
                    "301",
                    b"203 HTTP/2 text/plain".as_slice(),
                    b"beta/beta/".as_slice()
                ),
                ("401", b"2".as_slice(), b"\xffk".as_slice()),
            ]
        );
    }
}
