//! Byte-safe multipart regressions checked against pinned Coraza 3.8.1.
use zentinel_modsec::{
    engine::Transaction,
    variables::{ByteCollection, RequestData},
    ModSecurity,
};

fn body(disposition: &[u8], contents: &[u8]) -> Vec<u8> {
    let mut body = b"--B\r\nContent-Disposition: ".to_vec();
    body.extend_from_slice(disposition);
    body.extend_from_slice(b"\r\n\r\n");
    body.extend_from_slice(contents);
    body.extend_from_slice(b"\r\n--B--\r\n");
    body
}
fn parsed(body: &[u8]) -> RequestData {
    let mut request = RequestData::new();
    request.append_body(body);
    assert!(request.parse_multipart_body("multipart/form-data; boundary=B"));
    request
}
fn run(rules: &str, body: &[u8]) -> Transaction {
    let engine = ModSecurity::from_string(&format!(
        "SecRequestBodyAccess On\nSecRuleEngine DetectionOnly\n{rules}"
    ))
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=B")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx
}

#[test]
fn crs_920120_quoted_semicolons_stay_visible_in_field_and_file_names() {
    let body = body(br#"form-data; name="fi;le"; filename="a;b.txt""#, b"abc");
    let request = parsed(&body);
    assert_eq!(
        request.files.get_bytes(b""),
        Some(vec![b"a;b.txt".as_slice()])
    );
    let tx = run(
        r#"SecRule FILES|FILES_NAMES "@contains ;" "id:920120,phase:2,pass""#,
        &body,
    );
    assert_eq!(tx.matched_rules(), ["920120"]);
}

#[test]
fn quoted_pairs_decode_quotes_without_corrupting_windows_paths() {
    let request = parsed(&body(
        br#"form-data; name="f\"ield"; filename="a\"b.txt""#,
        b"abc",
    ));
    assert_eq!(
        request.files.get_bytes(b""),
        Some(vec![b"a\"b.txt".as_slice()])
    );
    let request = parsed(&body(
        br#"form-data; name="f"; filename="C:\dir\file.txt""#,
        b"abc",
    ));
    assert_eq!(
        request.files.get_bytes(b""),
        Some(vec![br"C:\dir\file.txt".as_slice()])
    );
}

#[test]
fn binary_form_fields_and_part_names_are_not_utf8_replaced() {
    let request = parsed(&body(b"form-data; name=\"f\xff\"", b"\xff\x00abc"));
    assert_eq!(
        request.args_post.get_bytes(b"f\xff"),
        Some(vec![b"\xff\x00abc".as_slice()])
    );
}

#[test]
fn boundary_like_substrings_inside_a_value_are_not_part_delimiters() {
    let value = b"abc--Bxyz\r\nabc\r\n--Bxmore";
    let request = parsed(&body(br#"form-data; name="f""#, value));
    assert_eq!(
        request.args_post.get_bytes(b"f"),
        Some(vec![value.as_slice()])
    );
}

#[test]
fn repeated_parts_keep_each_value_and_filename() {
    let mut input = body(br#"form-data; name="f"; filename="first.txt""#, b"abc");
    input.truncate(input.len() - b"--B--\r\n".len());
    input.extend_from_slice(&body(
        br#"form-data; name="f"; filename="second.txt""#,
        b"def",
    ));
    let request = parsed(&input);
    assert_eq!(
        request.files.get_bytes(b""),
        Some(vec![b"first.txt".as_slice(), b"second.txt".as_slice()])
    );
}

#[test]
fn extended_filename_preserves_raw_percent_bytes_and_the_plain_alternative() {
    let request = parsed(&body(
        br#"form-data; name="f"; filename="safe.txt"; filename*=iso-8859-1'en'evil%3B%FF.txt"#,
        b"abc",
    ));
    assert_eq!(
        request.files.get_bytes(b""),
        Some(vec![b"evil;\xff.txt".as_slice(), b"safe.txt".as_slice()])
    );
}

#[test]
fn quoted_extended_filenames_are_inspected_and_report_strict_quoting() {
    let input = body(
        br#"form-data; name="f"; filename*="utf-8''evil%3B.txt""#,
        b"abc",
    );
    let tx = run(
        r#"SecRule FILES "@streq evil;.txt" "id:1,phase:2,pass"
SecRule MULTIPART_STRICT_ERROR "@eq 1" "id:2,phase:2,pass""#,
        &input,
    );
    assert_eq!(tx.matched_rules(), ["1", "2"]);
}

#[test]
fn combined_size_counts_payload_bytes_in_files_and_fields_without_framing() {
    let mut input = body(br#"form-data; name="f"; filename="x.bin""#, b"\xff\x00ab");
    input.truncate(input.len() - b"--B--\r\n".len());
    input.extend_from_slice(&body(br#"form-data; name="field""#, b"xyz"));
    let tx = run(
        r#"SecRule FILES_COMBINED_SIZE "@eq 7" "id:920410,phase:2,pass"
SecRule FILES_SIZES:x.bin "@eq 4" "id:2,phase:2,pass""#,
        &input,
    );
    assert_eq!(tx.matched_rules(), ["920410", "2"]);
}

#[test]
fn empty_filenames_are_form_fields_and_missing_names_are_not_dropped() {
    let request = parsed(&body(br#"form-data; name="f"; filename="""#, b"abc"));
    assert_eq!(
        request.args_post.get_bytes(b"f"),
        Some(vec![b"abc".as_slice()])
    );
    let request = parsed(&body(b"form-data", b"abc"));
    assert_eq!(
        request.args_post.get_bytes(b""),
        Some(vec![b"abc".as_slice()])
    );
}

#[test]
fn externally_truncated_payloads_remain_inspected_and_set_strict_error() {
    let input = b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nattack";
    let tx = run(
        r#"SecRule ARGS:f "@streq attack" "id:1,phase:2,pass"
SecRule MULTIPART_STRICT_ERROR "@eq 1" "id:200003,phase:2,pass""#,
        input,
    );
    assert_eq!(tx.matched_rules(), ["1", "200003"]);
}

#[test]
fn duplicate_headers_keep_the_first_interpretation_and_set_strict_error() {
    let input = b"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a\"\r\nContent-Disposition: form-data; name=\"f\"; filename=\"b\"\r\n\r\nabc\r\n--B--\r\n";
    let tx = run(
        r#"SecRule FILES "@streq a" "id:1,phase:2,pass"
SecRule MULTIPART_STRICT_ERROR "@eq 1" "id:200003,phase:2,pass""#,
        input,
    );
    assert_eq!(tx.matched_rules(), ["1", "200003"]);
}

#[test]
fn malformed_headers_report_body_and_strict_errors() {
    let tx = run(
        r#"SecRule REQBODY_ERROR "@eq 1" "id:200002,phase:2,pass"
SecRule MULTIPART_STRICT_ERROR "@eq 1" "id:200003,phase:2,pass""#,
        b"--B\r\n Content-Disposition: form-data; name=\"f\"\r\n\r\nabc\r\n--B--\r\n",
    );
    assert_eq!(tx.matched_rules(), ["200002", "200003"]);
}

#[test]
fn lf_only_framing_is_valid_in_the_reference() {
    let tx = run(
        r#"SecRule ARGS:f "@streq abc" "id:1,phase:2,pass"
SecRule MULTIPART_STRICT_ERROR "@eq 1" "id:200003,phase:2,pass""#,
        b"--B\nContent-Disposition: form-data; name=\"f\"\n\nabc\n--B--\n",
    );
    assert_eq!(tx.matched_rules(), ["1"]);
}

#[test]
fn a_waf_retained_prefix_does_not_create_an_external_truncation_error() {
    let mut request = RequestData::new();
    request.inbound_data_error = true;
    request.append_body(b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nattack");
    assert!(request.parse_multipart_body("multipart/form-data; boundary=B"));
    assert!(!request.multipart_strict_error);
    assert!(request.body_error.is_none());
    assert_eq!(
        request.args_post.get_bytes(b"f"),
        Some(vec![b"attack".as_slice()])
    );
    let mut request = RequestData::new();
    request.inbound_data_error = true;
    request.append_body(b"--B\r\n badheader\r\n\r\nattack");
    assert!(request.parse_multipart_body("multipart/form-data; boundary=B"));
    assert!(request.multipart_strict_error);
    assert!(request.body_error.is_some());
}

#[test]
fn empty_collection_keys_use_the_reference_matched_variable_name() {
    let tx = run(
        r#"SecRule FILES "@contains .txt" "id:1,phase:2,pass"
SecRule MATCHED_VAR_NAME "@streq FILES" "id:2,phase:2,pass""#,
        &body(br#"form-data; name="f"; filename="x.txt""#, b"abc"),
    );
    assert_eq!(tx.matched_rules(), ["1", "2"]);
}

#[test]
fn engine_uses_original_binary_boundary_header_bytes() {
    let mut request = RequestData::new();
    request.append_body(
        b"--B\xff\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nattack\r\n--B\xff--\r\n",
    );
    assert!(request.parse_multipart_body_bytes(b"multipart/form-data; boundary=\"B\xff\""));
    assert_eq!(
        request.args_post.get_bytes(b"f"),
        Some(vec![b"attack".as_slice()]),
        "{:?}",
        request.body_error
    );

    let engine = ModSecurity::from_string(
        r#"SecRequestBodyAccess On
SecRule ARGS:f "@streq attack" "id:1,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header_bytes(b"Content-Type", b"multipart/form-data; boundary=\"B\xff\"")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(
        b"--B\xff\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nattack\r\n--B\xff--\r\n",
    )
    .unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1"]);
}

fn transfer_body(encoding: &[u8], value: &[u8]) -> Vec<u8> {
    let mut input =
        b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Transfer-Encoding: "
            .to_vec();
    input.extend_from_slice(encoding);
    input.extend_from_slice(b"\r\n\r\n");
    input.extend_from_slice(value);
    input.extend_from_slice(b"\r\n--B--\r\n");
    input
}

#[test]
fn quoted_printable_transfer_encoding_cannot_hide_an_attack() {
    let input = transfer_body(b"Quoted-Printable", b"att=61=\r\nck");
    let tx = run(
        r#"SecRule ARGS:f "@streq attack" "id:1,phase:2,pass"
SecRule FILES_COMBINED_SIZE "@eq 6" "id:2,phase:2,pass""#,
        &input,
    );
    assert_eq!(tx.matched_rules(), ["1", "2"]);
}

#[test]
fn quoted_printable_values_keep_binary_bytes_and_remove_the_transfer_header() {
    let request = parsed(&transfer_body(b"quoted-printable", b"\xff=00z"));
    assert_eq!(
        request.args_post.get_bytes(b"f"),
        Some(vec![b"\xff\x00z".as_slice()])
    );
    assert_eq!(request.files_combined_size, 3);
    assert!(request
        .multipart_part_headers
        .all_bytes()
        .iter()
        .all(|(_, value)| !value.starts_with(b"Content-Transfer-Encoding:")));
}

#[test]
fn quoted_printable_whitespace_and_invalid_hex_follow_the_reference() {
    let request = parsed(&transfer_body(
        b"quoted-printable",
        b"a \t\r\nb=20\t\r\nx=GG",
    ));
    assert_eq!(
        request.args_post.get_bytes(b"f"),
        Some(vec![b"a\r\nb \r\nx=GG".as_slice()])
    );
    assert!(!request.multipart_strict_error);
}

#[test]
fn invalid_quoted_printable_controls_report_a_visible_body_error() {
    let tx = run(
        r#"SecRule REQBODY_ERROR "@eq 1" "id:200002,phase:2,pass"
SecRule MULTIPART_STRICT_ERROR "@eq 1" "id:200003,phase:2,pass""#,
        &transfer_body(b"quoted-printable", b"good\x00bad"),
    );
    assert_eq!(tx.matched_rules(), ["200002", "200003"]);
}

#[test]
fn base64_transfer_encoding_remains_raw_as_in_the_reference() {
    let request = parsed(&transfer_body(b"base64", b"YXR0YWNr"));
    assert_eq!(
        request.args_post.get_bytes(b"f"),
        Some(vec![b"YXR0YWNr".as_slice()])
    );
}

#[test]
fn extended_and_continued_part_names_match_the_reference() {
    for disposition in [
        br#"form-data; name="plain"; name*=utf-8''evil%3Bfield; filename="x""#.as_slice(),
        br#"form-data; name*0="evil;"; name*1="field"; filename="x""#.as_slice(),
    ] {
        let request = parsed(&body(disposition, b"abc"));
        assert_eq!(
            request.files_names.get_bytes(b""),
            Some(vec![b"evil;field".as_slice()])
        );
    }
}

#[test]
fn filename_continuations_preserve_the_plain_and_resolved_readings() {
    let input = body(br#"form-data; name="f"; filename="plain.txt"; filename*0*=utf-8''evil%3B; filename*1*=.txt"#, b"abc");
    let request = parsed(&input);
    assert_eq!(
        request.files.get_bytes(b""),
        Some(vec![b"plain.txt".as_slice(), b"evil;.txt".as_slice()])
    );
    assert!(request.multipart_strict_error);
    let tx = run(
        r#"SecRule FILES "@contains ;" "id:920120,phase:2,pass""#,
        &input,
    );
    assert_eq!(tx.matched_rules(), ["920120"]);
}

#[test]
fn continuation_only_filenames_reassemble_raw_bytes_without_transcoding() {
    let request = parsed(&body(
        br#"form-data; name="f"; filename*0*=utf-8''x%FF; filename*1*=.txt"#,
        b"abc",
    ));
    assert_eq!(
        request.files.get_bytes(b""),
        Some(vec![b"x\xff.txt".as_slice()])
    );
    assert!(request.multipart_strict_error);
    assert_eq!(request.files_combined_size, 3);
}

#[test]
fn an_extended_boundary_parameter_selects_the_actual_delimiter() {
    let mut request = RequestData::new();
    request.append_body(&body(br#"form-data; name="f""#, b"attack"));
    assert!(request.parse_multipart_body("multipart/form-data; boundary*=utf-8''B"));
    assert_eq!(
        request.args_post.get_bytes(b"f"),
        Some(vec![b"attack".as_slice()])
    );
    assert!(!request.multipart_strict_error);
}

#[test]
fn unsupported_extended_name_charsets_keep_the_plain_parameter() {
    let request = parsed(&body(
        br#"form-data; name="plain"; name*=iso-8859-1''evil%3Bfield; filename="x""#,
        b"abc",
    ));
    assert_eq!(
        request.files_names.get_bytes(b""),
        Some(vec![b"plain".as_slice()])
    );
}

#[test]
fn invalid_continuation_pieces_do_not_hide_later_parameter_content() {
    for (disposition, expected) in [
        (
            br#"form-data; name="plain"; name*0*=iso-8859-1''evil; name*1=";field"; filename="x""#.as_slice(),
            b";field".as_slice(),
        ),
        (
            br#"form-data; name="plain"; name*0*=utf-8''evil; name*1*=%GG; name*2=";field"; filename="x""#.as_slice(),
            b"evil;field".as_slice(),
        ),
    ] {
        let input = body(disposition, b"abc");
        let request = parsed(&input);
        assert_eq!(request.files_names.get_bytes(b""), Some(vec![expected]));
        assert!(!request.multipart_strict_error);
        assert_eq!(
            run(r#"SecRule FILES_NAMES "@contains ;" "id:920120,phase:2,pass""#, &input).matched_rules(),
            ["920120"]
        );
    }
}
