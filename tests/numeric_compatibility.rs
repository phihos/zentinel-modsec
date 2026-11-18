use zentinel_modsec::{
    operators::{EqOperator, GeOperator, GtOperator, LeOperator, LtOperator, Operator},
    ModSecurity,
};

#[test]
fn numeric_operators_use_pinned_integer_conversion_on_both_sides() {
    for (raw, number) in [
        (b"".as_slice(), 0),
        (b"abc", 0),
        (b"123abc", 0),
        (b" 1", 0),
        (b"1 ", 0),
        (b"+1", 1),
        (b"-1", -1),
        (b"1.9", 0),
        (b"1e2", 0),
        (b"0x10", 0),
        (b"\xff", 0),
        (b"9223372036854775808", i64::MAX),
        (b"-9223372036854775809", i64::MIN),
        (b"9223372036854775808x", 0),
        (b"18446744073709551616x", i64::MAX),
        (b"-18446744073709551616x", i64::MIN),
    ] {
        let target = number.to_string();
        let ops: Vec<(Box<dyn Operator>, bool)> = vec![
            (Box::new(EqOperator::new(&target)), true),
            (Box::new(GtOperator::new(&target)), false),
            (Box::new(LtOperator::new(&target)), false),
            (Box::new(GeOperator::new(&target)), true),
            (Box::new(LeOperator::new(&target)), true),
        ];
        for (op, expected) in ops {
            let result = op.execute_bytes(raw).unwrap();
            assert_eq!(result.matched, expected, "{} {:?}", op.name(), raw);
            if expected {
                assert_eq!(result.matched_value.as_deref(), Some(raw));
            }
            if let Ok(text) = std::str::from_utf8(raw) {
                assert_eq!(op.execute(text).matched, expected);
            }
        }
    }
    for argument in ["", "abc", "1.5", " 1", "1x"] {
        assert!(EqOperator::new(argument).execute("0").matched);
        assert!(GtOperator::new(argument).execute("1").matched);
        assert!(LtOperator::new(argument).execute("-1").matched);
    }
}

#[test]
fn empty_numeric_scalars_and_negation_preserve_benign_requests() {
    // Exact blocking rule from pinned @coraza.conf-recommended. Empty initial
    // MULTIPART_STRICT_ERROR must compare as zero, including on nonmultipart.
    let engine=ModSecurity::from_string(r#"SecRuleEngine On
SecRequestBodyAccess On
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:200003,phase:2,t:none,log,deny,msg:'Multipart request body failed strict validation.'"
SecRule ARGS:x "@eq 0" "id:10,phase:2,pass"
SecRule ARGS:x "!@eq 0" "id:11,phase:2,pass"
SecRule ARGS:x "@eq %{ARGS.target}" "id:12,phase:2,pass""#).unwrap();
    for (ct, body) in [
        ("", b"".as_slice()),
        ("application/x-www-form-urlencoded", b"name=alice"),
        ("application/json", b"{\"name\":\"alice\"}"),
        ("application/xml", b"<name>alice</name>"),
        (
            "multipart/form-data; boundary=abc",
            b"--abc\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nalice\r\n--abc--\r\n",
        ),
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri(
            "/?x=&target=abc",
            if body.is_empty() { "GET" } else { "POST" },
            "HTTP/1.1",
        )
        .unwrap();
        if !ct.is_empty() {
            tx.add_request_header("Content-Type", ct).unwrap();
        }
        tx.process_request_headers().unwrap();
        tx.append_request_body(body).unwrap();
        tx.process_request_body().unwrap();
        assert!(
            tx.intervention().is_none(),
            "{ct}: {:?}",
            tx.matched_rules()
        );
        assert_eq!(tx.matched_rules(), ["10", "12"]);
    }
}

#[test]
fn expanded_operands_use_the_same_conversion_as_values() {
    use zentinel_modsec::operators::compile_operator_bytes;
    use zentinel_modsec::parser::{OperatorName, OperatorSpec};
    for (name, input, expected) in [
        (OperatorName::Eq, "0", true),
        (OperatorName::Gt, "1", true),
        (OperatorName::Ge, "0", true),
        (OperatorName::Lt, "-1", true),
        (OperatorName::Le, "1", false),
    ] {
        let spec = OperatorSpec {
            name,
            argument: "%{tx.target}".into(),
            negated: false,
        };
        for expanded in [&b"invalid"[..], &b"\xff"[..]] {
            let op = compile_operator_bytes(&spec, expanded).unwrap();
            assert_eq!(op.execute(input).matched, expected);
        }
    }
}
