//! Coraza v3.8.1 arithmetic uses native signed-int wrapping on 64-bit targets.
//! Captured boundary operands must not turn a request into a Rust panic.
use zentinel_modsec::{
    engine::SetVarChange,
    variables::{ByteCollection, Collection, HashMapCollection, MutableCollection, TxCollection},
    ModSecurity,
};

fn captured_operation(initial: i64, operand: i64, operation: char, expected: i64) {
    let rules = format!(
        r#"SecRuleEngine DetectionOnly
SecAction "id:1,phase:1,pass,setvar:tx.x=%{{tx.initial}}"
SecRule ARGS:n "@rx ^(.*)$" "id:2,phase:1,pass,capture,setvar:tx.x={operation}%{{tx.1}}""#,
    );
    let engine = ModSecurity::from_string(&rules).unwrap();
    for record in [false, true] {
        let mut tx = engine.new_transaction();
        tx.set_record_setvar_effects(record);
        tx.tx_mut().set("initial".into(), initial.to_string());
        // Both extreme signs must travel through a request, capture, macro,
        // arithmetic and (when enabled) the effect recorder unchanged.
        tx.process_uri(&format!("/?n={operand}"), "GET", "HTTP/1.1")
            .unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), ["1", "2"]);
        assert_eq!(tx.tx().get("x"), Some(vec![expected.to_string().as_str()]));
        if record {
            assert_eq!(
                tx.setvar_effects().last().unwrap().op,
                if operation == '-' {
                    SetVarChange::Decrement(operand)
                } else {
                    SetVarChange::Increment(operand)
                }
            );
        } else {
            assert!(tx.setvar_effects().is_empty());
        }
    }
}

#[test]
fn captured_addition_wraps_at_both_boundaries() {
    captured_operation(i64::MAX, 1, '+', i64::MIN);
    captured_operation(i64::MIN, -1, '+', i64::MAX);
    captured_operation(0, i64::MIN, '+', i64::MIN);
}

#[test]
fn captured_subtraction_handles_the_minimum_operand_and_records_it_exactly() {
    captured_operation(0, i64::MIN, '-', i64::MIN);
    captured_operation(i64::MIN, 1, '-', i64::MAX);
    captured_operation(0, i64::MAX, '-', -i64::MAX);
}

#[test]
fn literal_minimum_decrement_does_not_panic_or_change_the_recorded_operand() {
    let engine = ModSecurity::from_string(
        r#"SecAction "id:1,phase:1,pass,setvar:tx.x=--9223372036854775808""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.set_record_setvar_effects(true);
    tx.process_request_headers().unwrap();
    assert_eq!(tx.tx().get("x"), Some(vec!["-9223372036854775808"]));
    assert_eq!(tx.setvar_effects()[0].op, SetVarChange::Decrement(i64::MIN));
}

fn collection_arithmetic<C: MutableCollection>(collection: &mut C) {
    collection.set("x".into(), i64::MAX.to_string());
    collection.increment("x", 1);
    assert_eq!(collection.get("x"), Some(vec!["-9223372036854775808"]));
    collection.decrement("x", 1);
    assert_eq!(collection.get("x"), Some(vec!["9223372036854775807"]));
    collection.set("x".into(), "0".into());
    collection.decrement("x", i64::MIN);
    assert_eq!(collection.get("x"), Some(vec!["-9223372036854775808"]));
}

#[test]
fn mutable_collection_and_tx_text_apis_use_the_same_wrapping_arithmetic() {
    collection_arithmetic(&mut HashMapCollection::new());
    collection_arithmetic(&mut TxCollection::new());
}

#[test]
fn tx_byte_api_wraps_under_binary_keys_without_changing_them() {
    let mut collection = TxCollection::new();
    collection.set_bytes(&b"X\xff"[..], i64::MAX.to_string());
    collection.increment_bytes(b"x\xff", 1);
    assert_eq!(
        collection.get_bytes(b"X\xff"),
        Some(vec![b"-9223372036854775808".as_slice()])
    );
    assert_eq!(collection.get_bytes(br"x\xff"), None);
}
