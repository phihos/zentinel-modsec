#[cfg(test)]
mod hash_seed_qualification {
    use super::*;
    use std::hash::BuildHasher;

    #[test]
    fn phase_one_replay_preserves_each_transactions_own_builder() {
        let engine = crate::ModSecurity::from_string(
            r#"SecAction "id:1,phase:1,pass,setvar:tx.9=ready,setvar:tx.a=1,setvar:tx.b=2,setvar:tx.c=3,setvar:tx.d=4,setvar:tx.e=5,setvar:tx.f=6,setvar:tx.g=7""#,
        ).unwrap();
        let signature = |tx: &TxCollection| {
            [b"a".as_slice(), b"field".as_slice(), b"another-key".as_slice()]
                .map(|key| tx.data.hasher().hash_one(key))
        };
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let mut tx = engine.new_transaction();
            let original = signature(tx.tx());
            assert!(seen.insert(original));
            tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
            tx.process_request_headers().unwrap();
            assert_eq!(tx.tx().get_bytes(b"9").unwrap()[0], b"ready");
            assert_eq!(original, signature(tx.tx()));
        }
    }
}
