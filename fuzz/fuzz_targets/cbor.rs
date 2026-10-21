#![no_main]
use libfuzzer_sys::fuzz_target;
use yubiquity::cbor;

fuzz_target!(|input: &[u8]| {
    if let Ok(value) = cbor::decode(input) {
        // Includes key validation and recursive canonicalization. Comparing
        // bytes, not Values, deliberately handles NaN != NaN correctly.
        let canonical = cbor::encode(&value);
        assert!(canonical.len() <= cbor::MAX_BYTES);
        let decoded = cbor::decode(&canonical).expect("encoder emitted invalid CTAP CBOR");
        assert_eq!(cbor::encode(&decoded), canonical);
    }
});
