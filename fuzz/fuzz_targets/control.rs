#![no_main]
use libfuzzer_sys::fuzz_target;
use yubiquity::control::Request;

fuzz_target!(|input: &[u8]| {
    // Same body bound as the length-prefixed local control protocol. Socket
    // framing/client lifetime/ownership are exercised by independent tests.
    if input.is_empty() || input.len() > 8192 {
        return;
    }
    if let Ok(request) = serde_json::from_slice::<Request>(input) {
        // All inputs here are deliberately synthetic; never real unlock data.
        let canonical = serde_json::to_vec(&request).unwrap();
        assert!(canonical.len() <= 8192);
        let decoded = serde_json::from_slice::<Request>(&canonical).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), canonical);
    }
});
