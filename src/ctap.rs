//! CTAP command dispatch. Capabilities expand only as implementations land.
use crate::cbor::{self, int, map, text};
use ciborium::Value;

// Project UUID, not a manufacturer's identity or trusted attestation claim.
pub const AAGUID: [u8; 16] = [
    0x64, 0xa9, 0x32, 0x72, 0x69, 0x0b, 0x4f, 0xf6, 0xa8, 0x2a, 0xc7, 0x41, 0xc0, 0x47, 0xb3, 0xb7,
];

/// Development transport profile. It intentionally does not create credentials.
pub fn transport_probe(request: &[u8]) -> Vec<u8> {
    match request {
        [0x04] => {
            let info = map([
                (int(1), Value::Array(vec![text("FIDO_2_0")])),
                (int(2), Value::Array(vec![])),
                (int(3), cbor::bytes(&AAGUID)),
                (
                    int(4),
                    map([
                        (text("rk"), Value::Bool(false)),
                        (text("up"), Value::Bool(false)),
                        (text("plat"), Value::Bool(false)),
                    ]),
                ),
                (int(5), int(crate::hid::MAX_MESSAGE as i64)),
            ]);
            let mut response = vec![0];
            response.extend(cbor::encode(&info));
            response
        }
        [0x04, ..] => vec![0x03], // command has no parameters
        [] => vec![0x03],
        _ => vec![0x01], // not yet implemented; never fake a successful ceremony
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn info_does_not_advertise_unimplemented_features() {
        let response = transport_probe(&[4]);
        assert_eq!(response[0], 0);
        let info = cbor::decode(&response[1..]).unwrap();
        let options = cbor::get(&info, &int(4)).unwrap();
        assert_eq!(cbor::get(options, &text("rk")), Some(&Value::Bool(false)));
        assert!(cbor::get(options, &text("clientPin")).is_none());
        assert!(cbor::get(options, &text("uv")).is_none());
        assert_eq!(transport_probe(&[1]), [1]);
    }
}
