//! Bounded CTAP CBOR decoding and deterministic encoding.
//!
//! Scan before invoking the general-purpose decoder: declared collection sizes,
//! nesting and item counts must not cause unbounded allocation or recursion.
use ciborium::Value;

pub const MAX_BYTES: usize = crate::hid::MAX_MESSAGE - 1;
const MAX_DEPTH: usize = 12;
const MAX_ITEMS: usize = 1024;
const MAX_COLLECTION: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCbor;

pub fn decode(bytes: &[u8]) -> Result<Value, InvalidCbor> {
    if bytes.len() > MAX_BYTES {
        return Err(InvalidCbor);
    }
    let mut scanner = Scanner {
        bytes,
        offset: 0,
        items: 0,
    };
    scanner.item(0)?;
    if scanner.offset != bytes.len() {
        return Err(InvalidCbor);
    }
    let value: Value = ciborium::from_reader(bytes).map_err(|_| InvalidCbor)?;
    validate_keys(&value)?;
    Ok(value)
}

struct Scanner<'a> {
    bytes: &'a [u8],
    offset: usize,
    items: usize,
}

impl Scanner<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8], InvalidCbor> {
        let end = self.offset.checked_add(length).ok_or(InvalidCbor)?;
        let result = self.bytes.get(self.offset..end).ok_or(InvalidCbor)?;
        self.offset = end;
        Ok(result)
    }

    fn argument(&mut self, additional: u8) -> Result<u64, InvalidCbor> {
        let (length, minimum) = match additional {
            0..=23 => return Ok(u64::from(additional)),
            24 => (1, 24),
            25 => (2, 256),
            26 => (4, 65536),
            27 => (8, 1u64 << 32),
            _ => return Err(InvalidCbor), // indefinite lengths and reserved forms
        };
        let mut value = 0u64;
        for byte in self.take(length)? {
            value = (value << 8) | u64::from(*byte);
        }
        if value < minimum {
            return Err(InvalidCbor);
        }
        Ok(value)
    }

    fn item(&mut self, depth: usize) -> Result<(), InvalidCbor> {
        self.items += 1;
        if depth > MAX_DEPTH || self.items > MAX_ITEMS {
            return Err(InvalidCbor);
        }
        let first = self.take(1)?[0];
        let major = first >> 5;
        if major == 7 {
            // CTAP preserves floating-point representations. Unknown fields and
            // extensions may carry them and must remain ignorable; command
            // validators still enforce types on every field they understand.
            let length = match first {
                0xf4..=0xf6 => 0,
                0xf9 => 2,
                0xfa => 4,
                0xfb => 8,
                _ => return Err(InvalidCbor),
            };
            self.take(length)?;
            return Ok(());
        }
        if major == 6 {
            return Err(InvalidCbor);
        } // CTAP does not use tagged data
        let argument = self.argument(first & 31)?;
        match major {
            0 | 1 => Ok(()),
            2 | 3 => {
                let length = usize::try_from(argument).map_err(|_| InvalidCbor)?;
                self.take(length)?;
                Ok(())
            }
            4 | 5 => {
                let count = usize::try_from(argument).map_err(|_| InvalidCbor)?;
                if count > MAX_COLLECTION {
                    return Err(InvalidCbor);
                }
                let count = if major == 5 { count * 2 } else { count };
                for _ in 0..count {
                    self.item(depth + 1)?;
                }
                Ok(())
            }
            _ => Err(InvalidCbor),
        }
    }
}

fn validate_keys(value: &Value) -> Result<(), InvalidCbor> {
    match value {
        Value::Map(entries) => {
            let mut previous: Option<Vec<u8>> = None;
            for (key, value) in entries {
                if !matches!(
                    key,
                    Value::Integer(_)
                        | Value::Text(_)
                        | Value::Bytes(_)
                        | Value::Bool(_)
                        | Value::Null
                ) {
                    return Err(InvalidCbor);
                }
                let encoded = encode(key);
                if let Some(prev) = &previous {
                    // CTAP canonical keys are strictly ordered, including no duplicates.
                    if prev >= &encoded {
                        return Err(InvalidCbor);
                    }
                }
                previous = Some(encoded);
                validate_keys(value)?;
            }
        }
        Value::Array(items) => {
            for value in items {
                validate_keys(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn encode(value: &Value) -> Vec<u8> {
    let mut value = value.clone();
    canonicalize(&mut value);
    let mut bytes = Vec::new();
    // Encoding our restricted Value data into Vec cannot fail with an I/O error.
    ciborium::into_writer(&value, &mut bytes).expect("in-memory CBOR encoding");
    bytes
}

fn canonicalize(value: &mut Value) {
    match value {
        Value::Map(entries) => {
            for (_, value) in entries.iter_mut() {
                canonicalize(value);
            }
            // CTAP ordering is major-type first, not RFC 7049 length-first.
            entries.sort_by_cached_key(|(key, _)| encode(key));
        }
        Value::Array(items) => {
            for value in items {
                canonicalize(value);
            }
        }
        _ => {}
    }
}

pub fn int(value: i64) -> Value {
    Value::Integer(value.into())
}
pub fn text(value: &str) -> Value {
    Value::Text(value.into())
}
pub fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.into())
}
pub fn map(entries: impl IntoIterator<Item = (Value, Value)>) -> Value {
    Value::Map(entries.into_iter().collect())
}
pub fn get<'a>(map: &'a Value, key: &Value) -> Option<&'a Value> {
    map.as_map()?
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_round_trip() {
        let value = map([
            (text("long-key"), int(4)),
            (text("a"), int(-7)),
            (int(1), bytes(&[1, 2, 3])),
        ]);
        let encoded = encode(&value);
        assert_eq!(encode(&decode(&encoded).unwrap()), encoded);
    }

    #[test]
    fn ctap_key_order_is_major_type_first() {
        assert_eq!(
            encode(&map([(int(-1), int(0)), (int(256), int(0))])),
            [0xa2, 0x19, 1, 0, 0, 0x20, 0]
        );
        assert!(decode(&[0xa2, 0x20, 0, 0x19, 1, 0, 0]).is_err());
    }

    #[test]
    fn floating_point_unknown_values_are_ignorable_but_bounded() {
        // All three permitted encodings of 1.5, including non-shortest floats.
        for value in [
            vec![0xf9, 0x3e, 0],
            vec![0xfa, 0x3f, 0xc0, 0, 0],
            vec![0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0],
        ] {
            let mut input = vec![0xa1, 0x01];
            input.extend(&value);
            assert_eq!(
                get(&decode(&input).unwrap(), &int(1)),
                Some(&Value::Float(1.5))
            );
            input.pop();
            assert!(decode(&input).is_err());
        }
    }

    #[test]
    fn rejects_malformed_and_noncanonical() {
        for invalid in [
            vec![],
            vec![0xa1],
            vec![0, 0],
            vec![0x18, 0x01],
            vec![0x9f, 0xff],
            vec![0xc0, 0],
            vec![0xfa, 0, 0, 0], // truncated float
            vec![0xa2, 1, 0, 1, 1],
            vec![0xa2, 2, 0, 1, 0],
            vec![0xa1, 0x80, 0],
            vec![0x61, 0xff],
            vec![0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert!(decode(&invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn bounds_depth_collections_and_input() {
        let mut deep = vec![0x81; MAX_DEPTH + 1];
        deep.push(0);
        assert!(decode(&deep).is_err());
        assert!(decode(&[0x99, 1, 1]).is_err());
        assert!(decode(&vec![0; MAX_BYTES + 1]).is_err());
    }

    #[test]
    fn arbitrary_inputs_do_not_panic() {
        let mut state = 0x12345678u32;
        for length in 0..2048 {
            let mut input = Vec::with_capacity(length);
            for _ in 0..length {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                input.push((state >> 24) as u8);
            }
            let _ = decode(&input);
        }
    }
}
