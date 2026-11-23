//! Explicit, read-only metadata projection. Never serialize a Credential itself.
use crate::control::{Response, MAX_WIRE};
use crate::store::{Credential, State};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub credential_id: String,
    pub rp_id: String,
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub user_handle: String,
    pub discoverable: bool,
    pub algorithm: i32,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl From<&Credential> for Metadata {
    fn from(credential: &Credential) -> Self {
        Self {
            credential_id: hex(&credential.id),
            rp_id: credential.rp_id.clone(),
            name: credential.user.name.clone(),
            display_name: credential.user.display_name.clone(),
            user_handle: hex(&credential.user.id),
            discoverable: credential.discoverable,
            algorithm: credential.algorithm,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub items: Vec<Metadata>,
    pub total: usize,
    pub next_offset: Option<usize>,
}

pub(crate) fn page(
    state: &State,
    revision: String,
    offset: usize,
    expected: Option<&str>,
) -> Response {
    let mut response = Response::ready(None);
    response.credentials_revision = Some(revision.clone());
    if offset > state.credentials.len() || (offset > 0 && expected.is_none()) {
        return response.error("invalid passkey page; refresh the list");
    }
    if expected.is_some_and(|value| value != revision) {
        return response.error("passkeys changed; refresh the list");
    }
    let mut items = Vec::new();
    let mut bytes = 0;
    // Leave room for the response envelope. Count encoded bytes, including
    // escaping, so maximum-length names cannot exceed the control wire limit.
    for credential in state.credentials.iter().skip(offset).take(32) {
        let item = Metadata::from(credential);
        let length = serde_json::to_vec(&item).expect("metadata is JSON").len() + 1;
        if bytes + length > MAX_WIRE - 1024 {
            break;
        }
        bytes += length;
        items.push(item);
    }
    if items.is_empty() && offset < state.credentials.len() {
        return response.error("passkey metadata exceeds the page limit");
    }
    let end = offset + items.len();
    response.credentials = Some(Page {
        items,
        total: state.credentials.len(),
        next_offset: (end < state.credentials.len()).then_some(end),
    });
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CredentialPolicy, User};

    fn credential(index: usize) -> Credential {
        let mut id = vec![0; 32];
        id[..8].copy_from_slice(&(index as u64).to_be_bytes());
        Credential {
            id,
            rp_id: "s".repeat(253),
            user: User {
                id: vec![0xab; 64],
                name: Some("\0".repeat(64)),
                display_name: Some("\n".repeat(64)),
            },
            discoverable: index.is_multiple_of(2),
            algorithm: -7,
            policy: CredentialPolicy::Ctap20,
            private_key: [0x7b; 32],
        }
    }

    #[test]
    fn large_lists_preserve_every_record_within_the_existing_wire_limit() {
        let state = State {
            credentials: (0..500).map(credential).collect(),
            pin: None,
        };
        let mut offset = 0;
        let mut found = Vec::new();
        loop {
            let response = page(&state, "revision".into(), offset, Some("revision"));
            assert!(response.ok);
            let encoded = serde_json::to_vec(&response).unwrap();
            assert!(encoded.len() <= MAX_WIRE);
            let response: Response = serde_json::from_slice(&encoded).unwrap();
            let rows = response.credentials.unwrap();
            assert_eq!(rows.total, 500);
            for row in &rows.items {
                assert_eq!(row.name.as_deref(), Some("\0".repeat(64).as_str()));
                let object = serde_json::to_value(row).unwrap();
                let keys: std::collections::BTreeSet<_> = object
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect();
                assert_eq!(
                    keys,
                    [
                        "credential_id",
                        "rp_id",
                        "name",
                        "display_name",
                        "user_handle",
                        "discoverable",
                        "algorithm"
                    ]
                    .into_iter()
                    .collect()
                );
                found.push(row.credential_id.clone());
            }
            if let Some(next) = rows.next_offset {
                assert_eq!(next, offset + rows.items.len());
                assert!(next > offset);
                offset = next;
            } else {
                break;
            }
        }
        assert_eq!(
            found,
            state
                .credentials
                .iter()
                .map(|c| hex(&c.id))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn empty_missing_names_and_invalid_or_stale_pages_are_explicit() {
        let empty = page(&State::default(), "first".into(), 0, None);
        assert_eq!(empty.credentials.unwrap().total, 0);
        let mut record = credential(0);
        record.user.name = None;
        record.user.display_name = None;
        let state = State {
            credentials: vec![record],
            pin: None,
        };
        let first = page(&state, "first".into(), 0, None);
        let item = &first.credentials.unwrap().items[0];
        assert!(item.name.is_none() && item.display_name.is_none());
        for (offset, revision) in [(1, None), (0, Some("old")), (2, Some("first"))] {
            let rejected = page(&state, "first".into(), offset, revision);
            assert!(!rejected.ok);
            assert!(rejected.credentials.is_none());
        }
    }
}
