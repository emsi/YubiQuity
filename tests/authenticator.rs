use ciborium::Value;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use yubiquity::authenticator::{Authenticator, CtapResult, Prompt, RequestContext, Status};
use yubiquity::cbor::{self, bytes, get, int, map, text};
use yubiquity::store::{MemoryStore, State, Store, StoreError};

struct Consent {
    now: u64,
    approve: bool,
    cancelled: bool,
    cancel_on_presence: bool,
    prompts: usize,
}
impl Default for Consent {
    fn default() -> Self {
        Self {
            now: 0,
            approve: true,
            cancelled: false,
            cancel_on_presence: false,
            prompts: 0,
        }
    }
}
impl RequestContext for Consent {
    fn now_ms(&self) -> u64 {
        self.now
    }
    fn cancelled(&self) -> bool {
        self.cancelled
    }
    fn presence(&mut self, _prompt: Prompt) -> CtapResult<()> {
        self.prompts += 1;
        self.cancelled |= self.cancel_on_presence;
        if self.approve {
            Ok(())
        } else {
            Err(Status::OperationDenied)
        }
    }
}

fn request(command: u8, value: Value) -> Vec<u8> {
    let mut data = vec![command];
    data.extend(cbor::encode(&value));
    data
}
fn make(user: &[u8], resident: bool) -> Vec<u8> {
    request(
        1,
        map([
            (int(1), bytes(&[1; 32])),
            (int(2), map([(text("id"), text("example.test"))])),
            (
                int(3),
                map([
                    (text("id"), bytes(user)),
                    (text("name"), text("alice")),
                    (text("displayName"), text("Alice")),
                ]),
            ),
            (
                int(4),
                Value::Array(vec![map([
                    (text("type"), text("public-key")),
                    (text("alg"), int(-7)),
                ])]),
            ),
            (int(7), map([(text("rk"), Value::Bool(resident))])),
        ]),
    )
}
fn assertion(rp: &str, ids: Option<&[Vec<u8>]>, up: bool) -> Vec<u8> {
    let mut parameters = vec![
        (int(1), text(rp)),
        (int(2), bytes(&[2; 32])),
        (int(5), map([(text("up"), Value::Bool(up))])),
    ];
    if let Some(ids) = ids {
        parameters.push((
            int(3),
            Value::Array(
                ids.iter()
                    .map(|id| map([(text("type"), text("public-key")), (text("id"), bytes(id))]))
                    .collect(),
            ),
        ));
    }
    request(2, map(parameters))
}
fn success(response: Vec<u8>) -> Value {
    assert_eq!(response[0], 0, "CTAP error: {response:?}");
    cbor::decode(&response[1..]).unwrap()
}
fn registered(response: &Value) -> (Vec<u8>, Value) {
    let data = get(response, &int(2)).unwrap().as_bytes().unwrap();
    assert_eq!(data[32], 0x41);
    assert_eq!(&data[33..37], &[0; 4]);
    let length = u16::from_be_bytes(data[53..55].try_into().unwrap()) as usize;
    (
        data[55..55 + length].to_vec(),
        cbor::decode(&data[55 + length..]).unwrap(),
    )
}
fn assert_status(result: Vec<u8>, status: Status) {
    assert_eq!(result, [status as u8]);
}

#[test]
fn independent_keys_and_verifiable_assertion_structure() {
    let mut auth = Authenticator::software(MemoryStore::default(), 0);
    let mut ctx = Consent::default();
    let first = success(auth.execute(1, &make(b"alice", false), &mut ctx));
    assert_eq!(get(&first, &int(1)), Some(&text("none")));
    assert!(get(&first, &int(3)).unwrap().as_map().unwrap().is_empty());
    let (id, public) = registered(&first);
    let second = success(auth.execute(1, &make(b"alice", false), &mut ctx));
    let (id2, public2) = registered(&second);
    assert_ne!(id, id2);
    assert_ne!(public, public2);
    let response =
        success(auth.execute(1, &assertion("example.test", Some(&[id]), true), &mut ctx));
    let data = get(&response, &int(2)).unwrap().as_bytes().unwrap();
    assert_eq!(data[32], 1);
    assert_eq!(&data[33..37], &[0; 4]);
    let mut sec1 = vec![4];
    sec1.extend(get(&public, &int(-2)).unwrap().as_bytes().unwrap());
    sec1.extend(get(&public, &int(-3)).unwrap().as_bytes().unwrap());
    let verifier = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let signature =
        Signature::from_der(get(&response, &int(3)).unwrap().as_bytes().unwrap()).unwrap();
    let mut signed = data.clone();
    signed.extend([2; 32]);
    verifier.verify(&signed, &signature).unwrap();
    *signed.last_mut().unwrap() ^= 1;
    assert!(verifier.verify(&signed, &signature).is_err());
    assert_eq!(ctx.prompts, 3);
}

#[test]
fn silent_probes_do_not_prompt_or_invent_up() {
    let mut auth = Authenticator::software(MemoryStore::default(), 0);
    let mut ctx = Consent::default();
    let (id, _) = registered(&success(auth.execute(1, &make(b"a", false), &mut ctx)));
    let result = success(auth.execute(
        1,
        &assertion("example.test", Some(std::slice::from_ref(&id)), false),
        &mut ctx,
    ));
    assert_eq!(get(&result, &int(2)).unwrap().as_bytes().unwrap()[32], 0);
    assert_eq!(ctx.prompts, 1);
    assert_status(
        auth.execute(1, &assertion("wrong.test", Some(&[id]), false), &mut ctx),
        Status::NoCredentials,
    );
    assert_status(
        auth.execute(1, &assertion("example.test", None, false), &mut ctx),
        Status::NoCredentials,
    );
}

#[test]
fn resident_replacement_accounts_privacy_and_enumeration() {
    let mut auth = Authenticator::software(MemoryStore::default(), 0);
    let mut ctx = Consent::default();
    let (old, _) = registered(&success(auth.execute(1, &make(b"a", true), &mut ctx)));
    success(auth.execute(1, &make(b"a", true), &mut ctx));
    let (newest, _) = registered(&success(auth.execute(1, &make(b"b", true), &mut ctx)));
    assert_eq!(auth.state().credentials.len(), 2);
    assert_status(
        auth.execute(1, &assertion("example.test", Some(&[old]), false), &mut ctx),
        Status::NoCredentials,
    );
    let first = success(auth.execute(1, &assertion("example.test", None, true), &mut ctx));
    assert_eq!(get(&first, &int(5)), Some(&int(2)));
    assert_eq!(
        get(get(&first, &int(1)).unwrap(), &text("id")),
        Some(&bytes(&newest))
    );
    assert_eq!(get(&first, &int(4)).unwrap().as_map().unwrap().len(), 1); // user ID only without UV
    let second = success(auth.execute(1, &[8], &mut ctx));
    assert_eq!(
        get(get(&second, &int(4)).unwrap(), &text("id")),
        Some(&bytes(b"a"))
    );
    assert!(get(&second, &int(5)).is_none());
    assert_status(auth.execute(1, &[8], &mut ctx), Status::NotAllowed);
    assert_eq!(ctx.prompts, 4); // getNextAssertion does not prompt again
}

#[test]
fn enumeration_is_channel_scoped_expires_and_is_invalidated() {
    let mut auth = Authenticator::software(MemoryStore::default(), 0);
    let mut ctx = Consent::default();
    success(auth.execute(1, &make(b"a", true), &mut ctx));
    success(auth.execute(1, &make(b"b", true), &mut ctx));
    success(auth.execute(1, &assertion("example.test", None, true), &mut ctx));
    assert_status(auth.execute(2, &[8], &mut ctx), Status::NotAllowed);
    success(auth.execute(1, &assertion("example.test", None, true), &mut ctx));
    ctx.now = 30_001;
    assert_status(auth.execute(1, &[8], &mut ctx), Status::NotAllowed);
    success(auth.execute(1, &assertion("example.test", None, true), &mut ctx));
    success(auth.execute(1, &[4], &mut ctx));
    assert_status(auth.execute(1, &[8], &mut ctx), Status::NotAllowed);
    success(auth.execute(1, &assertion("example.test", None, true), &mut ctx));
    auth.invalidate();
    assert_status(auth.execute(1, &[8], &mut ctx), Status::NotAllowed);
}

#[test]
fn unknown_credential_type_cannot_turn_allow_list_into_discovery() {
    let mut auth = Authenticator::software(MemoryStore::default(), 0);
    let mut ctx = Consent::default();
    success(auth.execute(1, &make(b"a", true), &mut ctx));
    let parameters = map([
        (int(1), text("example.test")),
        (int(2), bytes(&[2; 32])),
        (
            int(3),
            Value::Array(vec![map([
                (text("type"), text("unknown")),
                (text("id"), bytes(b"ignored")),
            ])]),
        ),
    ]);
    assert_status(
        auth.execute(1, &request(2, parameters), &mut ctx),
        Status::NoCredentials,
    );
    success(auth.execute(1, &assertion("example.test", Some(&[]), false), &mut ctx));
}

#[test]
fn deny_and_cancel_never_create_a_credential() {
    let mut auth = Authenticator::software(MemoryStore::default(), 0);
    let mut ctx = Consent {
        approve: false,
        ..Consent::default()
    };
    assert_status(
        auth.execute(1, &make(b"a", true), &mut ctx),
        Status::OperationDenied,
    );
    ctx.approve = true;
    ctx.cancel_on_presence = true;
    assert_status(
        auth.execute(1, &make(b"a", true), &mut ctx),
        Status::Cancelled,
    );
    assert!(auth.state().credentials.is_empty());
}

#[test]
fn exclusion_requires_presence_and_exact_rp() {
    let mut auth = Authenticator::software(MemoryStore::default(), 0);
    let mut ctx = Consent::default();
    let (id, _) = registered(&success(auth.execute(1, &make(b"a", false), &mut ctx)));
    let mut value = cbor::decode(&make(b"b", false)[1..]).unwrap();
    value.as_map_mut().unwrap().push((
        int(5),
        Value::Array(vec![map([
            (text("type"), text("public-key")),
            (text("id"), bytes(&id)),
        ])]),
    ));
    assert_status(
        auth.execute(1, &request(1, value.clone()), &mut ctx),
        Status::CredentialExcluded,
    );
    assert_eq!(ctx.prompts, 2);
    for (k, v) in value.as_map_mut().unwrap() {
        if *k == int(2) {
            *v = map([(text("id"), text("another.test"))]);
        }
    }
    success(auth.execute(1, &request(1, value), &mut ctx));
}

struct FailingStore(State);
impl Store for FailingStore {
    fn state(&self) -> &State {
        &self.0
    }
    fn commit(&mut self, _next: State) -> Result<(), StoreError> {
        Err(StoreError)
    }
}

#[test]
fn failed_commit_cannot_return_registration_success() {
    let mut auth = Authenticator::software(FailingStore(State::default()), 0);
    let mut ctx = Consent::default();
    assert_status(auth.execute(1, &make(b"a", true), &mut ctx), Status::Other);
    assert!(auth.state().credentials.is_empty());
}

#[test]
fn reset_window_and_denial() {
    let mut auth = Authenticator::software(MemoryStore::default(), 0);
    let mut ctx = Consent::default();
    success(auth.execute(1, &make(b"a", true), &mut ctx));
    ctx.approve = false;
    assert_status(auth.execute(1, &[7], &mut ctx), Status::OperationDenied);
    assert_eq!(auth.state().credentials.len(), 1);
    ctx.approve = true;
    ctx.now = 10_001;
    assert_status(auth.execute(1, &[7], &mut ctx), Status::NotAllowed);
    ctx.now = 9999;
    assert_eq!(auth.execute(1, &[7], &mut ctx), [0]);
    assert!(auth.state().credentials.is_empty());
}

#[test]
fn malformed_input_and_unsupported_uv_fail_without_prompts() {
    let mut auth = Authenticator::software(MemoryStore::default(), 0);
    let mut ctx = Consent::default();
    assert_status(auth.execute(1, &[1, 0xff], &mut ctx), Status::InvalidCbor);
    assert_status(
        auth.execute(1, &request(1, map([])), &mut ctx),
        Status::MissingParameter,
    );
    let mut value = cbor::decode(&make(b"a", true)[1..]).unwrap();
    for (k, v) in value.as_map_mut().unwrap() {
        if *k == int(7) {
            *v = map([(text("uv"), Value::Bool(true))]);
        }
    }
    assert_status(
        auth.execute(1, &request(1, value), &mut ctx),
        Status::UnsupportedOption,
    );
    assert_eq!(ctx.prompts, 0);
}
