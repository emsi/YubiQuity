use aes::Aes256;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use ciborium::Value;
use hmac::{Hmac, Mac};
use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use yubiquity::authenticator::{Authenticator, CtapResult, Prompt, RequestContext, Status};
use yubiquity::cbor::{self, bytes, get, int, map, text};
use yubiquity::store::{MemoryStore, State, Store, StoreError};

struct Consent;
impl RequestContext for Consent {
    fn now_ms(&self) -> u64 {
        0
    }
    fn cancelled(&self) -> bool {
        false
    }
    fn presence(&mut self, _: Prompt) -> CtapResult<()> {
        Ok(())
    }
}

fn call<S: Store>(
    auth: &mut Authenticator<S>,
    command: u8,
    parameters: Value,
) -> Result<Value, u8> {
    let mut request = vec![command];
    request.extend(cbor::encode(&parameters));
    let response = auth.execute(1, &request, &mut Consent);
    if response[0] != 0 {
        return Err(response[0]);
    }
    if response.len() == 1 {
        return Ok(Value::Null);
    }
    Ok(cbor::decode(&response[1..]).unwrap())
}

fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    hmac.update(data);
    hmac.finalize().into_bytes()[..16].to_vec()
}
fn encrypt(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut buffer = data.to_vec();
    cbc::Encryptor::<Aes256>::new(key.into(), &[0; 16].into())
        .encrypt_padded_mut::<NoPadding>(&mut buffer, data.len())
        .unwrap();
    buffer
}
fn decrypt(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut buffer = data.to_vec();
    cbc::Decryptor::<Aes256>::new(key.into(), &[0; 16].into())
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .unwrap();
    buffer
}

struct Client {
    shared: [u8; 32],
    peer: Value,
}
impl Client {
    fn new<S: Store>(auth: &mut Authenticator<S>) -> Self {
        let response = call(auth, 6, map([(int(1), int(1)), (int(2), int(2))])).unwrap();
        let public = get(&response, &int(1)).unwrap();
        let mut point = vec![4];
        point.extend(get(public, &int(-2)).unwrap().as_bytes().unwrap());
        point.extend(get(public, &int(-3)).unwrap().as_bytes().unwrap());
        let device_key = PublicKey::from_sec1_bytes(&point).unwrap();
        let private = SecretKey::from_slice(&[0x11; 32]).unwrap(); // test-only key
        let shared = diffie_hellman(private.to_nonzero_scalar(), device_key.as_affine());
        let public = private.public_key().to_encoded_point(false);
        Self {
            shared: Sha256::digest(shared.raw_secret_bytes()).into(),
            peer: map([
                (int(1), int(2)),
                (int(3), int(-25)),
                (int(-1), int(1)),
                (int(-2), bytes(public.x().unwrap())),
                (int(-3), bytes(public.y().unwrap())),
            ]),
        }
    }
    fn set<S: Store>(&self, auth: &mut Authenticator<S>, pin: &str) -> Result<Value, u8> {
        let mut plain = pin.as_bytes().to_vec();
        plain.resize(64, 0);
        let encrypted = encrypt(&self.shared, &plain);
        call(
            auth,
            6,
            map([
                (int(1), int(1)),
                (int(2), int(3)),
                (int(3), self.peer.clone()),
                (int(4), bytes(&mac(&self.shared, &encrypted))),
                (int(5), bytes(&encrypted)),
            ]),
        )
    }
    fn token<S: Store>(&self, auth: &mut Authenticator<S>, pin: &str) -> Result<Vec<u8>, u8> {
        let hash = Sha256::digest(pin.as_bytes());
        let result = call(
            auth,
            6,
            map([
                (int(1), int(1)),
                (int(2), int(5)),
                (int(3), self.peer.clone()),
                (int(6), bytes(&encrypt(&self.shared, &hash[..16]))),
            ]),
        )?;
        Ok(decrypt(
            &self.shared,
            get(&result, &int(2)).unwrap().as_bytes().unwrap(),
        ))
    }
}

fn initialized() -> Authenticator<MemoryStore> {
    let mut auth = Authenticator::software(MemoryStore::default(), 0);
    Client::new(&mut auth).set(&mut auth, "1234").unwrap();
    auth
}
fn pin_assertion<S: Store>(auth: &mut Authenticator<S>, token: &[u8]) -> Result<Value, u8> {
    call(
        auth,
        2,
        map([
            (int(1), text("example.test")),
            (int(2), bytes(&[7; 32])),
            (int(5), map([(text("up"), Value::Bool(false))])),
            (int(6), bytes(&mac(token, &[7; 32]))),
            (int(7), int(1)),
        ]),
    )
}

#[test]
fn restart_preserves_retries_and_clears_only_temporary_blocking() {
    let mut auth = initialized();
    for expected in [
        Status::PinInvalid,
        Status::PinInvalid,
        Status::PinAuthBlocked,
    ] {
        let client = Client::new(&mut auth);
        assert_eq!(client.token(&mut auth, "wrong"), Err(expected as u8));
    }
    assert_eq!(auth.state().pin.as_ref().unwrap().retries, 5);
    let client = Client::new(&mut auth);
    assert_eq!(
        client.token(&mut auth, "1234"),
        Err(Status::PinAuthBlocked as u8)
    );
    let mut reopened = Authenticator::software(MemoryStore::from(auth.state().clone()), 0);
    assert_eq!(reopened.state().pin.as_ref().unwrap().retries, 5);
    let client = Client::new(&mut reopened);
    assert_eq!(client.token(&mut reopened, "1234").unwrap().len(), 32);
    assert_eq!(reopened.state().pin.as_ref().unwrap().retries, 8);
}

#[test]
fn eight_bad_attempts_permanently_block_even_across_restarts() {
    let mut auth = initialized();
    for attempt in 1..=8 {
        let client = Client::new(&mut auth);
        let expected = if attempt == 8 {
            Status::PinBlocked
        } else if attempt % 3 == 0 {
            Status::PinAuthBlocked
        } else {
            Status::PinInvalid
        };
        assert_eq!(client.token(&mut auth, "wrong"), Err(expected as u8));
        assert_eq!(auth.state().pin.as_ref().unwrap().retries, 8 - attempt);
        if attempt % 3 == 0 {
            auth = Authenticator::software(MemoryStore::from(auth.state().clone()), 0);
        }
    }
    let mut reopened = Authenticator::software(MemoryStore::from(auth.state().clone()), 0);
    let client = Client::new(&mut reopened);
    assert_eq!(
        client.token(&mut reopened, "1234"),
        Err(Status::PinBlocked as u8)
    );
    assert_eq!(reopened.execute(1, &[7], &mut Consent), [0]);
    assert!(reopened.state().pin.is_none());
    Client::new(&mut reopened)
        .set(&mut reopened, "1234")
        .unwrap();
}

#[test]
fn restart_invalidates_old_pin_tokens_and_key_agreement() {
    let mut auth = initialized();
    let old_client = Client::new(&mut auth);
    let old_token = old_client.token(&mut auth, "1234").unwrap();
    assert_eq!(
        pin_assertion(&mut auth, &old_token),
        Err(Status::NoCredentials as u8)
    );
    let mut reopened = Authenticator::software(MemoryStore::from(auth.state().clone()), 0);
    assert_eq!(
        pin_assertion(&mut reopened, &old_token),
        Err(Status::PinAuthInvalid as u8)
    );
    assert_eq!(
        old_client.token(&mut reopened, "1234"),
        Err(Status::PinInvalid as u8)
    );
    let new_client = Client::new(&mut reopened);
    let token = new_client.token(&mut reopened, "1234").unwrap();
    assert_ne!(old_token, token);
    assert_eq!(
        pin_assertion(&mut reopened, &token),
        Err(Status::NoCredentials as u8)
    );
}

struct FailWrite {
    state: State,
    calls: usize,
    fail_at: usize,
}
impl Store for FailWrite {
    fn state(&self) -> &State {
        &self.state
    }
    fn commit(&mut self, next: State) -> Result<(), StoreError> {
        self.calls += 1;
        if self.calls == self.fail_at {
            return Err(StoreError);
        }
        self.state = next;
        Ok(())
    }
}

#[test]
fn retry_write_failure_never_issues_token_or_allows_further_operations() {
    for fail_at in [1, 2] {
        let state = initialized().state().clone();
        let mut auth = Authenticator::software(
            FailWrite {
                state,
                calls: 0,
                fail_at,
            },
            0,
        );
        let client = Client::new(&mut auth);
        assert_eq!(client.token(&mut auth, "1234"), Err(Status::Other as u8));
        assert_eq!(
            auth.state().pin.as_ref().unwrap().retries,
            if fail_at == 1 { 8 } else { 7 }
        );
        // Fail closed even for a metadata read; don't keep using uncertain state.
        assert_eq!(auth.execute(1, &[4], &mut Consent), [Status::Other as u8]);
        assert_eq!(auth.execute(1, &[7], &mut Consent), [Status::Other as u8]);
    }
}

#[test]
fn invalid_token_authentication_blocks_until_restart_but_not_permanently() {
    let mut auth = initialized();
    let client = Client::new(&mut auth);
    let token = client.token(&mut auth, "1234").unwrap();
    for error in [
        Status::PinAuthInvalid,
        Status::PinAuthInvalid,
        Status::PinAuthBlocked,
    ] {
        assert_eq!(pin_assertion(&mut auth, &[0; 32]), Err(error as u8));
    }
    assert_eq!(
        pin_assertion(&mut auth, &token),
        Err(Status::PinAuthBlocked as u8)
    );
    assert_eq!(auth.state().pin.as_ref().unwrap().retries, 8);
    let mut reopened = Authenticator::software(MemoryStore::from(auth.state().clone()), 0);
    let client = Client::new(&mut reopened);
    let token = client.token(&mut reopened, "1234").unwrap();
    assert_eq!(
        pin_assertion(&mut reopened, &token),
        Err(Status::NoCredentials as u8)
    );
}
