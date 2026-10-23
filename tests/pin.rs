use aes::Aes256;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use ciborium::Value;
use hmac::{Hmac, Mac};
use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use yubiquity::authenticator::{Authenticator, CtapResult, Prompt, RequestContext, Status};
use yubiquity::cbor::{self, bytes, get, int, map, text};
use yubiquity::store::{MemoryStore, State, Store, StoreError};
use yubiquity::vault::Vault;

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
    fn change<S: Store>(
        &self,
        auth: &mut Authenticator<S>,
        current: &str,
        new: &str,
    ) -> Result<Value, u8> {
        let mut plain = new.as_bytes().to_vec();
        plain.resize(64, 0);
        let encrypted = encrypt(&self.shared, &plain);
        let hash = encrypt(&self.shared, &Sha256::digest(current.as_bytes())[..16]);
        let mut message = encrypted.clone();
        message.extend(&hash);
        call(
            auth,
            6,
            map([
                (int(1), int(1)),
                (int(2), int(4)),
                (int(3), self.peer.clone()),
                (int(4), bytes(&mac(&self.shared, &message))),
                (int(5), bytes(&encrypted)),
                (int(6), bytes(&hash)),
            ]),
        )
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
fn wrong_pins_never_block_verification_or_change_even_across_restarts() {
    let mut auth = initialized();
    for _ in 0..2 {
        // Cross both old lockout thresholds and the former u8 counter range.
        for _ in 0..260 {
            let client = Client::new(&mut auth);
            assert_eq!(
                client.token(&mut auth, "wrong"),
                Err(Status::PinInvalid as u8)
            );
            let client = Client::new(&mut auth);
            assert_eq!(
                client.change(&mut auth, "wrong", "5678"),
                Err(Status::PinInvalid as u8)
            );
        }
        let response = call(&mut auth, 6, map([(int(1), int(1)), (int(2), int(1))])).unwrap();
        assert_eq!(get(&response, &int(3)), Some(&int(8)));
        let client = Client::new(&mut auth);
        assert_eq!(client.token(&mut auth, "1234").unwrap().len(), 32);
        auth = Authenticator::software(MemoryStore::from(auth.state().clone()), 0);
    }
    let client = Client::new(&mut auth);
    client.change(&mut auth, "1234", "5678").unwrap();
    assert_eq!(client.token(&mut auth, "5678").unwrap().len(), 32);
}

#[test]
fn legacy_retry_values_including_zero_cannot_block_the_pin() {
    for retries in 0..=8 {
        let mut state = initialized().state().clone();
        state.pin.as_mut().unwrap().retries = retries;
        let mut auth = Authenticator::software(MemoryStore::from(state), 0);
        let response = call(&mut auth, 6, map([(int(1), int(1)), (int(2), int(1))])).unwrap();
        assert_eq!(get(&response, &int(3)), Some(&int(8)));
        let client = Client::new(&mut auth);
        let token = client.token(&mut auth, "1234").unwrap();
        assert_eq!(
            pin_assertion(&mut auth, &token),
            Err(Status::NoCredentials as u8)
        );
        client.change(&mut auth, "1234", "5678").unwrap();
        assert_eq!(client.token(&mut auth, "5678").unwrap().len(), 32);
    }
}

#[test]
fn a_previously_blocked_vault_reopens_without_reset_or_credential_loss() {
    let mut auth = initialized();
    let client = Client::new(&mut auth);
    let token = client.token(&mut auth, "1234").unwrap();
    call(
        &mut auth,
        1,
        map([
            (int(1), bytes(&[7; 32])),
            (int(2), map([(text("id"), text("example.test"))])),
            (int(3), map([(text("id"), bytes(b"alice"))])),
            (
                int(4),
                Value::Array(vec![map([
                    (text("type"), text("public-key")),
                    (text("alg"), int(-7)),
                ])]),
            ),
            (int(7), map([(text("rk"), Value::Bool(true))])),
            (int(8), bytes(&mac(&token, &[7; 32]))),
            (int(9), int(1)),
        ]),
    )
    .unwrap();
    let credential_id = auth.state().credentials[0].id.clone();
    let mut legacy = auth.state().clone();
    legacy.pin.as_mut().unwrap().retries = 0;
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = directory.path().join("legacy.yq");
    let password = b"disposable test passphrase";
    let mut vault = Vault::create(&path, password).unwrap();
    vault.commit(legacy).unwrap();
    drop(vault);
    let original = std::fs::read(&path).unwrap();
    let vault = Vault::open(&path, password).unwrap();
    let mut auth = Authenticator::software(vault, 0);
    let client = Client::new(&mut auth);
    let token = client.token(&mut auth, "1234").unwrap();
    let assertion = pin_assertion(&mut auth, &token).unwrap();
    assert_eq!(
        get(get(&assertion, &int(1)).unwrap(), &text("id")),
        Some(&bytes(&credential_id))
    );
    assert_eq!(std::fs::read(&path).unwrap(), original);
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
            return Err(StoreError::Failed);
        }
        self.state = next;
        Ok(())
    }
}

#[test]
fn checking_pins_does_not_write_but_setting_or_changing_still_requires_durability() {
    for configured in [false, true] {
        let state = if configured {
            initialized().state().clone()
        } else {
            State::default()
        };
        let mut auth = Authenticator::software(
            FailWrite {
                state,
                calls: 0,
                fail_at: 1,
            },
            0,
        );
        if configured {
            for _ in 0..16 {
                let client = Client::new(&mut auth);
                assert_eq!(
                    client.token(&mut auth, "wrong"),
                    Err(Status::PinInvalid as u8)
                );
            }
            let client = Client::new(&mut auth);
            let token = client.token(&mut auth, "1234").unwrap();
            assert_eq!(
                pin_assertion(&mut auth, &token),
                Err(Status::NoCredentials as u8)
            );
            assert_eq!(
                client.change(&mut auth, "1234", "5678"),
                Err(Status::Other as u8)
            );
        } else {
            let client = Client::new(&mut auth);
            assert_eq!(client.set(&mut auth, "1234"), Err(Status::Other as u8));
        }
        // Fail closed even for a metadata read; don't keep using uncertain state.
        assert_eq!(auth.execute(1, &[4], &mut Consent), [Status::Other as u8]);
        assert_eq!(auth.execute(1, &[7], &mut Consent), [Status::Other as u8]);
    }
}

#[test]
fn invalid_token_authentication_never_blocks_a_valid_token() {
    let mut auth = initialized();
    let client = Client::new(&mut auth);
    let token = client.token(&mut auth, "1234").unwrap();
    for _ in 0..260 {
        assert_eq!(
            pin_assertion(&mut auth, &[0; 32]),
            Err(Status::PinAuthInvalid as u8)
        );
    }
    assert_eq!(
        pin_assertion(&mut auth, &token),
        Err(Status::NoCredentials as u8)
    );
}

#[test]
fn desktop_pin_setup_interoperates_with_ctap_and_invalidates_old_tokens() {
    let mut auth = Authenticator::software(MemoryStore::default(), 0);
    auth.configure_pin(b"", b"1234", &Consent).unwrap();
    let client = Client::new(&mut auth);
    let token = client.token(&mut auth, "1234").unwrap();
    for _ in 0..20 {
        assert_eq!(
            auth.configure_pin(b"wrong", b"5678", &Consent),
            Err(Status::PinInvalid)
        );
    }
    // A stale setup window cannot replace an already configured PIN.
    assert_eq!(
        auth.configure_pin(b"", b"5678", &Consent),
        Err(Status::PinInvalid)
    );
    for invalid in [b"123".as_slice(), b"1234\0", "🔑🔑".as_bytes(), &[b'a'; 64]] {
        assert_eq!(
            auth.configure_pin(b"1234", invalid, &Consent),
            Err(Status::PinPolicyViolation)
        );
    }
    auth.configure_pin(b"1234", b"5678", &Consent).unwrap();
    let client = Client::new(&mut auth);
    let fresh = client.token(&mut auth, "5678").unwrap();
    assert_ne!(token, fresh);
    assert_eq!(
        client.token(&mut auth, "1234"),
        Err(Status::PinInvalid as u8)
    );
    let client = Client::new(&mut auth);
    client.token(&mut auth, "5678").unwrap();
}

#[test]
fn cancelled_desktop_pin_setup_does_not_mutate_vault() {
    struct Cancelled;
    impl RequestContext for Cancelled {
        fn now_ms(&self) -> u64 {
            0
        }
        fn cancelled(&self) -> bool {
            true
        }
        fn presence(&mut self, _: Prompt) -> CtapResult<()> {
            panic!("local setup must not ask presence")
        }
    }
    let mut auth = Authenticator::software(MemoryStore::default(), 0);
    assert_eq!(
        auth.configure_pin(b"", b"1234", &Cancelled),
        Err(Status::Cancelled)
    );
    assert!(auth.state().pin.is_none());
}
