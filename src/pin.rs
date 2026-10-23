//! CTAP2.0 ClientPIN protocol 1 with deliberately unlimited attempts.
//! PIN hashes live in the encrypted store; ECDH secrets and tokens live only in
//! this attachment. Failed PINs or token MACs reject only the current request.
use crate::authenticator::{
    as_bytes, as_integer, as_map, required, CtapResult, RequestContext, Status,
};
use crate::cbor::{bytes, int, map};
use crate::crypto::{CredentialSigner, RandomSource, SoftwareSigner};
use crate::store::{PinState, Store};
use aes::Aes256;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use ciborium::Value;
use hmac::{Hmac, Mac};
use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// ClientPIN has no "unlimited" retry value. Always advertise its normal full
// budget, without enforcing or persisting an attempt limit. This intentionally
// differs from CTAP's lockout policy for this software authenticator.
const REPORTED_RETRIES: u8 = 8;

#[derive(Default)]
pub struct PinRuntime {
    agreement: Option<SecretKey>,
    token: Option<Zeroizing<[u8; 32]>>,
}

impl PinRuntime {
    fn rekey(&mut self, random: &mut dyn RandomSource) -> CtapResult<()> {
        // Invalidate first: failed entropy must not preserve the old ECDH key.
        self.agreement = None;
        let key = SoftwareSigner.generate(random)?;
        self.agreement = Some(SecretKey::from_slice(key.as_ref()).map_err(|_| Status::Other)?);
        Ok(())
    }

    fn renew_token(&mut self, random: &mut dyn RandomSource) -> CtapResult<()> {
        self.token = None;
        let mut token = Zeroizing::new([0; 32]);
        random.fill(token.as_mut())?;
        self.token = Some(token);
        Ok(())
    }

    fn ensure_secrets(&mut self, random: &mut dyn RandomSource) -> CtapResult<()> {
        if self.agreement.is_none() {
            self.rekey(random)?;
        }
        if self.token.is_none() {
            self.renew_token(random)?;
        }
        Ok(())
    }

    fn public_key(&self) -> CtapResult<Value> {
        let point = self
            .agreement
            .as_ref()
            .ok_or(Status::Other)?
            .public_key()
            .to_encoded_point(false);
        Ok(map([
            (int(1), int(2)),
            (int(3), int(-25)),
            (int(-1), int(1)),
            (int(-2), bytes(point.x().ok_or(Status::Other)?)),
            (int(-3), bytes(point.y().ok_or(Status::Other)?)),
        ]))
    }

    fn shared_secret(&self, peer: &Value) -> CtapResult<Zeroizing<[u8; 32]>> {
        as_map(peer)?;
        for (key, expected) in [(1, 2), (3, -25), (-1, 1)] {
            if as_integer(required(peer, &int(key))?)? != expected {
                return Err(Status::InvalidParameter);
            }
        }
        let x = as_bytes(required(peer, &int(-2))?)?;
        let y = as_bytes(required(peer, &int(-3))?)?;
        if x.len() != 32 || y.len() != 32 {
            return Err(Status::InvalidParameter);
        }
        let mut point = [0; 65];
        point[0] = 4;
        point[1..33].copy_from_slice(x);
        point[33..].copy_from_slice(y);
        // Validates the curve point, including rejection of infinity/off-curve.
        let peer = PublicKey::from_sec1_bytes(&point).map_err(|_| Status::InvalidParameter)?;
        let secret = self.agreement.as_ref().ok_or(Status::Other)?;
        let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        Ok(Zeroizing::new(
            Sha256::digest(shared.raw_secret_bytes()).into(),
        ))
    }

    pub fn execute<S: Store>(
        &mut self,
        parameters: &Value,
        store: &mut S,
        random: &mut dyn RandomSource,
        context: &dyn RequestContext,
    ) -> CtapResult<Option<Value>> {
        if as_integer(required(parameters, &int(1))?)? != 1 {
            return Err(Status::InvalidParameter);
        }
        let command = as_integer(required(parameters, &int(2))?)?;
        if !(1..=5).contains(&command) {
            return Err(Status::InvalidParameter);
        }
        self.ensure_secrets(random)?;
        match command {
            1 => Ok(Some(map([(int(3), int(REPORTED_RETRIES as i64))]))),
            2 => Ok(Some(map([(int(1), self.public_key()?)]))),
            3 => {
                let peer = required(parameters, &int(3))?;
                let auth = as_bytes(required(parameters, &int(4))?)?;
                let encrypted = new_pin_parameter(required(parameters, &int(5))?)?;
                if store.state().pin.is_some() {
                    return Err(Status::PinAuthInvalid);
                }
                let shared = self.shared_secret(peer)?;
                verify_mac(shared.as_ref(), &[encrypted], auth)?;
                let hash = new_pin_hash(&shared, encrypted)?;
                // Invalidate any earlier token before publishing a new PIN.
                self.renew_token(random)?;
                let mut next = store.state().clone();
                next.pin = Some(PinState {
                    hash: *hash,
                    retries: REPORTED_RETRIES,
                });
                commit(store, next, context)?;
                Ok(None)
            }
            4 | 5 => {
                let peer = required(parameters, &int(3))?;
                let encrypted_hash = as_bytes(required(parameters, &int(6))?)?;
                if encrypted_hash.len() != 16 {
                    return Err(Status::InvalidParameter);
                }
                let change = if command == 4 {
                    Some((
                        as_bytes(required(parameters, &int(4))?)?,
                        new_pin_parameter(required(parameters, &int(5))?)?,
                    ))
                } else {
                    None
                };
                let stored = store.state().pin.as_ref().ok_or(Status::PinNotSet)?;
                let shared = self.shared_secret(peer)?;
                if let Some((auth, encrypted)) = change {
                    verify_mac(shared.as_ref(), &[encrypted, encrypted_hash], auth)?;
                }
                let candidate = decrypt(&shared, encrypted_hash)?;
                if !bool::from(candidate.as_slice().ct_eq(&stored.hash)) {
                    self.rekey(random)?;
                    return Err(Status::PinInvalid);
                }
                if let Some((_, encrypted)) = change {
                    let hash = new_pin_hash(&shared, encrypted)?;
                    self.renew_token(random)?;
                    let mut next = store.state().clone();
                    next.pin = Some(PinState {
                        hash: *hash,
                        retries: REPORTED_RETRIES,
                    });
                    commit(store, next, context)?;
                    Ok(None)
                } else {
                    let token = self.token.as_ref().ok_or(Status::Other)?;
                    Ok(Some(map([(
                        int(2),
                        bytes(&encrypt(&shared, token.as_ref())?),
                    )])))
                }
            }
            _ => unreachable!(),
        }
    }

    /// Validate a PIN-token MAC for MakeCredential/GetAssertion. A successfully
    /// unlocked vault or terminal approval is never a substitute for this check.
    pub fn authorize(
        &mut self,
        stored: Option<&PinState>,
        hash: &[u8; 32],
        auth: Option<&[u8]>,
        protocol: Option<i64>,
    ) -> CtapResult<bool> {
        let Some(auth) = auth else { return Ok(false) };
        if protocol != Some(1) || auth.len() != 16 {
            return Err(Status::PinAuthInvalid);
        }
        stored.ok_or(Status::PinNotSet)?;
        let valid = self
            .token
            .as_ref()
            .is_some_and(|token| verify_mac(token.as_ref(), &[hash], auth).is_ok());
        if !valid {
            return Err(Status::PinAuthInvalid);
        }
        Ok(true)
    }
}

fn commit<S: Store>(
    store: &mut S,
    next: crate::store::State,
    context: &dyn RequestContext,
) -> CtapResult<()> {
    if context.cancelled() {
        return Err(Status::Cancelled);
    }
    store.commit(next).map_err(|_| Status::Other)
}

fn verify_mac(key: &[u8], pieces: &[&[u8]], auth: &[u8]) -> CtapResult<()> {
    if auth.len() != 16 {
        return Err(Status::PinAuthInvalid);
    }
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Status::Other)?;
    for piece in pieces {
        hmac.update(piece);
    }
    hmac.verify_truncated_left(auth)
        .map_err(|_| Status::PinAuthInvalid)
}

fn decrypt(key: &[u8; 32], encrypted: &[u8]) -> CtapResult<Zeroizing<Vec<u8>>> {
    let mut plain = Zeroizing::new(encrypted.to_vec());
    cbc::Decryptor::<Aes256>::new(key.into(), &[0; 16].into())
        .decrypt_padded_mut::<NoPadding>(&mut plain)
        .map_err(|_| Status::InvalidParameter)?;
    Ok(plain)
}

fn encrypt(key: &[u8; 32], plain: &[u8]) -> CtapResult<Zeroizing<Vec<u8>>> {
    let mut encrypted = Zeroizing::new(plain.to_vec());
    cbc::Encryptor::<Aes256>::new(key.into(), &[0; 16].into())
        .encrypt_padded_mut::<NoPadding>(&mut encrypted, plain.len())
        .map_err(|_| Status::Other)?;
    Ok(encrypted)
}

fn new_pin_parameter(value: &Value) -> CtapResult<&[u8]> {
    let encrypted = as_bytes(value)?;
    if !(64..=256).contains(&encrypted.len()) || encrypted.len() % 16 != 0 {
        return Err(Status::PinPolicyViolation);
    }
    Ok(encrypted)
}

fn new_pin_hash(key: &[u8; 32], encrypted: &[u8]) -> CtapResult<Zeroizing<[u8; 16]>> {
    let plain = decrypt(key, encrypted)?;
    let end = plain
        .iter()
        .position(|&b| b == 0)
        .ok_or(Status::PinPolicyViolation)?;
    if !(4..=63).contains(&end) || plain[end..].iter().any(|&b| b != 0) {
        return Err(Status::PinPolicyViolation);
    }
    let pin = std::str::from_utf8(&plain[..end]).map_err(|_| Status::PinPolicyViolation)?;
    if pin.chars().count() < 4 {
        return Err(Status::PinPolicyViolation);
    }
    let digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(pin.as_bytes())));
    let mut hash = Zeroizing::new([0; 16]);
    hash.copy_from_slice(&digest[..16]);
    Ok(hash)
}
