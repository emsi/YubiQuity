//! Cryptographic operations use RustCrypto implementations; no custom primitives.
use crate::authenticator::{CtapResult, Status};
use crate::cbor::{bytes, int, map};
use ciborium::Value;
use p256::{
    ecdsa::{signature::Signer as _, Signature, SigningKey},
    SecretKey,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

pub trait RandomSource: Send {
    fn fill(&mut self, output: &mut [u8]) -> CtapResult<()>;
}

pub struct OsRandom;
impl RandomSource for OsRandom {
    fn fill(&mut self, output: &mut [u8]) -> CtapResult<()> {
        OsRng.try_fill_bytes(output).map_err(|_| Status::Other)
    }
}

pub trait CredentialSigner: Send {
    fn generate(&self, random: &mut dyn RandomSource) -> CtapResult<Zeroizing<[u8; 32]>>;
    fn public_key(&self, key: &[u8; 32]) -> CtapResult<Value>;
    fn sign(&self, key: &[u8; 32], data: &[u8]) -> CtapResult<Vec<u8>>;
}

pub struct SoftwareSigner;
impl CredentialSigner for SoftwareSigner {
    fn generate(&self, random: &mut dyn RandomSource) -> CtapResult<Zeroizing<[u8; 32]>> {
        let mut candidate = Zeroizing::new([0u8; 32]);
        // Bounded rejection sampling; a faulty injected RNG must not hang forever.
        for _ in 0..16 {
            random.fill(candidate.as_mut())?;
            if SecretKey::from_slice(candidate.as_ref()).is_ok() {
                return Ok(candidate);
            }
        }
        Err(Status::Other)
    }
    fn public_key(&self, key: &[u8; 32]) -> CtapResult<Value> {
        let signing = SigningKey::from_slice(key).map_err(|_| Status::Other)?;
        let point = signing.verifying_key().to_encoded_point(false);
        Ok(map([
            (int(1), int(2)),  // EC2
            (int(3), int(-7)), // ES256
            (int(-1), int(1)), // P-256
            (int(-2), bytes(point.x().ok_or(Status::Other)?)),
            (int(-3), bytes(point.y().ok_or(Status::Other)?)),
        ]))
    }
    fn sign(&self, key: &[u8; 32], data: &[u8]) -> CtapResult<Vec<u8>> {
        let signing = SigningKey::from_slice(key).map_err(|_| Status::Other)?;
        // The Signer implementation hashes data with SHA-256 and uses RFC6979.
        let signature: Signature = signing.try_sign(data).map_err(|_| Status::Other)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
