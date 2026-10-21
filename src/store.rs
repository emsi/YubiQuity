//! State and durable-commit boundary. A failed commit must never report success.
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const MAX_CREDENTIALS: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub id: Vec<u8>,
    pub name: Option<String>,
    pub display_name: Option<String>,
}

// Deliberately no Debug implementation: credentials contain signing secrets.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub id: Vec<u8>,
    pub rp_id: String,
    pub user: User,
    pub discoverable: bool,
    pub algorithm: i32,
    pub policy: CredentialPolicy,
    pub(crate) private_key: [u8; 32],
}

/// Baseline policy: request-driven presence, optional PIN-mediated assertion UV,
/// and PIN authentication for registration once a global PIN is configured.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPolicy {
    Ctap20,
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    // Append order is creation order; resident replacement removes then appends.
    pub credentials: Vec<Credential>,
    pub pin: Option<PinState>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinState {
    pub(crate) hash: [u8; 16],
    pub retries: u8,
}

impl Drop for PinState {
    fn drop(&mut self) {
        self.hash.zeroize();
    }
}

#[derive(Debug)]
pub struct StoreError;

pub trait Store: Send {
    fn state(&self) -> &State;
    /// Publish the new state only after its durable write succeeds. Implementations
    /// must fail closed if a partially completed commit makes durability uncertain.
    fn commit(&mut self, next: State) -> Result<(), StoreError>;
}

/// Once a write fails, no operation may use possibly-stale in-memory state.
/// This also covers a write that reached rename but failed directory fsync.
pub(crate) struct GuardedStore<S> {
    inner: S,
    failed: bool,
}

impl<S: Store> GuardedStore<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            failed: false,
        }
    }
    pub fn healthy(&self) -> bool {
        !self.failed
    }
}

impl<S: Store> Store for GuardedStore<S> {
    fn state(&self) -> &State {
        self.inner.state()
    }
    fn commit(&mut self, next: State) -> Result<(), StoreError> {
        if self.failed {
            return Err(StoreError);
        }
        let result = self.inner.commit(next);
        self.failed = result.is_err();
        result
    }
}

/// Explicitly ephemeral development store. Never silently substitutes for a vault.
#[derive(Default)]
pub struct MemoryStore(State);

impl From<State> for MemoryStore {
    fn from(state: State) -> Self {
        Self(state)
    }
}

impl Store for MemoryStore {
    fn state(&self) -> &State {
        &self.0
    }
    fn commit(&mut self, next: State) -> Result<(), StoreError> {
        self.0 = next;
        Ok(())
    }
}
