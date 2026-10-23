//! CTAP credential operations independent of transport, UI, clock and storage.
use crate::cbor::{self, bytes, get, int, map, text};
use crate::crypto::{CredentialSigner, OsRandom, RandomSource, SoftwareSigner};
use crate::ctap::AAGUID;
use crate::pin::PinRuntime;
use crate::store::{Credential, CredentialPolicy, GuardedStore, State, Store, StoreError, User};
use ciborium::Value;
use sha2::{Digest, Sha256};

pub type CtapResult<T> = Result<T, Status>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    UnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    CredentialExcluded = 0x19,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    KeyStoreFull = 0x28,
    UnsupportedOption = 0x2b,
    InvalidOption = 0x2c,
    Cancelled = 0x2d,
    NoCredentials = 0x2e,
    UserActionTimeout = 0x2f,
    NotAllowed = 0x30,
    PinInvalid = 0x31,
    PinAuthInvalid = 0x33,
    PinNotSet = 0x35,
    PinRequired = 0x36,
    PinPolicyViolation = 0x37,
    Other = 0x7f,
}

#[derive(Debug, Clone)]
pub struct Prompt {
    pub operation: &'static str,
    pub rp_id: String,
    pub account: Option<String>,
}

/// A single request's authorization context. Implementations bind approval to
/// the request, honor cancellation, and return to PROCESSING after presence.
pub trait RequestContext {
    fn now_ms(&self) -> u64;
    fn cancelled(&self) -> bool;
    fn presence(&mut self, prompt: Prompt) -> CtapResult<()>;
}

struct Enumeration {
    channel: u32,
    ids: Vec<Vec<u8>>,
    next: usize,
    hash: [u8; 32],
    up: bool,
    uv: bool,
    last_ms: u64,
}

pub struct Authenticator<S: Store> {
    store: GuardedStore<S>,
    signer: Box<dyn CredentialSigner>,
    random: Box<dyn RandomSource>,
    enumeration: Option<Enumeration>,
    attached_ms: u64,
    pin: PinRuntime,
}

impl<S: Store> Authenticator<S> {
    pub fn software(store: S, attached_ms: u64) -> Self {
        Self::new(
            store,
            Box::new(SoftwareSigner),
            Box::new(OsRandom),
            attached_ms,
        )
    }

    pub fn new(
        store: S,
        signer: Box<dyn CredentialSigner>,
        random: Box<dyn RandomSource>,
        attached_ms: u64,
    ) -> Self {
        Self {
            store: GuardedStore::new(store),
            signer,
            random,
            enumeration: None,
            attached_ms,
            pin: PinRuntime::default(),
        }
    }

    pub fn state(&self) -> &State {
        self.store.state()
    }
    pub fn healthy(&self) -> bool {
        self.store.healthy()
    }
    pub fn configure_pin(
        &mut self,
        current: &[u8],
        new: &[u8],
        context: &dyn RequestContext,
    ) -> CtapResult<()> {
        if !self.healthy() {
            return Err(Status::Other);
        }
        self.invalidate();
        self.pin.configure(&mut self.store, current, new, context)
    }
    pub fn invalidate(&mut self) {
        self.enumeration = None;
    }

    pub fn execute(
        &mut self,
        channel: u32,
        request: &[u8],
        context: &mut dyn RequestContext,
    ) -> Vec<u8> {
        let response = self.dispatch(channel, request, context);
        if context.cancelled() {
            self.invalidate();
            return vec![Status::Cancelled as u8];
        }
        match response {
            Ok(Some(value)) => {
                let mut output = vec![0];
                output.extend(cbor::encode(&value));
                output
            }
            Ok(None) => vec![0],
            Err(error) => {
                self.invalidate();
                vec![error as u8]
            }
        }
    }

    fn dispatch(
        &mut self,
        channel: u32,
        request: &[u8],
        context: &mut dyn RequestContext,
    ) -> CtapResult<Option<Value>> {
        check_cancelled(context)?;
        if !self.store.healthy() {
            return Err(Status::Other);
        }
        let (&command, data) = request.split_first().ok_or(Status::InvalidLength)?;
        if command != 0x08 {
            self.invalidate();
        }
        match command {
            0x01 | 0x02 | 0x06 => {
                let parameters = cbor::decode(data).map_err(|_| Status::InvalidCbor)?;
                as_map(&parameters)?;
                if command == 1 {
                    self.make_credential(&parameters, context).map(Some)
                } else if command == 2 {
                    self.get_assertion(channel, &parameters, context).map(Some)
                } else {
                    self.pin
                        .execute(&parameters, &mut self.store, self.random.as_mut(), context)
                }
            }
            0x04 => {
                if !data.is_empty() {
                    return Err(Status::InvalidLength);
                }
                Ok(Some(self.info()))
            }
            0x07 => {
                if !data.is_empty() {
                    return Err(Status::InvalidLength);
                }
                // Deliberately short power-up reset window, requiring local presence.
                if context.now_ms().saturating_sub(self.attached_ms) > 10_000 {
                    return Err(Status::NotAllowed);
                }
                context.presence(Prompt {
                    operation: "reset",
                    rp_id: String::new(),
                    account: None,
                })?;
                self.commit(State::default(), context)?;
                self.pin = PinRuntime::default();
                Ok(None)
            }
            0x08 => {
                if !data.is_empty() {
                    return Err(Status::InvalidLength);
                }
                self.get_next(channel, context).map(Some)
            }
            _ => Err(Status::InvalidCommand),
        }
    }

    fn info(&self) -> Value {
        map([
            (int(1), Value::Array(vec![text("FIDO_2_0")])),
            (int(2), Value::Array(vec![])),
            (int(3), bytes(&AAGUID)),
            (
                int(4),
                map([
                    (text("rk"), Value::Bool(true)),
                    (text("up"), Value::Bool(true)),
                    (text("plat"), Value::Bool(false)),
                    (
                        text("clientPin"),
                        Value::Bool(self.store.state().pin.is_some()),
                    ),
                ]),
            ),
            (int(5), int(crate::hid::MAX_MESSAGE as i64)),
            (int(6), Value::Array(vec![int(1)])),
            (int(7), int(64)), // maximum credential descriptors per request
            (int(8), int(32)), // credential ID length
            (
                int(10),
                Value::Array(vec![map([
                    (text("type"), text("public-key")),
                    (text("alg"), int(-7)),
                ])]),
            ),
        ])
    }

    fn make_credential(
        &mut self,
        parameters: &Value,
        context: &mut dyn RequestContext,
    ) -> CtapResult<Value> {
        let hash = hash_parameter(required(parameters, &int(1))?)?;
        let rp = required(parameters, &int(2))?;
        as_map(rp)?;
        let rp_id = rp_id(required(rp, &text("id"))?)?;
        if let Some(name) = get(rp, &text("name")) {
            as_text(name)?;
        }
        let user = user_parameter(required(parameters, &int(3))?)?;
        let algorithms = as_array(required(parameters, &int(4))?)?;
        if algorithms.is_empty() || algorithms.len() > 64 {
            return Err(Status::LimitExceeded);
        }
        let mut es256 = false;
        for algorithm in algorithms {
            as_map(algorithm)?;
            let kind = as_text(required(algorithm, &text("type"))?)?;
            let value = as_integer(required(algorithm, &text("alg"))?)?;
            es256 |= kind == "public-key" && value == -7;
        }
        if !es256 {
            return Err(Status::UnsupportedAlgorithm);
        }
        let exclude = descriptor_list(get(parameters, &int(5)))?;
        if let Some(extensions) = get(parameters, &int(6)) {
            as_map(extensions)?;
        }
        let options = options(get(parameters, &int(7)))?;
        if options.up.is_some() {
            return Err(Status::InvalidOption);
        }
        if options.uv == Some(true) {
            return Err(Status::UnsupportedOption);
        }
        let auth = get(parameters, &int(8)).map(as_bytes).transpose()?;
        let protocol = get(parameters, &int(9)).map(as_integer).transpose()?;
        self.select_if_requested(auth, &rp_id, context)?;
        let resident = options.rk.unwrap_or(false);
        let excluded = self
            .store
            .state()
            .credentials
            .iter()
            .any(|c| c.rp_id == rp_id && exclude.contains(&c.id));
        if excluded {
            context.presence(Prompt {
                operation: "register",
                rp_id,
                account: user.name,
            })?;
            check_cancelled(context)?;
            return Err(Status::CredentialExcluded);
        }
        let uv = self
            .pin
            .authorize(self.store.state().pin.as_ref(), &hash, auth, protocol)?;
        if !uv && self.store.state().pin.is_some() {
            return Err(Status::PinRequired);
        }
        // Exclusion also requires approval: don't expose credential membership to
        // an unauthenticated caller through a presence-free registration query.
        context.presence(Prompt {
            operation: "register",
            rp_id: rp_id.clone(),
            account: user.name.clone(),
        })?;
        check_cancelled(context)?;

        let key = self.signer.generate(self.random.as_mut())?;
        let mut id = vec![0; 32];
        let mut unique = false;
        for _ in 0..16 {
            self.random.fill(&mut id)?;
            if !self.store.state().credentials.iter().any(|c| c.id == id) {
                unique = true;
                break;
            }
        }
        if !unique {
            return Err(Status::Other);
        }
        let public = self.signer.public_key(&key)?;
        let mut data = authenticator_data(&rp_id, true, uv, true);
        data.extend(AAGUID);
        data.extend((id.len() as u16).to_be_bytes());
        data.extend(&id);
        data.extend(cbor::encode(&public));
        let mut state = self.store.state().clone();
        if resident {
            state
                .credentials
                .retain(|c| !(c.discoverable && c.rp_id == rp_id && c.user.id == user.id));
        }
        state.credentials.push(Credential {
            id,
            rp_id,
            user,
            discoverable: resident,
            algorithm: -7,
            policy: CredentialPolicy::Ctap20,
            private_key: *key,
        });
        // None attestation binds the credential public key via authData. It makes
        // no attestation-key or manufacturer-trust claim; hash is still validated.
        self.commit(state, context)?;
        Ok(map([
            (int(1), text("none")),
            (int(2), bytes(&data)),
            (int(3), map([])),
        ]))
    }

    fn get_assertion(
        &mut self,
        channel: u32,
        parameters: &Value,
        context: &mut dyn RequestContext,
    ) -> CtapResult<Value> {
        let rp_id = rp_id(required(parameters, &int(1))?)?;
        let hash = hash_parameter(required(parameters, &int(2))?)?;
        let allowed = descriptor_list(get(parameters, &int(3)))?;
        if let Some(extensions) = get(parameters, &int(4)) {
            as_map(extensions)?;
        }
        let options = options(get(parameters, &int(5)))?;
        if options.rk.is_some() {
            return Err(Status::InvalidOption);
        }
        if options.uv == Some(true) {
            return Err(Status::UnsupportedOption);
        }
        let auth = get(parameters, &int(6)).map(as_bytes).transpose()?;
        let protocol = get(parameters, &int(7)).map(as_integer).transpose()?;
        self.select_if_requested(auth, &rp_id, context)?;
        let uv = self
            .pin
            .authorize(self.store.state().pin.as_ref(), &hash, auth, protocol)?;
        let up = options.up.unwrap_or(true);
        // Missing/empty allowList selects only discoverable credentials.
        let discover = match get(parameters, &int(3)) {
            None => true,
            Some(list) => as_array(list)?.is_empty(),
        };
        let mut eligible: Vec<_> = self
            .store
            .state()
            .credentials
            .iter()
            .rev()
            .filter(|c| {
                c.rp_id == rp_id
                    && if discover {
                        c.discoverable
                    } else {
                        allowed.contains(&c.id)
                    }
            })
            .map(|c| c.id.clone())
            .collect();
        if !discover {
            eligible.truncate(1);
        }
        if up {
            let account = if eligible.len() == 1 {
                self.store
                    .state()
                    .credentials
                    .iter()
                    .find(|c| c.id == eligible[0])
                    .and_then(|c| c.user.name.clone())
            } else {
                None
            };
            context.presence(Prompt {
                operation: "authenticate",
                rp_id,
                account,
            })?;
        }
        check_cancelled(context)?;
        if eligible.is_empty() {
            return Err(Status::NoCredentials);
        }
        let first = self.assertion(
            &eligible[0],
            &hash,
            up,
            uv,
            if eligible.len() > 1 {
                Some(eligible.len())
            } else {
                None
            },
        )?;
        if eligible.len() > 1 {
            self.enumeration = Some(Enumeration {
                channel,
                ids: eligible,
                next: 1,
                hash,
                up,
                uv,
                last_ms: context.now_ms(),
            });
        }
        Ok(first)
    }

    fn get_next(&mut self, channel: u32, context: &dyn RequestContext) -> CtapResult<Value> {
        let enumeration = self.enumeration.as_ref().ok_or(Status::NotAllowed)?;
        if enumeration.channel != channel
            || context.now_ms().saturating_sub(enumeration.last_ms) > 30_000
            || enumeration.next >= enumeration.ids.len()
        {
            return Err(Status::NotAllowed);
        }
        check_cancelled(context)?;
        let result = self.assertion(
            &enumeration.ids[enumeration.next],
            &enumeration.hash,
            enumeration.up,
            enumeration.uv,
            None,
        )?;
        let enumeration = self.enumeration.as_mut().unwrap();
        enumeration.next += 1;
        enumeration.last_ms = context.now_ms();
        if enumeration.next == enumeration.ids.len() {
            self.enumeration = None;
        }
        Ok(result)
    }

    fn assertion(
        &self,
        id: &[u8],
        hash: &[u8; 32],
        up: bool,
        uv: bool,
        count: Option<usize>,
    ) -> CtapResult<Value> {
        let credential = self
            .store
            .state()
            .credentials
            .iter()
            .find(|c| c.id == id)
            .ok_or(Status::NoCredentials)?;
        let data = authenticator_data(&credential.rp_id, up, uv, false);
        let mut signed = data.clone();
        signed.extend(hash);
        let signature = self.signer.sign(&credential.private_key, &signed)?;
        let mut response = vec![
            (
                int(1),
                map([(text("type"), text("public-key")), (text("id"), bytes(id))]),
            ),
            (int(2), bytes(&data)),
            (int(3), bytes(&signature)),
        ];
        if credential.discoverable {
            let mut user = vec![(text("id"), bytes(&credential.user.id))];
            if uv {
                if let Some(name) = &credential.user.name {
                    user.push((text("name"), text(name)));
                }
                if let Some(name) = &credential.user.display_name {
                    user.push((text("displayName"), text(name)));
                }
            }
            response.push((int(4), map(user)));
        }
        if let Some(count) = count {
            response.push((int(5), int(count as i64)));
        }
        Ok(map(response))
    }

    fn commit(&mut self, next: State, context: &dyn RequestContext) -> CtapResult<()> {
        check_cancelled(context)?;
        self.store.commit(next).map_err(|error| match error {
            StoreError::Full => Status::KeyStoreFull,
            StoreError::Failed => Status::Other,
        })
    }

    fn select_if_requested(
        &self,
        auth: Option<&[u8]>,
        rp_id: &str,
        context: &mut dyn RequestContext,
    ) -> CtapResult<()> {
        if auth == Some(&[]) {
            // Zero-length pinAuth is device selection, NOT a registration/login
            // approval and never grants UV. It deliberately ignores PIN protocol.
            context.presence(Prompt {
                operation: "select-device",
                rp_id: rp_id.into(),
                account: None,
            })?;
            check_cancelled(context)?;
            return Err(if self.store.state().pin.is_some() {
                Status::PinInvalid
            } else {
                Status::PinNotSet
            });
        }
        Ok(())
    }
}

fn check_cancelled(context: &dyn RequestContext) -> CtapResult<()> {
    if context.cancelled() {
        Err(Status::Cancelled)
    } else {
        Ok(())
    }
}

fn authenticator_data(rp: &str, up: bool, uv: bool, attested: bool) -> Vec<u8> {
    let mut data = Sha256::digest(rp.as_bytes()).to_vec();
    data.push(u8::from(up) | (u8::from(uv) << 2) | (u8::from(attested) << 6));
    data.extend([0; 4]); // consistently zero counter; BE=BS=0
    data
}

pub(crate) fn required<'a>(value: &'a Value, key: &Value) -> CtapResult<&'a Value> {
    get(value, key).ok_or(Status::MissingParameter)
}
pub(crate) fn as_map(value: &Value) -> CtapResult<&[(Value, Value)]> {
    value
        .as_map()
        .map(Vec::as_slice)
        .ok_or(Status::UnexpectedType)
}
pub(crate) fn as_array(value: &Value) -> CtapResult<&[Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(Status::UnexpectedType)
}
pub(crate) fn as_bytes(value: &Value) -> CtapResult<&[u8]> {
    value
        .as_bytes()
        .map(Vec::as_slice)
        .ok_or(Status::UnexpectedType)
}
pub(crate) fn as_text(value: &Value) -> CtapResult<&str> {
    value.as_text().ok_or(Status::UnexpectedType)
}
pub(crate) fn as_integer(value: &Value) -> CtapResult<i64> {
    value
        .as_integer()
        .ok_or(Status::UnexpectedType)?
        .try_into()
        .map_err(|_| Status::InvalidParameter)
}

fn hash_parameter(value: &Value) -> CtapResult<[u8; 32]> {
    as_bytes(value)?
        .try_into()
        .map_err(|_| Status::InvalidLength)
}
fn rp_id(value: &Value) -> CtapResult<String> {
    let id = as_text(value)?;
    if id.is_empty() || id.len() > 253 || id.chars().any(char::is_control) {
        return Err(Status::InvalidParameter);
    }
    Ok(id.into())
}
fn metadata(value: Option<&Value>) -> CtapResult<Option<String>> {
    value
        .map(|v| {
            let text = as_text(v)?;
            let mut end = text.len().min(64);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            Ok(text[..end].into())
        })
        .transpose()
}
fn user_parameter(value: &Value) -> CtapResult<User> {
    as_map(value)?;
    let id = as_bytes(required(value, &text("id"))?)?;
    if id.is_empty() || id.len() > 64 {
        return Err(Status::InvalidLength);
    }
    Ok(User {
        id: id.into(),
        name: metadata(get(value, &text("name")))?,
        display_name: metadata(get(value, &text("displayName")))?,
    })
}

fn descriptor_list(value: Option<&Value>) -> CtapResult<Vec<Vec<u8>>> {
    let Some(value) = value else {
        return Ok(vec![]);
    };
    let list = as_array(value)?;
    if list.len() > 64 {
        return Err(Status::LimitExceeded);
    }
    let mut result = vec![];
    for descriptor in list {
        as_map(descriptor)?;
        let kind = as_text(required(descriptor, &text("type"))?)?;
        let id = as_bytes(required(descriptor, &text("id"))?)?;
        // Unknown credential types are ignored, not interpreted as our keys.
        if kind == "public-key" {
            result.push(id.to_vec());
        }
    }
    Ok(result)
}

#[derive(Default)]
struct Options {
    rk: Option<bool>,
    up: Option<bool>,
    uv: Option<bool>,
}
fn options(value: Option<&Value>) -> CtapResult<Options> {
    let Some(value) = value else {
        return Ok(Options::default());
    };
    let mut result = Options::default();
    for (key, value) in as_map(value)? {
        let key = as_text(key)?;
        let target = match key {
            "rk" => &mut result.rk,
            "up" => &mut result.up,
            "uv" => &mut result.uv,
            _ => continue,
        };
        *target = Some(value.as_bool().ok_or(Status::UnexpectedType)?);
    }
    Ok(result)
}
