#![no_main]
use ciborium::Value;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use yubiquity::authenticator::{Authenticator, CtapResult, Prompt, RequestContext, Status};
use yubiquity::cbor::{self, bytes, int, map, text};
use yubiquity::crypto::{RandomSource, SoftwareSigner};
use yubiquity::hid::MAX_MESSAGE;
use yubiquity::store::{MemoryStore, State, MAX_CREDENTIALS};

// Deliberately predictable test-only randomness, never linked into the daemon.
struct TestRandom(u8);
impl RandomSource for TestRandom {
    fn fill(&mut self, output: &mut [u8]) -> CtapResult<()> {
        for byte in output {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}
struct Context {
    cancelled: bool,
}
impl RequestContext for Context {
    fn now_ms(&self) -> u64 {
        1
    }
    fn cancelled(&self) -> bool {
        self.cancelled
    }
    fn presence(&mut self, _: Prompt) -> CtapResult<()> {
        Ok(())
    }
}
fn authenticator(state: State) -> Authenticator<MemoryStore> {
    Authenticator::new(
        state.into(),
        Box::new(SoftwareSigner),
        Box::new(TestRandom(97)),
        0,
    )
}
fn initial_state() -> State {
    static INITIAL: OnceLock<State> = OnceLock::new();
    INITIAL
        .get_or_init(|| {
            let mut auth = authenticator(State::default());
            for user in [b"alice".as_slice(), b"bob"] {
                let request = map([
                    (int(1), bytes(&[0; 32])),
                    (int(2), map([(text("id"), text("example.test"))])),
                    (int(3), map([(text("id"), bytes(user))])),
                    (
                        int(4),
                        Value::Array(vec![map([
                            (text("alg"), int(-7)),
                            (text("type"), text("public-key")),
                        ])]),
                    ),
                    (int(7), map([(text("rk"), Value::Bool(true))])),
                ]);
                let mut input = vec![1];
                input.extend(cbor::encode(&request));
                assert_eq!(
                    auth.execute(1, &input, &mut Context { cancelled: false })[0],
                    0
                );
            }
            auth.state().clone()
        })
        .clone()
}
fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_MESSAGE + 1 {
        return;
    }
    let mut auth = authenticator(initial_state());
    let mut context = Context { cancelled: false };
    let response = auth.execute(1, input, &mut context);
    assert!(!response.is_empty() && response.len() <= MAX_MESSAGE);
    if response[0] == 0 && response.len() > 1 {
        cbor::decode(&response[1..]).expect("successful command returned malformed CBOR");
    }
    // Exercise enumeration continuation, invalidation, and wrong-channel scope.
    for channel in [1, 2, 1] {
        let next = auth.execute(channel, &[8], &mut context);
        assert!(!next.is_empty() && next.len() <= MAX_MESSAGE);
    }
    assert!(auth.state().credentials.len() <= MAX_CREDENTIALS);
    if let Some(pin) = &auth.state().pin {
        assert!(pin.retries <= 8);
    }
    context.cancelled = true;
    assert_eq!(
        auth.execute(1, input, &mut context),
        [Status::Cancelled as u8]
    );
});
