//! Protocol core and Linux transport for a software FIDO2 authenticator.
pub mod authenticator;
pub mod cbor;
pub mod control;
pub mod crypto;
pub mod ctap;
pub mod hid;
pub mod pin;
pub mod secret_input;
pub mod service;
pub mod store;
pub mod uhid;
pub mod vault;
