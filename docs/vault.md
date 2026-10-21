# Encrypted vault v1

The vault is a small, local, whole-file encrypted store, not a hardware boundary.
Normal operation is `init`, then `run --vault PATH`; the daemon unlocks before
attaching the UHID device. The local vault passphrase and browser-mediated
authenticator PIN are independent secrets with different purposes.

## Cryptography and limits

The implementation uses RustCrypto Argon2id v0x13 and XChaCha20-Poly1305. These
are published library interfaces, not new cryptographic primitives.
[Argon2 key derivation](https://docs.rs/argon2/0.5.3/argon2/#key-derivation),
[XChaCha20-Poly1305](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/).

New vaults use 65,536 KiB (64 MiB), three passes, one lane, a fresh random 16-byte
salt and a 32-byte derived encryption key. Each write uses a fresh random 24-byte
nonce. The full header is authenticated as AEAD associated data. A wrong passphrase
and authenticated ciphertext corruption cannot be distinguished reliably; both
produce the explicit “wrong vault passphrase or corrupt/tampered encrypted data”
error. Structural corruption and unsupported versions have separate errors.

Before deriving a key, the reader validates the fixed header, total size and KDF
bounds: 16–128 MiB, 2–6 passes, and 1–4 lanes. Only production defaults are exposed
by the CLI; the lower allowed boundary is used in unit tests. Plaintext is limited
to 1 MiB, credentials to 256, IDs to 32 bytes, RP IDs to 253 bytes, user handles to
64 bytes, and account metadata to 64 UTF-8 bytes per field. The versioned payload
rejects unknown fields/policies, invalid keys, duplicate IDs/resident identities,
unsupported algorithms and impossible retry counts.

Passphrases must be 12–1024 bytes with no NUL or line breaks. This is an input
constraint, not a claim that every 12-byte password is strong. Use a strong,
unique passphrase. The default terminal input disables echo and asks for
confirmation on initialization. Automation must explicitly provide an inherited
descriptor >= 3; one trailing LF is accepted. Stdin remains the approval channel.
Passphrases are not accepted as command arguments or environment variables.

Measured on this development container, release-build CLI unlocks using default
parameters took 134–140 ms (five samples, median 135.38 ms). This includes process
startup and parsing, not just KDF time. Reproduce with:

```bash
cargo build --release --locked
/usr/bin/python3 scripts/benchmark-vault.py
```

## On-disk envelope

All integer fields below are unsigned little-endian. The header is exactly 68
bytes; the following ciphertext includes the 16-byte Poly1305 authentication tag.
The plaintext JSON contains `{version: 1, state: ...}` with credentials and PIN
hash/retry state. ECDH secrets, PIN tokens, temporary blocking and enumeration
state are never persisted.

| Offset | Length | Value |
|---|---|---|
| 0 | 8 | `YQVAULT` followed by NUL |
| 8 | 4 | Envelope version, currently 1 |
| 12 | 4 | Argon2 memory in KiB |
| 16 | 4 | Argon2 passes |
| 20 | 4 | Argon2 lanes |
| 24 | 16 | Random salt |
| 40 | 24 | Fresh write nonce |
| 64 | 4 | Ciphertext-plus-tag length |
| 68 | Variable | Authenticated encrypted payload |

Credential records contain their RP ID, user handle/metadata, discoverability,
ES256 algorithm identifier, explicit CTAP2.0 policy, random ID and P-256 private
key. The stored PIN verifier is the protocol's first 16 bytes of SHA-256(PIN),
protected by the same vault encryption as keys. There is no manufacturer
attestation secret.

`tests/vault_crypto.py` checks this format independently using Argon2 and libsodium
bindings against a disposable fixture. It is not an export/import interface.

## Filesystem safety and writes

The vault directory must be owned by the running unprivileged user with mode
`0700`. Vault and lock files must be regular, owned by that user, mode `0600`, and
have only one hard link. Symlinks in any path component are rejected. Ancestors
must be root- or user-owned and not group/world writable, except trusted
root-owned sticky directories such as `/tmp`. Filenames must be non-hidden and
at most 180 bytes. Parent traversal is rejected. The CLI never changes permissions
on existing directories/files to make an unsafe path pass validation.

All operations are anchored to open, checked directory descriptors. A separate
`.FILENAME.lock` file is exclusively locked for the entire unlocked lifetime.
It is intentionally retained after exit: unlinking and recreating lock files can
split the lock across different inodes. Read/list/delete operations take the same
lock, so stop the daemon first. Locking assumes cooperating processes on a local
filesystem with working `flock`, atomic rename and `fsync` semantics.

Each mutation follows this order:

1. Validate next state and the current file/directory identity and permissions.
2. Serialize in bounded memory and encrypt using a fresh nonce.
3. Exclusively create a random private temporary file in the same directory.
4. Write header/ciphertext and sync the file.
5. Atomically rename it over the selected vault; initialization uses no-replace.
6. Sync the containing directory, then publish the new in-memory state/respond.

PIN retry decrements are committed before checking an attempted PIN; success
resets retries through the same commit path before issuing a token. Registration
is committed before returning success. If any commit fails, the encryption key
is cleared, subsequent credential commands are rejected, and the service detaches
and exits nonzero. The user must reopen the vault to determine the stored state.
In particular, rename followed by directory-sync failure has uncertain durability:
the implementation never reports success in that case.

Ordinary failures clean up only their own temporary inode. SIGKILL/power loss
during writing can leave an encrypted `.yubiquity-write-*` file; it is never loaded
as a vault or automatically promoted on restart. No plaintext is written to disk.
Tests inject failures at write, partial-write, file-sync, rename and directory-sync
boundaries, and use a real file-size resource limit to force `EFBIG` in the daemon.

## Locking, deletion and security limits

Typing `lock`/`quit`, closing stdin, or sending the normal termination signal cancels work, detaches
the device, drops transient PIN/approval state and releases the writer lock.
Derived keys, credential keys, PIN hashes, decrypt/serialize buffers and Argon2
working memory are zeroized where practical. The CLI disables core dumps and
ordinary process dumping. These measures do not prove that all secret copies
are absent from memory, swap, snapshots, crash infrastructure or privileged tools.

Deletion requires an exact full credential ID, the explicit vault path and
`--confirm`. It removes the selected record only after a durable write. It is not
secure erasure of old ciphertext or filesystem snapshots. There is no supported
credential export, backup/restore, sync or recovery workflow, and forgetting the
vault passphrase means losing access. Keep tests disposable.

This design trusts the browser, daemon, local user account, OS and filesystem.
It does not prevent a compromised user/root/kernel from reading an unlocked key,
replacing files or rolling back a saved vault, including PIN retry state. It is
not rollback-resistant hardware storage. Signature counters remain zero and
backup eligibility/state flags remain zero. None of these flags proves hardware
protection.
