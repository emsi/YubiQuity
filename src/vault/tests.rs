use super::*;
use crate::store::{Credential, CredentialPolicy, PinState, User};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use tempfile::TempDir;

const PASSWORD: &[u8] = b"a disposable test passphrase";
fn private_temp() -> TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
fn fast_kdf() -> Kdf {
    Kdf {
        memory: 16_384,
        passes: 2,
        lanes: 1,
    }
}
fn create(path: &Path) -> Vault {
    Vault::create_with_kdf(path, PASSWORD, fast_kdf()).unwrap()
}
fn sample() -> State {
    State {
        credentials: vec![Credential {
            id: vec![0x41; 32],
            rp_id: "private.example.test".into(),
            user: User {
                id: b"account-handle".to_vec(),
                name: Some("private-account".into()),
                display_name: Some("Private Account".into()),
            },
            discoverable: true,
            algorithm: -7,
            policy: CredentialPolicy::Ctap20,
            private_key: [3; 32],
        }],
        pin: Some(PinState {
            hash: [7; 16],
            retries: 8,
        }),
    }
}
fn no_temporaries(directory: &Path) {
    assert!(!fs::read_dir(directory).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .as_bytes()
        .starts_with(b".yubiquity-write-")));
}

#[test]
fn round_trip_ciphertext_permissions_and_fresh_nonce() {
    let root = private_temp();
    let path = root.path().join("private/credentials.yq");
    let mut vault = create(&path);
    assert_eq!(
        fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o7777,
        0o700
    );
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    vault.commit(sample()).unwrap();
    let first = fs::read(&path).unwrap();
    for secret in [
        b"private.example.test".as_slice(),
        b"private-account",
        PASSWORD,
    ] {
        assert!(!first.windows(secret.len()).any(|part| part == secret));
    }
    let old_inode = fs::metadata(&path).unwrap().ino();
    vault.commit(vault.state().clone()).unwrap();
    let second = fs::read(&path).unwrap();
    assert_ne!(old_inode, fs::metadata(&path).unwrap().ino());
    assert_eq!(&first[24..40], &second[24..40]); // stable per-vault KDF salt
    assert_ne!(&first[40..64], &second[40..64]); // fresh per-write AEAD nonce
    assert_ne!(first, second);
    drop(vault);
    let reopened = Vault::open(&path, PASSWORD).unwrap();
    assert_eq!(reopened.state().credentials[0].private_key, [3; 32]);
    assert_eq!(reopened.state().pin.as_ref().unwrap().retries, 8);
    assert_eq!(reopened.state().credentials[0].user.id, b"account-handle");
    no_temporaries(path.parent().unwrap());
}

#[test]
fn independent_vaults_get_different_salts_and_ciphertexts() {
    let root = private_temp();
    let one = root.path().join("one.yq");
    let two = root.path().join("two.yq");
    drop(create(&one));
    drop(create(&two));
    let one = fs::read(one).unwrap();
    let two = fs::read(two).unwrap();
    assert_ne!(&one[24..40], &two[24..40]);
    assert_ne!(one, two);
}

#[test]
fn exclusive_writer_and_non_overwriting_initialization() {
    let root = private_temp();
    let path = root.path().join("vault.yq");
    let vault = create(&path);
    assert!(matches!(
        Vault::open(&path, PASSWORD),
        Err(VaultError::Busy)
    ));
    assert!(matches!(
        Vault::create_with_kdf(&path, PASSWORD, fast_kdf()),
        Err(VaultError::Busy)
    ));
    let original = fs::read(&path).unwrap();
    drop(vault);
    assert!(matches!(
        Vault::create_with_kdf(&path, PASSWORD, fast_kdf()),
        Err(VaultError::AlreadyExists)
    ));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(Vault::open(&path, PASSWORD).is_ok());
}

#[test]
fn wrong_passphrase_and_authenticated_header_or_ciphertext_tampering_fail() {
    let root = private_temp();
    let path = root.path().join("vault.yq");
    drop(create(&path));
    assert!(matches!(
        Vault::open(&path, b"a wrong test passphrase"),
        Err(VaultError::Authentication)
    ));
    let original = fs::read(&path).unwrap();
    for offset in [24, 40, HEADER_LEN, original.len() - 1] {
        let mut modified = original.clone();
        modified[offset] ^= 1;
        fs::write(&path, modified).unwrap();
        assert!(
            matches!(
                Vault::open(&path, PASSWORD),
                Err(VaultError::Authentication)
            ),
            "offset {offset}"
        );
    }
    fs::write(&path, original).unwrap();
    assert!(Vault::open(&path, PASSWORD).is_ok());
}

#[test]
fn invalid_version_lengths_and_kdf_are_rejected_before_derivation() {
    let valid = header(fast_kdf(), &[1; 16], &[2; 24], 64);
    let mut unsupported = valid;
    unsupported[8..12].copy_from_slice(&2u32.to_le_bytes());
    assert!(matches!(
        parse_header(&unsupported),
        Err(VaultError::UnsupportedVersion)
    ));
    for (offset, values) in [
        (12, vec![0, 16_383, 131_073, u32::MAX]),
        (16, vec![0, 1, 7, u32::MAX]),
        (20, vec![0, 5, u32::MAX]),
        (64, vec![0, 15, (MAX_PLAIN + TAG_LEN + 1) as u32, u32::MAX]),
    ] {
        for value in values {
            let mut invalid = valid;
            invalid[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(matches!(
                parse_header(&invalid),
                Err(VaultError::InvalidHeader)
            ));
        }
    }
    let root = private_temp();
    let path = root.path().join("vault.yq");
    drop(create(&path));
    let original = fs::read(&path).unwrap();
    fs::write(&path, &original[..original.len() - 1]).unwrap();
    assert!(matches!(
        Vault::open(&path, PASSWORD),
        Err(VaultError::InvalidHeader)
    ));
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len((HEADER_LEN + MAX_PLAIN + TAG_LEN + 1) as u64)
        .unwrap();
    assert!(matches!(
        Vault::open(&path, PASSWORD),
        Err(VaultError::InvalidHeader)
    ));
}

#[test]
fn ancestor_policy_only_relaxes_user_owned_group_write_for_vaults() {
    let user = 1000;
    for (owner, mode, vault_allowed, control_allowed) in [
        (user, 0o700, true, true),
        (user, 0o755, true, true),
        (user, 0o770, true, false),
        (user, 0o775, true, false),
        (user, 0o2775, true, false),
        (user, 0o777, false, false),
        (user, 0o1777, false, false),
        (0, 0o755, true, true),
        (0, 0o775, false, false),
        (0, 0o777, false, false),
        (0, 0o1777, true, true),
        (2000, 0o755, false, false),
        (2000, 0o775, false, false),
        (2000, 0o1777, false, false),
    ] {
        assert_eq!(
            DirectoryPolicy::Vault.allows_ancestor(owner, mode, user),
            vault_allowed,
            "vault: owner={owner} mode={mode:o}"
        );
        assert_eq!(
            DirectoryPolicy::ControlSocket.allows_ancestor(owner, mode, user),
            control_allowed,
            "control: owner={owner} mode={mode:o}"
        );
    }
}

#[test]
fn user_owned_group_writable_ancestors_allow_create_and_reopen() {
    let root = private_temp();
    let local = root.path().join(".local");
    let share = local.join("share");
    let app = share.join("yubiquity");
    fs::create_dir_all(&app).unwrap();
    for ancestor in [&local, &share] {
        fs::set_permissions(ancestor, fs::Permissions::from_mode(0o775)).unwrap();
    }
    fs::set_permissions(&app, fs::Permissions::from_mode(0o700)).unwrap();
    let path = app.join("host-test/credentials.yq");

    let mut vault = create(&path);
    vault.commit(sample()).unwrap();
    drop(vault);
    let reopened = Vault::open(&path, PASSWORD).unwrap();
    assert_eq!(reopened.state().credentials[0].private_key, [3; 32]);
    assert_eq!(reopened.state().pin.as_ref().unwrap().retries, 8);
    assert_eq!(
        fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o7777,
        0o700
    );
    for file in [&path, &path.parent().unwrap().join(".credentials.yq.lock")] {
        assert_eq!(fs::metadata(file).unwrap().mode() & 0o7777, 0o600);
    }
    // Compatibility must not silently chmod the user's existing directories.
    for ancestor in [&local, &share] {
        assert_eq!(fs::metadata(ancestor).unwrap().mode() & 0o7777, 0o775);
    }
}

#[test]
fn unsafe_directory_file_and_lock_modes_are_rejected() {
    let root = private_temp();
    let directory = root.path().join("private");
    let path = directory.join("vault.yq");
    drop(create(&path));
    for mode in [0o755, 0o770, 0o775, 0o777] {
        fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            Vault::open(&path, PASSWORD),
            Err(VaultError::UnsafePath(_))
        ));
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    for target in [&path, &directory.join(".vault.yq.lock")] {
        for mode in [0o644, 0o660, 0o666] {
            fs::set_permissions(target, fs::Permissions::from_mode(mode)).unwrap();
            assert!(matches!(
                Vault::open(&path, PASSWORD),
                Err(VaultError::UnsafePath(_))
            ));
        }
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn symlinks_hardlinks_and_world_writable_ancestors_are_rejected() {
    let root = private_temp();
    let path = root.path().join("private/vault.yq");
    drop(create(&path));
    let alias = root.path().join("private/alias.yq");
    symlink(&path, &alias).unwrap();
    assert!(Vault::open(&alias, PASSWORD).is_err());
    symlink(path.parent().unwrap(), root.path().join("link")).unwrap();
    assert!(Vault::open(&root.path().join("link/vault.yq"), PASSWORD).is_err());
    let lock_alias = root.path().join("private/locked.yq");
    symlink(&path, root.path().join("private/.locked.yq.lock")).unwrap();
    assert!(Vault::open(&lock_alias, PASSWORD).is_err());
    fs::hard_link(&path, root.path().join("hardlink")).unwrap();
    assert!(matches!(
        Vault::open(&path, PASSWORD),
        Err(VaultError::UnsafePath(_))
    ));
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        Vault::create_with_kdf(&root.path().join("another/new.yq"), PASSWORD, fast_kdf()),
        Err(VaultError::UnsafePath(_))
    ));
}

#[test]
fn world_writable_user_owned_ancestors_reject_create_and_open() {
    let root = private_temp();
    let path = root.path().join("private/vault.yq");
    drop(create(&path));
    for mode in [0o777, 0o1777] {
        fs::set_permissions(root.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            Vault::open(&path, PASSWORD),
            Err(VaultError::UnsafePath(_))
        ));
        assert!(matches!(
            Vault::create_with_kdf(&root.path().join("new/vault.yq"), PASSWORD, fast_kdf()),
            Err(VaultError::UnsafePath(_))
        ));
        assert!(!root.path().join("new").exists());
    }
}

#[test]
fn special_file_does_not_block_and_path_traversal_is_rejected() {
    let root = private_temp();
    let fifo = root.path().join("pipe.yq");
    let name = cstring(fifo.as_os_str()).unwrap();
    // SAFETY: terminated name in our private temporary test directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(matches!(
        Vault::open(&fifo, PASSWORD),
        Err(VaultError::UnsafePath(_))
    ));
    assert!(matches!(
        directory(&root.path().join("../bad.yq"), true, DirectoryPolicy::Vault),
        Err(VaultError::UnsafePath(_))
    ));
}

#[test]
fn failures_at_every_write_stage_fail_closed_without_partial_files() {
    for stage in [
        Stage::Write,
        Stage::PartialWrite,
        Stage::FileSync,
        Stage::Rename,
        Stage::DirectorySync,
    ] {
        let root = private_temp();
        let path = root.path().join("vault.yq");
        let mut vault = create(&path);
        vault.commit(sample()).unwrap();
        let original = fs::read(&path).unwrap();
        let mut next = vault.state().clone();
        next.pin.as_mut().unwrap().retries = 7;
        vault.fault = Some(stage);
        assert!(vault.commit(next).is_err());
        assert_eq!(vault.state().pin.as_ref().unwrap().retries, 8);
        assert!(vault.key.iter().all(|&b| b == 0));
        assert!(vault.commit(sample()).is_err());
        if stage != Stage::DirectorySync {
            assert_eq!(fs::read(&path).unwrap(), original);
        }
        no_temporaries(root.path());
        drop(vault);
        let reopened = Vault::open(&path, PASSWORD).unwrap();
        assert_eq!(
            reopened.state().pin.as_ref().unwrap().retries,
            if stage == Stage::DirectorySync { 7 } else { 8 }
        );
    }
}

#[test]
fn externally_replaced_file_is_not_overwritten_and_deletion_is_exact() {
    let root = private_temp();
    let path = root.path().join("vault.yq");
    let mut vault = create(&path);
    vault.commit(sample()).unwrap();
    assert!(vault.remove_credential(&[0x41; 31]).is_err());
    assert_eq!(vault.state().credentials.len(), 1);
    vault.remove_credential(&[0x41; 32]).unwrap();
    assert!(vault.state().credentials.is_empty());
    fs::rename(&path, root.path().join("original.yq")).unwrap();
    fs::write(&path, b"not our old file").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(vault.commit(sample()).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"not our old file");
}

#[test]
fn invalid_state_and_unsupported_decrypted_payload_fail() {
    let mut invalid = sample();
    invalid.pin.as_mut().unwrap().retries = 9;
    assert!(validate_state(&invalid).is_err());
    let mut invalid = sample();
    invalid.credentials[0].private_key.fill(0);
    assert!(validate_state(&invalid).is_err());
    let mut invalid = sample();
    invalid.credentials[0].algorithm = -8;
    assert!(validate_state(&invalid).is_err());
    let mut invalid = sample();
    invalid.credentials.push(invalid.credentials[0].clone());
    assert!(validate_state(&invalid).is_err());
    let root = private_temp();
    let path = root.path().join("vault.yq");
    let vault = create(&path);
    let mut plain = b"{\"unexpected\":true}".to_vec();
    let nonce = [9; 24];
    let header = header(vault.kdf, &vault.salt, &nonce, plain.len() + TAG_LEN);
    XChaCha20Poly1305::new(vault.key.as_ref().into())
        .encrypt_in_place((&nonce).into(), &header, &mut plain)
        .unwrap();
    let mut contents = header.to_vec();
    contents.extend(plain);
    fs::write(&path, contents).unwrap();
    drop(vault);
    assert!(matches!(
        Vault::open(&path, PASSWORD),
        Err(VaultError::InvalidState)
    ));
}

#[test]
fn passphrase_bounds_and_bounded_serialization() {
    for invalid in [
        b"short".as_slice(),
        b"contains\nlinebreak",
        b"contains\0null",
    ] {
        assert!(validate_passphrase(invalid).is_err());
    }
    assert!(validate_passphrase(&vec![b'a'; MAX_PASSPHRASE + 1]).is_err());
    let mut output = BoundedBuffer(Zeroizing::new(Vec::with_capacity(MAX_PLAIN + TAG_LEN)));
    output.write_all(&vec![0; MAX_PLAIN]).unwrap();
    assert!(output.write_all(&[0]).is_err());
    assert_eq!(output.0.len(), MAX_PLAIN);
}
