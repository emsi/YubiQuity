use super::*;
use std::os::unix::fs::symlink;

fn private_temp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn send_request(stream: &mut UnixStream, request: &Request) {
    let bytes = serde_json::to_vec(request).unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
}

#[test]
fn private_socket_round_trip_exclusive_owner_and_cleanup() {
    let directory = private_temp();
    let path = directory.path().join("control.sock");
    let mut server = Server::bind(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    assert!(Server::bind(&path).is_err());
    let client_path = path.clone();
    let client = std::thread::spawn(move || call(&client_path, &Request::Status {}).unwrap());
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some((id, request)) = server.poll().unwrap() {
            assert!(matches!(request, Request::Status {}));
            server.respond(id, Response::locked()).unwrap();
        }
        if client.is_finished() {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(client.join().unwrap().state, "locked");
    drop(server);
    assert!(!path.exists());
    // Lifetime lock file remains: never unlink a shared lock inode.
    assert!(directory.path().join(".control.sock.lock").exists());
}

#[test]
fn rejects_unsafe_paths_and_only_recovers_a_stale_owned_socket() {
    let directory = private_temp();
    let path = directory.path().join("control.sock");
    std::fs::write(&path, b"unrelated file").unwrap();
    assert!(Server::bind(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"unrelated file");
    std::fs::remove_file(&path).unwrap();
    symlink("missing", &path).unwrap();
    assert!(Server::bind(&path).is_err());
    std::fs::remove_file(&path).unwrap();
    let live = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    assert!(Server::bind(&path).is_err());
    drop(live);
    let recovered = Server::bind(&path).unwrap();
    drop(recovered);
    std::fs::set_permissions(directory.path(), Permissions::from_mode(0o755)).unwrap();
    assert!(Server::bind(&path).is_err());
    assert!(call(&path, &Request::Status {}).is_err());
}

#[test]
fn drop_never_unlinks_a_replacement_file_or_socket() {
    let directory = private_temp();
    let path = directory.path().join("control.sock");
    let server = Server::bind(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let replacement = UnixListener::bind(&path).unwrap();
    let identity = std::fs::symlink_metadata(&path).unwrap().ino();
    drop(server);
    assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), identity);
    drop(replacement);
}

#[test]
fn malformed_partial_oversize_and_excess_clients_are_bounded() {
    let directory = private_temp();
    let path = directory.path().join("control.sock");
    let mut server = Server::bind(&path).unwrap();
    for input in [
        vec![0; 4],
        u32::MAX.to_be_bytes().to_vec(),
        b"\0\0\0\x02{}".to_vec(),
        b"\0\0\0\x18{\"command\":\"not-a-command\"}".to_vec(),
    ] {
        let mut client = connect(&path).unwrap();
        client.write_all(&input).unwrap();
        assert!(server.poll().unwrap().is_none());
        assert!(server.clients.is_empty());
    }
    let mut clients = vec![];
    for _ in 0..MAX_CLIENTS + 2 {
        let mut stream = connect(&path).unwrap();
        stream.write_all(&[0]).unwrap();
        clients.push(stream);
        assert!(server.poll().unwrap().is_none());
        assert!(server.clients.len() <= MAX_CLIENTS);
    }
    assert_eq!(server.clients.len(), MAX_CLIENTS);
    // Inject only the clock in this unit test; production timeout remains 5s.
    for client in &mut server.clients {
        client.accepted -= CLIENT_LIFETIME;
    }
    assert!(server.poll().unwrap().is_none());
    assert!(server.clients.is_empty());
    let mut client = connect(&path).unwrap();
    send_request(&mut client, &Request::Status {});
    assert!(matches!(
        server.poll().unwrap(),
        Some((_, Request::Status {}))
    ));
}

#[test]
fn requests_reject_unknown_fields_and_cli_checks_endpoint_permissions() {
    assert!(serde_json::from_slice::<Request>(br#"{"command":"status","extra":true}"#).is_err());
    assert!(serde_json::from_slice::<Request>(br#"{"command":"approve"}"#).is_err());
    assert!(
        serde_json::from_slice::<Request>(br#"{"command":"unlock","passphrase":"not-bytes"}"#)
            .is_err()
    );
    let directory = private_temp();
    let path = directory.path().join("control.sock");
    let _server = Server::bind(&path).unwrap();
    std::fs::set_permissions(&path, Permissions::from_mode(0o666)).unwrap();
    assert!(call(&path, &Request::Status {}).is_err());
}
