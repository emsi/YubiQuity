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
fn desktop_bridge_validates_versions_sequences_sizes_and_rejections() {
    let good =
        serde_json::json!({"version":1,"sequence":1,"snapshot":{"ok":true,"state":"locked"}});
    for (frames, expected, emitted) in [
        (vec![good.clone(), good.clone()], "out-of-order", 1),
        (
            vec![
                serde_json::json!({"version":2,"sequence":1,"snapshot":{"ok":true,"state":"locked"}}),
            ],
            "unsupported",
            0,
        ),
        (
            vec![
                serde_json::json!({"ok":false,"state":"locked","error":"another desktop client is already connected"}),
            ],
            "another desktop client",
            0,
        ),
        (
            vec![serde_json::json!({"padding":"x".repeat(MAX_WIRE)})],
            "size",
            0,
        ),
        (
            vec![serde_json::json!({"version":1})],
            "invalid desktop snapshot",
            0,
        ),
    ] {
        let directory = private_temp();
        let path = directory.path().join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        let fixture = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut size = [0; 4];
            stream.read_exact(&mut size).unwrap();
            let mut request = vec![0; u32::from_be_bytes(size) as usize];
            stream.read_exact(&mut request).unwrap();
            assert!(matches!(
                serde_json::from_slice::<Request>(&request).unwrap(),
                Request::Watch {
                    version: WATCH_VERSION
                }
            ));
            for frame in frames {
                let bytes = serde_json::to_vec(&frame).unwrap();
                stream
                    .write_all(&(bytes.len() as u32).to_be_bytes())
                    .unwrap();
                // A size rejection may close before the oversized body is read.
                let _ = stream.write_all(&bytes);
            }
        });
        let mut count = 0;
        let error = watch(&path, |_| {
            count += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(count, emitted);
        fixture.join().unwrap();
    }
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
fn group_writable_ancestor_is_still_rejected_for_control_endpoints() {
    let directory = private_temp();
    let runtime = directory.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, Permissions::from_mode(0o700)).unwrap();
    let path = runtime.join("control.sock");
    let _server = Server::bind(&path).unwrap();

    std::fs::set_permissions(directory.path(), Permissions::from_mode(0o775)).unwrap();
    assert!(Server::bind(&runtime.join("other.sock")).is_err());
    assert!(call(&path, &Request::Status {}).is_err());
    assert!(!runtime.join("other.sock").exists());
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

#[test]
fn delayed_attachment_reply_gets_a_fresh_bounded_flush_window() {
    let directory = private_temp();
    let path = directory.path().join("control.sock");
    let mut server = Server::bind(&path).unwrap();
    let mut client = connect(&path).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    send_request(&mut client, &Request::Unlock { passphrase: vec![] });
    let (id, _) = server.poll().unwrap().unwrap();
    server.clients[0].accepted -= CLIENT_LIFETIME * 2;
    server
        .respond(id, Response::locked().error("device attachment failed"))
        .unwrap();
    server.poll().unwrap();
    let mut length = [0; 4];
    client.read_exact(&mut length).unwrap();
    let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
    client.read_exact(&mut bytes).unwrap();
    let response: Response = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response.error.as_deref(), Some("device attachment failed"));
}

fn receive_json(stream: &mut UnixStream) -> serde_json::Value {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn desktop_watch_is_versioned_exclusive_and_latches_disconnect() {
    let directory = private_temp();
    let path = directory.path().join("control.sock");
    let mut server = Server::bind(&path).unwrap();
    let mut first = connect(&path).unwrap();
    send_request(
        &mut first,
        &Request::Watch {
            version: WATCH_VERSION,
        },
    );
    let (owner, _) = server.poll().unwrap().unwrap();
    server
        .watch(owner, WATCH_VERSION, Response::locked())
        .unwrap();
    server.poll().unwrap();
    assert_eq!(
        receive_json(&mut first),
        serde_json::json!({
            "version": 1, "sequence": 1, "snapshot": {"ok": true, "state": "locked"}
        })
    );
    // Idle live subscriptions outlive the ordinary five-second request limit.
    server.clients[0].accepted -= CLIENT_LIFETIME * 2;
    server.poll().unwrap();
    assert_eq!(server.watcher, Some(owner));
    let mut second = connect(&path).unwrap();
    send_request(
        &mut second,
        &Request::Watch {
            version: WATCH_VERSION,
        },
    );
    let (id, _) = server.poll().unwrap().unwrap();
    server.watch(id, WATCH_VERSION, Response::locked()).unwrap();
    server.poll().unwrap();
    assert_eq!(receive_json(&mut second)["ok"], false);
    drop(first);
    server.poll().unwrap();
    assert_eq!(server.take_watcher_loss(), Some(owner));
    assert_eq!(server.take_watcher_loss(), None);
}

#[test]
fn watch_rejects_version_mismatch_and_extra_input() {
    let directory = private_temp();
    let path = directory.path().join("control.sock");
    let mut server = Server::bind(&path).unwrap();
    let mut client = connect(&path).unwrap();
    send_request(&mut client, &Request::Watch { version: 999 });
    let (id, _) = server.poll().unwrap().unwrap();
    server.watch(id, 999, Response::locked()).unwrap();
    server.poll().unwrap();
    assert_eq!(receive_json(&mut client)["ok"], false);
    assert!(server.watcher.is_none());
    let mut client = connect(&path).unwrap();
    send_request(
        &mut client,
        &Request::Watch {
            version: WATCH_VERSION,
        },
    );
    let (id, _) = server.poll().unwrap().unwrap();
    server.watch(id, WATCH_VERSION, Response::locked()).unwrap();
    server.poll().unwrap();
    receive_json(&mut client);
    client.write_all(b"extra request").unwrap();
    server.poll().unwrap();
    assert_eq!(server.take_watcher_loss(), Some(id));
}

#[test]
fn watch_snapshots_are_bounded_coalesced_and_expiring() {
    let directory = private_temp();
    let path = directory.path().join("control.sock");
    let mut server = Server::bind(&path).unwrap();
    let mut client = connect(&path).unwrap();
    send_request(
        &mut client,
        &Request::Watch {
            version: WATCH_VERSION,
        },
    );
    let (id, _) = server.poll().unwrap().unwrap();
    server.watch(id, WATCH_VERSION, Response::locked()).unwrap();
    // Updating cannot overwrite a partially flushed frame or grow a queue.
    let first = server.clients[0].outgoing.clone().unwrap();
    for _ in 0..100 {
        server.publish(Response::ready(None)).unwrap();
    }
    assert_eq!(server.clients[0].outgoing.as_ref(), Some(&first));
    server.poll().unwrap();
    receive_json(&mut client);
    server.publish(Response::ready(None)).unwrap();
    server.poll().unwrap();
    let next = receive_json(&mut client);
    assert_eq!(next["sequence"], 2);
    assert_eq!(next["snapshot"]["state"], "ready");
    server.publish(Response::ready(None)).unwrap();
    assert!(server.clients[0].outgoing.is_none());
    server.last_publish -= Duration::from_secs(2);
    server.publish(Response::ready(None)).unwrap();
    assert!(server.clients[0].outgoing.is_some());
    server.clients[0].accepted -= CLIENT_LIFETIME;
    server.poll().unwrap();
    assert_eq!(server.take_watcher_loss(), Some(id));
}
