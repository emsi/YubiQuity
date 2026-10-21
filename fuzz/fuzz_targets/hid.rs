#![no_main]
use libfuzzer_sys::fuzz_target;
use yubiquity::hid::{self, Engine, Event, Transaction};

fn check(events: Vec<Event>, active: &mut Option<Transaction>, stale: &mut Vec<Transaction>) {
    // At most one timeout response plus one maximum-size framed response.
    assert!(events.len() <= 132);
    for event in events {
        match event {
            Event::Request {
                transaction,
                payload,
            } => {
                assert!(active.replace(transaction).is_none());
                assert!(!payload.is_empty() && payload.len() <= hid::MAX_MESSAGE);
            }
            Event::Abort(transaction) => {
                assert_eq!(active.take(), Some(transaction));
                stale.push(transaction);
            }
            Event::Send(_) | Event::Resynchronize(_) => {}
        }
    }
}

fuzz_target!(|input: &[u8]| {
    // Bound work even when invoked outside the documented fuzzer max_len.
    if input.len() > 16_384 {
        return;
    }
    let mut engine = Engine::default();
    for _ in 0..2 {
        engine.receive(
            hid::frame(hid::BROADCAST, hid::INIT, &[0; 8]).unwrap()[0],
            0,
        );
    }
    let mut active = None;
    let mut stale = Vec::new();
    let mut now = 0u64;
    // Each step: action byte, little-endian elapsed milliseconds, raw report.
    for step in input.chunks(67) {
        let mut data = [0u8; 67];
        data[..step.len()].copy_from_slice(step);
        now += u64::from(u16::from_le_bytes([data[1], data[2]]));
        check(engine.tick(now), &mut active, &mut stale);
        let mut report: hid::Report = data[3..].try_into().unwrap();
        let channel = 1 + u32::from(data[0] >> 7);
        let events = match data[0] & 7 {
            0 => engine.receive(report, now),
            1 | 2 => {
                // Route most frames to real channels, not only invalid CIDs.
                report[..4].copy_from_slice(&channel.to_be_bytes());
                engine.receive(report, now)
            }
            3 => engine.receive(
                hid::frame(channel, hid::CBOR, &report[..usize::from(report[0]) % 58]).unwrap()[0],
                now,
            ),
            4 => engine.receive(hid::frame(channel, hid::CANCEL, &[]).unwrap()[0], now),
            5 => engine.receive(
                hid::frame(channel, hid::INIT, &report[..8]).unwrap()[0],
                now,
            ),
            6 => match active.take() {
                Some(transaction) => {
                    let events = engine.complete(transaction, &report);
                    stale.push(transaction);
                    events
                }
                None => vec![],
            },
            _ => match active {
                Some(transaction) => engine.processing_status(transaction, report[0], now),
                None => vec![],
            },
        };
        check(events, &mut active, &mut stale);
        for &transaction in &stale {
            assert!(engine.complete(transaction, b"late result").is_empty());
        }
    }
    check(
        engine.tick(now + hid::OPERATION_TIMEOUT_MS),
        &mut active,
        &mut stale,
    );
    assert!(active.is_none());
    let ping = hid::frame(1, hid::PING, b"recovery").unwrap()[0];
    let recovered = engine.receive(ping, now + hid::OPERATION_TIMEOUT_MS + 1);
    assert!(matches!(recovered.as_slice(), [Event::Send(report)] if *report == ping));
});
