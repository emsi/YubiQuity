//! CTAPHID state machine, independent of the OS, clock and authenticator.
use zeroize::Zeroizing;

pub type Report = [u8; 64];
pub const MAX_MESSAGE: usize = 57 + 128 * 59;
pub const BROADCAST: u32 = u32::MAX;
pub const PING: u8 = 0x01;
pub const INIT: u8 = 0x06;
pub const CBOR: u8 = 0x10;
pub const CANCEL: u8 = 0x11;
pub const KEEPALIVE: u8 = 0x3b;
pub const ERROR: u8 = 0x3f;
pub const FRAME_TIMEOUT_MS: u64 = 750;
pub const OPERATION_TIMEOUT_MS: u64 = 30_000;
pub const KEEPALIVE_INTERVAL_MS: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HidError {
    InvalidCommand = 1,
    InvalidLength = 3,
    InvalidSequence = 4,
    Timeout = 5,
    Busy = 6,
    InvalidChannel = 11,
    Other = 127,
}

/// A transaction ID guards asynchronous results across CANCEL and INIT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transaction {
    pub id: u64,
    pub channel: u32,
}

#[derive(Debug)]
pub enum Event {
    Send(Report),
    Request {
        transaction: Transaction,
        payload: Zeroizing<Vec<u8>>,
    },
    Abort(Transaction),
    /// A valid INIT flushes higher-layer enumeration/session request state too.
    Resynchronize(u32),
}

struct Receiving {
    channel: u32,
    command: u8,
    length: usize,
    payload: Zeroizing<Vec<u8>>,
    sequence: u8,
    last_frame_ms: u64,
}

struct Processing {
    transaction: Transaction,
    started_ms: u64,
    keepalive_ms: u64,
    status: u8,
}

#[derive(Default)]
pub struct Engine {
    // Sequential never-reused IDs allow validation with constant memory. No
    // per-client table, expiry or eviction is needed; CIDs are not secrets.
    last_channel: u32,
    next_transaction: u64,
    receiving: Option<Receiving>,
    processing: Option<Processing>,
}

pub fn frame(channel: u32, command: u8, payload: &[u8]) -> Result<Vec<Report>, HidError> {
    if payload.len() > MAX_MESSAGE {
        return Err(HidError::InvalidLength);
    }
    if command & 0x80 != 0 {
        return Err(HidError::InvalidCommand);
    }
    let mut reports = Vec::with_capacity(1 + payload.len().saturating_sub(57).div_ceil(59));
    let mut first = [0u8; 64];
    first[..4].copy_from_slice(&channel.to_be_bytes());
    first[4] = command | 0x80;
    first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let first_length = payload.len().min(57);
    first[7..7 + first_length].copy_from_slice(&payload[..first_length]);
    reports.push(first);
    for (sequence, chunk) in payload[first_length..].chunks(59).enumerate() {
        let mut report = [0u8; 64];
        report[..4].copy_from_slice(&channel.to_be_bytes());
        report[4] = sequence as u8;
        report[5..5 + chunk.len()].copy_from_slice(chunk);
        reports.push(report);
    }
    Ok(reports)
}

fn response(channel: u32, command: u8, data: &[u8]) -> Vec<Event> {
    // Oversize internal responses fail closed, not as truncated success.
    match frame(channel, command, data) {
        Ok(frames) => frames.into_iter().map(Event::Send).collect(),
        Err(_) => error(channel, HidError::Other),
    }
}

fn error(channel: u32, code: HidError) -> Vec<Event> {
    frame(channel, ERROR, &[code as u8])
        .unwrap()
        .into_iter()
        .map(Event::Send)
        .collect()
}

impl Engine {
    fn active_channel(&self) -> Option<u32> {
        self.receiving
            .as_ref()
            .map(|r| r.channel)
            .or_else(|| self.processing.as_ref().map(|p| p.transaction.channel))
    }

    pub fn receive(&mut self, report: Report, now_ms: u64) -> Vec<Event> {
        let mut events = self.tick(now_ms);
        events.extend(self.receive_inner(report, now_ms));
        events
    }

    fn receive_inner(&mut self, report: Report, now_ms: u64) -> Vec<Event> {
        let channel = u32::from_be_bytes(report[..4].try_into().unwrap());
        let initial = report[4] & 0x80 != 0;
        let command = report[4] & 0x7f;
        let length = u16::from_be_bytes([report[5], report[6]]) as usize;

        // CANCEL is never a transaction and never gets its own response.
        if initial && command == CANCEL {
            if length == 0
                && self
                    .processing
                    .as_ref()
                    .is_some_and(|p| p.transaction.channel == channel)
            {
                let pending = self.processing.take().unwrap();
                let mut events = vec![Event::Abort(pending.transaction)];
                events.extend(response(channel, CBOR, &[0x2d]));
                return events;
            }
            return vec![];
        }

        if !initial {
            // Ignore unsolicited continuations. They cannot acquire ownership.
            let Some(receiving) = self.receiving.as_mut() else {
                return vec![];
            };
            if channel != receiving.channel {
                return vec![];
            }
            if report[4] != receiving.sequence {
                self.receiving = None;
                return error(channel, HidError::InvalidSequence);
            }
            let take = (receiving.length - receiving.payload.len()).min(59);
            receiving.payload.extend_from_slice(&report[5..5 + take]);
            receiving.last_frame_ms = now_ms;
            if receiving.payload.len() == receiving.length {
                let request = self.receiving.take().unwrap();
                return self.dispatch(request.channel, request.command, request.payload, now_ms);
            }
            receiving.sequence += 1; // max sequence 127 completes a bounded message
            return vec![];
        }

        if channel == 0
            || (channel != BROADCAST && channel > self.last_channel)
            || (channel == BROADCAST && command != INIT)
        {
            return error(channel, HidError::InvalidChannel);
        }
        if self
            .active_channel()
            .is_some_and(|active| active != channel)
        {
            return error(channel, HidError::Busy);
        }

        if command == INIT {
            if length != 8 {
                return error(channel, HidError::InvalidLength);
            }
            let allocated = if channel == BROADCAST {
                if self.last_channel == BROADCAST - 1 {
                    return error(channel, HidError::Busy);
                }
                self.last_channel += 1;
                self.last_channel
            } else {
                channel
            };
            self.receiving = None;
            let mut events = self
                .processing
                .take()
                .map(|p| vec![Event::Abort(p.transaction)])
                .unwrap_or_default();
            let mut data = report[7..15].to_vec();
            events.push(Event::Resynchronize(allocated));
            data.extend(allocated.to_be_bytes());
            data.extend([2, 0, 1, 0, 0x0c]); // HID v2; CBOR, no MSG; no WINK/LOCK
            events.extend(response(channel, INIT, &data));
            return events;
        }

        if self.processing.is_some() {
            return error(channel, HidError::Busy);
        }
        if self.receiving.take().is_some() {
            return error(channel, HidError::InvalidSequence);
        }
        if !matches!(command, PING | CBOR) {
            return error(channel, HidError::InvalidCommand);
        }
        if length > MAX_MESSAGE || (command == CBOR && length == 0) {
            return error(channel, HidError::InvalidLength);
        }
        let take = length.min(57);
        let mut payload = Zeroizing::new(Vec::with_capacity(length));
        payload.extend_from_slice(&report[7..7 + take]);
        if take == length {
            return self.dispatch(channel, command, payload, now_ms);
        }
        self.receiving = Some(Receiving {
            channel,
            command,
            length,
            payload,
            sequence: 0,
            last_frame_ms: now_ms,
        });
        vec![]
    }

    fn dispatch(
        &mut self,
        channel: u32,
        command: u8,
        payload: Zeroizing<Vec<u8>>,
        now_ms: u64,
    ) -> Vec<Event> {
        if command == PING {
            return response(channel, PING, &payload);
        }
        self.next_transaction = self
            .next_transaction
            .checked_add(1)
            .expect("transaction ID space exhausted");
        let transaction = Transaction {
            id: self.next_transaction,
            channel,
        };
        self.processing = Some(Processing {
            transaction,
            started_ms: now_ms,
            keepalive_ms: now_ms,
            status: 1,
        });
        vec![Event::Request {
            transaction,
            payload,
        }]
    }

    pub fn complete(&mut self, transaction: Transaction, payload: &[u8]) -> Vec<Event> {
        if !self
            .processing
            .as_ref()
            .is_some_and(|p| p.transaction == transaction)
        {
            return vec![];
        }
        self.processing = None;
        response(transaction.channel, CBOR, payload)
    }

    pub fn presence_needed(&mut self, transaction: Transaction, now_ms: u64) -> Vec<Event> {
        self.processing_status(transaction, 2, now_ms)
    }

    pub fn processing_status(
        &mut self,
        transaction: Transaction,
        status: u8,
        now_ms: u64,
    ) -> Vec<Event> {
        if !matches!(status, 1 | 2) {
            return vec![];
        }
        if let Some(pending) = &mut self.processing {
            if pending.transaction == transaction {
                pending.status = status;
                pending.keepalive_ms = now_ms;
                return response(transaction.channel, KEEPALIVE, &[status]);
            }
        }
        vec![]
    }

    pub fn tick(&mut self, now_ms: u64) -> Vec<Event> {
        if self
            .receiving
            .as_ref()
            .is_some_and(|r| now_ms.saturating_sub(r.last_frame_ms) >= FRAME_TIMEOUT_MS)
        {
            let request = self.receiving.take().unwrap();
            return error(request.channel, HidError::Timeout);
        }
        if let Some(pending) = &mut self.processing {
            if now_ms.saturating_sub(pending.started_ms) >= OPERATION_TIMEOUT_MS {
                let pending = self.processing.take().unwrap();
                let mut events = vec![Event::Abort(pending.transaction)];
                events.extend(response(pending.transaction.channel, CBOR, &[0x2f]));
                return events;
            }
            if now_ms.saturating_sub(pending.keepalive_ms) >= KEEPALIVE_INTERVAL_MS {
                pending.keepalive_ms = now_ms;
                return response(pending.transaction.channel, KEEPALIVE, &[pending.status]);
            }
        }
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn report(events: &[Event]) -> Report {
        match events.last().unwrap() {
            Event::Send(r) => *r,
            _ => panic!("expected response"),
        }
    }
    fn allocate(engine: &mut Engine) -> u32 {
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let output = report(&engine.receive(frame(BROADCAST, INIT, &nonce).unwrap()[0], 0));
        assert_eq!(&output[7..15], &nonce);
        assert_eq!(output[23], 0x0c);
        u32::from_be_bytes(output[15..19].try_into().unwrap())
    }
    fn request(engine: &mut Engine, channel: u32) -> Transaction {
        let result = engine.receive(frame(channel, CBOR, &[4]).unwrap()[0], 0);
        match result[0] {
            Event::Request { transaction, .. } => transaction,
            _ => panic!(),
        }
    }
    #[test]
    fn ping_all_boundary_lengths() {
        for length in [0, 1, 57, 58, 116, 117, 1024, MAX_MESSAGE] {
            let mut engine = Engine::default();
            let channel = allocate(&mut engine);
            let payload: Vec<_> = (0..length).map(|i| i as u8).collect();
            let input = frame(channel, PING, &payload).unwrap();
            let mut output = vec![];
            for part in &input {
                output.extend(engine.receive(*part, 0));
            }
            let output: Vec<_> = output
                .iter()
                .map(|e| report(std::slice::from_ref(e)))
                .collect();
            assert_eq!(output, input);
        }
        assert!(frame(1, PING, &vec![0; MAX_MESSAGE + 1]).is_err());
    }
    #[test]
    fn bounded_channels_never_reuse() {
        let mut engine = Engine::default();
        for expected in 1..1000 {
            assert_eq!(allocate(&mut engine), expected);
        }
        engine.last_channel = BROADCAST - 1;
        assert_eq!(
            report(&engine.receive(frame(BROADCAST, INIT, &[0; 8]).unwrap()[0], 0))[7],
            HidError::Busy as u8
        );
    }
    #[test]
    fn busy_and_invalid_channel() {
        let mut engine = Engine::default();
        let a = allocate(&mut engine);
        let b = allocate(&mut engine);
        let tx = request(&mut engine, a);
        assert_eq!(
            report(&engine.receive(frame(b, PING, &[]).unwrap()[0], 0))[7],
            HidError::Busy as u8
        );
        assert_eq!(
            report(&engine.receive(frame(0, PING, &[]).unwrap()[0], 0))[7],
            HidError::InvalidChannel as u8
        );
        assert_eq!(report(&engine.complete(tx, &[0]))[7], 0);
    }
    #[test]
    fn cancel_has_only_original_cbor_response_and_invalidates_result() {
        let mut engine = Engine::default();
        let a = allocate(&mut engine);
        let b = allocate(&mut engine);
        let tx = request(&mut engine, a);
        assert!(engine
            .receive(frame(b, CANCEL, &[]).unwrap()[0], 0)
            .is_empty());
        let result = engine.receive(frame(a, CANCEL, &[]).unwrap()[0], 0);
        assert!(matches!(result[0], Event::Abort(t) if t == tx));
        assert_eq!(&report(&result)[4..8], &[CBOR | 0x80, 0, 1, 0x2d]);
        assert!(engine.complete(tx, &[0]).is_empty());
        assert!(engine
            .receive(frame(a, CANCEL, &[]).unwrap()[0], 0)
            .is_empty());
        let next = request(&mut engine, a);
        assert_ne!(next, tx);
        assert!(engine.complete(tx, &[0]).is_empty());
    }
    #[test]
    fn resync_invalidates_pending_and_partial_requests() {
        let mut engine = Engine::default();
        let a = allocate(&mut engine);
        let tx = request(&mut engine, a);
        let result = engine.receive(frame(a, INIT, &[9; 8]).unwrap()[0], 0);
        assert!(matches!(result[0], Event::Abort(t) if t == tx));
        assert!(engine.complete(tx, &[0]).is_empty());
        let parts = frame(a, PING, &[0; 100]).unwrap();
        assert!(engine.receive(parts[0], 0).is_empty());
        engine.receive(frame(a, INIT, &[0; 8]).unwrap()[0], 0);
        assert!(engine.receive(parts[1], 0).is_empty());
    }
    #[test]
    fn malformed_sequence_and_frame_timeout_recover() {
        let mut engine = Engine::default();
        let a = allocate(&mut engine);
        let mut parts = frame(a, PING, &[0; 100]).unwrap();
        engine.receive(parts[0], 0);
        parts[1][4] = 1;
        assert_eq!(
            report(&engine.receive(parts[1], 1))[7],
            HidError::InvalidSequence as u8
        );
        engine.receive(parts[0], 1);
        assert!(engine.tick(FRAME_TIMEOUT_MS).is_empty());
        assert_eq!(
            report(&engine.tick(FRAME_TIMEOUT_MS + 1))[7],
            HidError::Timeout as u8
        );
        assert_eq!(
            report(&engine.receive(frame(a, PING, &[7]).unwrap()[0], 1000))[7],
            7
        );
    }
    #[test]
    fn keepalive_and_processing_timeout() {
        let mut engine = Engine::default();
        let a = allocate(&mut engine);
        let tx = request(&mut engine, a);
        assert!(engine.tick(99).is_empty());
        assert_eq!(report(&engine.tick(100))[7], 1);
        assert_eq!(report(&engine.presence_needed(tx, 101))[7], 2);
        assert_eq!(report(&engine.tick(201))[7], 2);
        assert_eq!(report(&engine.tick(OPERATION_TIMEOUT_MS))[7], 0x2f);
        assert!(engine.complete(tx, &[0]).is_empty());
    }
    #[test]
    fn oversized_and_empty_cbor_rejected() {
        let mut engine = Engine::default();
        let a = allocate(&mut engine);
        let mut r = frame(a, PING, &[]).unwrap()[0];
        r[5..7].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            report(&engine.receive(r, 0))[7],
            HidError::InvalidLength as u8
        );
        assert_eq!(
            report(&engine.receive(frame(a, CBOR, &[]).unwrap()[0], 0))[7],
            HidError::InvalidLength as u8
        );
    }
}
