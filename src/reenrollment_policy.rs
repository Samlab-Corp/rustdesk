//! Fixed reenrollment policy; no sockets, commands, credentials or live writes.
pub const PURPOSE: &str = "samlab-guardian-reenrollment-v1";
pub const PREPARE_HASH: &str = "a36c1be5d4a82aed206b5a71d2d4b5a3487d5a4a03575025ad723785e7248c8b";
pub const ROTATE_HASH: &str = "f2a12c397002b89af6f6ac850fd8c45e07b16b88bb34fc3a876a30662eec2ff7";
pub const STATUS_HASH: &str = "70dec11d7604540243885b662dd91beace4e7ee496b02ee4c118e8e8910dab35";
pub const MAX_FRAME: usize = 16384;
pub const EXECUTE_SECONDS: u64 = 90;
pub fn action_hash(action: &str) -> Option<&'static str> {
    match action {
        "prepare" => Some(PREPARE_HASH),
        "rotate" => Some(ROTATE_HASH),
        "status" => Some(STATUS_HASH),
        _ => None,
    }
}
pub fn uuid4(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                *c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(c)
            }
        })
        && b[14] == b'4'
        && [b'8', b'9', b'a', b'b'].contains(&b[19])
}
pub fn address(value: &str) -> bool {
    (6..=16).contains(&value.len())
        && !value.starts_with('0')
        && value.bytes().all(|b| b.is_ascii_digit())
}
pub fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn nonce(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
pub fn device(value: &str) -> bool {
    (1..=50).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
pub fn rotation(
    old: &str,
    new: &str,
    operation: &str,
    old_enrollment: &str,
    new_enrollment: &str,
    target: &str,
) -> bool {
    (8..=256).contains(&old.len())
        && !old.chars().any(char::is_control)
        && (24..=128).contains(&new.len())
        && new
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        && old != new
        && uuid4(operation)
        && uuid4(old_enrollment)
        && uuid4(new_enrollment)
        && old_enrollment != new_enrollment
        && address(target)
}
#[derive(Clone, Debug)]
pub struct Request {
    pub delivery_id: String,
    pub operation_id: String,
    pub action: String,
    pub device_id: String,
    pub guardian_sha256: String,
    pub scope_json: Vec<u8>,
    pub probe_only: bool,
}
impl Request {
    pub fn valid(&self) -> bool {
        uuid4(&self.delivery_id)
            && uuid4(&self.operation_id)
            && action_hash(&self.action).is_some()
            && device(&self.device_id)
            && hash(&self.guardian_sha256)
            && !self.scope_json.is_empty()
            && self.scope_json.len() <= 4096
    }
}
pub struct Gate {
    request: Request,
    challenge: String,
    consumed: bool,
}
impl Gate {
    pub fn new(
        request: Request,
        challenge: String,
        fresh_password: bool,
    ) -> Result<Self, &'static str> {
        if !request.valid() || !nonce(&challenge) || !fresh_password {
            return Err("reenrollment_not_ready");
        }
        Ok(Self {
            request,
            challenge,
            consumed: false,
        })
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
    pub fn reject(&mut self) {
        self.consumed = true;
    }
    pub fn consume(
        &mut self,
        version: u32,
        delivery: &str,
        challenge: &str,
        token_length: usize,
    ) -> Result<(), &'static str> {
        let replay = self.consumed;
        self.consumed = true;
        if replay {
            return Err("reenrollment_replayed");
        }
        if self.request.probe_only
            || version != 1
            || delivery != self.request.delivery_id
            || challenge != self.challenge
            || !(100..=8192).contains(&token_length)
        {
            return Err("reenrollment_protocol_rejected");
        }
        Ok(())
    }
}
#[derive(Default)]
pub struct Deliveries(std::collections::HashSet<String>);
impl Deliveries {
    pub fn reserve(&mut self, delivery: &str) -> Result<(), &'static str> {
        if !uuid4(delivery) || self.0.contains(delivery) {
            return Err("reenrollment_replayed");
        }
        if self.0.len() >= 2048 {
            return Err("reenrollment_not_ready");
        }
        self.0.insert(delivery.into());
        Ok(())
    }
}
pub fn fixed_reason(value: &str) -> &'static str {
    match value {
        "reenrollment_not_ready" => "reenrollment_not_ready",
        "reenrollment_protocol_rejected" => "reenrollment_protocol_rejected",
        "reenrollment_replayed" => "reenrollment_replayed",
        "reenrollment_capability_unavailable" => "reenrollment_capability_unavailable",
        "reenrollment_identity_untrusted" => "reenrollment_identity_untrusted",
        "reenrollment_timeout_unconfirmed" => "reenrollment_timeout_unconfirmed",
        "reenrollment_output_unconfirmed" => "reenrollment_output_unconfirmed",
        _ => "reenrollment_execution_unconfirmed",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            delivery_id: "11111111-1111-4111-8111-111111111111".into(),
            operation_id: "22222222-2222-4222-8222-222222222222".into(),
            action: "prepare".into(),
            device_id: "fixture-device".into(),
            guardian_sha256: "a".repeat(64),
            scope_json: b"{}".to_vec(),
            probe_only: false,
        }
    }
    #[test]
    fn fixed_actions_and_exact_shapes() {
        assert!(request().valid());
        assert!(action_hash("execute").is_none());
        assert!(!uuid4("11111111-1111-1111-8111-111111111111"));
        assert!(!address("00123456"));
        assert!(!hash(&"A".repeat(64)));
        assert!(!device("device;command"));
    }
    #[test]
    fn fresh_password_and_real_challenge_before_single_consumption() {
        assert!(Gate::new(request(), "n".repeat(43), false).is_err());
        assert!(Gate::new(request(), String::new(), true).is_err());
        let mut gate = Gate::new(request(), "n".repeat(43), true).unwrap();
        assert!(gate
            .consume(1, &request().delivery_id, &"n".repeat(43), 100)
            .is_ok());
        assert_eq!(
            gate.consume(1, &request().delivery_id, &"n".repeat(43), 100),
            Err("reenrollment_replayed")
        );
    }
    #[test]
    fn probe_and_rejected_input_cannot_later_execute() {
        let mut r = request();
        r.probe_only = true;
        let mut gate = Gate::new(r, "n".repeat(43), true).unwrap();
        assert!(gate
            .consume(1, &request().delivery_id, &"n".repeat(43), 100)
            .is_err());
        let mut gate = Gate::new(request(), "n".repeat(43), true).unwrap();
        gate.reject();
        assert!(gate
            .consume(1, &request().delivery_id, &"n".repeat(43), 100)
            .is_err());
    }
    #[test]
    fn changed_fields_and_replays_fail_closed() {
        for (version, id, challenge, length) in [
            (2, request().delivery_id, "n".repeat(43), 100),
            (
                1,
                "33333333-3333-4333-8333-333333333333".into(),
                "n".repeat(43),
                100,
            ),
            (1, request().delivery_id, "x".repeat(43), 100),
            (1, request().delivery_id, "n".repeat(43), 8193),
        ] {
            let mut g = Gate::new(request(), "n".repeat(43), true).unwrap();
            assert!(g.consume(version, &id, &challenge, length).is_err());
            assert!(g
                .consume(1, &request().delivery_id, &"n".repeat(43), 100)
                .is_err());
        }
        let mut deliveries = Deliveries::default();
        assert!(deliveries.reserve(&request().delivery_id).is_ok());
        assert!(deliveries.reserve(&request().delivery_id).is_err());
    }
    #[test]
    fn rotation_requires_exact_old_new_and_distinct_scope() {
        let op = &request().operation_id;
        let old = "33333333-3333-4333-8333-333333333333";
        let new = "44444444-4444-4444-8444-444444444444";
        assert!(rotation(
            "old-fixture-password",
            &"n".repeat(24),
            op,
            old,
            new,
            "12345678"
        ));
        for (password, new_id, target) in [
            ("short".into(), new, "12345678"),
            ("n".repeat(24), old, "12345678"),
            ("n".repeat(24), new, "1;cmd"),
        ] {
            assert!(!rotation(
                "old-fixture-password",
                &password,
                op,
                old,
                new_id,
                target
            ));
        }
    }
}
