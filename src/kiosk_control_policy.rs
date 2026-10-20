//! Dependency-free policy: never send secret payload into a terminal/PTY.
pub const VERSION: u32 = 1;
pub const ACTION: &str = "letmeup-kiosk-control-v1";
pub const MAX_PAYLOAD: usize = 32768;
pub const MAX_RECEIPT: usize = 32768;
pub fn uuid4(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 36
        && b[14] == b'4'
        && b"89ab".contains(&b[19])
        && b.iter().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                *c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(c)
            }
        })
}
pub fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub fn device(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
}
pub fn nonce(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
#[derive(Clone)]
pub struct Request {
    pub version: u32,
    pub delivery_id: String,
    pub operation_id: String,
    pub expected_device_id: String,
    pub wrapper_sha256: String,
    pub payload_sha256: String,
    pub timeout_seconds: u32,
    pub output_limit_bytes: u32,
    pub probe_only: bool,
}
impl Request {
    pub fn valid(&self) -> bool {
        self.version == VERSION
            && uuid4(&self.delivery_id)
            && uuid4(&self.operation_id)
            && device(&self.expected_device_id)
            && digest(&self.wrapper_sha256)
            && if self.probe_only {
                self.payload_sha256.is_empty()
            } else {
                digest(&self.payload_sha256)
            }
            && (1..=300).contains(&self.timeout_seconds)
            && (1..=MAX_RECEIPT as u32).contains(&self.output_limit_bytes)
    }
}
pub struct Gate {
    request: Request,
    challenge: String,
    spent: bool,
    issued: std::time::Instant,
}
impl Gate {
    pub fn new(
        request: Request,
        challenge: String,
        fresh_password: bool,
    ) -> Result<Self, &'static str> {
        if !request.valid() || !nonce(&challenge) || !fresh_password {
            return Err("kiosk_control_not_authorized");
        }
        Ok(Self {
            request,
            challenge,
            spent: false,
            issued: std::time::Instant::now(),
        })
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
    pub fn begin(
        &mut self,
        version: u32,
        delivery: &str,
        challenge: &str,
        size: usize,
        hash: &str,
    ) -> Result<(), &'static str> {
        if self.spent {
            return Err("kiosk_control_delivery_seen");
        }
        self.spent = true; // Any attempted execution consumes this connection.
        if self.issued.elapsed() > std::time::Duration::from_secs(20)
            || self.request.probe_only
            || version != VERSION
            || delivery != self.request.delivery_id
            || challenge != self.challenge
            || size == 0
            || size > MAX_PAYLOAD
            || hash != self.request.payload_sha256
        {
            return Err("kiosk_control_protocol_rejected");
        }
        Ok(())
    }
    pub fn reject_input(&mut self) {
        self.spent = true;
    }
}
/// Bounded, no-eviction delivery guard across connections in this service.
/// The app's durable operation state additionally protects mutations after restart.
pub struct Deliveries(std::collections::HashSet<String>);
impl Default for Deliveries {
    fn default() -> Self {
        Self(std::collections::HashSet::new())
    }
}
impl Deliveries {
    pub fn reserve(&mut self, id: &str) -> Result<(), &'static str> {
        if !uuid4(id) {
            return Err("kiosk_control_protocol_rejected");
        }
        if self.0.contains(id) {
            return Err("kiosk_control_delivery_seen");
        }
        if self.0.len() >= 4096 {
            return Err("kiosk_control_delivery_limit");
        }
        self.0.insert(id.into());
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            version: 1,
            delivery_id: "11111111-1111-4111-8111-111111111111".into(),
            operation_id: "22222222-2222-4222-8222-222222222222".into(),
            expected_device_id: "fixture-device".into(),
            wrapper_sha256: "a".repeat(64),
            payload_sha256: "b".repeat(64),
            timeout_seconds: 60,
            output_limit_bytes: 32768,
            probe_only: false,
        }
    }
    #[test]
    fn identity_bounds_and_no_unknown_mode() {
        let mut r = request();
        assert!(r.valid());
        r.version = 2;
        assert!(!r.valid());
        r = request();
        r.timeout_seconds = 0;
        assert!(!r.valid());
        r = request();
        r.wrapper_sha256 = "A".repeat(64);
        assert!(!r.valid());
        assert!(!uuid4("11111111-1111-4111-8111-11111111111A"));
    }
    #[test]
    fn no_secret_input_until_password_and_exact_challenge() {
        assert!(Gate::new(request(), "n".repeat(43), false).is_err());
        let mut g = Gate::new(request(), "n".repeat(43), true).unwrap();
        assert!(g
            .begin(
                1,
                &request().delivery_id,
                &"m".repeat(43),
                10,
                &"b".repeat(64)
            )
            .is_err());
        assert_eq!(
            g.begin(
                1,
                &request().delivery_id,
                &"n".repeat(43),
                10,
                &"b".repeat(64)
            ),
            Err("kiosk_control_delivery_seen")
        );
    }
    #[test]
    fn probes_never_execute_and_success_is_single_use() {
        let mut r = request();
        r.probe_only = true;
        r.payload_sha256.clear();
        let mut g = Gate::new(r, "n".repeat(43), true).unwrap();
        assert!(g
            .begin(
                1,
                &request().delivery_id,
                &"n".repeat(43),
                10,
                &"b".repeat(64)
            )
            .is_err());
        let mut g = Gate::new(request(), "n".repeat(43), true).unwrap();
        assert!(g
            .begin(
                1,
                &request().delivery_id,
                &"n".repeat(43),
                MAX_PAYLOAD,
                &"b".repeat(64)
            )
            .is_ok());
        assert!(g
            .begin(
                1,
                &request().delivery_id,
                &"n".repeat(43),
                1,
                &"b".repeat(64)
            )
            .is_err());
    }
    #[test]
    fn reconnection_does_not_repeat_an_accepted_delivery() {
        let mut d = Deliveries::default();
        assert!(d.reserve(&request().delivery_id).is_ok());
        assert_eq!(
            d.reserve(&request().delivery_id),
            Err("kiosk_control_delivery_seen")
        );
    }
    #[test]
    fn ordinary_terminal_input_poisoning_cannot_then_execute() {
        let mut g = Gate::new(request(), "n".repeat(43), true).unwrap();
        g.reject_input();
        assert!(g
            .begin(
                1,
                &request().delivery_id,
                &"n".repeat(43),
                1,
                &"b".repeat(64)
            )
            .is_err());
    }
    #[test]
    fn stale_capability_is_spent_without_execution() {
        let mut gate=Gate::new(request(),"n".repeat(43),true).unwrap();
        gate.issued=std::time::Instant::now()-std::time::Duration::from_secs(21);
        assert!(gate.begin(1,&request().delivery_id,&"n".repeat(43),1,&"b".repeat(64)).is_err());
    }
}
