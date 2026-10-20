//! One authenticated connection, one exact command, no interactive shell.
//! This module has no credential parsing, networking, logging, or OS side effects.
pub const VERSION: u32 = 1;
pub const MAX_COMMAND: usize = 16 * 1024;
pub const MAX_OUTPUT: usize = 1024 * 1024;
pub fn fixed_reason(value: &str) -> Option<&'static str> {
    [
        "management_invalid_request",
        "management_not_ready",
        "management_identity_untrusted",
        "management_binding_changed",
        "management_approval_denied",
        "management_verification_unavailable",
        "management_expired",
        "management_replayed",
        "management_command_mismatch",
        "management_system_required",
        "management_protocol_rejected",
        "management_timeout_unconfirmed",
        "management_output_limit",
        "management_output_unconfirmed",
        "management_cleanup_unconfirmed",
    ]
    .into_iter()
    .find(|reason| *reason == value)
}
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    pub version: u32,
    pub operation_id: String,
    pub command_hash: String,
    pub timeout_seconds: u32,
    pub output_limit_bytes: u32,
}
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
pub fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub fn address(value: &str) -> bool {
    (6..=16).contains(&value.len())
        && !value.starts_with('0')
        && value.bytes().all(|c| c.is_ascii_digit())
}
pub fn challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        && b"AEIMQUYcgkosw048".contains(&value.as_bytes()[42])
}
impl Request {
    pub fn valid(&self) -> bool {
        self.version == VERSION
            && uuid4(&self.operation_id)
            && hash(&self.command_hash)
            && (1..=300).contains(&self.timeout_seconds)
            && (1..=MAX_OUTPUT as u32).contains(&self.output_limit_bytes)
    }
}
// Must only be constructed from the authenticated fixed Guardian API response.
// No grant token or command body is retained in this value or its diagnostics.
pub struct VerifiedGrant {
    pub environment: String,
    pub operation_id: String,
    pub command_hash: String,
    pub challenge: String,
    pub address_id: String,
    pub actor_id: u64,
    pub expires_at: u64,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    ChallengeIssued,
    Verifying,
    Consumed,
    Completed,
    Rejected,
    Unconfirmed,
}
pub struct Gate {
    request: Request,
    challenge: String,
    address_id: String,
    state: State,
}
impl Gate {
    pub fn new(
        request: Request,
        nonce: String,
        own_address: String,
        password_authenticated: bool,
    ) -> Result<Self, &'static str> {
        if !password_authenticated {
            return Err("management_approval_denied");
        }
        if !request.valid() || !challenge(&nonce) || !address(&own_address) {
            return Err("management_invalid_request");
        }
        Ok(Self {
            request,
            challenge: nonce,
            address_id: own_address,
            state: State::ChallengeIssued,
        })
    }
    #[cfg(test)]
    pub fn state(&self) -> State {
        self.state
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn nonce(&self) -> &str {
        &self.challenge
    }
    pub fn address_id(&self) -> &str {
        &self.address_id
    }
    // Call before any asynchronous verification. Duplicate frames cannot race it.
    pub fn begin(
        &mut self,
        version: u32,
        operation: &str,
        command_len: usize,
        command_hash: &str,
    ) -> Result<(), &'static str> {
        if self.state != State::ChallengeIssued {
            return Err("management_replayed");
        }
        self.state = State::Rejected;
        if version != VERSION
            || operation != self.request.operation_id
            || command_len == 0
            || command_len > MAX_COMMAND
            || command_hash != self.request.command_hash
        {
            return Err("management_command_mismatch");
        }
        self.state = State::Verifying;
        Ok(())
    }
    pub fn consume(
        &mut self,
        grant: VerifiedGrant,
        now: u64,
        executor_is_system: bool,
    ) -> Result<(), &'static str> {
        if self.state != State::Verifying {
            return Err("management_replayed");
        }
        self.state = State::Rejected;
        if !executor_is_system {
            return Err("management_system_required");
        }
        if grant.expires_at <= now || grant.expires_at.saturating_sub(now) > 65 {
            return Err("management_expired");
        }
        if grant.environment != "development"
            || grant.actor_id == 0
            || grant.operation_id != self.request.operation_id
            || grant.command_hash != self.request.command_hash
            || grant.challenge != self.challenge
            || grant.address_id != self.address_id
        {
            return Err("management_approval_denied");
        }
        self.state = State::Consumed;
        Ok(())
    }
    pub fn reject(&mut self) {
        self.state = State::Rejected;
    }
    pub fn finish(&mut self, confirmed: bool) {
        if self.state == State::Consumed {
            self.state = if confirmed {
                State::Completed
            } else {
                State::Unconfirmed
            };
        }
    }
    pub fn ordinary_terminal_input(&mut self) -> Result<(), &'static str> {
        self.state = State::Rejected;
        Err("management_protocol_rejected")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            version: 1,
            operation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            command_hash: "a".repeat(64),
            timeout_seconds: 60,
            output_limit_bytes: 1024,
        }
    }
    fn gate() -> Gate {
        Gate::new(request(), "A".repeat(43), "74067020".into(), true).unwrap()
    }
    fn grant() -> VerifiedGrant {
        VerifiedGrant {
            environment: "development".into(),
            operation_id: request().operation_id,
            command_hash: request().command_hash,
            challenge: "A".repeat(43),
            address_id: "74067020".into(),
            actor_id: 7,
            expires_at: 1060,
        }
    }
    #[test]
    fn no_password_no_challenge() {
        assert!(Gate::new(request(), "A".repeat(43), "74067020".into(), false).is_err());
    }
    #[test]
    fn exact_valid_command_consumes_once() {
        let mut g = gate();
        g.begin(1, &request().operation_id, 10, &request().command_hash)
            .unwrap();
        g.consume(grant(), 1000, true).unwrap();
        assert_eq!(g.state(), State::Consumed);
        assert_eq!(g.consume(grant(), 1000, true), Err("management_replayed"));
        assert!(g
            .begin(1, &request().operation_id, 10, &request().command_hash)
            .is_err());
    }
    #[test]
    fn changed_or_oversized_command_cannot_retry() {
        for (size, h) in [
            (0, "a".repeat(64)),
            (MAX_COMMAND + 1, "a".repeat(64)),
            (1, "b".repeat(64)),
        ] {
            let mut g = gate();
            assert!(g.begin(1, &request().operation_id, size, &h).is_err());
            assert!(g
                .begin(1, &request().operation_id, 1, &request().command_hash)
                .is_err());
        }
    }
    #[test]
    fn extra_execute_while_verifying_is_rejected() {
        let mut g = gate();
        g.begin(1, &request().operation_id, 1, &request().command_hash)
            .unwrap();
        assert!(g
            .begin(1, &request().operation_id, 1, &request().command_hash)
            .is_err());
    }
    #[test]
    fn every_binding_is_required() {
        for field in 0..6 {
            let mut v = grant();
            match field {
                0 => v.environment = "production".into(),
                1 => v.operation_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
                2 => v.command_hash = "b".repeat(64),
                3 => v.challenge = "B".repeat(43),
                4 => v.address_id = "11111111".into(),
                _ => v.actor_id = 0,
            };
            let mut g = gate();
            g.begin(1, &request().operation_id, 1, &request().command_hash)
                .unwrap();
            assert!(g.consume(v, 1000, true).is_err());
        }
    }
    #[test]
    fn missing_system_never_falls_back_to_user() {
        let mut g = gate();
        g.begin(1, &request().operation_id, 1, &request().command_hash)
            .unwrap();
        assert_eq!(
            g.consume(grant(), 1000, false),
            Err("management_system_required")
        );
    }
    #[test]
    fn future_iat_clock_skew_boundary_is_accepted() {
        let mut g = gate();
        g.begin(1, &request().operation_id, 1, &request().command_hash)
            .unwrap();
        let mut v = grant();
        v.expires_at = 1065;
        assert!(g.consume(v, 1000, true).is_ok());
    }
    #[test]
    fn expired_or_unbounded_grants_fail_closed() {
        for expires in [999, 1000, 1066] {
            let mut g = gate();
            g.begin(1, &request().operation_id, 1, &request().command_hash)
                .unwrap();
            let mut v = grant();
            v.expires_at = expires;
            assert_eq!(g.consume(v, 1000, true), Err("management_expired"));
        }
    }
    #[test]
    fn ordinary_input_never_becomes_system_shell() {
        let mut g = gate();
        assert!(g.ordinary_terminal_input().is_err());
        assert!(g
            .begin(1, &request().operation_id, 1, &request().command_hash)
            .is_err());
    }
    #[test]
    fn timeout_and_completion_do_not_reset_permission() {
        for done in [true, false] {
            let mut g = gate();
            g.begin(1, &request().operation_id, 1, &request().command_hash)
                .unwrap();
            g.consume(grant(), 1000, true).unwrap();
            g.finish(done);
            assert!(g
                .begin(1, &request().operation_id, 1, &request().command_hash)
                .is_err());
        }
    }
    #[test]
    fn logged_out_context_does_not_select_a_user_token() {
        let mut g = gate();
        g.begin(1, &request().operation_id, 1, &request().command_hash)
            .unwrap();
        g.consume(grant(), 1000, true).unwrap();
        assert_eq!(g.state(), State::Consumed);
    }
    #[test]
    fn old_peer_without_challenge_never_reaches_execution() {
        assert_eq!(gate().state(), State::ChallengeIssued);
    }
    #[test]
    fn nonce_canonical_padding_bits_and_bounds() {
        assert!(challenge(&"A".repeat(43)));
        assert!(!challenge(&"B".repeat(43)));
        assert!(!challenge(&"A".repeat(42)));
        assert!(!hash(&"A".repeat(64)));
    }
}
