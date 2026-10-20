//! Separate execute-once protocol. Ordinary terminal input is never forwarded.
use crate::native_management_policy::{Gate, Request};
use hbb_common::{
    base64::{self, Engine},
    message_proto::*,
    rand::{rngs::OsRng, RngCore},
    tokio,
};
use sha2::{Digest, Sha256};
#[derive(Default)]
pub struct Session {
    request: Option<Request>,
    gate: Option<Gate>,
    password_authenticated: bool,
}
impl Session {
    pub fn from_proto(value: NativeManagementSession) -> Result<Self, &'static str> {
        let request = Request {
            version: value.management_version,
            operation_id: value.operation_id,
            command_hash: value.command_hash,
            timeout_seconds: value.timeout_seconds,
            output_limit_bytes: value.output_limit_bytes,
        };
        if !request.valid() {
            return Err("management_invalid_request");
        }
        Ok(Self {
            request: Some(request),
            ..Default::default()
        })
    }
    pub fn password_verified(&mut self) {
        self.password_authenticated = true;
    }
    pub fn prepare(&mut self, address: String) -> Result<(), &'static str> {
        if self.gate.is_some() {
            return Ok(());
        }
        if !system() {
            return Err("management_system_required");
        }
        let mut nonce = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| "management_not_ready")?;
        let request = self
            .request
            .as_ref()
            .ok_or("management_invalid_request")?
            .clone();
        self.gate = Some(Gate::new(
            request,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
            address,
            self.password_authenticated,
        )?);
        Ok(())
    }
    pub fn challenge(&self) -> Option<NativeManagementChallenge> {
        self.gate.as_ref().map(|g| NativeManagementChallenge {
            management_version: 1,
            operation_id: g.request().operation_id.clone(),
            command_hash: g.request().command_hash.clone(),
            challenge: g.nonce().into(),
            address_id: g.address_id().into(),
            ..Default::default()
        })
    }
    pub async fn execute(&mut self, input: NativeManagementExecute) -> NativeManagementResult {
        let operation = self
            .request
            .as_ref()
            .map(|r| r.operation_id.clone())
            .unwrap_or_default();
        let mut result = NativeManagementResult {
            management_version: 1,
            operation_id: operation,
            status: "rejected".into(),
            reason: "management_protocol_rejected".into(),
            ..Default::default()
        };
        let Some(mut gate) = self.gate.take() else {
            return result;
        };
        let digest = hex::encode(Sha256::digest(input.command.as_bytes()));
        if let Err(reason) = gate.begin(
            input.management_version,
            &input.operation_id,
            input.command.len(),
            &digest,
        ) {
            result.reason = reason.into();
            self.gate = Some(gate);
            return result;
        }
        if input.grant_token.is_empty() || input.grant_token.len() > 8192 {
            gate.reject();
            result.reason = "management_invalid_request".into();
            self.gate = Some(gate);
            return result;
        }
        // Move the entire verifying gate into one worker. It cannot be borrowed
        // by another frame while HTTPS/pipe validation is awaiting completion.
        let verified = tokio::task::spawn_blocking(move || {
            let grant = crate::native_management_guardian::verify(&gate, &input.grant_token);
            (gate, grant, input.command)
        })
        .await;
        let (mut gate, grant, command) = match verified {
            Ok(v) => v,
            Err(_) => {
                result.reason = "management_verification_unavailable".into();
                return result;
            }
        };
        let grant = match grant {
            Ok(g) => g,
            Err(reason) => {
                gate.reject();
                result.reason = reason.into();
                self.gate = Some(gate);
                return result;
            }
        };
        let outcome = tokio::task::spawn_blocking(move || {
            // Recheck time and actual SID after scheduling, immediately before
            // consuming the permission and starting this one child.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(u64::MAX);
            let outcome = execute_granted(
                &mut gate,
                grant,
                &command,
                now,
                system(),
                crate::native_management_executor::execute,
            );
            (gate, outcome)
        })
        .await;
        let (mut gate, outcome) = match outcome {
            Ok(v) => v,
            Err(_) => {
                result.status = "unconfirmed".into();
                result.reason = "management_timeout_unconfirmed".into();
                return result;
            }
        };
        match outcome {
            Ok(v) => {
                gate.finish(v.exit_code.is_some());
                result.status = if v.exit_code.is_some() {
                    "completed"
                } else {
                    "unconfirmed"
                }
                .into();
                result.reason = v.reason.into();
                result.exit_code = v.exit_code.unwrap_or_default();
                result.exit_code_confirmed = v.exit_code.is_some();
                result.stdout = v.stdout.into();
                result.stderr = v.stderr.into();
                result.executor_is_system = v.executor_is_system;
            }
            Err(reason) => {
                result.reason = reason.into();
            }
        }
        self.gate = Some(gate);
        result
    }
    pub fn reject_input(&mut self) {
        if let Some(g) = self.gate.as_mut() {
            let _ = g.ordinary_terminal_input();
        }
    }
}
fn execute_granted(
    gate: &mut Gate,
    grant: crate::native_management_policy::VerifiedGrant,
    command: &str,
    now: u64,
    is_system: bool,
    executor: impl FnOnce(&str, u32, u32) -> crate::native_management_executor::Outcome,
) -> Result<crate::native_management_executor::Outcome, &'static str> {
    gate.consume(grant, now, is_system)?;
    Ok(executor(
        command,
        gate.request().timeout_seconds,
        gate.request().output_limit_bytes,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_management_policy::{State, VerifiedGrant};
    fn gate() -> Gate {
        let mut g = Gate::new(
            Request {
                version: 1,
                operation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                command_hash: "a".repeat(64),
                timeout_seconds: 60,
                output_limit_bytes: 1024,
            },
            "A".repeat(43),
            "74067020".into(),
            true,
        )
        .unwrap();
        g.begin(
            1,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            10,
            &"a".repeat(64),
        )
        .unwrap();
        g
    }
    fn grant() -> VerifiedGrant {
        VerifiedGrant {
            environment: "development".into(),
            operation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            command_hash: "a".repeat(64),
            challenge: "A".repeat(43),
            address_id: "74067020".into(),
            actor_id: 7,
            expires_at: 1060,
        }
    }
    #[test]
    fn valid_system_grant_executes_once_without_a_user_session_or_user_token() {
        let mut g = gate();
        let mut calls = 0;
        let outcome = execute_granted(
            &mut g,
            grant(),
            "fixture-command",
            1000,
            true,
            |command, timeout, cap| {
                calls += 1;
                assert_eq!((command, timeout, cap), ("fixture-command", 60, 1024));
                crate::native_management_executor::Outcome {
                    reason: "",
                    exit_code: Some(0),
                    stdout: vec![],
                    stderr: vec![],
                    executor_is_system: true,
                }
            },
        )
        .unwrap();
        assert_eq!(calls, 1);
        assert!(outcome.executor_is_system);
        assert_eq!(g.state(), State::Consumed);
        assert!(execute_granted(
            &mut g,
            grant(),
            "fixture-command",
            1000,
            true,
            |_, _, _| panic!("duplicate command")
        )
        .is_err());
    }
    #[test]
    fn expired_cross_nonce_or_non_system_proof_never_calls_the_executor() {
        for case in 0..3 {
            let mut g = gate();
            let mut proof = grant();
            if case == 0 {
                proof.expires_at = 1000
            }
            if case == 1 {
                proof.challenge = "E".repeat(43)
            }
            assert!(execute_granted(
                &mut g,
                proof,
                "fixture-command",
                1000,
                case != 2,
                |_, _, _| panic!("rejected command executed")
            )
            .is_err());
        }
    }
}
fn system() -> bool {
    #[cfg(windows)]
    {
        crate::platform::is_process_running_as_system(std::process::id()).unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        false
    }
}
