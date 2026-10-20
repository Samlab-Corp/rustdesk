//! SYSTEM-only provider CAS. No ordinary installer setter is weakened.
use crate::reenrollment_policy as policy;
use hbb_common::{
    config::{Config, PermanentPasswordUpdate},
    tokio,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, OnceLock};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Cas,
    Status,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    mode: Mode,
    body: String,
}
impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReenrollmentPasswordFrame([redacted])")
    }
}
fn wipe(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    bytes.fill(0);
}
impl Drop for Frame {
    fn drop(&mut self) {
        wipe(&mut self.body);
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    old_password: String,
    new_password: String,
    operation_id: String,
    old_enrollment_id: String,
    new_enrollment_id: String,
    expected_address_id: String,
}
impl Drop for Request {
    fn drop(&mut self) {
        wipe(&mut self.old_password);
        wipe(&mut self.new_password);
    }
}
impl Request {
    fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err("invalid_input");
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| "invalid_input")?;
        if !policy::rotation(
            &value.old_password,
            &value.new_password,
            &value.operation_id,
            &value.old_enrollment_id,
            &value.new_enrollment_id,
            &value.expected_address_id,
        ) {
            return Err("invalid_input");
        }
        Ok(value)
    }
    fn binding(&self) -> Result<[u8; 32], &'static str> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| "invalid_input")?;
        let result = Sha256::digest(&bytes).into();
        bytes.fill(0);
        Ok(result)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    cas_version: u8,
    status: String,
    reason: String,
    operation_id: String,
    old_enrollment_id: String,
    new_enrollment_id: String,
    address_id: String,
    daemon_accepted: bool,
    persisted: bool,
    new_matches: bool,
    old_matches: bool,
    rotation_in_flight: bool,
    server_verified: bool,
}
impl Status {
    fn failure(reason: &str, request: Option<&Request>) -> Self {
        Self {
            cas_version: 1,
            status: "uncertain".into(),
            reason: reason.into(),
            operation_id: request.map(|r| r.operation_id.clone()).unwrap_or_default(),
            old_enrollment_id: request
                .map(|r| r.old_enrollment_id.clone())
                .unwrap_or_default(),
            new_enrollment_id: request
                .map(|r| r.new_enrollment_id.clone())
                .unwrap_or_default(),
            address_id: request
                .map(|r| r.expected_address_id.clone())
                .unwrap_or_default(),
            daemon_accepted: false,
            persisted: false,
            new_matches: false,
            old_matches: false,
            rotation_in_flight: false,
            server_verified: false,
        }
    }
    fn confirmed(&self) -> bool {
        self.cas_version == 1
            && ["completed", "observed"].contains(&self.status.as_str())
            && self.daemon_accepted
            && self.persisted
            && !self.rotation_in_flight
            && self.server_verified
    }
}
#[derive(Default)]
struct Operations {
    used: std::collections::HashMap<String, [u8; 32]>,
}
static OPERATIONS: OnceLock<Mutex<Operations>> = OnceLock::new();
pub(crate) fn apply(frame: &Frame, system_peer: bool) -> Status {
    let request = match Request::parse(frame.body.as_bytes()) {
        Ok(value) => value,
        Err(reason) => return Status::failure(reason, None),
    };
    if !system_peer
        || !crate::platform::is_process_running_as_system(std::process::id()).unwrap_or(false)
        || !crate::platform::is_installed()
        || crate::core_main::is_cli_setting_change_disabled()
        || Config::is_disable_change_permanent_password()
    {
        return Status::failure("system_service_required", Some(&request));
    }
    if !crate::installer_password::company_server_verified()
        || Config::get_id_or(String::new()) != request.expected_address_id
    {
        return Status::failure("provider_identity_unconfirmed", Some(&request));
    }
    let mut operations = match OPERATIONS.get_or_init(Default::default).try_lock() {
        Ok(value) => value,
        Err(_) => {
            let mut out = Status::failure("rotation_in_flight", Some(&request));
            out.rotation_in_flight = true;
            return out;
        }
    };
    let binding = match request.binding() {
        Ok(value) => value,
        Err(reason) => return Status::failure(reason, Some(&request)),
    };
    if operations
        .used
        .get(&request.operation_id)
        .is_some_and(|old| old != &binding)
    {
        return Status::failure("operation_conflict", Some(&request));
    }
    let mut accepted = true;
    if frame.mode == Mode::Cas {
        if operations.used.contains_key(&request.operation_id) {
            return Status::failure("rotation_already_attempted", Some(&request));
        }
        if operations.used.len() >= 1024 {
            return Status::failure("rotation_capacity_unavailable", Some(&request));
        }
        // The Guardian has durably fenced Applying before this single call.
        // Reserve here before checking/mutating so a same-process replay cannot
        // repeat an uncertain setter. After any timeout, callers use status only.
        operations
            .used
            .insert(request.operation_id.clone(), binding);
        accepted = Config::compare_exchange_permanent_password(
            &request.old_password,
            &request.new_password,
        ) == PermanentPasswordUpdate::Accepted;
    }
    let Some(observed) =
        Config::observe_permanent_password_pair(&request.old_password, &request.new_password)
    else {
        return Status::failure("persistence_unconfirmed", Some(&request));
    };
    let mut result = Status::failure("provider_state_unconfirmed", Some(&request));
    result.daemon_accepted = true;
    result.persisted = observed.persisted;
    result.new_matches = observed.new_matches;
    result.old_matches = observed.old_matches;
    result.server_verified = crate::installer_password::company_server_verified()
        && Config::get_id_or(String::new()) == request.expected_address_id;
    if result.persisted && result.server_verified {
        if frame.mode == Mode::Status {
            result.status = "observed".into();
            result.reason = "observed".into();
        } else if accepted && result.new_matches && !result.old_matches {
            result.status = "completed".into();
            result.reason = "cas_applied".into();
        }
    }
    result
}
pub(crate) fn respond(frame: Frame, system_peer: bool) -> Frame {
    let status = apply(&frame, system_peer);
    Frame {
        mode: frame.mode,
        body: serde_json::to_string(&status).unwrap_or_else(|_| "{}".into()),
    }
}
fn read_input() -> Result<Vec<u8>, &'static str> {
    use std::io::{IsTerminal, Read};
    if std::io::stdin().is_terminal() {
        return Err("redirected_stdin_required");
    }
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = std::io::stdin()
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| "input_unconfirmed");
        let _ = tx.send(
            if result.is_ok() && !bytes.is_empty() && bytes.len() <= 4096 {
                Ok(bytes)
            } else {
                bytes.fill(0);
                Err("invalid_input")
            },
        );
    });
    rx.recv_timeout(std::time::Duration::from_secs(10))
        .map_err(|_| "input_timeout")?
}
#[tokio::main(flavor = "current_thread")]
async fn send(frame: Frame) -> Result<Status, &'static str> {
    let mut connection = crate::ipc::connect(1000, "")
        .await
        .map_err(|_| "daemon_response_unconfirmed")?;
    let peer = crate::ipc::reenrollment_service_verified(&connection)
        .map_err(|_| "provider_identity_unconfirmed")?;
    peer.check(&connection)
        .map_err(|_| "provider_identity_unconfirmed")?;
    let mode = frame.mode;
    connection
        .send(&crate::ipc::Data::ReenrollmentPassword(frame))
        .await
        .map_err(|_| "daemon_response_unconfirmed")?;
    match connection
        .next_timeout(18000)
        .await
        .map_err(|_| "daemon_response_unconfirmed")?
    {
        Some(crate::ipc::Data::ReenrollmentPassword(frame))
            if frame.mode == mode && frame.body.len() <= 8192 =>
        {
            peer.check(&connection)
                .map_err(|_| "provider_identity_unconfirmed")?;
            serde_json::from_str(&frame.body).map_err(|_| "daemon_response_unconfirmed")
        }
        _ => Err("daemon_response_unconfirmed"),
    }
}
pub fn run(args: &[String]) -> i32 {
    hbb_common::log::set_max_level(hbb_common::log::LevelFilter::Off);
    std::panic::set_hook(Box::new(|_| {}));
    let mode = if args.len() == 1 {
        match args[0].as_str() {
            "--reenrollment-password-cas-stdin" => Some(Mode::Cas),
            "--reenrollment-password-status-stdin" => Some(Mode::Status),
            _ => None,
        }
    } else {
        None
    };
    let outcome = (|| {
        let mode = mode.ok_or("invalid_arguments")?;
        if !crate::platform::is_process_running_as_system(std::process::id()).unwrap_or(false)
            || !crate::platform::is_installed()
        {
            return Err("system_service_required");
        }
        let mut bytes = read_input()?;
        let parsed = Request::parse(&bytes);
        bytes.fill(0);
        let request = parsed?;
        let frame = Frame {
            mode,
            body: serde_json::to_string(&request).map_err(|_| "invalid_input")?,
        };
        let status = send(frame)?;
        if status.operation_id != request.operation_id
            || status.old_enrollment_id != request.old_enrollment_id
            || status.new_enrollment_id != request.new_enrollment_id
            || status.address_id != request.expected_address_id
        {
            return Err("provider_identity_unconfirmed");
        }
        Ok(status)
    })();
    let status = outcome.unwrap_or_else(|reason| Status::failure(reason, None));
    let success = status.confirmed();
    if let Ok(value) = serde_json::to_string(&status) {
        println!("{value}");
    } else {
        println!("{{\"casVersion\":1,\"status\":\"uncertain\",\"reason\":\"output_unconfirmed\"}}");
    }
    if success {
        0
    } else {
        1
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> String {
        serde_json::json!({"old_password":"old-synthetic-password","new_password":"n".repeat(24),"operation_id":"11111111-1111-4111-8111-111111111111",
        "old_enrollment_id":"22222222-2222-4222-8222-222222222222","new_enrollment_id":"33333333-3333-4333-8333-333333333333","expected_address_id":"12345678"}).to_string()
    }
    #[test]
    fn secrets_are_not_debuggable_and_unknown_or_duplicate_fields_are_rejected() {
        let text = input();
        assert!(Request::parse(text.as_bytes()).is_ok());
        let frame = Frame {
            mode: Mode::Cas,
            body: text.clone(),
        };
        let debug = format!("{frame:?}");
        assert!(!debug.contains("synthetic"));
        assert!(!debug.contains(&"n".repeat(24)));
        assert!(Request::parse(
            text.replacen('{', "{\"command\":\"private\",", 1)
                .as_bytes()
        )
        .is_err());
        assert!(Request::parse(
            text.replacen('{', "{\"old_password\":\"private\",", 1)
                .as_bytes()
        )
        .is_err());
    }
    #[test]
    fn unauthorized_peer_fails_before_any_live_configuration_write() {
        let result = apply(
            &Frame {
                mode: Mode::Cas,
                body: input(),
            },
            false,
        );
        assert!(!result.daemon_accepted);
        assert!(!result.persisted);
        assert_eq!(result.reason, "system_service_required");
        assert!(!serde_json::to_string(&result)
            .unwrap()
            .contains("synthetic"));
    }
}
