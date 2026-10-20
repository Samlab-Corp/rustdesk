//! Dedicated management command. All authentication and command input is stdin.
//! No OpenTerminal, terminal input, local credential persistence or auto retry.
use crate::native_management_policy as policy;
use crate::{
    client::{Data, Interface, QualityStatus},
    ui_session_interface::{InvokeUiSession, Session},
};
use hbb_common::{log, message_proto::*, rendezvous_proto::ConnType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Scope {
    management_version: u32,
    environment: String,
    operation_id: String,
    #[serde(default)]
    command_hash: String,
    #[serde(default)]
    challenge: String,
    merchant_id: u64,
    kiosk_option_id: u64,
    device_id: String,
    enrollment_id: String,
    address_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    password: String,
    operator_access_token: String,
    command: String,
    scope: Scope,
    timeout_seconds: u32,
    output_limit_bytes: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantResponse {
    success: bool,
    data: Grant,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    management_version: u32,
    grant_token: String,
    operation_id: String,
    command_hash: String,
    challenge: String,
    expires_at: u64,
}
enum Event {
    Connected,
    Challenge(NativeManagementChallenge),
    Result(NativeManagementResult),
    Failed(&'static str),
}
#[derive(Clone, Default)]
struct Handler {
    tx: Option<mpsc::SyncSender<Event>>,
    overflow: Arc<AtomicBool>,
    encrypted: Arc<AtomicBool>,
}
impl Handler {
    fn emit(&self, event: Event) {
        if let Some(tx) = &self.tx {
            if tx.try_send(event).is_err() {
                self.overflow.store(true, Ordering::Release);
            }
        }
    }
}
fn failure_code(_: &str, _: &str, _: &str) -> &'static str {
    "management_connection_failed"
}
fn valid(r: &Request, target: &str) -> bool {
    policy::address(target)
        && r.scope.address_id == target
        && r.scope.management_version == 1
        && r.scope.environment == "development"
        && policy::uuid4(&r.scope.operation_id)
        && policy::uuid4(&r.scope.enrollment_id)
        && r.scope.merchant_id > 0
        && r.scope.kiosk_option_id > 0
        && !r.scope.device_id.is_empty()
        && r.scope.device_id.len() <= 50
        && r.scope
            .device_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
        && !r.password.is_empty()
        && r.password.len() <= 1024
        && !r.operator_access_token.is_empty()
        && r.operator_access_token.len() <= 8192
        && !r.command.is_empty()
        && r.command.len() <= policy::MAX_COMMAND
        && (1..=300).contains(&r.timeout_seconds)
        && (1..=policy::MAX_OUTPUT as u32).contains(&r.output_limit_bytes)
        && (r.scope.command_hash.is_empty()
            || r.scope.command_hash == hex::encode(Sha256::digest(r.command.as_bytes())))
        && r.scope.challenge.is_empty()
}
fn issue(scope: &Scope, operator: &str, timeout: Duration) -> Result<Grant, &'static str> {
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout.min(Duration::from_secs(8)))
        .build()
        .map_err(|_| "management_verification_unavailable")?;
    let response=client.post("https://dev-kiosk-api-server.letmeup.co.kr/v2/backoffice/kiosk-native-management/grant")
        .bearer_auth(operator).json(scope).send().map_err(|_|"management_verification_unavailable")?;
    if !response.status().is_success() {
        return Err("management_approval_denied");
    }
    let mut bytes = Vec::new();
    response
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| "management_verification_unavailable")?;
    if bytes.len() > 16384 {
        return Err("management_protocol_rejected");
    }
    let parsed: Result<GrantResponse, _> = serde_json::from_slice(&bytes);
    bytes.fill(0);
    let response = parsed.map_err(|_| "management_protocol_rejected")?;
    let grant = response.data;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX);
    if !response.success
        || grant.management_version != 1
        || grant.operation_id != scope.operation_id
        || grant.command_hash != scope.command_hash
        || grant.challenge != scope.challenge
        || grant.grant_token.is_empty()
        || grant.grant_token.len() > 8192
        || grant.expires_at <= now
        || grant.expires_at.saturating_sub(now) > 65
    {
        return Err("management_approval_denied");
    }
    Ok(grant)
}
fn report(status: &str, reason: &str, operation: &str, result: Option<NativeManagementResult>) {
    if let Some(r) = result {
        println!(
            "{}",
            serde_json::json!({"status":status,"reason":reason,"operationId":operation,"executorIsSystem":r.executor_is_system,
        "exitCodeConfirmed":r.exit_code_confirmed,"exitCode":if r.exit_code_confirmed{Some(r.exit_code)}else{None},
        "stdout":String::from_utf8_lossy(&r.stdout),"stderr":String::from_utf8_lossy(&r.stderr)})
        );
    } else {
        println!(
            "{}",
            serde_json::json!({"status":status,"reason":reason,"operationId":operation,"executorIsSystem":false,"exitCodeConfirmed":false})
        );
    }
}
fn drive(
    request: &mut Request,
    target: &str,
    rx: &mpsc::Receiver<Event>,
    overflow: &AtomicBool,
    deadline: Instant,
    handshake: Instant,
    mut issuer: impl FnMut(&Scope, &str, Duration) -> Result<Grant, &'static str>,
    mut sender: impl FnMut(NativeManagementExecute),
) -> (
    i32,
    &'static str,
    &'static str,
    Option<NativeManagementResult>,
) {
    let operation = request.scope.operation_id.clone();
    let mut connected = false;
    let mut sent = false;
    loop {
        if overflow.load(Ordering::Acquire) {
            break (1, "unconfirmed", "management_protocol_rejected", None);
        }
        let until = if sent { deadline } else { handshake };
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break (
                124,
                if sent { "unconfirmed" } else { "failed" },
                if sent {
                    "management_timeout_unconfirmed"
                } else {
                    "management_challenge_required"
                },
                None,
            );
        }
        match rx.recv_timeout(remaining) {
            Ok(Event::Connected) => connected = true,
            Ok(Event::Challenge(c)) => {
                if sent
                    || !connected
                    || c.management_version != 1
                    || c.operation_id != operation
                    || c.command_hash != request.scope.command_hash
                    || c.address_id != target
                    || !policy::challenge(&c.challenge)
                {
                    break (
                        1,
                        if sent { "unconfirmed" } else { "failed" },
                        "management_protocol_rejected",
                        None,
                    );
                }
                request.scope.challenge = c.challenge;
                let grant = match issuer(
                    &request.scope,
                    &request.operator_access_token,
                    deadline.saturating_duration_since(Instant::now()),
                ) {
                    Ok(g) => g,
                    Err(reason) => break (1, "failed", reason, None),
                };
                request.operator_access_token.clear();
                let execute = NativeManagementExecute {
                    management_version: 1,
                    operation_id: operation.clone(),
                    grant_token: grant.grant_token,
                    command: std::mem::take(&mut request.command),
                    ..Default::default()
                };
                sent = true;
                sender(execute);
            }
            Ok(Event::Result(r)) => {
                if !sent
                    || r.management_version != 1
                    || r.operation_id != operation
                    || r.stdout.len().saturating_add(r.stderr.len())
                        > request.output_limit_bytes as usize
                {
                    break (1, "unconfirmed", "management_protocol_rejected", None);
                }
                if r.status == "completed"
                    && r.reason.is_empty()
                    && r.exit_code_confirmed
                    && r.executor_is_system
                {
                    break (
                        if r.exit_code == 0 { 0 } else { 1 },
                        "completed",
                        "",
                        Some(r),
                    );
                }
                let reason =
                    policy::fixed_reason(&r.reason).unwrap_or("management_execution_unconfirmed");
                let status = if r.status == "rejected" && !r.exit_code_confirmed {
                    "rejected"
                } else {
                    "unconfirmed"
                };
                break (1, status, reason, Some(r));
            }
            Ok(Event::Failed(reason)) => {
                break (1, if sent { "unconfirmed" } else { "failed" }, reason, None)
            }
            Err(_) => {
                break (
                    124,
                    if sent { "unconfirmed" } else { "failed" },
                    if sent {
                        "management_timeout_unconfirmed"
                    } else {
                        "management_challenge_required"
                    },
                    None,
                )
            }
        }
    }
}
pub fn run() -> i32 {
    log::set_max_level(log::LevelFilter::Off);
    std::panic::set_hook(Box::new(|_| {}));
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (target, force) = match args.as_slice() {
        [flag, id] if flag == "--target" => (id.clone(), false),
        [flag, id, relay] if flag == "--target" && relay == "--force-relay" => (id.clone(), true),
        _ => {
            report("failed", "management_invalid_request", "", None);
            return 2;
        }
    };
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let ok = io::stdin().take(196609).read_to_end(&mut b).is_ok() && b.len() <= 196608;
        let r = if ok {
            serde_json::from_slice::<Request>(&b).ok()
        } else {
            None
        };
        b.fill(0);
        let _ = tx.send(r);
    });
    let mut request = match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(Some(r)) if valid(&r, &target) => r,
        _ => {
            report("failed", "management_invalid_request", "", None);
            return 2;
        }
    };
    if request.scope.command_hash.is_empty() {
        request.scope.command_hash = hex::encode(Sha256::digest(request.command.as_bytes()));
    }
    let operation = request.scope.operation_id.clone();
    let deadline = Instant::now() + Duration::from_secs(request.timeout_seconds as u64 + 30);
    let handshake = Instant::now() + Duration::from_secs(20);
    let (tx, rx) = mpsc::sync_channel(16);
    let overflow = Arc::new(AtomicBool::new(false));
    let session = Session::<Handler> {
        password: std::mem::take(&mut request.password),
        ui_handler: Handler {
            tx: Some(tx),
            overflow: overflow.clone(),
            encrypted: Arc::new(AtomicBool::new(false)),
        },
        ..Default::default()
    };
    {
        let mut lc = match session.lc.write() {
            Ok(lc) => lc,
            Err(_) => {
                report("failed", "management_not_ready", &operation, None);
                return 1;
            }
        };
        lc.ephemeral = true;
        lc.initialize(
            target.clone(),
            ConnType::TERMINAL,
            None,
            force,
            None,
            None,
            None,
        );
        lc.remember = false;
        lc.is_terminal_admin = false;
        lc.native_management = Some(NativeManagementSession {
            management_version: 1,
            operation_id: operation.clone(),
            command_hash: request.scope.command_hash.clone(),
            timeout_seconds: request.timeout_seconds,
            output_limit_bytes: request.output_limit_bytes,
            ..Default::default()
        });
    }
    let worker = session.clone();
    std::thread::spawn(move || {
        let round = match worker.connection_round_state.lock() {
            Ok(mut s) => s.new_round(),
            Err(_) => return,
        };
        crate::ui_session_interface::io_loop(worker, round);
    });
    let (code, status, reason, result) = drive(
        &mut request,
        &target,
        &rx,
        &overflow,
        deadline,
        handshake,
        issue,
        |execute| {
            let mut message = Message::new();
            message.set_native_management_execute(execute);
            session.send(Data::Message(message));
        },
    );
    session.close();
    report(status, reason, &operation, result);
    code
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            password: "fixture-password".into(),
            operator_access_token: "fixture-operator".into(),
            command: "Write-Output 1".into(),
            scope: Scope {
                management_version: 1,
                environment: "development".into(),
                operation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                command_hash: hex::encode(Sha256::digest(b"Write-Output 1")),
                challenge: String::new(),
                merchant_id: 1,
                kiosk_option_id: 2,
                device_id: "fixture-device".into(),
                enrollment_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
                address_id: "74067020".into(),
            },
            timeout_seconds: 1,
            output_limit_bytes: 1024,
        }
    }
    fn challenge() -> NativeManagementChallenge {
        let r = request();
        NativeManagementChallenge {
            management_version: 1,
            operation_id: r.scope.operation_id,
            command_hash: r.scope.command_hash,
            challenge: "A".repeat(43),
            address_id: "74067020".into(),
            ..Default::default()
        }
    }
    fn grant(s: &Scope) -> Grant {
        Grant {
            management_version: 1,
            grant_token: "fixture-purpose".into(),
            operation_id: s.operation_id.clone(),
            command_hash: s.command_hash.clone(),
            challenge: s.challenge.clone(),
            expires_at: 1060,
        }
    }
    #[test]
    fn old_server_terminal_response_causes_zero_grants_and_zero_command_frames() {
        let (tx, rx) = mpsc::sync_channel(4);
        let handler = Handler {
            tx: Some(tx),
            ..Default::default()
        };
        handler.set_connection_type(true, false, "");
        handler.set_peer_info(&PeerInfo {
            platform: "Windows".into(),
            ..Default::default()
        });
        handler.handle_terminal_response(TerminalResponse::new());
        let result = drive(
            &mut request(),
            "74067020",
            &rx,
            &handler.overflow,
            Instant::now() + Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            |_, _, _| panic!("old server must not issue a grant"),
            |_| panic!("old server must not receive command or input"),
        );
        assert_eq!(
            (result.1, result.2),
            ("failed", "management_protocol_rejected")
        );
    }
    #[test]
    fn no_management_challenge_is_a_finite_failure_without_command() {
        let (tx, rx) = mpsc::sync_channel(2);
        tx.send(Event::Connected).unwrap();
        let now = Instant::now();
        let result = drive(
            &mut request(),
            "74067020",
            &rx,
            &AtomicBool::new(false),
            now + Duration::from_secs(1),
            now + Duration::from_millis(5),
            |_, _, _| panic!("no challenge"),
            |_| panic!("no command"),
        );
        assert_eq!(result.2, "management_challenge_required");
        assert!(now.elapsed() < Duration::from_secs(1));
        drop(tx);
    }
    #[test]
    fn cross_target_or_unencrypted_challenge_never_issues_or_sends() {
        for connected in [true, false] {
            let (tx, rx) = mpsc::sync_channel(3);
            if connected {
                tx.send(Event::Connected).unwrap()
            }
            let mut c = challenge();
            if connected {
                c.address_id = "11111111".into()
            }
            tx.send(Event::Challenge(c)).unwrap();
            let now = Instant::now();
            let result = drive(
                &mut request(),
                "74067020",
                &rx,
                &AtomicBool::new(false),
                now + Duration::from_secs(1),
                now + Duration::from_secs(1),
                |_, _, _| panic!("untrusted challenge"),
                |_| panic!("no command"),
            );
            assert_eq!(result.1, "failed");
        }
    }
    #[test]
    fn repeated_challenge_never_renews_grant_or_reexecutes_uncertain_command() {
        let (tx, rx) = mpsc::sync_channel(3);
        tx.send(Event::Connected).unwrap();
        tx.send(Event::Challenge(challenge())).unwrap();
        tx.send(Event::Challenge(challenge())).unwrap();
        let mut issued = 0;
        let mut sent = 0;
        let now = Instant::now();
        let result = drive(
            &mut request(),
            "74067020",
            &rx,
            &AtomicBool::new(false),
            now + Duration::from_secs(1),
            now + Duration::from_secs(1),
            |s, _, _| {
                issued += 1;
                Ok(grant(s))
            },
            |_| sent += 1,
        );
        assert_eq!((issued, sent), (1, 1));
        assert_eq!(result.1, "unconfirmed");
    }
    #[test]
    fn successful_exit_without_actual_system_proof_is_unconfirmed() {
        let (tx, rx) = mpsc::sync_channel(3);
        tx.send(Event::Connected).unwrap();
        tx.send(Event::Challenge(challenge())).unwrap();
        tx.send(Event::Result(NativeManagementResult {
            management_version: 1,
            operation_id: request().scope.operation_id,
            status: "completed".into(),
            exit_code_confirmed: true,
            executor_is_system: false,
            ..Default::default()
        }))
        .unwrap();
        let now = Instant::now();
        let result = drive(
            &mut request(),
            "74067020",
            &rx,
            &AtomicBool::new(false),
            now + Duration::from_secs(1),
            now + Duration::from_secs(1),
            |s, _, _| Ok(grant(s)),
            |_| {},
        );
        assert_eq!(result.1, "unconfirmed");
    }
    #[test]
    fn stdin_scope_hash_and_target_are_exact() {
        let mut r = request();
        assert!(valid(&r, "74067020"));
        r.command.push(' ');
        assert!(!valid(&r, "74067020"));
        r = request();
        assert!(!valid(&r, "11111111"));
        r.scope.environment = "production".into();
        assert!(!valid(&r, "74067020"));
    }
}

#[allow(unused_variables)]
impl InvokeUiSession for Handler {
    fn set_peer_info(&self, peer_info: &PeerInfo) {
        if !self.encrypted.load(Ordering::Acquire) {
            self.emit(Event::Failed("encrypted_connection_required"));
        } else if peer_info.platform != "Windows" {
            self.emit(Event::Failed("unsupported_remote_platform"));
        } else {
            self.emit(Event::Connected);
        }
    }
    fn msgbox(&self, msgtype: &str, title: &str, text: &str, link: &str, retry: bool) {
        self.emit(Event::Failed(failure_code(msgtype, title, text)));
    }
    fn set_connection_type(&self, is_secured: bool, direct: bool, stream_type: &str) {
        self.encrypted.store(is_secured, Ordering::Release);
        if !is_secured {
            self.emit(Event::Failed("encrypted_connection_required"));
        }
    }
    fn handle_terminal_response(&self, response: TerminalResponse) {
        self.emit(Event::Failed("management_protocol_rejected"));
    }
    fn handle_native_management_challenge(&self, response: NativeManagementChallenge) {
        self.emit(Event::Challenge(response));
    }
    fn handle_native_management_result(&self, response: NativeManagementResult) {
        self.emit(Event::Result(response));
    }
    fn new_message(&self, msg: String) {
        self.emit(Event::Failed("connection_closed"));
    }
    fn set_multiple_windows_session(&self, sessions: Vec<WindowsSession>) {
        self.emit(Event::Failed("session_selection_required"));
    }
    fn get_rgba(&self, display: usize) -> *const u8 {
        std::ptr::null()
    }
    #[cfg(feature = "flutter")]
    fn is_multi_ui_session(&self) -> bool {
        false
    }
    #[cfg(all(feature = "vram", feature = "flutter"))]
    fn on_texture(&self, display: usize, texture: *mut std::ffi::c_void) {}
    fn set_cursor_data(&self, cd: CursorData) {}
    fn set_cursor_id(&self, id: String) {}
    fn set_cursor_position(&self, cp: CursorPosition) {}
    fn set_display(&self, x: i32, y: i32, w: i32, h: i32, cursor_embedded: bool, scale: f64) {}
    fn switch_display(&self, display: &SwitchDisplay) {}
    fn set_displays(&self, displays: &Vec<DisplayInfo>) {}
    fn set_platform_additions(&self, data: &str) {}
    fn on_connected(&self, conn_type: ConnType) {}
    fn update_privacy_mode(&self) {}
    fn set_permission(&self, name: &str, value: bool) {}
    fn close_success(&self) {}
    fn update_quality_status(&self, qs: QualityStatus) {}
    fn set_fingerprint(&self, fingerprint: String) {}
    fn job_error(&self, id: i32, err: String, file_num: i32) {}
    fn job_done(&self, id: i32, file_num: i32) {}
    fn clear_all_jobs(&self) {}
    fn update_transfer_list(&self) {}
    fn load_last_job(&self, cnt: i32, job_json: &str, auto_start: bool) {}
    fn update_folder_files(
        &self,
        id: i32,
        entries: &Vec<FileEntry>,
        path: String,
        is_local: bool,
        only_count: bool,
    ) {
    }
    fn confirm_delete_files(&self, id: i32, i: i32, name: String) {}
    fn override_file_confirm(
        &self,
        id: i32,
        file_num: i32,
        to: String,
        is_upload: bool,
        is_identical: bool,
    ) {
    }
    fn update_block_input_state(&self, on: bool) {}
    fn job_progress(&self, id: i32, file_num: i32, speed: f64, finished_size: f64) {}
    fn adapt_size(&self) {}
    fn on_rgba(&self, display: usize, rgba: &mut scrap::ImageRgb) {}
    fn cancel_msgbox(&self, tag: &str) {}
    fn switch_back(&self, id: &str) {}
    fn portable_service_running(&self, running: bool) {}
    fn on_voice_call_started(&self) {}
    fn on_voice_call_closed(&self, reason: &str) {}
    fn on_voice_call_waiting(&self) {}
    fn on_voice_call_incoming(&self) {}
    fn next_rgba(&self, display: usize) {}
    fn set_current_display(&self, disp_idx: i32) {}
    fn update_record_status(&self, start: bool) {}
    fn printer_request(&self, id: i32, path: String) {}
    fn handle_screenshot_resp(&self, sid: String, msg: String) {}
}
