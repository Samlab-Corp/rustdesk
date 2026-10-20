//! Dedicated non-PTY reenrollment client. Credentials enter through stdin only.
use crate::{
    client::{Data, Interface, QualityStatus},
    reenrollment_payload::{self as wire, Scope},
    reenrollment_policy as p,
    ui_session_interface::{InvokeUiSession, Session},
};
use hbb_common::{log, message_proto::*, rendezvous_proto::ConnType};
use serde::Deserialize;
use std::{
    io::{self, Read},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    password: String,
    #[serde(default)]
    connection_token: Option<String>,
    #[serde(default)]
    delegation_token: Option<String>,
    delivery_id: String,
    guardian_sha256: String,
    action: String,
    scope: Scope,
}
fn wipe(s: &mut String) {
    let mut b = std::mem::take(s).into_bytes();
    b.fill(0);
}
impl Drop for Request {
    fn drop(&mut self) {
        wipe(&mut self.password);
        if let Some(s) = self.connection_token.as_mut() {
            wipe(s)
        }
        if let Some(s) = self.delegation_token.as_mut() {
            wipe(s)
        }
    }
}
enum Event {
    Connected,
    Challenge(ReenrollmentCapability),
    Result(ReenrollmentResult),
    Failed(&'static str),
}
#[derive(Clone, Default)]
struct Handler {
    tx: Option<mpsc::SyncSender<Event>>,
    overflow: Arc<AtomicBool>,
    encrypted: Arc<AtomicBool>,
}
impl Handler {
    fn emit(&self, e: Event) {
        if self.tx.as_ref().map_or(false, |tx| tx.try_send(e).is_err()) {
            self.overflow.store(true, Ordering::Release)
        }
    }
}
fn failure_code(_: &str, _: &str, _: &str) -> &'static str {
    "reenrollment_connection_failed"
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_and_commands_are_not_optional_wire_extensions() {
        let value = serde_json::json!({"password":"fixture-only","delivery_id":"11111111-1111-4111-8111-111111111111","guardian_sha256":"a".repeat(64),"action":"prepare","scope":{"reenrollmentVersion":1,"environment":"development","operationId":"11111111-1111-4111-8111-111111111111","merchantId":1,"kioskOptionId":2,"expectedRevision":1,"deviceId":"fixture","location":"outer","number":1,"oldEnrollmentId":"22222222-2222-4222-8222-222222222222","newEnrollmentId":"33333333-3333-4333-8333-333333333333","addressId":"74067020"}});
        assert!(serde_json::from_value::<Request>(value.clone()).is_ok());
        for field in [
            "command",
            "commandHash",
            "path",
            "timeout",
            "grantToken",
            "old_password",
        ] {
            let mut bad = value.clone();
            bad[field] = "private-fixture".into();
            assert!(serde_json::from_value::<Request>(bad).is_err());
        }
        let r: Request = serde_json::from_value(value).unwrap();
        let g = serde_json::json!({"protocolVersion":1,"ok":true,"purpose":p::PURPOSE,"reenrollmentVersion":1,"scope":r.scope,"action":"prepare","commandHash":p::PREPARE_HASH,"system":true,"readOnly":true,"requiresOnlineAuthorization":true});
        let c = ReenrollmentCapability {
            reenrollment_version: 1,
            delivery_id: r.delivery_id.clone(),
            operation_id: r.scope.operation_id.clone(),
            action: r.action.clone(),
            command_hash: p::PREPARE_HASH.into(),
            scope_json: serde_json::to_vec(&r.scope).unwrap().into(),
            guardian_sha256: r.guardian_sha256.clone(),
            address_id: r.scope.address_id.clone(),
            challenge: "n".repeat(43),
            executor_is_system: true,
            executor_process_id: 123,
            executor_session_id: 7,
            non_pty: true,
            guardian_capability: serde_json::to_vec(&g).unwrap().into(),
            ..Default::default()
        };
        assert!(capability(&c, &r, "74067020")); // SYSTEM can run in a nonzero measured session.
        for n in 0..8 {
            let mut bad = c.clone();
            match n {
                0 => bad.non_pty = false,
                1 => bad.executor_is_system = false,
                2 => bad.executor_process_id = 0,
                3 => bad.guardian_sha256 = "b".repeat(64),
                4 => bad.address_id = "12345678".into(),
                5 => bad.challenge.clear(),
                6 => bad.command_hash = p::ROTATE_HASH.into(),
                _ => bad.guardian_capability = b"{}".to_vec().into(),
            };
            assert!(!capability(&bad, &r, "74067020"));
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantEnvelope {
    success: bool,
    data: Grant,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    reenrollment_version: u8,
    grant_token: String,
    action: String,
    operation_id: String,
    delivery_id: String,
    command_hash: String,
    expires_at: u64,
}
impl Drop for Grant {
    fn drop(&mut self) {
        wipe(&mut self.grant_token)
    }
}
fn issue(r: &Request, c: &ReenrollmentCapability) -> Result<Grant, &'static str> {
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .no_proxy()
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "reenrollment_authorization_rejected")?;
    let response=client.post("https://dev-kiosk-api-server.letmeup.co.kr/v2/kiosk/device/guardian-reenrollment/management-grant").bearer_auth(r.delegation_token.as_deref().ok_or("reenrollment_authorization_rejected")?).json(&serde_json::json!({"deliveryId":r.delivery_id,"challenge":c.challenge,"commandHash":p::action_hash(&r.action).unwrap()})).send().map_err(|_|"reenrollment_authorization_rejected")?;
    if !response.status().is_success() {
        return Err("reenrollment_authorization_rejected");
    }
    let mut bytes = Vec::new();
    response
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| "reenrollment_authorization_rejected")?;
    if bytes.len() > 16384 {
        bytes.fill(0);
        return Err("reenrollment_protocol_rejected");
    }
    let parsed = serde_json::from_slice::<GrantEnvelope>(&bytes);
    bytes.fill(0);
    let envelope = parsed.map_err(|_| "reenrollment_protocol_rejected")?;
    let g = envelope.data;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    if !envelope.success
        || g.reenrollment_version != 1
        || g.action != r.action
        || g.operation_id != r.scope.operation_id
        || g.delivery_id != r.delivery_id
        || Some(g.command_hash.as_str()) != p::action_hash(&r.action)
        || !(100..=8192).contains(&g.grant_token.len())
        || g.expires_at <= now
        || g.expires_at - now > 60
    {
        return Err("reenrollment_authorization_rejected");
    }
    Ok(g)
}
fn capability(c: &ReenrollmentCapability, r: &Request, target: &str) -> bool {
    c.reenrollment_version == 1
        && c.delivery_id == r.delivery_id
        && c.operation_id == r.scope.operation_id
        && c.action == r.action
        && Some(c.command_hash.as_str()) == p::action_hash(&r.action)
        && c.guardian_sha256 == r.guardian_sha256
        && c.address_id == target
        && c.address_id == r.scope.address_id
        && c.executor_is_system
        && c.executor_process_id > 0
        && c.non_pty
        && p::nonce(&c.challenge)
        && Scope::parse(&c.scope_json).map_or(false, |s| s == r.scope)
        && wire::capability(&c.guardian_capability, &r.scope, &r.action).is_ok()
}
fn report(
    status: &str,
    reason: &str,
    r: Option<&Request>,
    c: Option<&ReenrollmentCapability>,
    receipt: Option<wire::Receipt>,
    confirmed: bool,
) {
    let guardian = c.and_then(|c| {
        r.and_then(|r| wire::capability(&c.guardian_capability, &r.scope, &r.action).ok())
    });
    let cap=c.zip(guardian).map(|(c,g)|serde_json::json!({"purpose":p::PURPOSE,"challenge":c.challenge,"addressId":c.address_id,"guardian":g}));
    println!(
        "{}",
        serde_json::json!({"reenrollmentVersion":1,"status":status,"reason":reason,"deliveryId":r.map(|r|&r.delivery_id),"operationId":r.map(|r|&r.scope.operation_id),"action":r.map(|r|&r.action),"scope":r.map(|r|&r.scope),"commandHash":r.and_then(|r|p::action_hash(&r.action)),"guardianSha256":r.map(|r|&r.guardian_sha256),"executorIsSystem":c.map_or(false,|c|c.executor_is_system),"executorProcessId":c.map(|c|c.executor_process_id),"executorSessionId":c.map(|c|c.executor_session_id),"nonPty":true,"capability":cap,"receipt":receipt,"responseConfirmed":confirmed})
    );
}
fn input() -> Result<Request, &'static str> {
    use std::io::IsTerminal;
    if io::stdin().is_terminal() {
        return Err("invalid_input");
    }
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let result = io::stdin().lock().take(32769).read_to_end(&mut b);
        let parsed = if result.is_ok() && b.len() <= 32768 {
            serde_json::from_slice(&b).ok()
        } else {
            None
        };
        b.fill(0);
        let _ = tx.send(parsed);
    });
    rx.recv_timeout(Duration::from_secs(10))
        .ok()
        .flatten()
        .ok_or("invalid_input")
}
pub fn run() -> i32 {
    let start = Instant::now();
    log::set_max_level(log::LevelFilter::Off);
    std::panic::set_hook(Box::new(|_| {}));
    let mut args = std::env::args().skip(1);
    let mut target = String::new();
    let mut mode = None;
    let mut force = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--guardian-reenrollment-probe" if mode.is_none() => mode = Some(true),
            "--guardian-reenrollment" if mode.is_none() => mode = Some(false),
            "--target" if target.is_empty() => target = args.next().unwrap_or_default(),
            "--force-relay" => force = true,
            _ => {
                report("rejected", "invalid_arguments", None, None, None, false);
                return 2;
            }
        }
    }
    let Some(probe) = mode else {
        report("rejected", "invalid_arguments", None, None, None, false);
        return 2;
    };
    let mut r = match input() {
        Ok(r) => r,
        Err(e) => {
            report("rejected", e, None, None, None, false);
            return 2;
        }
    };
    if !p::address(&target)
        || target != r.scope.address_id
        || !r.scope.valid()
        || !p::uuid4(&r.delivery_id)
        || !p::hash(&r.guardian_sha256)
        || p::action_hash(&r.action).is_none()
        || r.password.is_empty()
        || r.password.len() > 1024
        || r.connection_token
            .as_ref()
            .map_or(false, |s| s.len() > 8192)
        || (!probe
            && r.delegation_token
                .as_ref()
                .map_or(true, |s| !(100..=8192).contains(&s.len())))
        || (probe && r.delegation_token.is_some())
    {
        report("rejected", "invalid_input", None, None, None, false);
        return 2;
    }
    let (tx, rx) = mpsc::sync_channel(32);
    let overflow = Arc::new(AtomicBool::new(false));
    let session = Session::<Handler> {
        password: std::mem::take(&mut r.password),
        ui_handler: Handler {
            tx: Some(tx),
            overflow: overflow.clone(),
            encrypted: Arc::new(AtomicBool::new(false)),
        },
        ..Default::default()
    };
    {
        let Ok(mut lc) = session.lc.write() else {
            report(
                "unavailable",
                "reenrollment_not_ready",
                Some(&r),
                None,
                None,
                false,
            );
            return 1;
        };
        lc.ephemeral = true;
        lc.initialize(
            target.clone(),
            ConnType::TERMINAL,
            None,
            force,
            None,
            None,
            r.connection_token.take(),
        );
        lc.remember = false;
        lc.is_terminal_admin = false;
        lc.reenrollment = Some(ReenrollmentSession {
            reenrollment_version: 1,
            delivery_id: r.delivery_id.clone(),
            action: r.action.clone(),
            scope_json: serde_json::to_vec(&r.scope).unwrap().into(),
            guardian_sha256: r.guardian_sha256.clone(),
            probe_only: probe,
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
    let mut connected = false;
    let mut sent = false;
    let mut cap = None;
    let mut deadline = start + Duration::from_secs(45);
    let code = loop {
        if overflow.load(Ordering::Acquire) {
            report(
                if sent { "uncertain" } else { "unavailable" },
                "reenrollment_protocol_rejected",
                Some(&r),
                cap.as_ref(),
                None,
                false,
            );
            break 1;
        }
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            report(
                if sent { "uncertain" } else { "unavailable" },
                "reenrollment_timeout_unconfirmed",
                Some(&r),
                cap.as_ref(),
                None,
                false,
            );
            break 124;
        }
        match rx.recv_timeout(remain) {
            Ok(Event::Connected) => connected = true,
            Ok(Event::Challenge(c)) => {
                if sent || cap.is_some() || !connected || !capability(&c, &r, &target) {
                    report(
                        if sent { "uncertain" } else { "unavailable" },
                        "reenrollment_protocol_rejected",
                        Some(&r),
                        None,
                        None,
                        false,
                    );
                    break 1;
                }
                cap = Some(c.clone());
                if probe {
                    report("supported", "", Some(&r), Some(&c), None, false);
                    break 0;
                }
                let mut grant = match issue(&r, &c) {
                    Ok(g) => g,
                    Err(e) => {
                        report("rejected", e, Some(&r), Some(&c), None, false);
                        break 1;
                    }
                };
                if let Some(s) = r.delegation_token.as_mut() {
                    wipe(s)
                }
                let mut m = Message::new();
                m.set_reenrollment_execute(ReenrollmentExecute {
                    reenrollment_version: 1,
                    delivery_id: r.delivery_id.clone(),
                    challenge: c.challenge.clone(),
                    grant_token: std::mem::take(&mut grant.grant_token),
                    ..Default::default()
                });
                sent = true;
                deadline = (Instant::now() + Duration::from_secs(95))
                    .min(start + Duration::from_secs(150));
                session.send(Data::Message(m));
            }
            Ok(Event::Result(v)) => {
                if sent
                    && v.reenrollment_version == 1
                    && v.delivery_id == r.delivery_id
                    && v.operation_id == r.scope.operation_id
                    && v.status == "completed"
                    && v.reason.is_empty()
                    && v.response_confirmed
                {
                    if let Ok(receipt) = wire::receipt(&v.receipt, &r.scope, &r.action) {
                        report("completed", "", Some(&r), cap.as_ref(), Some(receipt), true);
                        break 0;
                    }
                }
                report(
                    if sent { "uncertain" } else { "rejected" },
                    "reenrollment_execution_unconfirmed",
                    Some(&r),
                    cap.as_ref(),
                    None,
                    false,
                );
                break 1;
            }
            Ok(Event::Failed(e)) => {
                report(
                    if sent { "uncertain" } else { "unavailable" },
                    e,
                    Some(&r),
                    cap.as_ref(),
                    None,
                    false,
                );
                break 1;
            }
            Err(_) => {
                report(
                    if sent { "uncertain" } else { "unavailable" },
                    "reenrollment_timeout_unconfirmed",
                    Some(&r),
                    cap.as_ref(),
                    None,
                    false,
                );
                break 124;
            }
        }
    };
    session.close();
    code
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
        self.emit(Event::Failed("reenrollment_protocol_rejected"));
    }
    fn handle_reenrollment_capability(&self, response: ReenrollmentCapability) {
        self.emit(Event::Challenge(response));
    }
    fn handle_reenrollment_result(&self, response: ReenrollmentResult) {
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
