//! CLI for the fixed, acknowledged current-user non-PTY protocol.
use crate::{
    client::{Data, Interface, QualityStatus},
    kiosk_control_policy as policy,
    ui_session_interface::{InvokeUiSession, Session},
};
use hbb_common::{log, message_proto::*, rendezvous_proto::ConnType};
use serde::Deserialize;
use sha2::{Digest, Sha256};
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
    delivery_id: String,
    operation_id: String,
    expected_device_id: String,
    wrapper_sha256: String,
    #[serde(default)]
    payload: Option<serde_json::Value>,
}
enum Event {
    Connected,
    Challenge(KioskControlCapability),
    Result(KioskControlResult),
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
    "kiosk_control_connection_failed"
}
fn report(
    status: &str,
    reason: &str,
    output: &str,
    exit: Option<i32>,
    capability: Option<&KioskControlCapability>,
) {
    let mut v =
        serde_json::json!({"status":status,"reason":reason,"output":output,"remoteExitCode":exit});
    if let Some(c) = capability {
        v["controlVersion"] = serde_json::json!(1);
        v["action"] = serde_json::json!(policy::ACTION);
        v["nonPty"] = serde_json::json!(true);
        v["currentUser"] = serde_json::json!(true);
        v["wrapperSha256"] = serde_json::json!(c.wrapper_sha256);
        v["expectedDeviceId"] = serde_json::json!(c.expected_device_id);
    }
    println!("{v}");
}
fn capability(c: &KioskControlCapability, r: &policy::Request, target: &str) -> bool {
    c.control_version == 1
        && c.delivery_id == r.delivery_id
        && c.operation_id == r.operation_id
        && c.expected_device_id == r.expected_device_id
        && c.wrapper_sha256 == r.wrapper_sha256
        && c.address_id == target
        && c.action == policy::ACTION
        && c.non_pty
        && c.current_user
        && policy::nonce(&c.challenge)
}
#[cfg(test)]
mod protocol_tests {
    use super::*;
    #[test]
    fn capability_binds_target_scope_hash_and_non_terminal_transport() {
        let r = policy::Request {
            version: 1,
            delivery_id: "11111111-1111-4111-8111-111111111111".into(),
            operation_id: "22222222-2222-4222-8222-222222222222".into(),
            expected_device_id: "fixture".into(),
            wrapper_sha256: "a".repeat(64),
            payload_sha256: "b".repeat(64),
            timeout_seconds: 60,
            output_limit_bytes: 32768,
            probe_only: false,
        };
        let c = KioskControlCapability {
            control_version: 1,
            delivery_id: r.delivery_id.clone(),
            operation_id: r.operation_id.clone(),
            expected_device_id: r.expected_device_id.clone(),
            wrapper_sha256: r.wrapper_sha256.clone(),
            address_id: "remote-fixture".into(),
            challenge: "n".repeat(43),
            action: policy::ACTION.into(),
            non_pty: true,
            current_user: true,
            ..Default::default()
        };
        assert!(capability(&c, &r, "remote-fixture"));
        assert!(!capability(&c, &r, "other-device"));
        for mutate in [0, 1, 2, 3, 4, 5, 6, 7] {
            let mut bad = c.clone();
            match mutate {
                0 => bad.non_pty = false,
                1 => bad.current_user = false,
                2 => bad.operation_id = r.delivery_id.clone(),
                3 => bad.wrapper_sha256 = "c".repeat(64),
                4 => bad.expected_device_id = "other".into(),
                5 => bad.delivery_id = r.operation_id.clone(),
                6 => bad.control_version = 2,
                _ => bad.challenge.clear(),
            }
            assert!(!capability(&bad, &r, "remote-fixture"));
        }
        assert!(!capability(
            &KioskControlCapability::default(),
            &r,
            "remote-fixture"
        ));
    }
    #[test]
    fn cli_rejects_arbitrary_command_and_secret_argument_extensions() {
        let base = serde_json::json!({"password":"fixture-only","delivery_id":"11111111-1111-4111-8111-111111111111",
            "operation_id":"22222222-2222-4222-8222-222222222222","expected_device_id":"fixture","wrapper_sha256":"a".repeat(64)});
        assert!(serde_json::from_value::<Request>(base.clone()).is_ok());
        for field in ["command", "command_stdin", "executable", "approvalToken"] {
            let mut value = base.clone();
            value[field] = serde_json::json!("fixture-only");
            assert!(serde_json::from_value::<Request>(value).is_err());
        }
    }
}
fn reason(value: &str) -> &'static str {
    match value {
        "kiosk_control_delivery_seen" => "kiosk_control_delivery_seen",
        "kiosk_control_delivery_limit" => "kiosk_control_delivery_limit",
        "kiosk_control_wrapper_unavailable" => "kiosk_control_wrapper_unavailable",
        "kiosk_control_current_user_required" => "kiosk_control_current_user_required",
        "kiosk_control_protocol_rejected" => "kiosk_control_protocol_rejected",
        _ => "kiosk_control_execution_unconfirmed",
    }
}
pub fn run() -> i32 {
    log::set_max_level(log::LevelFilter::Off);
    std::panic::set_hook(Box::new(|_| {}));
    let mut args = std::env::args().skip(1);
    let mut target = String::new();
    let mut force = false;
    let mut mode = None;
    let mut timeout = 60u64;
    let mut cap = 32768u32;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--kiosk-control-probe" if mode.is_none() => mode = Some(true),
            "--kiosk-control" if mode.is_none() => mode = Some(false),
            "--force-relay" => force = true,
            "--target" if target.is_empty() => target = args.next().unwrap_or_default(),
            "--timeout-seconds" => timeout = args.next().and_then(|s| s.parse().ok()).unwrap_or(0),
            "--max-output-bytes" => cap = args.next().and_then(|s| s.parse().ok()).unwrap_or(0),
            _ => {
                report("failed", "invalid_arguments", "", None, None);
                return 2;
            }
        }
    }
    let Some(probe) = mode else {
        report("failed", "invalid_arguments", "", None, None);
        return 2;
    };
    if !(3..=16).contains(&target.len())
        || !target.bytes().all(|c| c.is_ascii_digit())
        || !(1..=300).contains(&timeout)
        || !(1..=32768).contains(&cap)
    {
        report("failed", "invalid_arguments", "", None, None);
        return 2;
    }
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let ok = io::stdin().take(65537).read_to_end(&mut bytes).is_ok() && bytes.len() <= 65536;
        let input = if ok {
            serde_json::from_slice::<Request>(&bytes).ok()
        } else {
            None
        };
        bytes.fill(0);
        let _ = tx.send(input);
    });
    let mut input = match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Some(r)) => r,
        _ => {
            report("failed", "invalid_input", "", None, None);
            return 2;
        }
    };
    let mut payload = match &input.payload {
        Some(v) if !probe => serde_json::to_vec(v).unwrap_or_default(),
        None if probe => vec![],
        _ => {
            report("failed", "invalid_input", "", None, None);
            return 2;
        }
    };
    let request = policy::Request {
        version: 1,
        delivery_id: input.delivery_id.clone(),
        operation_id: input.operation_id.clone(),
        expected_device_id: input.expected_device_id.clone(),
        wrapper_sha256: input.wrapper_sha256.clone(),
        payload_sha256: if probe {
            String::new()
        } else {
            hex::encode(Sha256::digest(&payload))
        },
        timeout_seconds: timeout as u32,
        output_limit_bytes: cap,
        probe_only: probe,
    };
    let action = if probe {
        String::new()
    } else {
        match crate::kiosk_control_payload::validate(&payload, &request) {
            Ok(v) => v,
            Err(_) => {
                report("failed", "invalid_input", "", None, None);
                return 2;
            }
        }
    };
    if !request.valid()
        || input.password.is_empty()
        || input.password.len() > 1024
        || input
            .connection_token
            .as_ref()
            .map_or(false, |s| s.len() > 8192)
    {
        report("failed", "invalid_input", "", None, None);
        return 2;
    }
    input.payload = None;
    let (tx, rx) = mpsc::sync_channel(32);
    let overflow = Arc::new(AtomicBool::new(false));
    let session = Session::<Handler> {
        password: std::mem::take(&mut input.password),
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
                report("failed", "kiosk_control_not_ready", "", None, None);
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
            input.connection_token,
        );
        lc.remember = false;
        lc.is_terminal_admin = false;
        lc.kiosk_control = Some(KioskControlSession {
            control_version: 1,
            delivery_id: request.delivery_id.clone(),
            operation_id: request.operation_id.clone(),
            expected_device_id: request.expected_device_id.clone(),
            wrapper_sha256: request.wrapper_sha256.clone(),
            payload_sha256: request.payload_sha256.clone(),
            timeout_seconds: request.timeout_seconds,
            output_limit_bytes: cap,
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
    let handshake = (Instant::now() + Duration::from_secs(20)).min(deadline);
    let mut connected = false;
    let mut sent = false;
    let code = loop {
        if overflow.load(Ordering::Acquire) {
            report(
                if sent { "unconfirmed" } else { "failed" },
                "kiosk_control_protocol_rejected",
                "",
                None,
                None,
            );
            break 1;
        }
        let remaining =
            if sent { deadline } else { handshake }.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            report(
                if sent { "unconfirmed" } else { "failed" },
                if sent {
                    "kiosk_control_execution_unconfirmed"
                } else {
                    "kiosk_control_capability_required"
                },
                "",
                None,
                None,
            );
            break 124;
        }
        match rx.recv_timeout(remaining) {
            Ok(Event::Connected) => connected = true,
            Ok(Event::Challenge(c)) => {
                if sent || !connected || !capability(&c, &request, &target) {
                    report(
                        if sent { "unconfirmed" } else { "failed" },
                        "kiosk_control_protocol_rejected",
                        "",
                        None,
                        None,
                    );
                    break 1;
                }
                if probe {
                    report("capable", "", "", None, Some(&c));
                    break 0;
                }
                let mut message = Message::new();
                message.set_kiosk_control_execute(KioskControlExecute {
                    control_version: 1,
                    delivery_id: request.delivery_id.clone(),
                    challenge: c.challenge,
                    payload: std::mem::take(&mut payload).into(),
                    ..Default::default()
                });
                sent = true;
                session.send(Data::Message(message));
            }
            Ok(Event::Result(r)) => {
                if !sent
                    || r.control_version != 1
                    || r.delivery_id != request.delivery_id
                    || r.operation_id != request.operation_id
                {
                    report(
                        "unconfirmed",
                        "kiosk_control_protocol_rejected",
                        "",
                        None,
                        None,
                    );
                    break 1;
                }
                if r.status == "completed" && r.reason.is_empty() && r.exit_code_confirmed {
                    if let Ok(receipt) =
                        crate::kiosk_control_payload::receipt(&r.receipt, &request, &action)
                    {
                        report(
                            "completed",
                            "",
                            std::str::from_utf8(&receipt).unwrap_or(""),
                            Some(r.exit_code),
                            None,
                        );
                        break if r.exit_code == 0 { 0 } else { 10 };
                    }
                }
                report(
                    if r.status == "rejected" {
                        "rejected"
                    } else {
                        "unconfirmed"
                    },
                    reason(&r.reason),
                    "",
                    None,
                    None,
                );
                break 1;
            }
            Ok(Event::Failed(failure)) => {
                report(
                    if sent { "unconfirmed" } else { "failed" },
                    failure,
                    "",
                    None,
                    None,
                );
                break 1;
            }
            Err(_) => {
                report(
                    if sent { "unconfirmed" } else { "failed" },
                    if sent {
                        "kiosk_control_execution_unconfirmed"
                    } else {
                        "kiosk_control_capability_required"
                    },
                    "",
                    None,
                    None,
                );
                break 124;
            }
        }
    };
    payload.fill(0);
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
        self.emit(Event::Failed("kiosk_control_protocol_rejected"));
    }
    fn handle_kiosk_control_capability(&self, response: KioskControlCapability) {
        self.emit(Event::Challenge(response));
    }
    fn handle_kiosk_control_result(&self, response: KioskControlResult) {
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
