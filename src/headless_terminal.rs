//! A console adapter for the existing authenticated RustDesk terminal protocol.
//! No listener, GUI, OS-login escalation, credential persistence, or new protocol.
#[path = "headless_terminal_policy.rs"]
mod policy;

use crate::{
    client::QualityStatus,
    ui_session_interface::{InvokeUiSession, Session},
};
use base64::Engine;
use hbb_common::{base64, log, message_proto::*, rendezvous_proto::ConnType};
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
    command: String,
    #[serde(default)]
    connection_token: Option<String>,
}

enum Event {
    Connected,
    Terminal(TerminalResponse),
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

fn failure_code(kind: &str, title: &str, text: &str) -> &'static str {
    let value = format!("{kind} {title} {text}").to_ascii_lowercase();
    if value.contains("2fa") || value.contains("verification code") || value.contains("two-factor")
    {
        "two_factor_required"
    } else if value.contains("permission") {
        "permission_denied"
    } else if value.contains("logged on")
        || value.contains("user token")
        || value.contains("os password")
        || value.contains("logon")
        || value.contains("os login")
    {
        "os_login_required"
    } else if value.contains("password") {
        "authentication_failed"
    } else if value.contains("insecure")
        || value.contains("fingerprint")
        || value.contains("key mismatch")
    {
        "security_confirmation_required"
    } else {
        "connection_failed"
    }
}

fn report(status: &str, reason: &str, output: &str, remote_exit: Option<i32>) {
    // Never serialize the input request, credentials, command, or peer metadata.
    println!(
        "{}",
        serde_json::json!({"status":status,"reason":reason,
        "output":output,"remoteExitCode":remote_exit})
    );
}

fn launch_command(command: &str, id: &str) -> String {
    let script = format!("$ErrorActionPreference='Stop';$global:LASTEXITCODE=0;[Console]::WriteLine('SAMLAB_START_{id}');$rc=0;try{{& {{\n{command}\n}};if(-not $?){{$rc=1}};if($global:LASTEXITCODE -ne 0){{$rc=[int]$global:LASTEXITCODE}}}}catch{{[Console]::Error.WriteLine($_.ToString());$rc=1}};[Console]::WriteLine(('`nSAMLAB_END_{id}:'+$rc).Replace('`n',[Environment]::NewLine));exit $rc");
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    format!("& ([IO.Path]::Combine($env:SystemRoot,'System32\\WindowsPowerShell\\v1.0\\powershell.exe')) -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}\r\n")
}

pub fn run() -> i32 {
    if std::env::args().any(|arg| matches!(arg.as_str(), "--kiosk-control" | "--kiosk-control-probe")) {
        return crate::headless_kiosk_control::run();
    }
    // Do not initialize the product logger: neither protocol diagnostics nor
    // panic payloads may disclose authentication input or command contents.
    log::set_max_level(log::LevelFilter::Off);
    std::panic::set_hook(Box::new(|_| {}));
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut target = String::new();
    let mut timeout = 60u64;
    let mut cap = 1024 * 1024usize;
    let mut force_relay = false;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--force-relay" {
            force_relay = true;
            i += 1;
            continue;
        }
        if i + 1 >= args.len() {
            report("failed", "invalid_arguments", "", None);
            return 2;
        }
        match args[i].as_str() {
            "--target" if target.is_empty() => target = args[i + 1].clone(),
            "--timeout-seconds" => timeout = args[i + 1].parse().unwrap_or(0),
            "--max-output-bytes" => cap = args[i + 1].parse().unwrap_or(0),
            _ => {
                report("failed", "invalid_arguments", "", None);
                return 2;
            }
        }
        i += 2;
    }
    if !policy::valid_target(&target)
        || !(1..=300).contains(&timeout)
        || !(1..=policy::MAX_OUTPUT).contains(&cap)
    {
        report("failed", "invalid_arguments", "", None);
        return 2;
    }
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let (input_tx, input_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = io::stdin()
            .take((policy::MAX_INPUT + 1) as u64)
            .read_to_end(&mut bytes);
        let result = if read.is_ok() && bytes.len() <= policy::MAX_INPUT {
            serde_json::from_slice::<Request>(&bytes).ok()
        } else {
            None
        };
        bytes.fill(0);
        let _ = input_tx.send(result);
    });
    let request = match input_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Some(value))
            if !value.password.is_empty()
                && value.password.len() <= 1024
                && policy::valid_command(&value.command)
                && value
                    .connection_token
                    .as_ref()
                    .map_or(true, |s| s.len() <= 8192) =>
        {
            value
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            report("failed", "input_timeout", "", None);
            return 124;
        }
        _ => {
            report("failed", "invalid_input", "", None);
            return 2;
        }
    };
    let (tx, rx) = mpsc::sync_channel(64);
    let overflow = Arc::new(AtomicBool::new(false));
    let session = Session::<Handler> {
        password: request.password,
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
                report("failed", "initialization_failed", "", None);
                return 1;
            }
        };
        lc.ephemeral = true;
        lc.initialize(
            target,
            ConnType::TERMINAL,
            None,
            force_relay,
            None,
            None,
            request.connection_token,
        );
        lc.remember = false;
        // Current interactive user only; never consume the GUI's admin flag.
        lc.is_terminal_admin = false;
    }
    let io_session = session.clone();
    std::thread::spawn(move || {
        let round = match io_session.connection_round_state.lock() {
            Ok(mut s) => s.new_round(),
            Err(_) => return,
        };
        crate::ui_session_interface::io_loop(io_session, round);
    });
    let command_id = uuid::Uuid::new_v4().simple().to_string();
    let mut frame = policy::OutputFrame::new(&command_id, cap);
    let mut command = Some(request.command);
    let mut opened = false;
    let mut terminal_open_requested = false;
    let result = loop {
        if overflow.load(Ordering::Acquire) {
            break (1, "event_limit", None);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break (124, "timeout", None);
        }
        match rx.recv_timeout(remaining) {
            Ok(Event::Failed(reason)) => break (1, reason, None),
            Ok(Event::Connected) if !terminal_open_requested => {
                terminal_open_requested = true;
                session.open_terminal(0, 24, 240);
            }
            Ok(Event::Connected) => {}
            Ok(Event::Terminal(response)) => {
                use hbb_common::message_proto::terminal_response::Union;
                match response.union {
                    Some(Union::Opened(value)) => {
                        if value.terminal_id != 0 || opened {
                            break (1, "unexpected_terminal", None);
                        }
                        if !value.success || value.replay_terminal_output {
                            break (1, "terminal_open_failed", None);
                        }
                        opened = true;
                        if let Some(value) = command.take() {
                            session.send_terminal_input(0, launch_command(&value, &command_id));
                        }
                    }
                    Some(Union::Data(value)) if opened && value.terminal_id == 0 => {
                        if value.data.len() > policy::MAX_OUTPUT {
                            break (1, "output_limit", None);
                        }
                        let bytes = if value.compressed {
                            hbb_common::compress::decompress(&value.data)
                        } else {
                            value.data.to_vec()
                        };
                        if bytes.len() > policy::MAX_OUTPUT {
                            break (1, "output_limit", None);
                        }
                        match frame.feed(&bytes) {
                            Ok(Some((output, code))) => {
                                report("completed", "remote_exit", &output, Some(code));
                                break (if code == 0 { 0 } else { 10 }, "", Some(code));
                            }
                            Err(_) => break (1, "output_limit", None),
                            Ok(None) => {}
                        }
                    }
                    Some(Union::Closed(_)) => break (1, "closed_without_completion", None),
                    Some(Union::Error(_)) => break (1, "terminal_error", None),
                    _ => break (1, "unexpected_terminal", None),
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break (124, "timeout", None),
            Err(_) => break (1, "connection_closed", None),
        }
    };
    session.close_terminal(0);
    session.close();
    if result.2.is_none() {
        report(
            if opened { "unconfirmed" } else { "failed" },
            result.1,
            "",
            None,
        );
    }
    // Do not await a hung networking thread; process exit closes its handles.
    result.0
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
        self.emit(Event::Terminal(response));
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_prompts_fail_without_retry() {
        assert_eq!(
            failure_code("input-password", "", ""),
            "authentication_failed"
        );
        assert_eq!(failure_code("input-2fa", "", ""), "two_factor_required");
        assert_eq!(
            failure_code("error", "", "No permission of terminal"),
            "permission_denied"
        );
        assert_eq!(
            failure_code("error", "", "No active console user logged on"),
            "os_login_required"
        );
    }
    #[test]
    fn command_wrapper_distinguishes_native_and_powershell_failure() {
        use std::process::Command;
        for (command, expected) in [
            ("Write-Output 'local-only'", 0),
            ("cmd.exe /d /c exit 7", 7),
            ("Write-Error 'local-test-error'", 1),
        ] {
            let line = launch_command(command, "test");
            let encoded = line
                .split_whitespace()
                .last()
                .expect("encoded local test command missing");
            let result = Command::new("powershell.exe")
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-EncodedCommand",
                    encoded,
                ])
                .output()
                .expect("local PowerShell test failed");
            let mut frame = policy::OutputFrame::new("test", 8192);
            let (_, code) = frame
                .feed(&result.stdout)
                .expect("local frame limit")
                .expect("local completion marker missing");
            assert_eq!(code, expected);
            assert_eq!(result.status.code(), Some(expected));
        }
    }
    #[test]
    fn explicit_exit_without_marker_remains_unconfirmed() {
        use std::process::Command;
        let line = launch_command("exit 7", "test");
        let encoded = line
            .split_whitespace()
            .last()
            .expect("encoded local test command missing");
        let result = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded,
            ])
            .output()
            .expect("local PowerShell test failed");
        let mut frame = policy::OutputFrame::new("test", 8192);
        assert!(frame
            .feed(&result.stdout)
            .expect("local frame limit")
            .is_none());
        assert_eq!(result.status.code(), Some(7));
    }
    #[test]
    #[ignore = "opt-in: existing local service, temporary password, hostname only"]
    fn existing_local_service_hostname() {
        use std::process::{Command, Stdio};
        let expected =
            std::env::var("SAMLAB_LOCAL_TERMINAL_ID").expect("explicit local target required");
        assert!(
            policy::valid_target(&expected),
            "invalid explicit local target"
        );
        // get_id() can update local configuration; use read-only IPC instead.
        let id = crate::ipc::get_config("id")
            .ok()
            .flatten()
            .expect("local IPC id unavailable");
        assert!(
            id == expected,
            "target does not match the current local service"
        );
        let password = crate::ipc::get_config("temporary-password")
            .ok()
            .flatten()
            .expect("local temporary password unavailable");
        assert!(!password.is_empty(), "local temporary password unavailable");
        let executable =
            std::env::var("SAMLAB_TERMINAL_EXE").expect("explicit CLI executable required");
        let mut child = Command::new(executable)
            .args([
                "--target",
                &id,
                "--force-relay",
                "--timeout-seconds",
                "30",
                "--max-output-bytes",
                "4096",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("CLI launch failed");
        let input = child.stdin.take().expect("CLI stdin unavailable");
        serde_json::to_writer(
            input,
            &serde_json::json!({"password": password,"command":"hostname"}),
        )
        .expect("CLI input write failed");
        let result = child.wait_with_output().expect("CLI wait failed");
        assert!(
            result.stdout.len() <= 8192 && result.stderr.len() <= 8192,
            "CLI exceeded output bound"
        );
        let value: serde_json::Value =
            serde_json::from_slice(&result.stdout).expect("CLI returned invalid JSON");
        assert!(
            result.status.success(),
            "local CLI connection or command failed"
        );
        assert!(
            value["status"] == "completed" && value["remoteExitCode"] == 0,
            "local command was not confirmed"
        );
        assert!(
            !value["output"].as_str().unwrap_or("").trim().is_empty(),
            "hostname output missing"
        );
    }
}
