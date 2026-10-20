//! Dedicated process: one ordinary encrypted desktop session, no UI or command execution.
use crate::{
    client::{Data, Interface, Key, QualityStatus, KEY_MAP},
    ui_session_interface::{InvokeUiSession, Session},
    viewer_policy::{self as policy, Command, Input},
};
use hbb_common::base64::{engine::general_purpose::STANDARD, Engine};
use hbb_common::{message_proto::*, rendezvous_proto::ConnType};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{self, BufRead, Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, Instant},
};

static ACTIVE: AtomicBool = AtomicBool::new(false);
lazy_static::lazy_static! {
    static ref OUTPUT_DEADLINE: Mutex<Option<Instant>> = Mutex::new(None);
}
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}
struct Frame {
    epoch: u64,
    sequence: u64,
    display: usize,
    w: usize,
    h: usize,
    jpeg: Vec<u8>,
}
struct Shared {
    encrypted: bool,
    peer: bool,
    keyboard: bool,
    error: Option<&'static str>,
    dirty: bool,
    display: usize,
    x: i32,
    y: i32,
    epoch: u64,
    sequence: u64,
    w: usize,
    h: usize,
    last: Option<Instant>,
    latest: Option<Frame>,
}
impl Default for Shared {
    fn default() -> Self {
        Self {
            encrypted: false,
            peer: false,
            keyboard: false,
            error: None,
            dirty: true,
            display: 0,
            x: 0,
            y: 0,
            epoch: 1,
            sequence: 0,
            w: 0,
            h: 0,
            last: None,
            latest: None,
        }
    }
}
#[derive(Clone, Default)]
struct Handler {
    state: Arc<Mutex<Shared>>,
}
impl Handler {
    fn fail(&self, reason: &'static str) {
        let mut s = self.state.lock().unwrap();
        s.error = Some(reason);
        s.dirty = true;
    }
    fn geometry(&self, display: usize, x: i32, y: i32, w: usize, h: usize) {
        let mut s = self.state.lock().unwrap();
        if s.display != display || s.x != x || s.y != y || s.w != w || s.h != h {
            s.epoch += 1;
            s.latest = None;
            s.display = display;
            s.x = x;
            s.y = y;
            s.w = w;
            s.h = h;
            s.dirty = true;
        }
    }
}

// Overwrite the owned stdin buffer before releasing it; no debugging of input.
fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}
fn line<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, ()> {
    let mut bytes = Vec::new();
    let read = reader
        .take((policy::MAX_LINE + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| ())?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.len() > policy::MAX_LINE || bytes.last() != Some(&b'\n') {
        wipe(&mut bytes);
        return Err(());
    }
    Ok(Some(bytes))
}
fn output(session: &str, kind: &str, extra: Value) -> bool {
    let mut v = extra;
    v["viewerVersion"] = 1.into();
    v["sessionId"] = session.into();
    v["type"] = kind.into();
    *OUTPUT_DEADLINE.lock().unwrap() = Some(Instant::now() + Duration::from_secs(5));
    let mut out = io::stdout().lock();
    let result = serde_json::to_writer(&mut out, &v).is_ok()
        && out.write_all(b"\n").is_ok()
        && out.flush().is_ok();
    *OUTPUT_DEADLINE.lock().unwrap() = None;
    result
}
fn input_thread(tx: mpsc::SyncSender<Result<Command, ()>>, handler: Handler) {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    loop {
        let result = match line(&mut reader) {
            Ok(Some(mut bytes)) => {
                let parsed = serde_json::from_slice(&bytes).map_err(|_| ());
                wipe(&mut bytes);
                parsed
            }
            _ => Err(()),
        };
        let stop = result.is_err();
        if tx.try_send(result).is_err() {
            handler.fail("input_queue_exceeded");
            return;
        }
        if stop {
            return;
        }
    }
}

/// Only the fixed flag is accepted; device IDs and credentials never enter argv.
pub fn run() -> i32 {
    hbb_common::log::set_max_level(hbb_common::log::LevelFilter::Off);
    std::panic::set_hook(Box::new(|_| {}));
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--stdio-v1"] {
        output("", "error", json!({"reason":"invalid_arguments"}));
        return 2;
    }
    // Covers blocked first input and blocked stdout, independently of the main loop.
    let started = Instant::now();
    let deadline = Arc::new(Mutex::new(started + Duration::from_secs(10)));
    let cleanup: Arc<Mutex<Option<(Session<Handler>, Arc<Mutex<Pressed>>)>>> =
        Arc::new(Mutex::new(None));
    let watch = deadline.clone();
    let watch_cleanup = cleanup.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(100));
        if Instant::now() > *watch.lock().unwrap() + Duration::from_secs(3)
            || OUTPUT_DEADLINE
                .lock()
                .unwrap()
                .map_or(false, |t| Instant::now() > t)
        {
            if let Some((session, pressed)) = watch_cleanup.lock().unwrap().as_ref() {
                pressed.lock().unwrap().release(session);
                std::thread::sleep(Duration::from_millis(100));
                session.close();
            }
            std::process::exit(1);
        }
    });
    let mut bytes = match line(&mut io::stdin().lock()) {
        Ok(Some(b)) => b,
        _ => {
            output("", "error", json!({"reason":"invalid_start"}));
            return 2;
        }
    };
    let parsed = serde_json::from_slice::<policy::Start>(&bytes);
    wipe(&mut bytes);
    let mut request = match parsed {
        Ok(r) if r.valid() => r,
        _ => {
            output("", "error", json!({"reason":"invalid_start"}));
            return 2;
        }
    };
    let session_id = request.session_id.clone();
    let ends = Instant::now() + Duration::from_secs(request.max_seconds);
    *deadline.lock().unwrap() = ends;
    ACTIVE.store(true, Ordering::Release);
    if !crate::installer_password::company_server_verified() {
        output(
            &session_id,
            "error",
            json!({"reason":"remote_server_mismatch"}),
        );
        return 1;
    }
    if hbb_common::config::Config::get_id_or(String::new()).is_empty() {
        output(
            &session_id,
            "error",
            json!({"reason":"viewer_local_identity_required"}),
        );
        return 1;
    }
    let handler = Handler::default();
    let session = Session::<Handler> {
        password: std::mem::take(&mut request.password),
        ui_handler: handler.clone(),
        ..Default::default()
    };
    {
        let mut lc = session.lc.write().unwrap();
        lc.ephemeral = true;
        lc.initialize(
            request.address_id.clone(),
            ConnType::DEFAULT_CONN,
            None,
            false,
            None,
            None,
            request.connection_token.take(),
        );
        lc.remember = false;
        lc.record_state = false;
        lc.record_permission = false;
        let mut config = lc.load_config();
        config.disable_audio.v = true;
        config.disable_clipboard.v = true;
        config.enable_file_copy_paste.v = false;
        config.sync_init_clipboard.v = false;
        config.view_only.v = !request.control_requested;
        config.image_quality = "custom".into();
        config.show_remote_cursor.v = true;
        config.lock_after_session_end.v = false;
        config.options.insert("custom-fps".into(), "5".into());
        config
            .options
            .insert("show-remote-cursor".into(), "Y".into());
        lc.save_config(config);
    }
    let (tx, rx) = mpsc::sync_channel(32);
    let reader_handler = handler.clone();
    std::thread::spawn(move || input_thread(tx, reader_handler));
    let mut gate = policy::Gate::default();
    let pressed = Arc::new(Mutex::new(Pressed::default()));
    *cleanup.lock().unwrap() = Some((session.clone(), pressed.clone()));
    let mut viewed = false;
    let mut peer_sent = false;
    let mut budget = (Instant::now(), 0usize);
    let reason;
    let mut exit = 0;
    if !output(
        &session_id,
        "state",
        json!({"phase":"connecting","reason":"connecting","controlAvailable":false}),
    ) {
        return 1;
    }
    let worker = session.clone();
    std::thread::spawn(move || {
        let round = worker.connection_round_state.lock().unwrap().new_round();
        crate::ui_session_interface::io_loop(worker, round);
    });
    'running: loop {
        let now = Instant::now();
        if now >= ends {
            reason = "session_expired";
            break;
        }
        if !viewed && now.duration_since(started) > Duration::from_secs(30) {
            reason = "first_frame_timeout";
            exit = 1;
            break;
        }
        {
            let mut state = handler.state.lock().unwrap();
            if let Some(error) = state.error {
                reason = error;
                exit = 1;
                break;
            }
            if state.peer && state.encrypted && !peer_sent {
                if !output(
                    &session_id,
                    "peer",
                    json!({"addressId":request.address_id,"deviceId":request.device_id,"encrypted":true,"hardwareIdentityVerified":false,"platform":"Windows"}),
                ) {
                    reason = "output_closed";
                    break;
                }
                peer_sent = true;
            }
            if state.dirty {
                state.dirty = false;
                if !state.keyboard || gate.epoch != state.epoch {
                    pressed.lock().unwrap().release(&session);
                }
                if !output(
                    &session_id,
                    "permissions",
                    json!({"controlAvailable":request.control_requested&&state.keyboard&&state.peer&&state.encrypted,"keyboard":state.keyboard}),
                ) {
                    reason = "output_closed";
                    break;
                }
            }
            if let Some(frame) = state.latest.take() {
                if state.encrypted && state.peer {
                    let value = json!({"sequence":frame.sequence,"frameEpoch":frame.epoch,"displayId":frame.display,"width":frame.w,"height":frame.h,"jpegBase64":STANDARD.encode(&frame.jpeg)});
                    if !output(&session_id, "frame", value) {
                        reason = "output_closed";
                        break;
                    }
                    gate.sent(frame.epoch, frame.sequence, frame.w, frame.h, now);
                    if !viewed {
                        viewed = true;
                        if !output(
                            &session_id,
                            "state",
                            json!({"phase":"viewing","reason":"first_frame_received","controlAvailable":request.control_requested&&state.keyboard}),
                        ) {
                            reason = "output_closed";
                            break;
                        }
                    }
                }
            }
        }
        // Bounded work per iteration; no backlog replay or automatic reconnect.
        for _ in 0..32 {
            let now = Instant::now();
            if now >= ends {
                reason = "session_expired";
                break 'running;
            }
            let command = match rx.try_recv() {
                Ok(Ok(c)) => c,
                Ok(Err(())) | Err(mpsc::TryRecvError::Disconnected) => {
                    reason = "input_closed";
                    break 'running;
                }
                Err(mpsc::TryRecvError::Empty) => break,
            };
            match command {
                Command::Close {
                    version,
                    session: target,
                } => {
                    reason = if version == 1 && target == session_id {
                        "closed"
                    } else {
                        "invalid_input"
                    };
                    break 'running;
                }
                Command::Input {
                    version,
                    session: target,
                    sequence,
                    epoch,
                    frame,
                    events,
                } => {
                    let state = handler.state.lock().unwrap();
                    let release_only =
                        events.len() == 1 && matches!(events[0], Input::ReleaseAll {});
                    if version != 1
                        || target != session_id
                        || (!release_only && epoch != state.epoch)
                        || !gate.accept(sequence, epoch, frame, &events, now)
                        || (!release_only
                            && (!request.control_requested
                                || !state.keyboard
                                || !state.peer
                                || !state.encrypted))
                    {
                        reason = "invalid_input";
                        exit = 1;
                        break 'running;
                    }
                    if now.duration_since(budget.0) >= Duration::from_secs(1) {
                        budget = (now, 0);
                    }
                    budget.1 += events.len();
                    if budget.1 > 256 {
                        reason = "input_rate_exceeded";
                        exit = 1;
                        break 'running;
                    }
                    for event in events {
                        if !pressed
                            .lock()
                            .unwrap()
                            .apply(&session, event, state.x, state.y)
                        {
                            reason = "invalid_input";
                            exit = 1;
                            break 'running;
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    pressed.lock().unwrap().release(&session);
    // Give queued releases the opportunity to reach the authenticated transport.
    std::thread::sleep(Duration::from_millis(100));
    session.close();
    if exit != 0 {
        output(&session_id, "error", json!({"reason":reason}));
    }
    output(
        &session_id,
        "closed",
        json!({"reason":reason,"phase":"closed","controlAvailable":false}),
    );
    exit
}

#[derive(Default)]
struct Pressed {
    keys: BTreeSet<String>,
    buttons: BTreeSet<i32>,
    x: i32,
    y: i32,
}
impl Pressed {
    fn modifiers(&self) -> Vec<hbb_common::protobuf::EnumOrUnknown<ControlKey>> {
        let mut out = Vec::new();
        for (left, right, key) in [
            ("ShiftLeft", "ShiftRight", ControlKey::Shift),
            ("ControlLeft", "ControlRight", ControlKey::Control),
            ("AltLeft", "AltRight", ControlKey::Alt),
            ("MetaLeft", "MetaRight", ControlKey::Meta),
        ] {
            if self.keys.contains(left) || self.keys.contains(right) {
                out.push(key.into());
            }
        }
        out
    }
    fn key(&self, session: &Session<Handler>, code: &str, down: bool) -> bool {
        let name = match policy::key_name(code) {
            Some(n) => n,
            None => return false,
        };
        let key = KEY_MAP.get(name.as_str()).cloned().or_else(|| match code {
            "Period" => Some(Key::Chr('.' as u32)),
            "Backquote" => Some(Key::Chr('`' as u32)),
            "Equal" => Some(Key::Chr('=' as u32)),
            _ => None,
        });
        let mut event = KeyEvent::new();
        match key {
            Some(Key::ControlKey(k)) => event.set_control_key(k),
            Some(Key::Chr(c)) | Some(Key::_Raw(c)) => event.set_chr(c),
            None => return false,
        };
        event.down = down;
        event.mode = KeyboardMode::Legacy.into();
        event.modifiers = self.modifiers();
        let mut msg = Message::new();
        msg.set_key_event(event);
        session.send(Data::Message(msg));
        true
    }
    fn mouse(&self, session: &Session<Handler>, mask: i32, x: i32, y: i32) {
        let mut event = MouseEvent {
            mask,
            x,
            y,
            ..Default::default()
        };
        event.modifiers = self.modifiers();
        let mut msg = Message::new();
        msg.set_mouse_event(event);
        session.send(Data::Message(msg));
    }
    fn apply(&mut self, session: &Session<Handler>, event: Input, ox: i32, oy: i32) -> bool {
        match event {
            Input::ReleaseAll {} => self.release(session),
            Input::Key { action, key } => {
                let down = action == "down";
                if down {
                    self.keys.insert(key.clone());
                } else {
                    self.keys.remove(&key);
                }
                if !self.key(session, &key, down) {
                    return false;
                }
            }
            Input::Text { text } => session.input_string(&text),
            Input::Pointer {
                action,
                x,
                y,
                button,
                delta_x,
                delta_y,
            } => {
                let (x, y) = match (x.checked_add(ox), y.checked_add(oy)) {
                    (Some(x), Some(y)) => (x, y),
                    _ => return false,
                };
                self.x = x;
                self.y = y;
                let b = match button.as_deref() {
                    Some("left") => 1,
                    Some("right") => 2,
                    Some("middle") => 4,
                    _ => 0,
                };
                match action.as_str() {
                    "move" => self.mouse(session, 0, x, y),
                    "down" => {
                        self.buttons.insert(b);
                        self.mouse(session, b << 3 | 1, x, y);
                    }
                    "up" => {
                        self.buttons.remove(&b);
                        self.mouse(session, b << 3 | 2, x, y);
                    }
                    "wheel" => {
                        // Browser delta is positive down/right; RustDesk wheel uses the opposite sign.
                        self.mouse(session, 3, -delta_x.unwrap_or(0), -delta_y.unwrap_or(0));
                    }
                    _ => return false,
                }
            }
        }
        true
    }
    fn release(&mut self, session: &Session<Handler>) {
        let keys = std::mem::take(&mut self.keys);
        for key in keys {
            self.key(session, &key, false);
        }
        let buttons = std::mem::take(&mut self.buttons);
        for b in buttons {
            self.mouse(session, b << 3 | 2, self.x, self.y);
        }
    }
}

#[allow(unused_variables)]
impl InvokeUiSession for Handler {
    fn set_peer_info(&self, pi: &PeerInfo) {
        if pi.platform != "Windows" {
            self.fail("unsupported_remote_platform");
            return;
        }
        if pi.current_display < 0 {
            self.fail("unsupported_display");
            return;
        }
        if let Some(d) = pi.displays.get(pi.current_display as usize) {
            self.geometry(
                pi.current_display as usize,
                d.x,
                d.y,
                d.width.max(0) as usize,
                d.height.max(0) as usize,
            );
        } else {
            self.fail("unsupported_display");
            return;
        }
        let mut s = self.state.lock().unwrap();
        if !s.encrypted {
            s.error = Some("encrypted_connection_required");
        } else {
            s.peer = true;
        }
        s.dirty = true;
    }
    fn set_connection_type(&self, is_secured: bool, direct: bool, stream_type: &str) {
        let mut s = self.state.lock().unwrap();
        s.encrypted = is_secured;
        if !is_secured {
            s.error = Some("encrypted_connection_required");
        }
        s.dirty = true;
    }
    fn set_permission(&self, name: &str, value: bool) {
        if name == "keyboard" {
            let mut s = self.state.lock().unwrap();
            s.keyboard = value;
            s.dirty = true;
        }
    }
    fn on_rgba(&self, display: usize, rgba: &mut scrap::ImageRgb) {
        let mut s = self.state.lock().unwrap();
        let now = Instant::now();
        if !s.encrypted
            || !s.peer
            || s.display != display
            || s.last
                .map_or(false, |t| now.duration_since(t) < policy::FRAME_INTERVAL)
        {
            return;
        }
        if rgba.w != s.w || rgba.h != s.h {
            s.epoch += 1;
            s.w = rgba.w;
            s.h = rgba.h;
            s.latest = None;
            s.dirty = true;
        }
        s.last = Some(now);
        if let Some(jpeg) = policy::jpeg(rgba) {
            s.sequence += 1;
            s.latest = Some(Frame {
                epoch: s.epoch,
                sequence: s.sequence,
                display,
                w: rgba.w,
                h: rgba.h,
                jpeg,
            });
        } else {
            s.error = Some("frame_limit_exceeded");
        }
    }
    fn switch_display(&self, d: &SwitchDisplay) {
        if d.display >= 0 {
            self.geometry(
                d.display as usize,
                d.x,
                d.y,
                d.width.max(0) as usize,
                d.height.max(0) as usize,
            );
        } else {
            self.fail("unsupported_display");
        }
    }
    fn msgbox(&self, msgtype: &str, title: &str, text: &str, link: &str, retry: bool) {
        self.fail("connection_unavailable");
    }
    fn new_message(&self, msg: String) {
        self.fail("connection_closed");
    }
    // Legacy callback means the connection dialog can close on the first video.
    fn close_success(&self) {}
    fn set_multiple_windows_session(&self, sessions: Vec<WindowsSession>) {
        self.fail("session_selection_required");
    }
    fn get_rgba(&self, display: usize) -> *const u8 {
        std::ptr::null()
    }
    #[cfg(feature = "flutter")]
    fn is_multi_ui_session(&self) -> bool {
        false
    }
    #[cfg(all(feature = "vram", feature = "flutter"))]
    fn on_texture(&self, display: usize, texture: *mut std::ffi::c_void) {
        self.fail("cpu_frame_required");
    }
    fn set_cursor_data(&self, cd: CursorData) {}
    fn set_cursor_id(&self, id: String) {}
    fn set_cursor_position(&self, cp: CursorPosition) {}
    fn set_display(&self, x: i32, y: i32, w: i32, h: i32, cursor_embedded: bool, scale: f64) {}
    fn set_displays(&self, displays: &Vec<DisplayInfo>) {}
    fn set_platform_additions(&self, data: &str) {}
    fn on_connected(&self, conn_type: ConnType) {}
    fn update_privacy_mode(&self) {}
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
    fn handle_terminal_response(&self, response: TerminalResponse) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_json_lines_and_eof() {
        assert!(line(&mut io::Cursor::new(vec![b'x'; policy::MAX_LINE + 1])).is_err());
        assert!(line(&mut io::Cursor::new(b"{}".to_vec())).is_err());
        assert!(line(&mut io::Cursor::new(Vec::<u8>::new()))
            .unwrap()
            .is_none());
    }
    #[test]
    fn all_dom_keys_resolve_in_existing_rustdesk_map() {
        for key in [
            "KeyA",
            "Digit9",
            "F12",
            "ControlRight",
            "MetaLeft",
            "ShiftRight",
            "Enter",
            "Equal",
        ] {
            let name = policy::key_name(key).unwrap();
            assert!(KEY_MAP.contains_key(name.as_str()) || key == "Equal");
        }
    }
    #[test]
    fn handler_requires_encryption_and_keyboard_permission() {
        let h = Handler::default();
        assert!(!h.state.lock().unwrap().keyboard);
        h.set_permission("keyboard", true);
        assert!(h.state.lock().unwrap().keyboard);
        h.set_connection_type(false, false, "");
        assert_eq!(
            h.state.lock().unwrap().error,
            Some("encrypted_connection_required")
        );
    }
    #[test]
    fn changing_geometry_invalidates_previous_epoch() {
        let h = Handler::default();
        h.geometry(0, 0, 0, 100, 100);
        let first = h.state.lock().unwrap().epoch;
        h.geometry(0, 0, 0, 100, 100);
        assert_eq!(first, h.state.lock().unwrap().epoch);
        h.geometry(0, -100, 0, 100, 100);
        assert!(h.state.lock().unwrap().epoch > first);
    }
    fn fake_session() -> (
        Session<Handler>,
        hbb_common::tokio::sync::mpsc::UnboundedReceiver<Data>,
    ) {
        let s = Session::<Handler>::default();
        let (tx, rx) = hbb_common::tokio::sync::mpsc::unbounded_channel();
        *s.sender.write().unwrap() = Some(tx);
        (s, rx)
    }
    #[test]
    fn actual_wire_key_button_release_and_display_origin() {
        let (s, mut rx) = fake_session();
        let mut p = Pressed::default();
        assert!(p.apply(
            &s,
            Input::Key {
                action: "down".into(),
                key: "ControlLeft".into()
            },
            0,
            0
        ));
        assert!(p.apply(
            &s,
            Input::Key {
                action: "down".into(),
                key: "KeyA".into()
            },
            0,
            0
        ));
        assert!(p.apply(
            &s,
            Input::Pointer {
                action: "down".into(),
                x: 5,
                y: 8,
                button: Some("left".into()),
                delta_x: None,
                delta_y: None
            },
            -100,
            200
        ));
        let mut messages = Vec::new();
        while let Ok(Data::Message(m)) = rx.try_recv() {
            messages.push(m);
        }
        assert_eq!(messages.len(), 3);
        let k = messages[1].key_event();
        assert!(k.down);
        assert_eq!(k.chr(), 'a' as u32);
        assert!(k.modifiers.contains(&ControlKey::Control.into()));
        let m = messages[2].mouse_event();
        assert_eq!((m.mask, m.x, m.y), (9, -95, 208));
        p.release(&s);
        let mut keys = 0;
        let mut buttons = 0;
        while let Ok(Data::Message(m)) = rx.try_recv() {
            match m.union {
                Some(message::Union::KeyEvent(k)) => {
                    assert!(!k.down);
                    keys += 1;
                }
                Some(message::Union::MouseEvent(m)) => {
                    assert_eq!(m.mask, 10);
                    buttons += 1;
                }
                _ => panic!("unexpected message"),
            }
        }
        assert_eq!((keys, buttons), (2, 1));
        assert!(p.keys.is_empty() && p.buttons.is_empty());
        p.release(&s);
        assert!(rx.try_recv().is_err());
    }
    #[test]
    fn actual_wire_wheel_direction_and_unicode_text() {
        let (s, mut rx) = fake_session();
        let mut p = Pressed::default();
        assert!(p.apply(
            &s,
            Input::Pointer {
                action: "wheel".into(),
                x: 0,
                y: 0,
                button: None,
                delta_x: Some(1),
                delta_y: Some(2)
            },
            0,
            0
        ));
        let m = match rx.try_recv().unwrap() {
            Data::Message(m) => m,
            _ => panic!(),
        };
        assert_eq!(
            (m.mouse_event().mask, m.mouse_event().x, m.mouse_event().y),
            (3, -1, -2)
        );
        assert!(p.apply(
            &s,
            Input::Text {
                text: "한글".into()
            },
            0,
            0
        ));
        let m = match rx.try_recv().unwrap() {
            Data::Message(m) => m,
            _ => panic!(),
        };
        assert_eq!(m.key_event().seq(), "한글");
    }
    #[test]
    fn frame_callback_has_one_latest_slot_and_five_fps_limit() {
        let h = Handler::default();
        {
            let mut s = h.state.lock().unwrap();
            s.peer = true;
            s.encrypted = true;
            s.w = 2;
            s.h = 2;
        }
        let mut image = scrap::ImageRgb::new(scrap::ImageFormat::ABGR, 1);
        image.w = 2;
        image.h = 2;
        image.raw = vec![255; 16];
        h.on_rgba(0, &mut image);
        let first = h.state.lock().unwrap().sequence;
        assert_eq!(first, 1);
        h.on_rgba(0, &mut image);
        assert_eq!(h.state.lock().unwrap().sequence, first);
        {
            h.state.lock().unwrap().last = None;
        }
        h.on_rgba(0, &mut image);
        let s = h.state.lock().unwrap();
        assert_eq!(s.sequence, 2);
        assert_eq!(s.latest.as_ref().unwrap().sequence, 2);
    }
}
