//! Public, bounded JSONL viewer protocol. No credential is ever serialized.
use serde::Deserialize;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

pub const MAX_LINE: usize = 32768;
pub const MAX_JPEG: usize = 512 * 1024;
pub const FRAME_INTERVAL: Duration = Duration::from_millis(200);
pub fn one() -> u8 {
    1
}
/// Existing host VERSION is numeric major.minor.patch. Do not echo arbitrary
/// strings received in a peer-info field, or manufacture a missing version.
pub fn valid_peer_version(version: &str) -> bool {
    let parts: Vec<_> = version.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 5
                && part.bytes().all(|b| b.is_ascii_digit())
                && part.parse::<u16>().is_ok()
        })
}

/// Caller holds the shared queue write lock; decoder popping holds its read lock.
/// At most one wake is needed while the next encoded frame is replaceable.
pub fn replace_latest<T>(queue: &crossbeam_queue::ArrayQueue<T>, value: T) -> bool {
    let wake = queue.is_empty();
    while queue.pop().is_some() {}
    queue.force_push(value);
    wake
}

/// Viewer input from the remote peer is a deliberately small protocol subset.
pub fn allowed_inbound(message: &hbb_common::message_proto::Message) -> bool {
    use hbb_common::message_proto::{message, misc, permission_info::Permission};
    match &message.union {
        Some(message::Union::Hash(_))
        | Some(message::Union::LoginResponse(_))
        | Some(message::Union::VideoFrame(_))
        | Some(message::Union::PeerInfo(_))
        | Some(message::Union::CursorData(_))
        | Some(message::Union::CursorId(_))
        | Some(message::Union::CursorPosition(_))
        | Some(message::Union::TestDelay(_)) => true,
        Some(message::Union::Misc(m)) => match &m.union {
            Some(misc::Union::PermissionInfo(p)) => {
                p.permission.enum_value() == Ok(Permission::Keyboard)
            }
            Some(misc::Union::SwitchDisplay(_)) | Some(misc::Union::CloseReason(_)) => true,
            _ => false,
        },
        _ => false,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Start {
    pub viewer_version: u8,
    pub session_id: String,
    pub device_id: String,
    pub address_id: String,
    pub password: String,
    #[serde(default, rename = "connection_token")]
    pub connection_token: Option<String>,
    pub control_requested: bool,
    pub max_seconds: u64,
}
impl Start {
    pub fn valid(&self) -> bool {
        self.viewer_version == 1
            && uuid::Uuid::parse_str(&self.session_id).is_ok()
            && uuid::Uuid::parse_str(&self.device_id).is_ok()
            && (6..=16).contains(&self.address_id.len())
            && self.address_id.bytes().all(|b| b.is_ascii_digit())
            && (1..=900).contains(&self.max_seconds)
            && !self.password.is_empty()
            && self.password.len() <= 256
            && !self.password.chars().any(char::is_control)
            && self
                .connection_token
                .as_ref()
                .map_or(true, |x| x.len() <= 4096)
    }
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Input {
    #[serde(rename = "pointer")]
    Pointer {
        action: String,
        x: i32,
        y: i32,
        #[serde(default)]
        button: Option<String>,
        #[serde(default, rename = "deltaX")]
        delta_x: Option<i32>,
        #[serde(default, rename = "deltaY")]
        delta_y: Option<i32>,
    },
    #[serde(rename = "key")]
    Key { action: String, key: String },
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "release-all")]
    ReleaseAll {},
}
#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Command {
    #[serde(rename = "input")]
    Input {
        #[serde(default = "one", rename = "viewerVersion")]
        version: u8,
        #[serde(rename = "sessionId")]
        session: String,
        sequence: u64,
        #[serde(rename = "frameEpoch")]
        epoch: u64,
        #[serde(rename = "frameSequence")]
        frame: u64,
        events: Vec<Input>,
    },
    #[serde(rename = "close")]
    Close {
        #[serde(default = "one", rename = "viewerVersion")]
        version: u8,
        #[serde(rename = "sessionId")]
        session: String,
    },
}

/// Only frames actually written to the output may authorize input.
#[derive(Default)]
pub struct Gate {
    pub sequence: u64,
    pub epoch: u64,
    pub width: usize,
    pub height: usize,
    frames: VecDeque<(u64, Instant)>,
}
impl Gate {
    pub fn sent(&mut self, epoch: u64, sequence: u64, w: usize, h: usize, now: Instant) {
        if self.epoch != epoch {
            self.frames.clear();
        }
        self.epoch = epoch;
        self.width = w;
        self.height = h;
        self.frames.push_back((sequence, now));
        while self.frames.len() > 12 {
            self.frames.pop_front();
        }
    }
    pub fn accept(
        &mut self,
        sequence: u64,
        epoch: u64,
        frame: u64,
        events: &[Input],
        now: Instant,
    ) -> bool {
        if sequence > self.sequence
            && events.len() == 1
            && matches!(events[0], Input::ReleaseAll {})
        {
            self.sequence = sequence;
            return true;
        }
        if sequence == 0
            || sequence <= self.sequence
            || epoch == 0
            || epoch != self.epoch
            || events.is_empty()
            || events.len() > 32
            || !events
                .iter()
                .all(|e| valid_event(e, self.width, self.height))
            || !self.frames.iter().any(|(n, t)| {
                *n == frame && now.saturating_duration_since(*t) <= Duration::from_secs(2)
            })
        {
            return false;
        }
        self.sequence = sequence;
        true
    }
}
pub fn valid_event(e: &Input, w: usize, h: usize) -> bool {
    match e {
        Input::Pointer {
            action,
            x,
            y,
            button,
            delta_x,
            delta_y,
        } => {
            *x >= 0
                && *y >= 0
                && (*x as usize) < w
                && (*y as usize) < h
                && match action.as_str() {
                    "move" => button.is_none() && delta_x.is_none() && delta_y.is_none(),
                    "down" | "up" => {
                        button
                            .as_deref()
                            .map_or(false, |b| matches!(b, "left" | "middle" | "right"))
                            && delta_x.is_none()
                            && delta_y.is_none()
                    }
                    "wheel" => {
                        button.is_none()
                            && delta_x.map_or(true, |v| (-120..=120).contains(&v))
                            && delta_y.map_or(true, |v| (-120..=120).contains(&v))
                            && (delta_x.unwrap_or(0) != 0 || delta_y.unwrap_or(0) != 0)
                    }
                    _ => false,
                }
        }
        Input::Key { action, key } => {
            matches!(action.as_str(), "down" | "up") && key_name(key).is_some()
        }
        Input::Text { text } => {
            !text.is_empty()
                && text.len() <= 1024
                && !text
                    .chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\t')
        }
        Input::ReleaseAll {} => true,
    }
}
/// A deliberate allowlist; never accepts RustDesk's special control actions.
pub fn key_name(code: &str) -> Option<String> {
    if code.len() == 4 && code.starts_with("Key") && code.as_bytes()[3].is_ascii_uppercase() {
        return Some(format!("VK_{}", &code[3..]));
    }
    if code.len() == 6 && code.starts_with("Digit") && code.as_bytes()[5].is_ascii_digit() {
        return Some(format!("VK_{}", &code[5..]));
    }
    if let Some(n) = code.strip_prefix('F').and_then(|s| s.parse::<u8>().ok()) {
        if (1..=12).contains(&n) && code == format!("F{n}") {
            return Some(format!("VK_F{n}"));
        }
    }
    Some(
        match code {
            "Enter" => "VK_RETURN",
            "Escape" => "VK_ESCAPE",
            "Backspace" => "VK_BACK",
            "Tab" => "VK_TAB",
            "Space" => "VK_SPACE",
            "ArrowLeft" => "VK_LEFT",
            "ArrowRight" => "VK_RIGHT",
            "ArrowUp" => "VK_UP",
            "ArrowDown" => "VK_DOWN",
            "Home" => "VK_HOME",
            "End" => "VK_END",
            "PageUp" => "VK_PRIOR",
            "PageDown" => "VK_NEXT",
            "Insert" => "VK_INSERT",
            "Delete" => "VK_DELETE",
            "ShiftLeft" => "VK_SHIFT",
            "ShiftRight" => "RShift",
            "ControlLeft" => "VK_CONTROL",
            "ControlRight" => "RControl",
            "AltLeft" => "VK_MENU",
            "AltRight" => "RAlt",
            "MetaLeft" => "Meta",
            "MetaRight" => "RWin",
            "CapsLock" => "VK_CAPITAL",
            "Comma" => "VK_COMMA",
            "Period" => "VK_PERIOD",
            "Slash" => "VK_SLASH",
            "Semicolon" => "VK_SEMICOLON",
            "Quote" => "VK_QUOTE",
            "BracketLeft" => "VK_LBRACKET",
            "BracketRight" => "VK_RBRACKET",
            "Backslash" => "VK_BACKSLASH",
            "Minus" => "VK_MINUS",
            "Equal" => "VK_EQUALS",
            "Backquote" => "VK_BACKQUOTE",
            _ => return None,
        }
        .to_owned(),
    )
}

/// libyuv ARGB is little-endian BGRA, ABGR is RGBA; Raw is RGB.
pub fn rgb(image: &scrap::ImageRgb) -> Option<Vec<u8>> {
    use scrap::ImageFormat;
    let (w, h, a) = (image.w, image.h, image.align);
    if w == 0 || h == 0 || w > 4096 || h > 2160 || a == 0 || a > 4096 || !a.is_power_of_two() {
        return None;
    }
    let bpp = match image.fmt {
        ImageFormat::Raw => 3,
        _ => 4,
    };
    let stride = (w * bpp + a - 1) & !(a - 1);
    if image.raw.len() < stride * h {
        return None;
    }
    let mut out = Vec::with_capacity(w * h * 3);
    for row in image.raw.chunks(stride).take(h) {
        for pixel in row[..w * bpp].chunks(bpp) {
            match image.fmt {
                ImageFormat::ARGB => out.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]),
                _ => out.extend_from_slice(&pixel[..3]),
            }
        }
    }
    Some(out)
}
pub fn jpeg(image: &scrap::ImageRgb) -> Option<Vec<u8>> {
    let rgb = rgb(image)?;
    for q in [75, 45, 20] {
        let mut encoded = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut encoded, q)
            .encode(&rgb, image.w as u32, image.h as u32, image::ColorType::Rgb8)
            .ok()?;
        if encoded.len() <= MAX_JPEG {
            return Some(encoded);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_actual_numeric_peer_versions_can_be_public() {
        assert!(valid_peer_version("1.4.9"));
        assert!(!valid_peer_version(""));
        assert!(!valid_peer_version("1.4.9 secret"));
        assert!(!valid_peer_version("1.4.9\n"));
        assert!(!valid_peer_version("70000.1.1"));
    }
    #[test]
    fn encoded_backlog_is_one_replaceable_frame_with_one_wake() {
        let q = crossbeam_queue::ArrayQueue::new(8);
        assert!(replace_latest(&q, 1));
        for n in 2..100 {
            assert!(!replace_latest(&q, n));
            assert_eq!(q.len(), 1);
        }
        assert_eq!(q.pop(), Some(99));
        assert!(replace_latest(&q, 100));
        assert_eq!(q.pop(), Some(100));
    }
    #[test]
    fn remote_files_audio_clipboard_commands_and_recording_are_not_processed() {
        use hbb_common::message_proto::*;
        let mut m = Message::new();
        m.set_clipboard(Clipboard::new());
        assert!(!allowed_inbound(&m));
        m.set_file_action(FileAction::new());
        assert!(!allowed_inbound(&m));
        m.set_audio_frame(AudioFrame::new());
        assert!(!allowed_inbound(&m));
        m.set_terminal_response(TerminalResponse::new());
        assert!(!allowed_inbound(&m));
        m.set_native_management_result(NativeManagementResult::new());
        assert!(!allowed_inbound(&m));
        let mut misc = Misc::new();
        misc.set_permission_info(PermissionInfo {
            permission: permission_info::Permission::Recording.into(),
            enabled: true,
            ..Default::default()
        });
        m.set_misc(misc);
        assert!(!allowed_inbound(&m));
        let mut misc = Misc::new();
        misc.set_permission_info(PermissionInfo {
            permission: permission_info::Permission::Keyboard.into(),
            enabled: true,
            ..Default::default()
        });
        m.set_misc(misc);
        assert!(allowed_inbound(&m));
        m.set_video_frame(VideoFrame::new());
        assert!(allowed_inbound(&m));
    }
    #[test]
    fn pixel_order_and_padding() {
        let mut i = scrap::ImageRgb::new(scrap::ImageFormat::ARGB, 16);
        i.w = 2;
        i.h = 2;
        i.raw = vec![0; 32];
        i.raw[..8].copy_from_slice(&[3, 2, 1, 255, 6, 5, 4, 255]);
        i.raw[16..24].copy_from_slice(&[9, 8, 7, 255, 12, 11, 10, 255]);
        assert_eq!(
            rgb(&i).unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        );
        i.fmt = scrap::ImageFormat::ABGR;
        assert_eq!(&rgb(&i).unwrap()[..3], &[3, 2, 1]);
        i.fmt = scrap::ImageFormat::Raw;
        assert_eq!(&rgb(&i).unwrap()[..6], &[3, 2, 1, 255, 6, 5]);
    }
    #[test]
    fn malformed_image_is_rejected() {
        let mut i = scrap::ImageRgb::new(scrap::ImageFormat::ABGR, 0);
        i.w = 1;
        i.h = 1;
        i.raw = vec![0; 4];
        assert!(rgb(&i).is_none());
        i.align = 3;
        assert!(rgb(&i).is_none());
        i.align = 1;
        i.w = 4097;
        assert!(rgb(&i).is_none());
        i.w = 1;
        i.raw.clear();
        assert!(rgb(&i).is_none());
    }
    #[test]
    fn jpeg_is_decodable_and_bounded() {
        let mut i = scrap::ImageRgb::new(scrap::ImageFormat::ABGR, 1);
        i.w = 3;
        i.h = 2;
        i.raw = vec![255; 24];
        let bytes = jpeg(&i).unwrap();
        assert!(bytes.len() <= MAX_JPEG);
        let d = image::load_from_memory(&bytes).unwrap();
        assert_eq!((d.width(), d.height()), (3, 2));
    }
    #[test]
    fn input_requires_recent_delivered_frame_and_monotonic_sequence() {
        let now = Instant::now();
        let mut g = Gate::default();
        let e = [Input::Text { text: "x".into() }];
        assert!(!g.accept(1, 1, 1, &e, now));
        g.sent(1, 1, 100, 100, now);
        assert!(g.accept(1, 1, 1, &e, now));
        assert!(!g.accept(1, 1, 1, &e, now));
        assert!(!g.accept(2, 1, 2, &e, now));
        assert!(!g.accept(2, 1, 1, &e, now + Duration::from_secs(3)));
        g.sent(2, 2, 100, 100, now);
        assert!(!g.accept(2, 1, 1, &e, now));
        assert!(g.accept(2, 2, 2, &e, now));
    }
    #[test]
    fn release_only_bypasses_frame_but_never_sequence() {
        let mut g = Gate::default();
        let now = Instant::now();
        assert!(g.accept(1, 0, 0, &[Input::ReleaseAll {}], now));
        assert!(!g.accept(1, 0, 0, &[Input::ReleaseAll {}], now));
        assert!(!g.accept(0, 0, 0, &[Input::ReleaseAll {}], now));
    }
    #[test]
    fn input_bounds_and_special_action_rejection() {
        assert!(key_name("KeyA").is_some());
        assert!(key_name("ControlRight").is_some());
        assert!(key_name("CTRL_ALT_DEL").is_none());
        assert!(key_name("LOCK_SCREEN").is_none());
        assert!(!valid_event(
            &Input::Pointer {
                action: "move".into(),
                x: 100,
                y: 0,
                button: None,
                delta_x: None,
                delta_y: None
            },
            100,
            100
        ));
        assert!(!valid_event(
            &Input::Text {
                text: "x".repeat(1025)
            },
            10,
            10
        ));
        assert!(
            serde_json::from_str::<Input>(r#"{"kind":"release-all","password":"secret"}"#).is_err()
        );
    }
    #[test]
    fn start_is_strict_and_never_accepts_command_or_target_url() {
        let make = |address: &str| {
            format!(
                r#"{{"viewerVersion":1,"sessionId":"550e8400-e29b-41d4-a716-446655440000","deviceId":"550e8400-e29b-41d4-a716-446655440001","addressId":"{address}","password":"fixture-only","controlRequested":false,"maxSeconds":1}}"#
            )
        };
        assert!(serde_json::from_str::<Start>(&make("74067020"))
            .unwrap()
            .valid());
        assert!(!serde_json::from_str::<Start>(&make("74067020@other"))
            .unwrap()
            .valid());
        let mut v: serde_json::Value = serde_json::from_str(&make("74067020")).unwrap();
        v["command"] = "whoami".into();
        assert!(serde_json::from_value::<Start>(v).is_err());
    }
}
